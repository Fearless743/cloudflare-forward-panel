use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde_json::{json, Value};
use sqlx::SqlitePool;

use crate::api::extractors::ApiError;
use crate::cfclient::manager::Manager;
use crate::cfclient::Client;

pub mod accounts;
pub mod auth_handlers;
pub mod certs;
pub mod extractors;
pub mod forward;
pub mod rate_limit;
pub mod settings;
pub mod users;
pub mod zones;

pub struct AppState {
    pub db: SqlitePool,
    pub manager: Arc<Manager>,
    pub jwt_secret: Vec<u8>,
    pub rate_limiter: rate_limit::RateLimiter,
    /// 保证定时检查与手动检查不会并发执行，避免重复修复产生冲突记录。
    pub forward_check_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// {"success": true, "message": ...}
pub fn ok_message(message: &str) -> Response {
    Json(json!({ "success": true, "message": message })).into_response()
}

/// 直接返回自定义 JSON 对象。
pub fn ok_json(value: Value) -> Response {
    Json(value).into_response()
}

pub fn router(state: Arc<AppState>) -> Router {
    let auth_routes = Router::new()
        .route("/auth/login", post(auth_handlers::login))
        .route(
            "/auth/change-password",
            post(auth_handlers::change_password),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::limit_auth,
        ));

    let api = Router::new()
        .merge(auth_routes)
        // ---- 需要登录 ----
        .route("/auth/me", get(auth_handlers::get_current_user))
        // ---- 端口转发规则 ----
        .route(
            "/forward-rules",
            get(forward::list_forward_rules).post(forward::create_forward_rule),
        )
        .route(
            "/forward-rules/",
            get(forward::list_forward_rules).post(forward::create_forward_rule),
        )
        .route("/forward-rules/zones", get(forward::list_local_zones))
        .route("/forward-rules/check", post(forward::check_forward_rules))
        .route(
            "/forward-rules/check/status",
            get(forward::forward_check_status),
        )
        .route(
            "/forward-rules/{ruleID}",
            put(forward::update_forward_rule).delete(forward::delete_forward_rule),
        )
        .route(
            "/forward-rules/{ruleID}/toggle",
            post(forward::toggle_forward_rule),
        )
        // ---- 系统设置 ----
        .route(
            "/settings",
            get(settings::get_settings).put(settings::update_settings),
        )
        .route("/settings/test", post(settings::test_connection))
        .route("/settings/test-telegram", post(settings::test_telegram))
        // ---- 账号管理 ----
        .route(
            "/accounts",
            get(accounts::list_accounts).post(accounts::create_account),
        )
        .route(
            "/accounts/",
            get(accounts::list_accounts).post(accounts::create_account),
        )
        .route("/accounts/status", get(accounts::get_account_status))
        .route(
            "/accounts/{accountID}",
            put(accounts::update_account).delete(accounts::delete_account),
        )
        .route(
            "/accounts/{accountID}/toggle",
            post(accounts::toggle_account),
        )
        .route(
            "/accounts/{accountID}/unblock",
            post(accounts::unblock_account),
        )
        // ---- 域名管理 ----
        .route("/zones", get(zones::list_zones).post(zones::create_zone))
        .route("/zones/", get(zones::list_zones).post(zones::create_zone))
        .route("/zones/{zoneID}", get(zones::get_zone))
        .route("/zones/{zoneID}/users", put(zones::update_zone_users))
        .route(
            "/zones/{zoneID}/dns",
            get(zones::list_dns_records).post(zones::create_dns_record),
        )
        .route(
            "/zones/{zoneID}/dns/",
            get(zones::list_dns_records).post(zones::create_dns_record),
        )
        .route(
            "/zones/{zoneID}/ssl",
            get(zones::get_ssl_settings).patch(zones::update_ssl_settings),
        )
        .route(
            "/zones/{zoneID}/ssl/",
            get(zones::get_ssl_settings).patch(zones::update_ssl_settings),
        )
        // ---- DNS 记录 ----
        .route(
            "/dns/{recordID}",
            put(zones::update_dns_record).delete(zones::delete_dns_record),
        )
        // ---- Origin 证书 ----
        .route(
            "/origin-certificates",
            post(certs::generate_origin_certificate),
        )
        // ---- 用户管理 ----
        .route("/users", get(users::list_users).post(users::create_user))
        .route(
            "/users/{userID}",
            put(users::update_user).delete(users::delete_user),
        )
        .route("/users/{userID}/toggle", post(users::toggle_user))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024));

    Router::new()
        .nest("/api", api)
        .fallback(static_handler)
        .layer(middleware::from_fn(cors_middleware))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

fn cors_allowed_origins() -> &'static Vec<String> {
    static ORIGINS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    ORIGINS.get_or_init(|| {
        std::env::var("CORS_ORIGINS")
            .ok()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    })
}

async fn cors_middleware(req: axum::extract::Request, next: Next) -> Response {
    let is_options = req.method() == Method::OPTIONS;
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut response = if is_options {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };

    let allowlist = cors_allowed_origins();
    if let Some(origin) = origin {
        let allowed = if allowlist.iter().any(|o| o == "*") {
            Some("*".to_string())
        } else if allowlist.iter().any(|o| o == &origin) {
            Some(origin)
        } else {
            None
        };
        if let Some(value) = allowed {
            let headers = response.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&value) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            }
            if value != "*" {
                headers.insert(header::VARY, HeaderValue::from_static("Origin"));
            }
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Content-Type, Authorization"),
            );
            headers.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("600"),
            );
        }
    }
    response
}

// ---------------------------------------------------------------------------
// 内嵌前端静态资源（SPA：找不到文件时回退 index.html）
// ---------------------------------------------------------------------------

#[derive(RustEmbed)]
#[folder = "frontend/dist"]
struct Assets;

async fn static_handler(uri: axum::http::Uri) -> Response {
    let raw_path = uri.path().trim_start_matches('/');
    let path = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if let Some(file) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref().to_string())],
            file.data,
        )
            .into_response();
    }

    match Assets::get("index.html") {
        Some(index) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
            index.data,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

impl AppState {
    pub async fn cf_client(&self) -> Result<Arc<Client>, ApiError> {
        self.manager
            .get_client()
            .await
            .map_err(ApiError::bad_request)
    }

    /// 获取指定账号的客户端；account_id 为 0（历史数据无归属）时回退到轮询客户端。
    pub async fn cf_client_for_account(&self, account_id: i64) -> Result<Arc<Client>, ApiError> {
        if account_id == 0 {
            return self.cf_client().await;
        }
        self.manager
            .get_client_by_account_id(account_id)
            .await
            .map_err(ApiError::bad_request)
    }

    /// 根据本地 Zone 镜像找到所属账号，用对应账号的凭证操作。
    pub async fn cf_client_for_zone(&self, zone_id: &str) -> Result<Arc<Client>, ApiError> {
        let account_id =
            sqlx::query_scalar::<_, i64>("SELECT account_id FROM zones WHERE cf_id = ?")
                .bind(zone_id)
                .fetch_optional(&self.db)
                .await
                .ok()
                .flatten()
                .unwrap_or(0);

        if account_id != 0 {
            self.cf_client_for_account(account_id).await
        } else {
            self.cf_client().await
        }
    }
}
