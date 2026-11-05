use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::api::AppState;
use crate::auth::{self, Claims};

/// 统一的 API 错误：以 {"error": "..."} 返回（与 Go 版 writeJSONError/respondError 兼容）。#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    pub fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::internal(err.to_string())
    }
}

impl From<crate::cfclient::CfError> for ApiError {
    fn from(err: crate::cfclient::CfError) -> Self {
        ApiError::bad_request(err.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// 已认证用户（携带数据库中的实时角色）。
pub struct AuthUser(pub Claims);

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("未提供认证信息"))?;

        let mut split = auth_header.splitn(2, ' ');
        let scheme = split.next().unwrap_or_default();
        let token = split.next().unwrap_or_default();
        if scheme != "Bearer" || token.is_empty() {
            return Err(ApiError::unauthorized("认证格式错误"));
        }

        let mut claims = auth::parse_token(&state.jwt_secret, token)
            .ok_or_else(|| ApiError::unauthorized("登录已过期，请重新登录"))?;

        // 每次请求校验用户状态，并用数据库实时角色覆盖 token 快照。
        let user = sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id = ?")
            .bind(claims.user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| ApiError::unauthorized("账号已禁用或不存在"))?;

        let Some(user) = user else {
            return Err(ApiError::unauthorized("账号已禁用或不存在"));
        };
        if !user.is_active {
            return Err(ApiError::unauthorized("账号已禁用或不存在"));
        }
        claims.role = user.role;
        claims.must_change_password = user.must_change_password;

        // 需要强制修改密码时，仅允许访问修改密码接口。
        if claims.must_change_password && !parts.uri.path().ends_with("/auth/change-password") {
            return Err(ApiError::forbidden("首次登录需修改密码"));
        }

        Ok(AuthUser(claims))
    }
}

/// JSON 请求体提取器：解析失败时与 Go 版一样返回 {"error":"invalid request body"}。
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|_| ApiError::bad_request("invalid request body"))?;
        Ok(ApiJson(value))
    }
}

/// 管理员用户。
pub struct AdminUser(pub Claims);

impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;
        if claims.role != "admin" {
            return Err(ApiError::forbidden("需要管理员权限"));
        }
        Ok(AdminUser(claims))
    }
}
