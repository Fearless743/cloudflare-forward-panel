use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::api::extractors::{AdminUser, ApiError, ApiJson, ApiResult};
use crate::api::settings::mask_secret;
use crate::api::{ok_json, ok_message, AppState};
use crate::db::now_db;
use crate::models::CfAccount;

pub async fn list_accounts(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let mut accounts = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts")
        .fetch_all(&state.db)
        .await?;
    for account in &mut accounts {
        account.api_key = mask_secret(&account.api_key);
    }
    Ok(ok_json(json!({ "success": true, "result": accounts })))
}

#[derive(Debug, Default, Deserialize)]
pub struct CreateAccountRequest {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub api_key: String,
    /// token（Account API Token，默认）或 global_key（旧版 Global API Key）
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub account_id: String,
}

fn normalize_auth_type(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "token" | "account_token" | "account_api_token" => Some("token"),
        "global_key" | "global" | "global_api_key" => Some("global_key"),
        _ => None,
    }
}

pub async fn create_account(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
    ApiJson(req): ApiJson<CreateAccountRequest>,
) -> ApiResult<Response> {
    let auth_type = normalize_auth_type(&req.auth_type)
        .ok_or_else(|| ApiError::bad_request("auth_type 仅支持 token 或 global_key"))?;
    if req.api_key.trim().is_empty() {
        return Err(ApiError::bad_request("api_key is required"));
    }
    if auth_type == "global_key" && req.email.trim().is_empty() {
        return Err(ApiError::bad_request("使用 Global API Key 时邮箱必填"));
    }
    if auth_type == "token" && req.account_id.trim().is_empty() {
        return Err(ApiError::bad_request(
            "使用 Account API Token 时请填写 CF 账号 ID",
        ));
    }

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM cf_accounts")
        .fetch_one(&state.db)
        .await?;
    let name = format!("账号{}", count + 1);

    let now = now_db();
    let id = sqlx::query(
        "INSERT INTO cf_accounts (name, email, api_key, auth_type, account_id, is_active, is_blocked, error_msg, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&name)
    .bind(req.email.trim())
    .bind(req.api_key.trim())
    .bind(auth_type)
    .bind(req.account_id.trim())
    .bind(true)
    .bind(false)
    .bind("")
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?
    .last_insert_rowid();

    // 刷新管理器、同步新账号 Zone、立即处理导入任务与封禁迁移
    state.manager.reload_accounts().await;
    state.manager.sync_local_zones().await;
    crate::api::forward::migrate_blocked_accounts(&state).await;

    let mut account = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    account.api_key = mask_secret(&account.api_key);

    Ok(ok_json(json!({ "success": true, "result": account })))
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateAccountRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub auth_type: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
}

pub async fn update_account(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<i64>,
    AdminUser(_claims): AdminUser,
    ApiJson(req): ApiJson<UpdateAccountRequest>,
) -> ApiResult<Response> {
    let mut account = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts WHERE id = ?")
        .bind(account_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;

    if let Some(email) = req.email.as_deref() {
        if !email.trim().is_empty() {
            account.email = email.trim().to_string();
        }
    }
    if let Some(api_key) = req.api_key.as_deref() {
        if !api_key.is_empty() && !api_key.contains("****") {
            account.api_key = api_key.trim().to_string();
        }
    }
    if let Some(auth_type) = req.auth_type.as_deref() {
        account.auth_type = normalize_auth_type(auth_type)
            .ok_or_else(|| ApiError::bad_request("auth_type 仅支持 token 或 global_key"))?
            .to_string();
    }
    // 使用 Option 区分「未传」与「传空字符串」：允许清空 CF 账号 ID
    if let Some(account_identifier) = req.account_id.as_deref() {
        account.account_id = account_identifier.trim().to_string();
    }

    if account.auth_type == "global_key" && account.email.trim().is_empty() {
        return Err(ApiError::bad_request("使用 Global API Key 时邮箱必填"));
    }
    if account.auth_type == "token" && account.account_id.trim().is_empty() {
        return Err(ApiError::bad_request(
            "使用 Account API Token 时请填写 CF 账号 ID",
        ));
    }

    sqlx::query(
        "UPDATE cf_accounts SET email = ?, api_key = ?, auth_type = ?, account_id = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&account.email)
    .bind(&account.api_key)
    .bind(&account.auth_type)
    .bind(&account.account_id)
    .bind(now_db())
    .bind(account.id)
    .execute(&state.db)
    .await?;

    state.manager.reload_accounts().await;
    state.manager.sync_local_zones().await;
    Ok(ok_message("账号已更新"))
}

pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<i64>,
    AdminUser(claims): AdminUser,
) -> ApiResult<Response> {
    let rule_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM forward_rules WHERE account_id = ?")
            .bind(account_id)
            .fetch_one(&state.db)
            .await?;
    if rule_count > 0 {
        return Err(ApiError::bad_request(format!(
            "该账号下有 {rule_count} 条转发规则，请先删除所有规则后再删除账号"
        )));
    }

    // 事务保护：删除账号 + 删除 Zone 镜像 + 域名分配关系原子完成。
    let mut tx = state.db.begin().await?;

    sqlx::query("DELETE FROM cf_accounts WHERE id = ?")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "DELETE FROM zone_users WHERE zone_id IN (SELECT id FROM zones WHERE account_id = ?)",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM zones WHERE account_id = ?")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    state.manager.reload_accounts().await;

    tracing::info!(
        admin = %claims.username,
        role = %claims.role,
        account_id,
        "[Admin] 删除 CF 账号"
    );
    Ok(ok_message("账号已删除"))
}

pub async fn toggle_account(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<i64>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let mut account = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts WHERE id = ?")
        .bind(account_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;

    account.is_active = !account.is_active;
    sqlx::query("UPDATE cf_accounts SET is_active = ?, updated_at = ? WHERE id = ?")
        .bind(account.is_active)
        .bind(now_db())
        .bind(account.id)
        .execute(&state.db)
        .await?;

    state.manager.reload_accounts().await;

    if account.is_active {
        state.manager.sync_local_zones().await;
    }

    Ok(ok_json(json!({ "success": true, "result": account })))
}

pub async fn unblock_account(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<i64>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    sqlx::query(
        "UPDATE cf_accounts SET is_blocked = ?, error_msg = ?, updated_at = ? WHERE id = ?",
    )
    .bind(false)
    .bind("")
    .bind(now_db())
    .bind(account_id)
    .execute(&state.db)
    .await?;

    state.manager.reload_accounts().await;
    state.manager.sync_local_zones().await;

    Ok(ok_message("账号已解除封禁"))
}

pub async fn get_account_status(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let status = state.manager.get_status().await;
    Ok(ok_json(json!({ "success": true, "result": status })))
}
