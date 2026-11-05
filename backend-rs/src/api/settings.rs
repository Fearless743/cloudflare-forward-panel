use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::api::extractors::{AdminUser, ApiError, ApiJson, ApiResult};
use crate::api::{ok_json, ok_message, AppState};
use crate::models::Setting;
use crate::telegram::TelegramClient;

pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let bytes = value.as_bytes();
    if bytes.len() <= 8 {
        return "****".to_string();
    }
    format!(
        "{}****{}",
        String::from_utf8_lossy(&bytes[..4]),
        String::from_utf8_lossy(&bytes[bytes.len() - 4..])
    )
}

async fn get_setting(
    state: &Arc<crate::api::AppState>,
    key: &str,
) -> Result<Option<Setting>, ApiError> {
    Ok(
        sqlx::query_as::<_, Setting>("SELECT * FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&state.db)
            .await?,
    )
}

pub async fn get_settings(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let token = get_setting(&state, "cf_api_token").await?;
    let telegram_token = get_setting(&state, "telegram_bot_token").await?;
    let telegram_chat_id = get_setting(&state, "telegram_chat_id").await?;

    Ok(ok_json(json!({
        "success": true,
        "result": {
            "cf_api_token": mask_secret(token.map(|s| s.value).unwrap_or_default().as_str()),
            "telegram_bot_token": mask_secret(telegram_token.map(|s| s.value).unwrap_or_default().as_str()),
            "telegram_chat_id": telegram_chat_id.map(|s| s.value).unwrap_or_default(),
        }
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(default)]
    pub cf_api_token: String,
    #[serde(default)]
    pub telegram_bot_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
}

async fn save_setting(state: &Arc<AppState>, key: &str, value: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(crate::db::now_db())
    .execute(&state.db)
    .await?;
    Ok(())
}

pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
    ApiJson(req): ApiJson<UpdateSettingsRequest>,
) -> ApiResult<Response> {
    let token = req.cf_api_token.trim();
    if !token.is_empty() && !token.contains("****") {
        save_setting(&state, "cf_api_token", token).await?;
    }

    let telegram_token = req.telegram_bot_token.trim();
    if !telegram_token.is_empty() && !telegram_token.contains("****") {
        save_setting(&state, "telegram_bot_token", telegram_token).await?;
    }

    save_setting(&state, "telegram_chat_id", req.telegram_chat_id.trim()).await?;

    state.manager.reload_accounts().await;

    Ok(ok_message("设置已保存"))
}

pub async fn test_connection(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let client = state
        .manager
        .get_client()
        .await
        .map_err(ApiError::bad_request)?;

    let zones = client
        .list_zones()
        .await
        .map_err(|e| ApiError::internal(format!("连接失败: {e}")))?;

    Ok(ok_json(json!({
        "success": true,
        "result": {
            "status": "ok",
            "zones_count": zones.len(),
        }
    })))
}

pub async fn test_telegram(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let token = get_setting(&state, "telegram_bot_token").await?;
    let chat_id = get_setting(&state, "telegram_chat_id").await?;

    let token = token.map(|s| s.value).unwrap_or_default();
    let chat_id = chat_id.map(|s| s.value).unwrap_or_default();
    if token.is_empty() || chat_id.is_empty() {
        return Err(ApiError::bad_request(
            "请先配置 Telegram Bot Token 和 Chat ID",
        ));
    }

    let client = TelegramClient::new(token, chat_id);
    client
        .send_message("✅ <b>测试通知</b>\n\nCloudflare 转发面板 Telegram 通知配置成功！")
        .await
        .map_err(|e| ApiError::internal(format!("发送测试通知失败: {e}")))?;

    Ok(ok_message("测试通知已发送"))
}
