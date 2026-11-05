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

/// 读取单个设置值（不存在时返回 None），供其他模块复用。
pub(crate) async fn setting_value(state: &Arc<AppState>, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

pub async fn get_settings(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let token = get_setting(&state, "cf_api_token").await?;
    let telegram_token = get_setting(&state, "telegram_bot_token").await?;
    let telegram_chat_id = get_setting(&state, "telegram_chat_id").await?;

    let check_enabled = setting_value(&state, "forward_check_enabled")
        .await
        .map(|v| v != "false")
        .unwrap_or(true);
    let check_interval_minutes = setting_value(&state, "forward_check_interval")
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30)
        .clamp(1, 1440);
    let check_auto_fix = setting_value(&state, "forward_check_auto_fix")
        .await
        .map(|v| v != "false")
        .unwrap_or(true);
    let check_last_report = setting_value(&state, "forward_check_last_report")
        .await
        .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
        .unwrap_or(serde_json::Value::Null);

    Ok(ok_json(json!({
        "success": true,
        "result": {
            "cf_api_token": mask_secret(token.map(|s| s.value).unwrap_or_default().as_str()),
            "telegram_bot_token": mask_secret(telegram_token.map(|s| s.value).unwrap_or_default().as_str()),
            "telegram_chat_id": telegram_chat_id.map(|s| s.value).unwrap_or_default(),
            "check_enabled": check_enabled,
            "check_interval_minutes": check_interval_minutes,
            "check_auto_fix": check_auto_fix,
            "check_last_report": check_last_report,
        }
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(default)]
    pub cf_api_token: Option<String>,
    #[serde(default)]
    pub telegram_bot_token: Option<String>,
    #[serde(default)]
    pub telegram_chat_id: Option<String>,
    #[serde(default)]
    pub check_enabled: Option<bool>,
    #[serde(default)]
    pub check_interval_minutes: Option<i64>,
    #[serde(default)]
    pub check_auto_fix: Option<bool>,
}

pub(crate) async fn save_setting(
    state: &Arc<AppState>,
    key: &str,
    value: &str,
) -> Result<(), ApiError> {
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
    if let Some(value) = req.cf_api_token.as_deref() {
        let token = value.trim();
        if !token.is_empty() && !token.contains("****") {
            save_setting(&state, "cf_api_token", token).await?;
        }
    }

    if let Some(value) = req.telegram_bot_token.as_deref() {
        let telegram_token = value.trim();
        if !telegram_token.is_empty() && !telegram_token.contains("****") {
            save_setting(&state, "telegram_bot_token", telegram_token).await?;
        }
    }

    if let Some(value) = req.telegram_chat_id.as_deref() {
        save_setting(&state, "telegram_chat_id", value.trim()).await?;
    }

    if let Some(enabled) = req.check_enabled {
        save_setting(
            &state,
            "forward_check_enabled",
            if enabled { "true" } else { "false" },
        )
        .await?;
    }

    if let Some(interval) = req.check_interval_minutes {
        let interval = interval.clamp(1, 1440);
        save_setting(&state, "forward_check_interval", &interval.to_string()).await?;
    }

    if let Some(auto_fix) = req.check_auto_fix {
        save_setting(
            &state,
            "forward_check_auto_fix",
            if auto_fix { "true" } else { "false" },
        )
        .await?;
    }

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
