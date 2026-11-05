use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Response;
use chrono::{Duration, Local, Months, TimeZone};
use serde::Deserialize;
use serde_json::json;

use crate::api::extractors::{AdminUser, ApiError, ApiJson, ApiResult};
use crate::api::{ok_json, ok_message, AppState};
use crate::auth;
use crate::db::now_db;
use crate::models::User;

fn format_dt(dt: chrono::DateTime<Local>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S%.9f%:z").to_string()
}

/// 解析订阅时间：
/// - 日期格式 "2024-12-31"（视为当天结束前有效）
/// - 相对时间 "30d" / "1M" / "1y"
pub fn parse_subscription(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty subscription".to_string());
    }

    if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let naive = date.and_hms_opt(0, 0, 0).ok_or("invalid date")?;
        if let Some(start) = Local.from_local_datetime(&naive).single() {
            return Ok(format_dt(start + Duration::days(1) - Duration::seconds(1)));
        }
        return Err("invalid date".to_string());
    }

    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 2 {
        return Err("invalid format".to_string());
    }
    let unit = chars[chars.len() - 1];
    let value_str: String = chars[..chars.len() - 1].iter().collect();
    let value: i64 = value_str
        .parse()
        .map_err(|_| format!("invalid number: {value_str}"))?;

    let now = Local::now();
    match unit {
        'd' => Ok(format_dt(now + Duration::days(value))),
        'M' => {
            let months = u32::try_from(value).map_err(|_| "invalid month value".to_string())?;
            now.checked_add_months(Months::new(months))
                .map(format_dt)
                .ok_or_else(|| "invalid month value".to_string())
        }
        'y' => {
            let months = value
                .checked_mul(12)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| "invalid year value".to_string())?;
            now.checked_add_months(Months::new(months))
                .map(format_dt)
                .ok_or_else(|| "invalid year value".to_string())
        }
        _ => Err(format!("unsupported unit: {unit} (use d/M/y)")),
    }
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&state.db)
        .await?;
    Ok(ok_json(json!({ "success": true, "result": users })))
}

#[derive(Debug, Default, Deserialize)]
pub struct CreateUserRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub subscription: Option<String>,
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
    ApiJson(req): ApiJson<CreateUserRequest>,
) -> ApiResult<Response> {
    if req.username.chars().count() < 3 || req.password.chars().count() < 6 {
        return Err(ApiError::bad_request("用户名至少3位，密码至少6位"));
    }

    let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_one(&state.db)
        .await?;
    if existing > 0 {
        return Err(ApiError::conflict("用户名已存在"));
    }

    let hash =
        auth::hash_password(&req.password).map_err(|_| ApiError::internal("密码加密失败"))?;

    let role = if req.role == "admin" || req.role == "user" {
        req.role
    } else {
        "user".to_string()
    };

    let mut subscription: Option<String> = None;
    if let Some(raw) = req.subscription.as_deref() {
        if !raw.is_empty() {
            subscription = Some(
                parse_subscription(raw).map_err(|_| ApiError::bad_request("订阅时间格式错误"))?,
            );
        }
    }

    let now = now_db();
    let id = sqlx::query(
        "INSERT INTO users (username, password, role, is_active, must_change_password, subscription, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&req.username)
    .bind(&hash)
    .bind(&role)
    .bind(true)
    .bind(false)
    .bind(&subscription)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?
    .last_insert_rowid();

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await?;

    Ok(ok_json(json!({ "success": true, "result": user })))
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub subscription: Option<String>,
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    AdminUser(claims): AdminUser,
    ApiJson(req): ApiJson<UpdateUserRequest>,
) -> ApiResult<Response> {
    let mut user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("用户不存在"))?;

    if let Some(password) = req.password.as_deref() {
        if !password.is_empty() {
            if password.chars().count() < 6 {
                return Err(ApiError::bad_request("密码至少6位"));
            }
            user.password =
                auth::hash_password(password).map_err(|_| ApiError::internal("密码加密失败"))?;
        }
    }

    if let Some(role) = req.role.as_deref() {
        if role == "admin" || role == "user" {
            // 防止管理员把自己降级后失去所有管理入口
            if role == "user" && user.role == "admin" && claims.user_id == user.id {
                return Err(ApiError::bad_request("不能取消自己的管理员权限"));
            }
            user.role = role.to_string();
        }
    }

    if let Some(subscription) = req.subscription.as_deref() {
        if subscription.is_empty() {
            user.subscription = None;
        } else {
            user.subscription = Some(
                parse_subscription(subscription)
                    .map_err(|_| ApiError::bad_request("订阅时间格式错误"))?,
            );
        }
    }

    sqlx::query(
        "UPDATE users SET password = ?, role = ?, subscription = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&user.password)
    .bind(&user.role)
    .bind(&user.subscription)
    .bind(now_db())
    .bind(user.id)
    .execute(&state.db)
    .await?;

    user.updated_at = Some(now_db());
    Ok(ok_json(json!({ "success": true, "result": user })))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    AdminUser(claims): AdminUser,
) -> ApiResult<Response> {
    if claims.user_id == user_id {
        return Err(ApiError::bad_request("不能删除自己"));
    }

    let rule_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM forward_rules WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    if rule_count > 0 {
        return Err(ApiError::bad_request(format!(
            "该用户下有 {rule_count} 条转发规则，请先删除所有规则后再删除用户"
        )));
    }

    sqlx::query("DELETE FROM zone_users WHERE user_id = ?")
        .bind(user_id)
        .execute(&state.db)
        .await?;

    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("用户不存在"));
    }

    tracing::info!(
        admin = %claims.username,
        role = %claims.role,
        user_id,
        "[Admin] 删除用户"
    );
    Ok(ok_message("用户已删除"))
}

pub async fn toggle_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    AdminUser(claims): AdminUser,
) -> ApiResult<Response> {
    let mut user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("用户不存在"))?;

    if claims.user_id == user.id {
        return Err(ApiError::bad_request("不能禁用自己"));
    }

    user.is_active = !user.is_active;
    sqlx::query("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?")
        .bind(user.is_active)
        .bind(now_db())
        .bind(user.id)
        .execute(&state.db)
        .await?;

    user.updated_at = Some(now_db());
    Ok(ok_json(json!({ "success": true, "result": user })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_date_as_end_of_day() {
        let parsed = parse_subscription("2030-12-31").expect("date parses");
        let dt = crate::db::parse_db_time(&parsed).expect("formatted date parses");
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2030-12-31 23:59:59"
        );
    }

    #[test]
    fn parses_relative_units() {
        assert!(parse_subscription("30d").is_ok());
        assert!(parse_subscription("1M").is_ok());
        assert!(parse_subscription("1y").is_ok());
        assert!(parse_subscription("1w").is_err());
        assert!(parse_subscription("").is_err());
    }
}
