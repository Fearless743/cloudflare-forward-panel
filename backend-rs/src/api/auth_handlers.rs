use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::api::extractors::{ApiError, ApiJson, ApiResult, AuthUser};
use crate::api::{ok_json, AppState};
use crate::auth;
use crate::models::User;

#[derive(Debug, Default, Deserialize)]
pub struct LoginRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<LoginRequest>,
) -> ApiResult<Response> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&state.db)
        .await?;

    let Some(user) = user else {
        return Err(ApiError::unauthorized("用户名或密码错误"));
    };

    if !user.is_active {
        return Err(ApiError::forbidden("账号已禁用"));
    }

    if !auth::check_password(&req.password, &user.password) {
        return Err(ApiError::unauthorized("用户名或密码错误"));
    }

    let token = auth::generate_token(
        &state.jwt_secret,
        user.id,
        &user.username,
        &user.role,
        user.must_change_password,
    )
    .map_err(|_| ApiError::internal("生成token失败"))?;

    Ok(ok_json(json!({
        "success": true,
        "result": {
            "token": token,
            "username": user.username,
            "role": user.role,
            "must_change_password": user.must_change_password,
        }
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(default)]
    pub old_password: String,
    #[serde(default)]
    pub new_password: String,
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    AuthUser(claims): AuthUser,
    ApiJson(req): ApiJson<ChangePasswordRequest>,
) -> ApiResult<Response> {
    if req.new_password.chars().count() < 6 {
        return Err(ApiError::bad_request("新密码至少6位"));
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(claims.user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("用户不存在"))?;

    if !auth::check_password(&req.old_password, &user.password) {
        return Err(ApiError::bad_request("原密码错误"));
    }

    if req.new_password == req.old_password {
        return Err(ApiError::bad_request("新密码不能与原密码相同"));
    }

    let hash =
        auth::hash_password(&req.new_password).map_err(|_| ApiError::internal("密码加密失败"))?;

    sqlx::query(
        "UPDATE users SET password = ?, must_change_password = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&hash)
    .bind(false)
    .bind(crate::db::now_db())
    .bind(user.id)
    .execute(&state.db)
    .await?;

    let token = auth::generate_token(
        &state.jwt_secret,
        user.id,
        &user.username,
        &user.role,
        false,
    )
    .map_err(|_| ApiError::internal("生成token失败"))?;

    Ok(ok_json(json!({
        "success": true,
        "result": { "token": token }
    })))
}

pub async fn get_current_user(
    State(_state): State<Arc<AppState>>,
    AuthUser(claims): AuthUser,
) -> Response {
    ok_json(json!({
        "success": true,
        "result": {
            "user_id": claims.user_id,
            "username": claims.username,
            "role": claims.role,
        }
    }))
}
