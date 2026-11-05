use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::extractors::{AdminUser, ApiError, ApiJson, ApiResult};
use crate::api::{ok_json, AppState};
use crate::cfclient::DnsRecord;
use crate::db::{now_db, placeholders};
use crate::models::{CfAccount, User, Zone, ZoneUser};

// ---------------------------------------------------------------------------
// 域名管理
// ---------------------------------------------------------------------------

pub async fn list_zones(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    if state.manager.client_count().await == 0 {
        return Err(ApiError::bad_request("没有可用的 Cloudflare 账号"));
    }

    let zones = state.manager.list_all_zones().await;
    let cf_ids: Vec<String> = zones.iter().map(|z| z.id.clone()).collect();

    let mut local_zones: Vec<Zone> = Vec::new();
    if !cf_ids.is_empty() {
        let sql = format!(
            "SELECT * FROM zones WHERE cf_id IN ({})",
            placeholders(cf_ids.len())
        );
        let mut query = sqlx::query_as::<_, Zone>(&sql);
        for id in &cf_ids {
            query = query.bind(id);
        }
        local_zones = query.fetch_all(&state.db).await?;
    }

    let local_by_cfid: HashMap<String, Zone> = local_zones
        .iter()
        .map(|z| (z.cf_id.clone(), z.clone()))
        .collect();
    let local_ids: Vec<i64> = local_zones.iter().map(|z| z.id).collect();

    let accounts = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts")
        .fetch_all(&state.db)
        .await?;
    let account_names: HashMap<i64, String> =
        accounts.into_iter().map(|a| (a.id, a.name)).collect();

    let mut assignments_by_zone: HashMap<i64, Vec<i64>> = HashMap::new();
    if !local_ids.is_empty() {
        let sql = format!(
            "SELECT * FROM zone_users WHERE zone_id IN ({}) ORDER BY id ASC",
            placeholders(local_ids.len())
        );
        let mut query = sqlx::query_as::<_, ZoneUser>(&sql);
        for id in &local_ids {
            query = query.bind(id);
        }
        for assignment in query.fetch_all(&state.db).await? {
            assignments_by_zone
                .entry(assignment.zone_id)
                .or_default()
                .push(assignment.user_id);
        }
    }

    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&state.db)
        .await?;
    let usernames: HashMap<i64, String> = users.into_iter().map(|u| (u.id, u.username)).collect();

    let result: Vec<Value> = zones
        .into_iter()
        .map(|zone| {
            let mut item = serde_json::to_value(&zone).unwrap_or_else(|_| json!({}));
            let mut account_id = 0;
            let mut account_name = String::new();
            let mut user_ids: Vec<i64> = Vec::new();
            let mut assigned_names: Vec<String> = Vec::new();

            if let Some(local) = local_by_cfid.get(&zone.id) {
                account_id = local.account_id;
                account_name = account_names
                    .get(&local.account_id)
                    .cloned()
                    .unwrap_or_default();
                if let Some(ids) = assignments_by_zone.get(&local.id) {
                    for uid in ids {
                        user_ids.push(*uid);
                        assigned_names.push(usernames.get(uid).cloned().unwrap_or_default());
                    }
                }
            }

            if let Value::Object(map) = &mut item {
                map.insert("account_id".to_string(), json!(account_id));
                map.insert("account_name".to_string(), json!(account_name));
                map.insert("user_ids".to_string(), json!(user_ids));
                map.insert("usernames".to_string(), json!(assigned_names));
            }
            item
        })
        .collect();

    Ok(ok_json(json!({ "success": true, "result": result })))
}

#[derive(Debug, Default, Deserialize)]
pub struct CreateZoneRequest {
    #[serde(default)]
    pub account_id: i64,
    #[serde(default)]
    pub domain: String,
}

fn domain_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
        )
        .expect("valid domain regex")
    })
}

pub async fn create_zone(
    State(state): State<Arc<AppState>>,
    AdminUser(claims): AdminUser,
    ApiJson(req): ApiJson<CreateZoneRequest>,
) -> ApiResult<Response> {
    if req.account_id == 0 {
        return Err(ApiError::bad_request("请选择要添加到的 CF 账号"));
    }

    let domain = req
        .domain
        .trim()
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();
    if domain.len() > 253 || !domain_regex().is_match(&domain) {
        return Err(ApiError::bad_request(
            "域名格式不正确，请输入根域名，例如 example.com",
        ));
    }

    let account = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts WHERE id = ?")
        .bind(req.account_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("CF 账号不存在"))?;

    if account.is_blocked {
        return Err(ApiError::bad_request("该账号已被封禁，无法添加域名"));
    }

    let client = state.cf_client_for_account(account.id).await?;

    // 目标账号已有同名 Zone 时直接复用，避免重复创建报错。
    let zones = client
        .list_all_zones()
        .await
        .map_err(|e| ApiError::bad_gateway(format!("查询账号域名失败: {e}")))?;
    let mut zone = zones
        .into_iter()
        .find(|z| z.name.eq_ignore_ascii_case(&domain));
    let existed = zone.is_some();

    if zone.is_none() {
        // 已接入其他账号的域名不允许重复添加（多账号下会产生归属歧义）。
        let other = sqlx::query_as::<_, Zone>(
            "SELECT * FROM zones WHERE LOWER(name) = ? AND account_id <> ? ORDER BY id ASC LIMIT 1",
        )
        .bind(&domain)
        .bind(account.id)
        .fetch_optional(&state.db)
        .await?;

        if let Some(other) = other {
            let mut other_name = format!("账号 {}", other.account_id);
            if let Ok(Some(other_account)) =
                sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts WHERE id = ?")
                    .bind(other.account_id)
                    .fetch_optional(&state.db)
                    .await
            {
                if !other_account.name.is_empty() {
                    other_name = other_account.name;
                }
            }
            return Err(ApiError::conflict(format!(
                "域名已存在于 {other_name}，不能重复添加"
            )));
        }

        zone = Some(
            client
                .create_zone(&domain)
                .await
                .map_err(|e| ApiError::bad_gateway(format!("创建 Zone 失败: {e}")))?,
        );
    }
    let zone = zone.expect("zone exists");

    // 写入/更新本地 Zone 镜像：多账号场景下必须记录归属。
    let existing_local = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE cf_id = ?")
        .bind(&zone.id)
        .fetch_optional(&state.db)
        .await?;

    match existing_local {
        None => {
            sqlx::query(
                "INSERT INTO zones (cf_id, account_id, name, status, name_servers, plan, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&zone.id)
            .bind(account.id)
            .bind(&zone.name)
            .bind(&zone.status)
            .bind(zone.name_servers.join(","))
            .bind(&zone.plan.name)
            .bind(now_db())
            .bind(now_db())
            .execute(&state.db)
            .await?;
        }
        Some(local) => {
            sqlx::query(
                "UPDATE zones SET account_id = ?, name = ?, status = ?, name_servers = ?, plan = ?, updated_at = ? WHERE id = ?",
            )
            .bind(account.id)
            .bind(&zone.name)
            .bind(&zone.status)
            .bind(zone.name_servers.join(","))
            .bind(&zone.plan.name)
            .bind(now_db())
            .bind(local.id)
            .execute(&state.db)
            .await?;
        }
    }

    let action = if existed { "同步已有" } else { "添加" };
    tracing::info!(
        admin = %claims.username,
        account = %account.name,
        action,
        domain = %zone.name,
        "[Admin] 域名操作"
    );

    Ok(ok_json(json!({
        "success": true,
        "result": zone,
        "existed": existed,
        "account_id": account.id,
        "account_name": account.name,
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateZoneUsersRequest {
    #[serde(default)]
    pub user_ids: Vec<i64>,
}

pub async fn update_zone_users(
    State(state): State<Arc<AppState>>,
    Path(zone_cfid): Path<String>,
    AdminUser(claims): AdminUser,
    ApiJson(req): ApiJson<UpdateZoneUsersRequest>,
) -> ApiResult<Response> {
    let zone = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE cf_id = ?")
        .bind(&zone_cfid)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("域名不存在或尚未同步到本地"))?;

    // 校验用户存在并去重
    let mut seen = std::collections::HashSet::new();
    let mut user_ids = Vec::new();
    for uid in req.user_ids {
        if !seen.insert(uid) {
            continue;
        }
        let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE id = ?")
            .bind(uid)
            .fetch_one(&state.db)
            .await?;
        if exists == 0 {
            return Err(ApiError::bad_request(format!("用户 {uid} 不存在")));
        }
        user_ids.push(uid);
    }

    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM zone_users WHERE zone_id = ?")
        .bind(zone.id)
        .execute(&mut *tx)
        .await?;
    for uid in &user_ids {
        sqlx::query("INSERT INTO zone_users (zone_id, user_id, created_at) VALUES (?, ?, ?)")
            .bind(zone.id)
            .bind(uid)
            .bind(now_db())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    tracing::info!(
        admin = %claims.username,
        zone = %zone.name,
        ?user_ids,
        "[Admin] 域名分配"
    );

    Ok(ok_json(json!({
        "success": true,
        "result": { "user_ids": user_ids }
    })))
}

pub async fn get_zone(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let client = state.cf_client_for_zone(&zone_id).await?;
    let zone = client
        .get_zone(&zone_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok_json(json!({ "success": true, "result": zone })))
}

// ---------------------------------------------------------------------------
// DNS 记录
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct DnsListQuery {
    #[serde(default, rename = "type")]
    pub record_type: Option<String>,
}

pub async fn list_dns_records(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
    Query(query): Query<DnsListQuery>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let client = state.cf_client_for_zone(&zone_id).await?;
    let record_type = query.record_type.unwrap_or_default();
    let records = client
        .list_dns_records(&zone_id, &record_type)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok_json(json!({ "success": true, "result": records })))
}

pub async fn create_dns_record(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
    AdminUser(_claims): AdminUser,
    ApiJson(record): ApiJson<DnsRecord>,
) -> ApiResult<Response> {
    let client = state.cf_client_for_zone(&zone_id).await?;
    let created = client
        .create_dns_record(&zone_id, &record)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok_json(json!({ "success": true, "result": created })))
}

#[derive(Debug, Default, Deserialize)]
pub struct ZoneIdQuery {
    #[serde(default)]
    pub zone_id: Option<String>,
}

pub async fn update_dns_record(
    State(state): State<Arc<AppState>>,
    Path(record_id): Path<String>,
    Query(query): Query<ZoneIdQuery>,
    AdminUser(_claims): AdminUser,
    ApiJson(record): ApiJson<DnsRecord>,
) -> ApiResult<Response> {
    let zone_id = query
        .zone_id
        .filter(|z| !z.is_empty())
        .ok_or_else(|| ApiError::bad_request("zone_id query parameter required"))?;

    let client = state.cf_client_for_zone(&zone_id).await?;
    let updated = client
        .update_dns_record(&zone_id, &record_id, &record)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok_json(json!({ "success": true, "result": updated })))
}

pub async fn delete_dns_record(
    State(state): State<Arc<AppState>>,
    Path(record_id): Path<String>,
    Query(query): Query<ZoneIdQuery>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let zone_id = query
        .zone_id
        .filter(|z| !z.is_empty())
        .ok_or_else(|| ApiError::bad_request("zone_id query parameter required"))?;

    let client = state.cf_client_for_zone(&zone_id).await?;

    // 检查该 DNS 记录是否被转发规则引用，阻止误删。
    let rule_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM forward_rules WHERE zone_id = ? AND dns_record_id = ?",
    )
    .bind(&zone_id)
    .bind(&record_id)
    .fetch_one(&state.db)
    .await?;
    if rule_count > 0 {
        return Err(ApiError::bad_request(format!(
            "该 DNS 记录被 {rule_count} 条转发规则引用，请先删除相关规则后再删除 DNS 记录"
        )));
    }

    client
        .delete_dns_record(&zone_id, &record_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok_json(json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// SSL/TLS
// ---------------------------------------------------------------------------

pub async fn get_ssl_settings(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let client = state.cf_client_for_zone(&zone_id).await?;
    let setting = client
        .get_ssl_settings(&zone_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok_json(json!({ "success": true, "result": setting })))
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateSslRequest {
    #[serde(default)]
    pub value: String,
}

pub async fn update_ssl_settings(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
    AdminUser(_claims): AdminUser,
    ApiJson(req): ApiJson<UpdateSslRequest>,
) -> ApiResult<Response> {
    let client = state.cf_client_for_zone(&zone_id).await?;

    let valid = ["off", "flexible", "full", "strict", "origin_pull"];
    if !valid.contains(&req.value.as_str()) {
        return Err(ApiError::bad_request("invalid ssl mode"));
    }

    let setting = client
        .update_ssl_settings(&zone_id, &req.value)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok_json(json!({ "success": true, "result": setting })))
}
