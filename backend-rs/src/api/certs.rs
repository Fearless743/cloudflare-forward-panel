use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::api::extractors::{AdminUser, ApiError, ApiJson, ApiResult};
use crate::api::{ok_json, AppState};
use crate::db::now_db;
use crate::models::{OriginCertificate, Zone};

/// 去重（保留传入顺序）+ 去空白 + 小写。
fn normalize_hostnames(hostnames: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(hostnames.len());
    for raw in hostnames {
        let host = raw.trim().to_lowercase();
        if host.is_empty() {
            continue;
        }
        if seen.insert(host.clone()) {
            result.push(host);
        }
    }
    result
}

/// 主机名查找键：去重 + 排序后逗号拼接，与传入顺序无关。
fn origin_cert_hostnames_key(hostnames: &[String]) -> String {
    let mut keys = hostnames.to_vec();
    keys.sort();
    keys.join(",")
}

fn parse_origin_cert_expiry(raw: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    crate::db::parse_db_time(raw)
}

/// 缓存证书可复用条件：能解析过期时间时，距现在至少 30 天。
fn origin_cert_usable(cert: &OriginCertificate) -> bool {
    match parse_origin_cert_expiry(&cert.expires_on) {
        Some(expires) => {
            let remaining = expires.with_timezone(&chrono::Utc) - chrono::Utc::now();
            remaining > chrono::Duration::days(30)
        }
        // 无法解析过期时间时保守复用（Origin 证书有效期 15 年）。
        None => true,
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct GenerateOriginCertRequest {
    #[serde(default)]
    pub zone_id: String,
    #[serde(default)]
    pub hostnames: Vec<String>,
}

pub async fn generate_origin_certificate(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
    ApiJson(req): ApiJson<GenerateOriginCertRequest>,
) -> ApiResult<Response> {
    if req.zone_id.is_empty() || req.hostnames.is_empty() {
        return Err(ApiError::bad_request("zone_id and hostnames are required"));
    }

    let hostnames = normalize_hostnames(&req.hostnames);
    if hostnames.is_empty() {
        return Err(ApiError::bad_request("hostnames are required"));
    }
    let hostnames_key = origin_cert_hostnames_key(&hostnames);

    let cached = sqlx::query_as::<_, OriginCertificate>(
        "SELECT * FROM origin_certificates WHERE zone_id = ? AND hostnames_key = ?",
    )
    .bind(&req.zone_id)
    .bind(&hostnames_key)
    .fetch_optional(&state.db)
    .await?;

    if let Some(cached) = cached.as_ref() {
        if origin_cert_usable(cached) {
            let cached_hostnames: Vec<String> = serde_json::from_str(&cached.hostnames)
                .unwrap_or_else(|_| {
                    cached
                        .hostnames_key
                        .split(',')
                        .map(str::to_string)
                        .collect()
                });
            return Ok(ok_json(json!({
                "success": true,
                "cached": true,
                "result": {
                    "id": cached.cf_cert_id,
                    "certificate": cached.certificate,
                    "private_key": cached.private_key,
                    "csr": cached.csr,
                    "hostnames": cached_hostnames,
                    "issuer": cached.issuer,
                    "expires_on": cached.expires_on,
                    "request_type": cached.request_type,
                    "status": cached.status,
                }
            })));
        }
    }

    let client = state.cf_client_for_zone(&req.zone_id).await?;
    let cert = client
        .generate_origin_certificate(&hostnames, 5475)
        .await
        .map_err(|e| ApiError::internal(format!("生成 Origin 证书失败: {e}")))?;

    let hostnames_json = serde_json::to_string(&hostnames).unwrap_or_else(|_| "[]".to_string());
    let zone_name = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE cf_id = ?")
        .bind(&req.zone_id)
        .fetch_optional(&state.db)
        .await?
        .map(|z| z.name)
        .unwrap_or_default();

    let now = now_db();
    if let Some(cached) = cached {
        let result = sqlx::query(
            "UPDATE origin_certificates SET zone_name = ?, hostnames = ?, hostnames_key = ?, \
             cf_cert_id = ?, certificate = ?, private_key = ?, csr = ?, issuer = ?, expires_on = ?, \
             request_type = ?, status = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&zone_name)
        .bind(&hostnames_json)
        .bind(&hostnames_key)
        .bind(&cert.id)
        .bind(&cert.certificate)
        .bind(&cert.private_key)
        .bind(&cert.csr)
        .bind(&cert.issuer)
        .bind(&cert.expires_on)
        .bind(&cert.request_type)
        .bind(&cert.status)
        .bind(&now)
        .bind(cached.id)
        .execute(&state.db)
        .await;
        if let Err(err) = result {
            tracing::warn!(zone_id = %req.zone_id, %err, "[OriginCertificate] 更新证书缓存失败");
        }
    } else {
        let result = sqlx::query(
            "INSERT INTO origin_certificates (zone_id, zone_name, hostnames, hostnames_key, cf_cert_id, \
             certificate, private_key, csr, issuer, expires_on, request_type, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&req.zone_id)
        .bind(&zone_name)
        .bind(&hostnames_json)
        .bind(&hostnames_key)
        .bind(&cert.id)
        .bind(&cert.certificate)
        .bind(&cert.private_key)
        .bind(&cert.csr)
        .bind(&cert.issuer)
        .bind(&cert.expires_on)
        .bind(&cert.request_type)
        .bind(&cert.status)
        .bind(&now)
        .bind(&now)
        .execute(&state.db)
        .await;
        if let Err(err) = result {
            tracing::warn!(zone_id = %req.zone_id, %err, "[OriginCertificate] 保存证书缓存失败");
        }
    }

    Ok(ok_json(json!({
        "success": true,
        "cached": false,
        "result": cert,
    })))
}
