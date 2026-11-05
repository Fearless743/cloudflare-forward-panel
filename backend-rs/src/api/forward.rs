use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Response;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::extractors::{AdminUser, ApiError, ApiJson, ApiResult, AuthUser};
use crate::api::settings;
use crate::api::{ok_json, AppState};
use crate::cfclient::{
    ActionParams, CfError, Client, DnsRecord, OriginParams, OriginRule, OriginRuleset,
};
use crate::db::{now_db, placeholders};
use crate::models::{CfAccount, ForwardRule, User, Zone};

type FResult<T> = Result<T, ApiError>;

fn ce(err: CfError) -> ApiError {
    ApiError::internal(err.to_string())
}

// ---------------------------------------------------------------------------
// 域名可用性 / 权限
// ---------------------------------------------------------------------------

/// 本地 zones 表中排除被封禁账号的域名。
pub async fn available_local_zones(state: &AppState) -> Result<Vec<Zone>, sqlx::Error> {
    let zones = sqlx::query_as::<_, Zone>("SELECT * FROM zones ORDER BY id ASC")
        .fetch_all(&state.db)
        .await?;

    let blocked: HashSet<i64> =
        sqlx::query_scalar::<_, i64>("SELECT id FROM cf_accounts WHERE is_blocked = ?")
            .bind(true)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();

    Ok(zones
        .into_iter()
        .filter(|z| z.account_id == 0 || !blocked.contains(&z.account_id))
        .collect())
}

async fn find_available_zone_by_cfid(state: &AppState, cfid: &str) -> FResult<Zone> {
    available_local_zones(state)
        .await?
        .into_iter()
        .find(|z| z.cf_id == cfid)
        .ok_or_else(|| ApiError::bad_request("指定的域名不存在或所属账号已被封禁"))
}

async fn authorized_zone_ids(state: &AppState, user_id: i64) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT zone_id FROM zone_users WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
}

async fn available_local_zones_for_user(
    state: &AppState,
    user_id: i64,
) -> Result<Vec<Zone>, sqlx::Error> {
    let zones = available_local_zones(state).await?;
    let allowed: HashSet<i64> = authorized_zone_ids(state, user_id)
        .await?
        .into_iter()
        .collect();
    if allowed.is_empty() {
        return Ok(Vec::new());
    }
    Ok(zones
        .into_iter()
        .filter(|z| allowed.contains(&z.id))
        .collect())
}

async fn user_can_use_zone(
    state: &AppState,
    user_id: i64,
    zone_id: i64,
) -> Result<bool, sqlx::Error> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM zone_users WHERE zone_id = ? AND user_id = ?",
    )
    .bind(zone_id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count > 0)
}

async fn user_can_use_zone_cfid(
    state: &AppState,
    user_id: i64,
    cfid: &str,
) -> Result<bool, sqlx::Error> {
    let zone = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE cf_id = ?")
        .bind(cfid)
        .fetch_optional(&state.db)
        .await?;
    match zone {
        Some(zone) => user_can_use_zone(state, user_id, zone.id).await,
        None => Ok(false),
    }
}

/// 开启转发所需的 Zone 设置：SSL Full、WebSockets、gRPC（幂等，忽略错误）。
pub async fn enable_zone_forwarding_settings(client: &Client, zone_id: &str) {
    let _ = client.update_ssl_settings(zone_id, "full").await;
    let _ = client.enable_websockets(zone_id).await;
    let _ = client.enable_grpc(zone_id).await;
}

// ---------------------------------------------------------------------------
// 列表
// ---------------------------------------------------------------------------

pub async fn list_forward_rules(
    State(state): State<Arc<AppState>>,
    AuthUser(claims): AuthUser,
) -> ApiResult<Response> {
    pause_expired_subscriptions(&state).await;

    // 所有用户（包括管理员）都只能查看自己创建的规则。
    let rules = sqlx::query_as::<_, ForwardRule>(
        "SELECT * FROM forward_rules WHERE user_id = ? ORDER BY created_at DESC, id DESC",
    )
    .bind(claims.user_id)
    .fetch_all(&state.db)
    .await?;

    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&state.db)
        .await?;
    let usernames: HashMap<i64, String> = users.into_iter().map(|u| (u.id, u.username)).collect();

    let result: Vec<Value> = rules
        .into_iter()
        .map(|rule| {
            let mut value = serde_json::to_value(&rule).unwrap_or_else(|_| json!({}));
            if let Value::Object(map) = &mut value {
                map.insert(
                    "username".to_string(),
                    json!(usernames.get(&rule.user_id).cloned().unwrap_or_default()),
                );
            }
            value
        })
        .collect();

    Ok(ok_json(json!({ "success": true, "result": result })))
}

pub async fn list_local_zones(
    State(state): State<Arc<AppState>>,
    AuthUser(claims): AuthUser,
) -> ApiResult<Response> {
    let zones = available_local_zones_for_user(&state, claims.user_id).await?;
    Ok(ok_json(json!({ "success": true, "result": zones })))
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

fn find_rule_index(rules: &[OriginRule], rule_id: &str) -> Option<usize> {
    if rule_id.is_empty() {
        return None;
    }
    rules.iter().position(|r| r.id == rule_id)
}

fn find_rule_id_by_port(rules: &[OriginRule], port: i64) -> String {
    rules
        .iter()
        .find(|r| {
            r.action_parameters
                .as_ref()
                .and_then(|p| p.origin.as_ref())
                .map(|o| o.port == port)
                .unwrap_or(false)
        })
        .map(|r| r.id.clone())
        .unwrap_or_default()
}

fn host_eq_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"http\.host\s+eq\s+"((?:[^"\\]|\\.)*)""#).unwrap())
}

fn unescape_go_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// 从 Cloudflare 规则表达式中解析全部主机名；历史数据可能是逗号分隔的纯 host 列表。
pub fn parse_hostname_list(expr: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    let mut matched = false;
    for caps in host_eq_regex().captures_iter(expr) {
        matched = true;
        if let Some(m) = caps.get(1) {
            let host = unescape_go_string(m.as_str()).trim().to_string();
            if !host.is_empty() && seen.insert(host.clone()) {
                out.push(host);
            }
        }
    }
    if matched {
        return out;
    }

    for part in expr.split(',') {
        let host = part.trim();
        if !host.is_empty() && seen.insert(host.to_string()) {
            out.push(host.to_string());
        }
    }
    out
}

/// 根据多个主机名构建 http.host 匹配表达式（排序保证稳定）。
pub fn build_host_expression(hostnames: &[String]) -> String {
    let mut uniq = Vec::new();
    let mut seen = HashSet::new();
    for host in hostnames {
        if !host.is_empty() && seen.insert(host.clone()) {
            uniq.push(host.clone());
        }
    }
    uniq.sort();

    if uniq.is_empty() {
        return String::new();
    }
    if uniq.len() == 1 {
        return format!("(http.host eq \"{}\")", uniq[0]);
    }
    let parts: Vec<String> = uniq
        .iter()
        .map(|h| format!("(http.host eq \"{h}\")"))
        .collect();
    format!("({})", parts.join(" or "))
}

/// IPv4 → A，IPv6 → AAAA，域名 → CNAME。
pub fn detect_dns_record_type(host: &str) -> &'static str {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => "AAAA",
        Ok(std::net::IpAddr::V4(_)) => "A",
        Err(_) => "CNAME",
    }
}

/// 生成指定长度的随机字符串（小写字母 + 数字）。
pub fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

async fn find_existing_rule_for_port_in_zones(
    state: &AppState,
    port: i64,
    zone_ids: &[String],
    exclude_id: i64,
) -> Result<Option<ForwardRule>, sqlx::Error> {
    if zone_ids.is_empty() {
        return Ok(None);
    }
    let mut sql = format!(
        "SELECT * FROM forward_rules WHERE origin_port = ? AND zone_id IN ({})",
        placeholders(zone_ids.len())
    );
    if exclude_id != 0 {
        sql.push_str(" AND id != ?");
    }
    sql.push_str(" ORDER BY id ASC LIMIT 1");

    let mut query = sqlx::query_as::<_, ForwardRule>(&sql).bind(port);
    for zone_id in zone_ids {
        query = query.bind(zone_id);
    }
    if exclude_id != 0 {
        query = query.bind(exclude_id);
    }
    query.fetch_optional(&state.db).await
}

/// 返回 CF 规则表达式中不属于任何本地 ForwardRule 的主机名（面板外手工添加）。
async fn external_hostnames(
    state: &AppState,
    rule: &ForwardRule,
    expression: &str,
) -> Result<Vec<String>, sqlx::Error> {
    if rule.cf_rule_set_id.is_empty() || rule.cf_rule_id.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, ForwardRule>(
        "SELECT * FROM forward_rules WHERE cf_rule_set_id = ? AND cf_rule_id = ?",
    )
    .bind(&rule.cf_rule_set_id)
    .bind(&rule.cf_rule_id)
    .fetch_all(&state.db)
    .await?;

    let managed: HashSet<String> = rows
        .into_iter()
        .map(|r| r.hostname.to_lowercase())
        .collect();

    let mut out = Vec::new();
    for host in parse_hostname_list(expression) {
        if host.eq_ignore_ascii_case(&rule.hostname) {
            continue;
        }
        if !managed.contains(&host.to_lowercase()) {
            out.push(host);
        }
    }
    Ok(out)
}

fn forward_rule_missing_err(err: &ApiError) -> bool {
    err.message.contains("[10001]") || err.message.contains("Cloudflare 规则不存在")
}

fn is_10001(err: &CfError) -> bool {
    err.to_string().contains("[10001]")
}

async fn update_rule_row(state: &AppState, rule: &ForwardRule) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE forward_rules SET user_id = ?, account_id = ?, zone_id = ?, zone_name = ?, hostname = ?, \
         origin_port = ?, origin_host = ?, enabled = ?, cf_rule_set_id = ?, cf_rule_id = ?, dns_record_id = ?, \
         updated_at = ? WHERE id = ?",
    )
    .bind(rule.user_id)
    .bind(rule.account_id)
    .bind(&rule.zone_id)
    .bind(&rule.zone_name)
    .bind(&rule.hostname)
    .bind(rule.origin_port)
    .bind(&rule.origin_host)
    .bind(rule.enabled)
    .bind(&rule.cf_rule_set_id)
    .bind(&rule.cf_rule_id)
    .bind(&rule.dns_record_id)
    .bind(now_db())
    .bind(rule.id)
    .execute(&state.db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Origin Ruleset 辅助
// ---------------------------------------------------------------------------

fn new_forward_ruleset(rules: Vec<OriginRule>) -> OriginRuleset {
    OriginRuleset {
        name: "CF Panel Port Forwarding".to_string(),
        description: "Port forwarding rules managed by CF Panel".to_string(),
        kind: "zone".to_string(),
        phase: "http_request_origin".to_string(),
        rules,
        ..Default::default()
    }
}

fn new_origin_rule(port: i64, expression: String, enabled: bool) -> OriginRule {
    OriginRule {
        description: format!("Forward to port {port}"),
        expression,
        action: "route".to_string(),
        action_parameters: Some(ActionParams {
            origin: Some(OriginParams {
                port,
                ..Default::default()
            }),
            ..Default::default()
        }),
        enabled,
        ..Default::default()
    }
}

/// 创建 Origin Ruleset；若 ruleset 数量超限（[20217]），则合并进现有 ruleset。
/// 返回 (ruleset, 是否本次新建)。
async fn ensure_origin_ruleset(
    client: &Client,
    zone_id: &str,
    new_ruleset: &OriginRuleset,
) -> FResult<(OriginRuleset, bool)> {
    match client.create_origin_ruleset(zone_id, new_ruleset).await {
        Ok(created) => Ok((created, true)),
        Err(err) => {
            if !err.to_string().contains("[20217]") {
                return Err(ce(err));
            }
            let existing_list = client
                .list_origin_rulesets(zone_id)
                .await
                .map_err(|list_err| {
                    ApiError::internal(format!("创建失败({err})且无法列出已有 ruleset({list_err})"))
                })?;

            let target = existing_list
                .iter()
                .find(|rs| rs.kind == "zone")
                .or_else(|| existing_list.first());

            let Some(target) = target else {
                return Err(ce(err));
            };

            let mut full = client
                .get_origin_ruleset(zone_id, &target.id)
                .await
                .map_err(|get_err| {
                    ApiError::internal(format!(
                        "创建失败({err})且获取 ruleset {} 失败({get_err})",
                        target.id
                    ))
                })?;

            for new_rule in &new_ruleset.rules {
                let mut merged = false;
                if let Some(new_port) = new_rule
                    .action_parameters
                    .as_ref()
                    .and_then(|p| p.origin.as_ref())
                    .map(|o| o.port)
                {
                    for existing in &mut full.rules {
                        let existing_port = existing
                            .action_parameters
                            .as_ref()
                            .and_then(|p| p.origin.as_ref())
                            .map(|o| o.port);
                        if existing_port != Some(new_port) {
                            continue;
                        }
                        // 禁用的新目标不能并入现有表达式，避免意外激活该主机名。
                        if new_rule.enabled {
                            let mut merged_set: HashSet<String> =
                                parse_hostname_list(&existing.expression)
                                    .into_iter()
                                    .collect();
                            merged_set.extend(parse_hostname_list(&new_rule.expression));
                            let merged_list: Vec<String> = merged_set.into_iter().collect();
                            existing.expression = build_host_expression(&merged_list);
                            existing.enabled = true;
                        }
                        merged = true;
                        break;
                    }
                }
                if !merged {
                    full.rules.push(new_rule.clone());
                }
            }

            let updated = client
                .update_origin_ruleset(zone_id, &full.id, &full)
                .await
                .map_err(|update_err| {
                    ApiError::internal(format!(
                        "创建失败({err})且合并到 ruleset {} 失败({update_err})",
                        full.id
                    ))
                })?;
            Ok((updated, false))
        }
    }
}

/// 根据数据库里所有引用该 CF rule 的「启用行」重建规则表达式。
async fn sync_rule_expression(
    state: &AppState,
    client: &Client,
    rule: &ForwardRule,
) -> FResult<()> {
    sync_rule_expression_inner(state, client, rule, true).await
}

/// 严格按面板数据重建表达式（不保留面板外手工主机名），用于定时检查自动修复。
async fn sync_rule_expression_strict(
    state: &AppState,
    client: &Client,
    rule: &ForwardRule,
) -> FResult<()> {
    sync_rule_expression_inner(state, client, rule, false).await
}

async fn sync_rule_expression_inner(
    state: &AppState,
    client: &Client,
    rule: &ForwardRule,
    preserve_external: bool,
) -> FResult<()> {
    let rows = sqlx::query_as::<_, ForwardRule>(
        "SELECT * FROM forward_rules WHERE cf_rule_set_id = ? AND cf_rule_id = ?",
    )
    .bind(&rule.cf_rule_set_id)
    .bind(&rule.cf_rule_id)
    .fetch_all(&state.db)
    .await?;

    let mut hosts: Vec<String> = rows
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| r.hostname)
        .collect();

    let mut full = client
        .get_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id)
        .await
        .map_err(|e| {
            if is_10001(&e) {
                ApiError::internal("Cloudflare 规则不存在")
            } else {
                ApiError::internal(format!("获取 Cloudflare 规则失败: {e}"))
            }
        })?;

    let Some(idx) = find_rule_index(&full.rules, &rule.cf_rule_id) else {
        return Err(ApiError::internal("Cloudflare 规则不存在"));
    };

    if preserve_external {
        hosts.extend(external_hostnames(state, rule, &full.rules[idx].expression).await?);
    }

    if hosts.is_empty() {
        full.rules[idx].enabled = false;
    } else {
        full.rules[idx].enabled = true;
        full.rules[idx].expression = build_host_expression(&hosts);
    }

    client
        .update_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id, &full)
        .await
        .map_err(|e| ApiError::internal(format!("更新 Cloudflare 规则失败: {e}")))?;
    Ok(())
}

async fn sync_rule_expression_with_reconcile(
    state: &AppState,
    client: &Client,
    rule: &mut ForwardRule,
) -> FResult<()> {
    match sync_rule_expression(state, client, rule).await {
        Ok(()) => Ok(()),
        Err(err) if forward_rule_missing_err(&err) => {
            match reconcile_zone_forward_rules(state, client, &rule.zone_id).await {
                Ok(_) => {}
                Err(rerr) => {
                    return Err(ApiError::internal(format!(
                        "自动修复规则失败: {}",
                        rerr.message
                    )))
                }
            }
            let refreshed =
                sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
                    .bind(rule.id)
                    .fetch_one(&state.db)
                    .await?;
            *rule = refreshed;
            sync_rule_expression(state, client, rule).await
        }
        Err(err) => Err(err),
    }
}

// ---------------------------------------------------------------------------
// CF 资源清理
// ---------------------------------------------------------------------------

async fn delete_ruleset(client: &Client, rule: &ForwardRule) -> FResult<()> {
    if rule.cf_rule_set_id.is_empty() {
        return Ok(());
    }
    match client
        .delete_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id)
        .await
    {
        Ok(()) => Ok(()),
        Err(err) if is_10001(&err) => Ok(()),
        Err(err) => Err(ApiError::internal(format!(
            "删除 ruleset {} 失败: {err}",
            rule.cf_rule_set_id
        ))),
    }
}

async fn remove_rule_from_ruleset(client: &Client, rule: &ForwardRule) -> FResult<()> {
    if rule.cf_rule_set_id.is_empty() {
        return Ok(());
    }
    let mut full = match client
        .get_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id)
        .await
    {
        Ok(full) => full,
        Err(err) if is_10001(&err) => return Ok(()),
        Err(err) => {
            return Err(ApiError::internal(format!(
                "获取 ruleset {} 失败: {err}",
                rule.cf_rule_set_id
            )))
        }
    };

    let Some(idx) = find_rule_index(&full.rules, &rule.cf_rule_id) else {
        return Ok(());
    };

    if full.rules.len() <= 1 {
        tracing::warn!(
            ruleset = %rule.cf_rule_set_id,
            "[ForwardRule] ruleset 仅剩一条 rule 但本地仍引用，跳过删除"
        );
        return Ok(());
    }

    full.rules.remove(idx);
    client
        .update_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id, &full)
        .await
        .map_err(|e| {
            ApiError::internal(format!("更新 ruleset {} 失败: {e}", rule.cf_rule_set_id))
        })?;
    Ok(())
}

async fn remove_hostname_from_rule(
    state: &AppState,
    client: &Client,
    rule: &ForwardRule,
) -> FResult<()> {
    let remaining = sqlx::query_as::<_, ForwardRule>(
        "SELECT * FROM forward_rules WHERE cf_rule_set_id = ? AND cf_rule_id = ? AND id != ?",
    )
    .bind(&rule.cf_rule_set_id)
    .bind(&rule.cf_rule_id)
    .bind(rule.id)
    .fetch_all(&state.db)
    .await?;

    if remaining.is_empty() {
        return Ok(());
    }

    let mut hosts: Vec<String> = remaining
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| r.hostname)
        .collect();

    let mut full = client
        .get_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id)
        .await
        .map_err(|e| ApiError::internal(format!("获取 Cloudflare 规则失败: {e}")))?;
    let Some(idx) = find_rule_index(&full.rules, &rule.cf_rule_id) else {
        return Err(ApiError::internal("Cloudflare 规则不存在"));
    };

    hosts.extend(external_hostnames(state, rule, &full.rules[idx].expression).await?);
    if hosts.is_empty() {
        full.rules[idx].enabled = false;
    } else {
        full.rules[idx].enabled = true;
        full.rules[idx].expression = build_host_expression(&hosts);
    }

    client
        .update_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id, &full)
        .await
        .map_err(|e| ApiError::internal(format!("更新 Cloudflare 规则失败: {e}")))?;
    Ok(())
}

/// 从旧 CF 资源中移除一条本地规则对应的 hostname/rule。
async fn detach_rule_from_cf(state: &AppState, client: &Client, rule: &ForwardRule) -> FResult<()> {
    if rule.cf_rule_set_id.is_empty() {
        return Ok(());
    }
    let mut full = match client
        .get_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id)
        .await
    {
        Ok(full) => full,
        Err(err) if is_10001(&err) => return Ok(()),
        Err(err) => return Err(ce(err)),
    };

    let Some(idx) = find_rule_index(&full.rules, &rule.cf_rule_id) else {
        return Ok(());
    };

    let remaining_same_rule = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM forward_rules WHERE cf_rule_set_id = ? AND cf_rule_id = ? AND id != ?",
    )
    .bind(&rule.cf_rule_set_id)
    .bind(&rule.cf_rule_id)
    .bind(rule.id)
    .fetch_one(&state.db)
    .await?;

    if remaining_same_rule > 0 {
        return remove_hostname_from_rule(state, client, rule).await;
    }

    // 没有其他本地行共享该规则：只移除本行 hostname，保留面板外手工主机名。
    let remaining_expr_hosts: Vec<String> = parse_hostname_list(&full.rules[idx].expression)
        .into_iter()
        .filter(|h| !h.eq_ignore_ascii_case(&rule.hostname))
        .collect();

    if !remaining_expr_hosts.is_empty() {
        full.rules[idx].expression = build_host_expression(&remaining_expr_hosts);
        client
            .update_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id, &full)
            .await
            .map_err(ce)?;
        return Ok(());
    }

    let remaining_set = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM forward_rules WHERE cf_rule_set_id = ? AND id != ?",
    )
    .bind(&rule.cf_rule_set_id)
    .bind(rule.id)
    .fetch_one(&state.db)
    .await?;

    if full.rules.len() <= 1 && remaining_set == 0 {
        return delete_ruleset(client, rule).await;
    }
    remove_rule_from_ruleset(client, rule).await
}

/// 清理某条规则在 CF 侧的独占资源（rule/ruleset/DNS），不删除本地行。
async fn cleanup_rule_from_zone(
    state: &AppState,
    client: &Client,
    rule: &ForwardRule,
) -> FResult<()> {
    if let Err(err) = detach_rule_from_cf(state, client, rule).await {
        if !forward_rule_missing_err(&err) {
            return Err(err);
        }
        tracing::info!("[ForwardRule] 迁移清理时 CF 侧规则已不存在，跳过");
    }

    if !rule.dns_record_id.is_empty() {
        match client
            .delete_dns_record(&rule.zone_id, &rule.dns_record_id)
            .await
        {
            Ok(()) => {}
            Err(err) if is_10001(&err) => {}
            Err(err) => return Err(ApiError::internal(format!("删除旧 DNS 记录失败: {err}"))),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS 记录更新
// ---------------------------------------------------------------------------

/// 更新规则对应 DNS 记录：类型不变时原地 PATCH，类型变化时新建并删除旧记录。
async fn update_rule_dns_record(
    client: &Client,
    rule: &ForwardRule,
    new_host: &str,
) -> FResult<String> {
    if rule.dns_record_id.is_empty() {
        return Ok(String::new());
    }
    let old_type = detect_dns_record_type(&rule.origin_host);
    let new_type = detect_dns_record_type(new_host);

    if old_type == new_type {
        let record = DnsRecord {
            name: rule.hostname.clone(),
            record_type: new_type.to_string(),
            content: new_host.to_string(),
            ttl: 1,
            proxied: true,
            ..Default::default()
        };
        client
            .update_dns_record(&rule.zone_id, &rule.dns_record_id, &record)
            .await
            .map_err(ce)?;
        return Ok(rule.dns_record_id.clone());
    }

    let old_id = rule.dns_record_id.clone();
    let created = client
        .create_dns_record(
            &rule.zone_id,
            &DnsRecord {
                zone_id: rule.zone_id.clone(),
                name: rule.hostname.clone(),
                record_type: new_type.to_string(),
                content: new_host.to_string(),
                ttl: 1,
                proxied: true,
                ..Default::default()
            },
        )
        .await
        .map_err(ce)?;

    if let Err(err) = client.delete_dns_record(&rule.zone_id, &old_id).await {
        tracing::warn!(dns_id = %old_id, %err, "[ForwardRule] 删除旧 DNS 记录失败");
    }
    Ok(created.id)
}

async fn update_rule_port(client: &Client, rule: &ForwardRule, new_port: i64) -> FResult<()> {
    if rule.cf_rule_set_id.is_empty() {
        return Ok(());
    }
    let mut full = client
        .get_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id)
        .await
        .map_err(ce)?;
    let Some(idx) = find_rule_index(&full.rules, &rule.cf_rule_id) else {
        return Err(ApiError::internal("Cloudflare 规则不存在"));
    };

    if full.rules[idx].action_parameters.is_none() {
        full.rules[idx].action_parameters = Some(ActionParams::default());
    }
    let params = full.rules[idx].action_parameters.as_mut().unwrap();
    if params.origin.is_none() {
        params.origin = Some(OriginParams::default());
    }
    params.origin.as_mut().unwrap().port = new_port;
    full.rules[idx].description = format!("Forward to port {new_port}");

    client
        .update_origin_ruleset(&rule.zone_id, &rule.cf_rule_set_id, &full)
        .await
        .map_err(ce)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 创建 / 更新 / 删除规则
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ForwardRuleRequest {
    #[serde(default)]
    pub origin_port: i64,
    #[serde(default)]
    pub origin_host: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub zone_id: String,
}

pub async fn create_forward_rule(
    State(state): State<Arc<AppState>>,
    AuthUser(claims): AuthUser,
    ApiJson(req): ApiJson<ForwardRuleRequest>,
) -> ApiResult<Response> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(claims.user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("用户不存在"))?;

    if claims.role != "admin" && !user.subscription_valid() {
        return Err(ApiError::forbidden("订阅已过期，无法创建转发规则"));
    }

    if !(1..=65535).contains(&req.origin_port) || req.origin_host.is_empty() {
        return Err(ApiError::bad_request(
            "origin_port 必须在 1-65535 之间，origin_host 不能为空",
        ));
    }

    // 指定域名时先解析并验证可用性
    let mut selected_zone: Option<Zone> = None;
    if !req.zone_id.is_empty() {
        let zone = find_available_zone_by_cfid(&state, &req.zone_id).await?;
        if !user_can_use_zone(&state, claims.user_id, zone.id).await? {
            return Err(ApiError::forbidden("无权使用该域名，请联系管理员分配"));
        }
        selected_zone = Some(zone);
    }

    let user_zones = if selected_zone.is_none() {
        let zones = available_local_zones_for_user(&state, claims.user_id).await?;
        if zones.is_empty() {
            return Err(ApiError::bad_request(
                "没有可用的域名，请联系管理员分配域名或解除账号封禁",
            ));
        }
        zones
    } else {
        Vec::new()
    };

    // 端口在「同一 Zone」内唯一：同 Zone 同端口复用一条 CF Origin Rule。
    let reuse_zone_ids: Vec<String> = match &selected_zone {
        Some(zone) => vec![zone.cf_id.clone()],
        None => user_zones.iter().map(|z| z.cf_id.clone()).collect(),
    };

    if let Some(existing) =
        find_existing_rule_for_port_in_zones(&state, req.origin_port, &reuse_zone_ids, 0).await?
    {
        let (new_hostname, dns_record_id) =
            add_hostname_to_rule(&state, &existing, &req.origin_host).await?;

        let now = now_db();
        let new_row_id = sqlx::query(
            "INSERT INTO forward_rules (user_id, account_id, zone_id, zone_name, hostname, origin_port, origin_host, \
             enabled, cf_rule_set_id, cf_rule_id, dns_record_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(claims.user_id)
        .bind(existing.account_id)
        .bind(&existing.zone_id)
        .bind(&existing.zone_name)
        .bind(&new_hostname)
        .bind(req.origin_port)
        .bind(&req.origin_host)
        .bind(req.enabled)
        .bind(&existing.cf_rule_set_id)
        .bind(&existing.cf_rule_id)
        .bind(&dns_record_id)
        .bind(&now)
        .bind(&now)
        .execute(&state.db)
        .await;

        let new_row_id = match new_row_id {
            Ok(result) => result.last_insert_rowid(),
            Err(err) => {
                if let Ok(c) = state.cf_client_for_account(existing.account_id).await {
                    let _ = c.delete_dns_record(&existing.zone_id, &dns_record_id).await;
                }
                return Err(ApiError::internal(format!("保存规则失败: {err}")));
            }
        };

        let mut new_row =
            sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
                .bind(new_row_id)
                .fetch_one(&state.db)
                .await?;

        // 按所有「启用行」统一重建共享规则表达式。
        let client = match state.cf_client_for_account(existing.account_id).await {
            Ok(client) => client,
            Err(err) => {
                let _ = sqlx::query("DELETE FROM forward_rules WHERE id = ?")
                    .bind(new_row.id)
                    .execute(&state.db)
                    .await;
                return Err(err);
            }
        };

        if let Err(err) = sync_rule_expression(&state, &client, &new_row).await {
            if !forward_rule_missing_err(&err) {
                let _ = sqlx::query("DELETE FROM forward_rules WHERE id = ?")
                    .bind(new_row.id)
                    .execute(&state.db)
                    .await;
                let _ = client
                    .delete_dns_record(&new_row.zone_id, &new_row.dns_record_id)
                    .await;
                return Err(err);
            }
            // CF 侧规则丢失：全量对账补全后重试
            if let Err(rerr) = reconcile_zone_forward_rules(&state, &client, &new_row.zone_id).await
            {
                let _ = sqlx::query("DELETE FROM forward_rules WHERE id = ?")
                    .bind(new_row.id)
                    .execute(&state.db)
                    .await;
                let _ = client
                    .delete_dns_record(&new_row.zone_id, &new_row.dns_record_id)
                    .await;
                return Err(ApiError::internal(format!(
                    "自动修复规则失败: {}",
                    rerr.message
                )));
            }
            new_row = sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
                .bind(new_row_id)
                .fetch_one(&state.db)
                .await?;
            if let Err(err) = sync_rule_expression(&state, &client, &new_row).await {
                let _ = sqlx::query("DELETE FROM forward_rules WHERE id = ?")
                    .bind(new_row.id)
                    .execute(&state.db)
                    .await;
                let _ = client
                    .delete_dns_record(&new_row.zone_id, &new_row.dns_record_id)
                    .await;
                return Err(err);
            }
        }

        enable_zone_forwarding_settings(&client, &existing.zone_id).await;

        return Ok(ok_json(json!({ "success": true, "result": new_row })));
    }

    // 选择域名：用户指定时直接使用，否则按「填满策略」自动选择。
    let best_zone: Zone = match selected_zone {
        Some(zone) => zone,
        None => choose_best_zone(&state, &user_zones).await?,
    };

    // 兜底校验：必须使用分配给当前用户的域名。
    if !user_can_use_zone(&state, claims.user_id, best_zone.id).await? {
        return Err(ApiError::forbidden("无权使用该域名，请联系管理员分配"));
    }

    let hostname = format!("{}.{}", generate_random_string(8), best_zone.name);

    let client = state.cf_client_for_account(best_zone.account_id).await?;

    let ruleset = new_forward_ruleset(vec![new_origin_rule(
        req.origin_port,
        build_host_expression(std::slice::from_ref(&hostname)),
        req.enabled,
    )]);

    let (created, is_new) = ensure_origin_ruleset(&client, &best_zone.cf_id, &ruleset)
        .await
        .map_err(|e| ApiError::internal(format!("创建 Cloudflare 规则失败: {}", e.message)))?;

    let record_type = detect_dns_record_type(&req.origin_host);
    let created_dns = match client
        .create_dns_record(
            &best_zone.cf_id,
            &DnsRecord {
                zone_id: best_zone.cf_id.clone(),
                name: hostname.clone(),
                record_type: record_type.to_string(),
                content: req.origin_host.clone(),
                ttl: 1,
                proxied: true,
                ..Default::default()
            },
        )
        .await
    {
        Ok(record) => record,
        Err(err) => {
            if is_new {
                let _ = client
                    .delete_origin_ruleset(&best_zone.cf_id, &created.id)
                    .await;
            }
            return Err(ApiError::internal(format!("创建 DNS 记录失败: {err}")));
        }
    };

    let mut cf_rule_id = find_rule_id_by_port(&created.rules, req.origin_port);
    if cf_rule_id.is_empty() && created.rules.len() == 1 {
        cf_rule_id = created.rules[0].id.clone();
    }

    let now = now_db();
    let insert = sqlx::query(
        "INSERT INTO forward_rules (user_id, account_id, zone_id, zone_name, hostname, origin_port, origin_host, \
         enabled, cf_rule_set_id, cf_rule_id, dns_record_id, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(claims.user_id)
    .bind(best_zone.account_id)
    .bind(&best_zone.cf_id)
    .bind(&best_zone.name)
    .bind(&hostname)
    .bind(req.origin_port)
    .bind(&req.origin_host)
    .bind(req.enabled)
    .bind(&created.id)
    .bind(&cf_rule_id)
    .bind(&created_dns.id)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await;

    let local_rule_id = match insert {
        Ok(result) => result.last_insert_rowid(),
        Err(err) => {
            let _ = client
                .delete_dns_record(&best_zone.cf_id, &created_dns.id)
                .await;
            if is_new {
                let _ = client
                    .delete_origin_ruleset(&best_zone.cf_id, &created.id)
                    .await;
            }
            return Err(ApiError::internal(format!("保存规则失败: {err}")));
        }
    };

    let local_rule = sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
        .bind(local_rule_id)
        .fetch_one(&state.db)
        .await?;

    enable_zone_forwarding_settings(&client, &best_zone.cf_id).await;

    Ok(ok_json(json!({ "success": true, "result": local_rule })))
}

/// 自动选择域名：优先使用「已有规则但最少」的域名，否则使用规则数为 0 的域名。
async fn choose_best_zone(state: &AppState, zones: &[Zone]) -> FResult<Zone> {
    if zones.is_empty() {
        return Err(ApiError::bad_request(
            "没有可用的域名，请联系管理员分配域名或解除账号封禁",
        ));
    }

    let mut client_by_account: HashMap<i64, Arc<Client>> = HashMap::new();
    let mut counted: Vec<(Zone, usize)> = Vec::new();

    for zone in zones {
        let client = if let Some(client) = client_by_account.get(&zone.account_id) {
            client.clone()
        } else {
            match state.cf_client_for_account(zone.account_id).await {
                Ok(client) => {
                    client_by_account.insert(zone.account_id, client.clone());
                    client
                }
                Err(err) => {
                    tracing::warn!(
                        zone = %zone.name,
                        error = %err.message,
                        "[ForwardRule] 获取域名所属账号客户端失败，跳过"
                    );
                    continue;
                }
            }
        };

        match client.count_origin_rules(&zone.cf_id).await {
            Ok(count) => counted.push((zone.clone(), count)),
            Err(err) => {
                tracing::warn!(
                    zone = %zone.name,
                    %err,
                    "[ForwardRule] 查询域名 CF 规则数失败，跳过"
                );
            }
        }
    }

    if counted.is_empty() {
        return Err(ApiError::bad_request(
            "无法获取任何域名的规则数，请联系管理员排查 Cloudflare 账号状态",
        ));
    }

    let used: Vec<&(Zone, usize)> = counted.iter().filter(|(_, count)| *count > 0).collect();
    if let Some(best) = used.into_iter().min_by_key(|item| item.1) {
        return Ok(best.0.clone());
    }
    // 没有已使用域名：返回第一个规则数为 0 的域名
    counted
        .into_iter()
        .find(|(_, count)| *count == 0)
        .map(|(zone, _)| zone)
        .ok_or_else(|| ApiError::bad_request("没有可用的域名，请联系管理员分配域名或解除账号封禁"))
}

async fn add_hostname_to_rule(
    state: &AppState,
    rule: &ForwardRule,
    origin_host: &str,
) -> FResult<(String, String)> {
    let client = state.cf_client_for_account(rule.account_id).await?;
    let hostname = format!("{}.{}", generate_random_string(8), rule.zone_name);

    let created = client
        .create_dns_record(
            &rule.zone_id,
            &DnsRecord {
                zone_id: rule.zone_id.clone(),
                name: hostname.clone(),
                record_type: detect_dns_record_type(origin_host).to_string(),
                content: origin_host.to_string(),
                ttl: 1,
                proxied: true,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| ApiError::internal(format!("创建 DNS 记录失败: {e}")))?;

    Ok((hostname, created.id))
}

pub async fn update_forward_rule(
    State(state): State<Arc<AppState>>,
    Path(rule_id): Path<i64>,
    AuthUser(claims): AuthUser,
    ApiJson(req): ApiJson<ForwardRuleRequest>,
) -> ApiResult<Response> {
    if !(1..=65535).contains(&req.origin_port) || req.origin_host.is_empty() {
        return Err(ApiError::bad_request(
            "origin_port 必须在 1-65535 之间，origin_host 不能为空",
        ));
    }

    let mut local_rule =
        sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
            .bind(rule_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::not_found("规则不存在"))?;

    if claims.role != "admin" && local_rule.user_id != claims.user_id {
        return Err(ApiError::forbidden("无权操作该规则"));
    }

    if claims.role != "admin" {
        let owner = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(local_rule.user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::not_found("用户不存在"))?;
        if !owner.subscription_valid() {
            return Err(ApiError::forbidden("订阅已过期，无法修改转发规则"));
        }
    }

    // 所有用户（包括管理员）只能把规则迁移到被分配的域名。
    if !req.zone_id.is_empty()
        && req.zone_id != local_rule.zone_id
        && !user_can_use_zone_cfid(&state, claims.user_id, &req.zone_id).await?
    {
        return Err(ApiError::forbidden("无权使用该域名，请联系管理员分配"));
    }

    let port_changed = req.origin_port != local_rule.origin_port;
    let zone_changed = !req.zone_id.is_empty() && req.zone_id != local_rule.zone_id;

    if port_changed || zone_changed {
        reconfigure_forward_rule(
            &state,
            &mut local_rule,
            req.origin_port,
            &req.origin_host,
            req.enabled,
            &req.zone_id,
        )
        .await?;

        let refreshed =
            sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
                .bind(rule_id)
                .fetch_one(&state.db)
                .await?;
        return Ok(ok_json(json!({ "success": true, "result": refreshed })));
    }

    let client = state.cf_client_for_account(local_rule.account_id).await?;

    if req.origin_host != local_rule.origin_host {
        let new_dns_id = update_rule_dns_record(&client, &local_rule, &req.origin_host).await?;
        if !new_dns_id.is_empty() {
            local_rule.dns_record_id = new_dns_id;
        }
    }

    local_rule.origin_port = req.origin_port;
    local_rule.origin_host = req.origin_host;
    local_rule.enabled = req.enabled;
    update_rule_row(&state, &local_rule).await?;

    sync_rule_expression_with_reconcile(&state, &client, &mut local_rule).await?;

    Ok(ok_json(json!({ "success": true, "result": local_rule })))
}

/// 处理规则的端口/域名变更。
async fn reconfigure_forward_rule(
    state: &Arc<AppState>,
    rule: &mut ForwardRule,
    new_port: i64,
    new_host: &str,
    enabled: bool,
    requested_zone_id: &str,
) -> FResult<()> {
    let old = rule.clone();

    // 1) 解析目标 zone（未指定或与当前相同时沿用旧 zone）。
    let target_zone = if !requested_zone_id.is_empty() && requested_zone_id != old.zone_id {
        find_available_zone_by_cfid(state, requested_zone_id).await?
    } else {
        Zone {
            cf_id: old.zone_id.clone(),
            name: old.zone_name.clone(),
            account_id: old.account_id,
            ..Default::default()
        }
    };

    // 2) 目标 Zone 内已有同端口规则：并入该端口的共享规则。
    if let Some(existing) = find_existing_rule_for_port_in_zones(
        state,
        new_port,
        std::slice::from_ref(&target_zone.cf_id),
        old.id,
    )
    .await?
    {
        if !existing.cf_rule_set_id.is_empty() {
            return merge_rule_into_existing_port(state, &old, &existing, new_host, enabled).await;
        }
    }

    let old_client = state.cf_client_for_account(old.account_id).await?;

    // 3) 同 zone：原地改端口或从共享规则中拆分。
    if target_zone.cf_id == old.zone_id {
        return change_rule_port_in_same_zone(
            &old_client,
            state,
            rule,
            new_port,
            new_host,
            enabled,
        )
        .await;
    }

    // 4) 跨 zone：复用迁移逻辑。
    rule.origin_port = new_port;
    rule.origin_host = new_host.to_string();
    rule.enabled = enabled;
    migrate_rule_to_zone(state, rule, &target_zone).await
}

async fn change_rule_port_in_same_zone(
    client: &Client,
    state: &AppState,
    rule: &mut ForwardRule,
    new_port: i64,
    new_host: &str,
    enabled: bool,
) -> FResult<()> {
    let shared_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM forward_rules WHERE cf_rule_set_id = ? AND cf_rule_id = ?",
    )
    .bind(&rule.cf_rule_set_id)
    .bind(&rule.cf_rule_id)
    .fetch_one(&state.db)
    .await?;

    if !rule.cf_rule_set_id.is_empty() && !rule.cf_rule_id.is_empty() && shared_count <= 1 {
        // 独占：先改 CF 端口，再同步目标地址与表达式。
        update_rule_port(client, rule, new_port)
            .await
            .map_err(|e| {
                ApiError::internal(format!("修改 Cloudflare 规则端口失败: {}", e.message))
            })?;
        let new_dns_id = update_rule_dns_record(client, rule, new_host)
            .await
            .map_err(|e| ApiError::internal(format!("更新 DNS 记录失败: {}", e.message)))?;
        rule.origin_port = new_port;
        rule.origin_host = new_host.to_string();
        rule.enabled = enabled;
        if !new_dns_id.is_empty() {
            rule.dns_record_id = new_dns_id;
        }
        update_rule_row(state, rule).await?;
        return sync_rule_expression_with_reconcile(state, client, rule).await;
    }

    // 共享：为新端口创建独立规则（本行独占），保留原 hostname/DNS。
    let old = rule.clone();
    let ruleset = new_forward_ruleset(vec![new_origin_rule(
        new_port,
        build_host_expression(std::slice::from_ref(&old.hostname)),
        enabled,
    )]);
    let (created, _) = ensure_origin_ruleset(client, &old.zone_id, &ruleset)
        .await
        .map_err(|e| {
            ApiError::internal(format!("为新端口创建 Cloudflare 规则失败: {}", e.message))
        })?;

    let mut new_rule_id = find_rule_id_by_port(&created.rules, new_port);
    if new_rule_id.is_empty() && created.rules.len() == 1 {
        new_rule_id = created.rules[0].id.clone();
    }
    if new_rule_id.is_empty() {
        return Err(ApiError::internal("未能定位新建的 Cloudflare 规则"));
    }

    let new_dns_id = update_rule_dns_record(client, &old, new_host)
        .await
        .map_err(|e| ApiError::internal(format!("更新 DNS 记录失败: {}", e.message)))?;

    rule.cf_rule_set_id = created.id;
    rule.cf_rule_id = new_rule_id;
    rule.origin_port = new_port;
    rule.origin_host = new_host.to_string();
    rule.enabled = enabled;
    if !new_dns_id.is_empty() {
        rule.dns_record_id = new_dns_id;
    }
    update_rule_row(state, rule).await?;

    // 本行已指向新规则，只清理旧规则中的本机名（DNS 复用，不删除）。
    let mut cleanup_old = old;
    cleanup_old.dns_record_id = String::new();
    if let Err(err) = detach_rule_from_cf(state, client, &cleanup_old).await {
        tracing::warn!(error = %err.message, "[ForwardRule] 拆分端口后清理旧规则失败");
    }
    Ok(())
}

async fn merge_rule_into_existing_port(
    state: &Arc<AppState>,
    old: &ForwardRule,
    existing: &ForwardRule,
    new_host: &str,
    enabled: bool,
) -> FResult<()> {
    let old_snapshot = old.clone();
    let old_client = state.cf_client_for_account(old_snapshot.account_id).await?;
    let target_client = state.cf_client_for_account(existing.account_id).await?;

    let same_zone = old_snapshot.zone_id == existing.zone_id;
    let mut new_hostname = old_snapshot.hostname.clone();
    let mut new_dns_id = old_snapshot.dns_record_id.clone();

    if !same_zone {
        let hostname = format!("{}.{}", generate_random_string(8), existing.zone_name);
        let created = target_client
            .create_dns_record(
                &existing.zone_id,
                &DnsRecord {
                    zone_id: existing.zone_id.clone(),
                    name: hostname.clone(),
                    record_type: detect_dns_record_type(new_host).to_string(),
                    content: new_host.to_string(),
                    ttl: 1,
                    proxied: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| ApiError::internal(format!("在新域名创建 DNS 记录失败: {e}")))?;
        new_hostname = hostname;
        new_dns_id = created.id;
    }

    // 指向目标共享规则。
    let mut updated = old.clone();
    updated.account_id = existing.account_id;
    updated.zone_id = existing.zone_id.clone();
    updated.zone_name = existing.zone_name.clone();
    updated.hostname = new_hostname;
    updated.dns_record_id = new_dns_id.clone();
    updated.cf_rule_set_id = existing.cf_rule_set_id.clone();
    updated.cf_rule_id = existing.cf_rule_id.clone();
    updated.origin_port = existing.origin_port;
    updated.origin_host = new_host.to_string();
    updated.enabled = enabled;

    if let Err(err) = update_rule_row(state, &updated).await {
        if !same_zone {
            let _ = target_client
                .delete_dns_record(&existing.zone_id, &new_dns_id)
                .await;
        }
        return Err(ApiError::internal(err.to_string()));
    }

    // 把新 hostname 并入目标规则表达式（本行此时已被查询到）。
    if let Err(err) = sync_rule_expression(state, &target_client, &updated).await {
        let _ = update_rule_row(state, &old_snapshot).await;
        if !same_zone {
            let _ = target_client
                .delete_dns_record(&existing.zone_id, &new_dns_id)
                .await;
        }
        return Err(ApiError::internal(format!(
            "同步目标规则失败: {}",
            err.message
        )));
    }

    // 同 zone 时 DNS 记录仍是旧的，需要把内容更新为新目标地址。
    if same_zone {
        match update_rule_dns_record(&target_client, &updated, new_host).await {
            Ok(dns_id) => {
                if !dns_id.is_empty() {
                    updated.dns_record_id = dns_id;
                    let _ = update_rule_row(state, &updated).await;
                }
            }
            Err(err) => {
                return Err(ApiError::internal(format!(
                    "更新 DNS 记录失败: {}",
                    err.message
                )))
            }
        }
    }

    // 清理旧规则中的本机名；同 zone 复用 DNS，不删除。
    let mut cleanup_old = old_snapshot.clone();
    if same_zone {
        cleanup_old.dns_record_id = String::new();
    }
    if let Err(err) = detach_rule_from_cf(state, &old_client, &cleanup_old).await {
        tracing::warn!(error = %err.message, "[ForwardRule] 并入共享端口后清理旧规则失败");
    }

    if !same_zone && !old_snapshot.dns_record_id.is_empty() {
        if let Err(err) = old_client
            .delete_dns_record(&old_snapshot.zone_id, &old_snapshot.dns_record_id)
            .await
        {
            if !is_10001(&err) {
                tracing::warn!(
                    dns_id = %old_snapshot.dns_record_id,
                    %err,
                    "[ForwardRule] 删除旧 DNS 记录失败"
                );
            }
        }
    }

    enable_zone_forwarding_settings(&target_client, &existing.zone_id).await;
    Ok(())
}

/// 将单条规则迁移到新 zone。
async fn migrate_rule_to_zone(
    state: &Arc<AppState>,
    rule: &mut ForwardRule,
    new_zone: &Zone,
) -> FResult<()> {
    let old_client = state.cf_client_for_account(rule.account_id).await?;
    let new_client = state.cf_client_for_account(new_zone.account_id).await?;

    // 1) 新 zone 建 DNS（随机子域名）
    let new_hostname = format!("{}.{}", generate_random_string(8), new_zone.name);
    let created_dns = new_client
        .create_dns_record(
            &new_zone.cf_id,
            &DnsRecord {
                zone_id: new_zone.cf_id.clone(),
                name: new_hostname.clone(),
                record_type: detect_dns_record_type(&rule.origin_host).to_string(),
                content: rule.origin_host.clone(),
                ttl: 1,
                proxied: true,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| ApiError::internal(format!("在新域名创建 DNS 记录失败: {e}")))?;

    // 2) 新 zone 建/合并 Origin Rule
    let ruleset = new_forward_ruleset(vec![new_origin_rule(
        rule.origin_port,
        build_host_expression(std::slice::from_ref(&new_hostname)),
        rule.enabled,
    )]);
    let (created, is_new) =
        match ensure_origin_ruleset(&new_client, &new_zone.cf_id, &ruleset).await {
            Ok(result) => result,
            Err(err) => {
                let _ = new_client
                    .delete_dns_record(&new_zone.cf_id, &created_dns.id)
                    .await;
                return Err(ApiError::internal(format!(
                    "在新域名创建规则失败: {}",
                    err.message
                )));
            }
        };

    let mut new_rule_id = find_rule_id_by_port(&created.rules, rule.origin_port);
    if new_rule_id.is_empty() && created.rules.len() == 1 {
        new_rule_id = created.rules[0].id.clone();
    }

    // 3) 清理旧 zone（成功建好新资源后再拆旧资源）
    if let Err(err) = cleanup_rule_from_zone(state, &old_client, rule).await {
        let _ = new_client
            .delete_dns_record(&new_zone.cf_id, &created_dns.id)
            .await;
        if is_new {
            let _ = new_client
                .delete_origin_ruleset(&new_zone.cf_id, &created.id)
                .await;
        }
        return Err(ApiError::internal(format!(
            "清理旧域名资源失败: {}",
            err.message
        )));
    }

    // 4) 新 zone 开启转发所需设置
    enable_zone_forwarding_settings(&new_client, &new_zone.cf_id).await;

    // 5) 更新本地行指向新 zone
    rule.account_id = new_zone.account_id;
    rule.zone_id = new_zone.cf_id.clone();
    rule.zone_name = new_zone.name.clone();
    rule.hostname = new_hostname;
    rule.dns_record_id = created_dns.id;
    rule.cf_rule_set_id = created.id;
    rule.cf_rule_id = new_rule_id;
    update_rule_row(state, rule).await?;
    Ok(())
}

pub async fn delete_forward_rule(
    State(state): State<Arc<AppState>>,
    Path(rule_id): Path<i64>,
    AuthUser(claims): AuthUser,
) -> ApiResult<Response> {
    let mut local_rule =
        sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
            .bind(rule_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::not_found("规则不存在"))?;

    if claims.role != "admin" && local_rule.user_id != claims.user_id {
        return Err(ApiError::forbidden("无权操作该规则"));
    }

    if claims.role != "admin" {
        let owner = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(local_rule.user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::not_found("用户不存在"))?;
        if !owner.subscription_valid() {
            return Err(ApiError::forbidden("订阅已过期，无法修改转发规则"));
        }
    }

    let client = state.cf_client_for_account(local_rule.account_id).await?;

    // 删除前先对账，保证删除决策基于准确数据。
    let _ = reconcile_zone_forward_rules(&state, &client, &local_rule.zone_id).await;
    local_rule = sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
        .bind(rule_id)
        .fetch_one(&state.db)
        .await?;

    if let Err(err) = detach_rule_from_cf(&state, &client, &local_rule).await {
        if !forward_rule_missing_err(&err) {
            return Err(err);
        }
        tracing::info!(
            hostname = %local_rule.hostname,
            "[ForwardRule] 删除规则时 CF 侧已不存在，跳过 CF 侧清理"
        );
    }

    if !local_rule.dns_record_id.is_empty() {
        match client
            .delete_dns_record(&local_rule.zone_id, &local_rule.dns_record_id)
            .await
        {
            Ok(()) => {}
            Err(err) if is_10001(&err) => {}
            Err(err) => {
                tracing::warn!(
                    dns_id = %local_rule.dns_record_id,
                    %err,
                    "[ForwardRule] 删除 DNS 记录失败，本地记录保留"
                );
                return Err(ApiError::internal(format!(
                    "删除 DNS 记录失败，本地记录已保留: {err}"
                )));
            }
        }
    }

    sqlx::query("DELETE FROM forward_rules WHERE id = ?")
        .bind(local_rule.id)
        .execute(&state.db)
        .await?;

    tracing::info!(
        admin = %claims.username,
        role = %claims.role,
        hostname = %local_rule.hostname,
        origin = %format!("{}:{}", local_rule.origin_host, local_rule.origin_port),
        "[ForwardRule] 删除转发规则"
    );

    Ok(ok_json(json!({ "success": true })))
}

pub async fn toggle_forward_rule(
    State(state): State<Arc<AppState>>,
    Path(rule_id): Path<i64>,
    AuthUser(claims): AuthUser,
) -> ApiResult<Response> {
    let mut local_rule =
        sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
            .bind(rule_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::not_found("规则不存在"))?;

    if claims.role != "admin" && local_rule.user_id != claims.user_id {
        return Err(ApiError::forbidden("无权操作该规则"));
    }

    if claims.role != "admin" {
        let owner = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(local_rule.user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::not_found("用户不存在"))?;
        if !owner.subscription_valid() {
            return Err(ApiError::forbidden("订阅已过期，无法修改转发规则"));
        }
    }

    let new_enabled = !local_rule.enabled;
    let client = state.cf_client_for_account(local_rule.account_id).await?;

    local_rule.enabled = new_enabled;
    update_rule_row(&state, &local_rule).await?;

    if let Err(err) = sync_rule_expression(&state, &client, &local_rule).await {
        if !forward_rule_missing_err(&err) {
            local_rule.enabled = !new_enabled;
            let _ = update_rule_row(&state, &local_rule).await;
            return Err(err);
        }
        if let Err(rerr) = reconcile_zone_forward_rules(&state, &client, &local_rule.zone_id).await
        {
            local_rule.enabled = !new_enabled;
            let _ = update_rule_row(&state, &local_rule).await;
            return Err(ApiError::internal(format!(
                "自动修复规则失败: {}",
                rerr.message
            )));
        }
        local_rule = sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE id = ?")
            .bind(rule_id)
            .fetch_one(&state.db)
            .await?;
        if let Err(err) = sync_rule_expression(&state, &client, &local_rule).await {
            local_rule.enabled = !new_enabled;
            let _ = update_rule_row(&state, &local_rule).await;
            return Err(err);
        }
    }

    Ok(ok_json(json!({ "success": true, "result": local_rule })))
}

// ---------------------------------------------------------------------------
// 对账
// ---------------------------------------------------------------------------

struct RuleGroup {
    rows: Vec<ForwardRule>,
    port: i64,
}

fn enabled_hosts(rows: &[ForwardRule]) -> Vec<String> {
    rows.iter()
        .filter(|r| r.enabled)
        .map(|r| r.hostname.clone())
        .collect()
}

/// 全量对账：把本地转发规则与 Cloudflare 侧对齐，重建丢失的 ruleset/rule/DNS。
async fn reconcile_zone_forward_rules(
    state: &AppState,
    client: &Client,
    zone_id: &str,
) -> FResult<usize> {
    let rows = sqlx::query_as::<_, ForwardRule>(
        "SELECT * FROM forward_rules WHERE zone_id = ? ORDER BY id ASC",
    )
    .bind(zone_id)
    .fetch_all(&state.db)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }

    let existing_list = client
        .list_origin_rulesets(zone_id)
        .await
        .map_err(|e| ApiError::internal(format!("列出 Cloudflare 规则失败: {e}")))?;

    let mut ruleset_map: HashMap<String, OriginRuleset> = HashMap::new();
    for ruleset in &existing_list {
        if let Ok(full) = client.get_origin_ruleset(zone_id, &ruleset.id).await {
            ruleset_map.insert(full.id.clone(), full);
        }
    }

    let dns_records = client
        .list_dns_records(zone_id, "")
        .await
        .unwrap_or_default();
    let dns_id_set: HashSet<String> = dns_records.into_iter().map(|r| r.id).collect();

    // 按 ruleset -> rule 分组（同端口多目标共享一条 CF rule）。
    let mut group_index: HashMap<String, usize> = HashMap::new();
    let mut groups_by_set: BTreeMap<String, Vec<RuleGroup>> = BTreeMap::new();
    for row in &rows {
        if row.cf_rule_set_id.is_empty() || row.cf_rule_id.is_empty() {
            continue;
        }
        let key = format!("{}\u{0}{}", row.cf_rule_set_id, row.cf_rule_id);
        if let Some(index) = group_index.get(&key) {
            groups_by_set
                .get_mut(&row.cf_rule_set_id)
                .expect("group set exists")[*index]
                .rows
                .push(row.clone());
        } else {
            let groups = groups_by_set.entry(row.cf_rule_set_id.clone()).or_default();
            group_index.insert(key, groups.len());
            groups.push(RuleGroup {
                rows: vec![row.clone()],
                port: row.origin_port,
            });
        }
    }

    let mut fixed = 0usize;

    for (set_id, groups) in &groups_by_set {
        let Some(full_original) = ruleset_map.get(set_id) else {
            // 整个 ruleset 丢失：按 rule-group 整体重建。
            match rebuild_zone_ruleset(state, client, zone_id, groups).await {
                Ok(recreated) => {
                    update_group_cfids(state, groups, &recreated).await;
                    for group in groups {
                        fixed += group.rows.len();
                    }
                }
                Err(err) => {
                    tracing::warn!(set_id, error = %err.message, "[ForwardRule] 重建 ruleset 失败");
                }
            }
            continue;
        };

        let mut full = full_original.clone();

        // ruleset 还在：逐条检查 rule 是否丢失。
        for group in groups {
            if find_rule_index(&full.rules, &group.rows[0].cf_rule_id).is_some() {
                continue;
            }

            let hosts = enabled_hosts(&group.rows);
            if hosts.is_empty() {
                continue;
            }

            let existing_idx = full.rules.iter().position(|r| {
                r.action_parameters
                    .as_ref()
                    .and_then(|p| p.origin.as_ref())
                    .map(|o| o.port == group.port)
                    .unwrap_or(false)
            });

            if let Some(idx) = existing_idx {
                // 同端口规则已存在：合并新 hostname 到现有规则表达式。
                let mut merged_set: HashSet<String> =
                    parse_hostname_list(&full.rules[idx].expression)
                        .into_iter()
                        .collect();
                merged_set.extend(hosts);
                let merged_list: Vec<String> = merged_set.into_iter().collect();
                full.rules[idx].expression = build_host_expression(&merged_list);
                full.rules[idx].enabled = true;

                if let Err(err) = client.update_origin_ruleset(zone_id, &full.id, &full).await {
                    tracing::warn!(ruleset = %full.id, %err, "[ForwardRule] 合并缺失 rule 失败");
                    continue;
                }
                for row in &group.rows {
                    let _ = sqlx::query(
                        "UPDATE forward_rules SET cf_rule_id = ?, updated_at = ? WHERE id = ?",
                    )
                    .bind(&full.rules[idx].id)
                    .bind(now_db())
                    .bind(row.id)
                    .execute(&state.db)
                    .await;
                }
                fixed += group.rows.len();
                continue;
            }

            // ruleset 中无同端口规则：追加新规则。
            full.rules.push(new_origin_rule(
                group.port,
                build_host_expression(&hosts),
                true,
            ));
            let updated = match client.update_origin_ruleset(zone_id, &full.id, &full).await {
                Ok(updated) => updated,
                Err(err) => {
                    tracing::warn!(ruleset = %full.id, %err, "[ForwardRule] 补回缺失 rule 失败");
                    continue;
                }
            };
            let mut new_rule_id = find_rule_id_by_port(&updated.rules, group.port);
            if new_rule_id.is_empty() && updated.rules.len() == 1 {
                new_rule_id = updated.rules[0].id.clone();
            }
            for row in &group.rows {
                let _ = sqlx::query(
                    "UPDATE forward_rules SET cf_rule_id = ?, updated_at = ? WHERE id = ?",
                )
                .bind(&new_rule_id)
                .bind(now_db())
                .bind(row.id)
                .execute(&state.db)
                .await;
            }
            fixed += group.rows.len();
        }
    }

    // DNS 对账
    for row in &rows {
        if row.dns_record_id.is_empty() || dns_id_set.contains(&row.dns_record_id) {
            continue;
        }
        let created = match client
            .create_dns_record(
                zone_id,
                &DnsRecord {
                    zone_id: zone_id.to_string(),
                    name: row.hostname.clone(),
                    record_type: detect_dns_record_type(&row.origin_host).to_string(),
                    content: row.origin_host.clone(),
                    ttl: 1,
                    proxied: true,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(created) => created,
            Err(err) => {
                tracing::warn!(hostname = %row.hostname, %err, "[ForwardRule] 重建 DNS 记录失败");
                continue;
            }
        };
        let _ =
            sqlx::query("UPDATE forward_rules SET dns_record_id = ?, updated_at = ? WHERE id = ?")
                .bind(&created.id)
                .bind(now_db())
                .bind(row.id)
                .execute(&state.db)
                .await;
        fixed += 1;
    }

    if fixed > 0 {
        tracing::info!(zone_id, fixed, "[ForwardRule] 对账完成");
    }
    Ok(fixed)
}

async fn rebuild_zone_ruleset(
    state: &AppState,
    client: &Client,
    zone_id: &str,
    groups: &[RuleGroup],
) -> FResult<OriginRuleset> {
    let mut rules = Vec::new();
    for group in groups {
        let hosts = enabled_hosts(&group.rows);
        if hosts.is_empty() {
            continue;
        }
        rules.push(new_origin_rule(
            group.port,
            build_host_expression(&hosts),
            true,
        ));
    }
    if rules.is_empty() {
        return Err(ApiError::internal("没有可重建的启用规则"));
    }

    let (recreated, _) =
        ensure_origin_ruleset(client, zone_id, &new_forward_ruleset(rules)).await?;
    let _ = state;
    Ok(recreated)
}

async fn update_group_cfids(state: &AppState, groups: &[RuleGroup], recreated: &OriginRuleset) {
    let mut rule_id_by_port: HashMap<i64, String> = HashMap::new();
    for rule in &recreated.rules {
        if let Some(port) = rule
            .action_parameters
            .as_ref()
            .and_then(|p| p.origin.as_ref())
            .map(|o| o.port)
        {
            rule_id_by_port.insert(port, rule.id.clone());
        }
    }

    for group in groups {
        let mut rule_id = rule_id_by_port
            .get(&group.port)
            .cloned()
            .unwrap_or_default();
        if rule_id.is_empty() && recreated.rules.len() == 1 {
            rule_id = recreated.rules[0].id.clone();
        }
        for row in &group.rows {
            let _ = sqlx::query(
                "UPDATE forward_rules SET cf_rule_set_id = ?, cf_rule_id = ?, updated_at = ? WHERE id = ?",
            )
            .bind(&recreated.id)
            .bind(&rule_id)
            .bind(now_db())
            .bind(row.id)
            .execute(&state.db)
            .await;
        }
    }
}

// ---------------------------------------------------------------------------
// 定时检查 / 自动修复
// ---------------------------------------------------------------------------

/// 单条与面板不一致的问题。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardCheckIssue {
    pub rule_id: i64,
    pub zone_id: String,
    pub zone_name: String,
    pub hostname: String,
    /// DNS 或 Origin Rules
    pub target: String,
    pub message: String,
}

/// 一次全量检查的结果，会持久化到 settings 供前端展示。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForwardCheckReport {
    pub checked_at: String,
    pub checked_zones: usize,
    pub checked_rules: usize,
    pub issues: Vec<ForwardCheckIssue>,
    pub fixed: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct ForwardCheckConfig {
    enabled: bool,
    interval_minutes: i64,
    auto_fix: bool,
}

async fn forward_check_config(state: &Arc<AppState>) -> ForwardCheckConfig {
    let enabled = settings::setting_value(state, "forward_check_enabled")
        .await
        .map(|v| v != "false")
        .unwrap_or(true);
    let interval_minutes = settings::setting_value(state, "forward_check_interval")
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30)
        .clamp(1, 1440);
    let auto_fix = settings::setting_value(state, "forward_check_auto_fix")
        .await
        .map(|v| v != "false")
        .unwrap_or(true);

    ForwardCheckConfig {
        enabled,
        interval_minutes,
        auto_fix,
    }
}

fn origin_rule_port(rule: &OriginRule) -> i64 {
    rule.action_parameters
        .as_ref()
        .and_then(|p| p.origin.as_ref())
        .map(|o| o.port)
        .unwrap_or(0)
}

/// 比较 DNS 记录内容：IP 归一化后比较，域名忽略大小写与结尾点。
fn dns_content_matches(record_type: &str, actual: &str, expected: &str) -> bool {
    let actual = actual.trim().trim_end_matches('.');
    let expected = expected.trim().trim_end_matches('.');
    if record_type.eq_ignore_ascii_case("A") || record_type.eq_ignore_ascii_case("AAAA") {
        if let (Ok(a), Ok(e)) = (
            actual.parse::<std::net::IpAddr>(),
            expected.parse::<std::net::IpAddr>(),
        ) {
            return a == e;
        }
    }
    if record_type.eq_ignore_ascii_case("CNAME") {
        return actual.eq_ignore_ascii_case(expected);
    }
    actual == expected
}

fn push_check_issue(
    issues: &mut Vec<ForwardCheckIssue>,
    row: &ForwardRule,
    target: &str,
    message: impl Into<String>,
) {
    issues.push(ForwardCheckIssue {
        rule_id: row.id,
        zone_id: row.zone_id.clone(),
        zone_name: row.zone_name.clone(),
        hostname: row.hostname.clone(),
        target: target.to_string(),
        message: message.into(),
    });
}

/// 纯比较逻辑：本地规则 vs Cloudflare 的 DNS 记录和 Origin Rules。
fn inspect_zone_forward_rules(
    rows: &[ForwardRule],
    dns_records: &[DnsRecord],
    rulesets: &HashMap<String, OriginRuleset>,
) -> Vec<ForwardCheckIssue> {
    let mut issues = Vec::new();

    let dns_by_id: HashMap<&str, &DnsRecord> = dns_records
        .iter()
        .filter(|record| !record.id.is_empty())
        .map(|record| (record.id.as_str(), record))
        .collect();
    let mut dns_name_counts: HashMap<String, usize> = HashMap::new();
    for record in dns_records {
        if !record.name.is_empty() {
            *dns_name_counts
                .entry(record.name.to_lowercase())
                .or_insert(0) += 1;
        }
    }

    for row in rows {
        // ---- DNS 记录 ----
        let expected_type = detect_dns_record_type(&row.origin_host);
        if row.dns_record_id.is_empty() {
            push_check_issue(&mut issues, row, "DNS", "DNS 记录关联缺失");
        } else if let Some(record) = dns_by_id.get(row.dns_record_id.as_str()) {
            let mut diffs = Vec::new();
            if !record.name.eq_ignore_ascii_case(&row.hostname) {
                diffs.push(format!("主机名 {} -> {}", row.hostname, record.name));
            }
            if !record.record_type.eq_ignore_ascii_case(expected_type) {
                diffs.push(format!("类型 {} -> {}", expected_type, record.record_type));
            }
            if !dns_content_matches(&record.record_type, &record.content, &row.origin_host) {
                diffs.push(format!("目标 {} -> {}", row.origin_host, record.content));
            }
            if !record.proxied {
                diffs.push("未开启代理".to_string());
            }
            if !diffs.is_empty() {
                push_check_issue(
                    &mut issues,
                    row,
                    "DNS",
                    format!("DNS 记录不一致: {}", diffs.join("，")),
                );
            }
        } else if dns_name_counts
            .get(&row.hostname.to_lowercase())
            .copied()
            .unwrap_or(0)
            > 0
        {
            push_check_issue(&mut issues, row, "DNS", "DNS 记录 ID 与 Cloudflare 不一致");
        } else {
            push_check_issue(&mut issues, row, "DNS", "DNS 记录不存在");
        }

        // ---- Origin Rules ----
        if row.cf_rule_set_id.is_empty() || row.cf_rule_id.is_empty() {
            push_check_issue(
                &mut issues,
                row,
                "Origin Rules",
                "缺少 Origin Ruleset/Rule 关联，无法自动修复",
            );
            continue;
        }

        let Some(ruleset) = rulesets.get(&row.cf_rule_set_id) else {
            push_check_issue(&mut issues, row, "Origin Rules", "Origin Ruleset 不存在");
            continue;
        };
        let Some(rule) = ruleset
            .rules
            .iter()
            .find(|rule| rule.id == row.cf_rule_id)
        else {
            push_check_issue(&mut issues, row, "Origin Rules", "Origin Rule 不存在");
            continue;
        };

        let hosts = parse_hostname_list(&rule.expression);
        let contains_host = hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(&row.hostname));

        if row.enabled {
            let mut diffs = Vec::new();
            let actual_port = origin_rule_port(rule);
            if actual_port != row.origin_port {
                diffs.push(format!("端口 {} -> {}", row.origin_port, actual_port));
            }
            if !contains_host {
                diffs.push("表达式未包含该主机名".to_string());
            }
            if !rule.enabled {
                diffs.push("规则已被停用".to_string());
            }
            if !diffs.is_empty() {
                push_check_issue(
                    &mut issues,
                    row,
                    "Origin Rules",
                    format!("Origin Rule 不一致: {}", diffs.join("，")),
                );
            }
        } else if contains_host {
            push_check_issue(
                &mut issues,
                row,
                "Origin Rules",
                "已禁用，但主机名仍存在于 Origin Rule 表达式",
            );
        }
    }

    issues
}

async fn fetch_zone_check_snapshot(
    client: &Client,
    zone_id: &str,
    rows: &[ForwardRule],
) -> FResult<(Vec<DnsRecord>, HashMap<String, OriginRuleset>)> {
    let dns_records = client
        .list_dns_records(zone_id, "")
        .await
        .map_err(|e| ApiError::internal(format!("列出 DNS 记录失败: {e}")))?;

    let wanted: HashSet<String> = rows
        .iter()
        .map(|row| row.cf_rule_set_id.clone())
        .filter(|id| !id.is_empty())
        .collect();

    let mut rulesets = HashMap::new();
    let list = client
        .list_origin_rulesets(zone_id)
        .await
        .map_err(|e| ApiError::internal(format!("列出 Cloudflare 规则失败: {e}")))?;
    for ruleset in list {
        if ruleset.id.is_empty() || !wanted.contains(&ruleset.id) {
            continue;
        }
        let full = client
            .get_origin_ruleset(zone_id, &ruleset.id)
            .await
            .map_err(|e| {
                ApiError::internal(format!("获取 Cloudflare 规则 {} 失败: {e}", ruleset.id))
            })?;
        rulesets.insert(full.id.clone(), full);
    }

    Ok((dns_records, rulesets))
}

async fn set_rule_dns_record_id(state: &AppState, rule_id: i64, dns_record_id: &str) {
    if let Err(err) = sqlx::query(
        "UPDATE forward_rules SET dns_record_id = ?, updated_at = ? WHERE id = ?",
    )
    .bind(dns_record_id)
    .bind(now_db())
    .bind(rule_id)
    .execute(&state.db)
    .await
    {
        tracing::warn!(rule_id, %err, "[ForwardCheck] 更新 DNS 记录 ID 失败");
    }
}

/// 修复单条规则对应的 DNS 记录（内容、类型、代理状态、记录 ID）。
async fn repair_rule_dns_record(
    state: &AppState,
    client: &Client,
    row: &ForwardRule,
    dns_records: &[DnsRecord],
) -> FResult<()> {
    let expected_type = detect_dns_record_type(&row.origin_host);
    let current = dns_records
        .iter()
        .find(|record| !row.dns_record_id.is_empty() && record.id == row.dns_record_id)
        .or_else(|| {
            dns_records
                .iter()
                .find(|record| record.name.eq_ignore_ascii_case(&row.hostname))
        });

    let Some(record) = current else {
        let created = client
            .create_dns_record(
                &row.zone_id,
                &DnsRecord {
                    zone_id: row.zone_id.clone(),
                    name: row.hostname.clone(),
                    record_type: expected_type.to_string(),
                    content: row.origin_host.clone(),
                    ttl: 1,
                    proxied: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(ce)?;
        set_rule_dns_record_id(state, row.id, &created.id).await;
        return Ok(());
    };

    let record_matches = record.name.eq_ignore_ascii_case(&row.hostname)
        && record.record_type.eq_ignore_ascii_case(expected_type)
        && dns_content_matches(&record.record_type, &record.content, &row.origin_host)
        && record.proxied;

    if record_matches {
        if record.id != row.dns_record_id {
            set_rule_dns_record_id(state, row.id, &record.id).await;
        }
        return Ok(());
    }

    if record.record_type.eq_ignore_ascii_case(expected_type) {
        let updated = client
            .update_dns_record(
                &row.zone_id,
                &record.id,
                &DnsRecord {
                    name: row.hostname.clone(),
                    record_type: expected_type.to_string(),
                    content: row.origin_host.clone(),
                    ttl: 1,
                    proxied: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(ce)?;
        set_rule_dns_record_id(state, row.id, &updated.id).await;
        return Ok(());
    }

    // 类型变化（A/AAAA/CNAME）无法可靠原地修改：新建后删除旧记录。
    let created = client
        .create_dns_record(
            &row.zone_id,
            &DnsRecord {
                zone_id: row.zone_id.clone(),
                name: row.hostname.clone(),
                record_type: expected_type.to_string(),
                content: row.origin_host.clone(),
                ttl: 1,
                proxied: true,
                ..Default::default()
            },
        )
        .await
        .map_err(ce)?;
    if let Err(err) = client.delete_dns_record(&row.zone_id, &record.id).await {
        tracing::warn!(dns_id = %record.id, %err, "[ForwardCheck] 删除旧 DNS 记录失败");
    }
    set_rule_dns_record_id(state, row.id, &created.id).await;
    Ok(())
}

/// 尽力修复某个域名下所有不一致，返回无法修复的错误信息。
async fn repair_zone_forward_rules(
    state: &AppState,
    client: &Client,
    zone_id: &str,
) -> Vec<String> {
    let mut errors = Vec::new();

    // 先补回丢失的 ruleset / rule / DNS 记录。
    if let Err(err) = reconcile_zone_forward_rules(state, client, zone_id).await {
        errors.push(format!("重建丢失的 Cloudflare 资源失败: {}", err.message));
    }

    let rows = match sqlx::query_as::<_, ForwardRule>(
        "SELECT * FROM forward_rules WHERE zone_id = ? ORDER BY id ASC",
    )
    .bind(zone_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(err) => {
            errors.push(format!("读取本地转发规则失败: {err}"));
            return errors;
        }
    };

    // DNS 修复
    let dns_records = match client.list_dns_records(zone_id, "").await {
        Ok(records) => records,
        Err(err) => {
            errors.push(format!("列出 DNS 记录失败: {err}"));
            Vec::new()
        }
    };
    for row in &rows {
        if let Err(err) = repair_rule_dns_record(state, client, row, &dns_records).await {
            errors.push(format!("修复 {} 的 DNS 记录失败: {}", row.hostname, err.message));
        }
    }

    // Origin Rules 修复：同一 (ruleset, rule) 只处理一次。
    let mut seen = HashSet::new();
    for row in &rows {
        if row.cf_rule_set_id.is_empty() || row.cf_rule_id.is_empty() {
            continue;
        }
        if !seen.insert((row.cf_rule_set_id.clone(), row.cf_rule_id.clone())) {
            continue;
        }

        let full = match client
            .get_origin_ruleset(&row.zone_id, &row.cf_rule_set_id)
            .await
        {
            Ok(full) => full,
            Err(err) => {
                errors.push(format!("获取 Cloudflare 规则 {} 失败: {err}", row.cf_rule_set_id));
                continue;
            }
        };

        let Some(rule) = full.rules.iter().find(|rule| rule.id == row.cf_rule_id) else {
            errors.push(format!("Cloudflare 规则 {} 不存在", row.cf_rule_id));
            continue;
        };

        // 先修正端口，再按面板数据重建表达式（会保留面板外手工主机名）。
        if origin_rule_port(rule) != row.origin_port {
            if let Err(err) = update_rule_port(client, row, row.origin_port).await {
                errors.push(format!("修复 {} 的端口失败: {}", row.hostname, err.message));
                continue;
            }
        }
        if let Err(err) = sync_rule_expression_strict(state, client, row).await {
            errors.push(format!("修复 {} 的 Origin Rule 失败: {}", row.hostname, err.message));
        }
    }

    errors
}

fn escape_telegram_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn notify_forward_check(state: &Arc<AppState>, report: &ForwardCheckReport) {
    if report.issues.is_empty() && report.errors.is_empty() && report.fixed == 0 {
        return;
    }

    // 相同问题不重复推送，避免定时检查反复刷屏。
    let mut signature = format!("fixed={};", report.fixed);
    for issue in &report.issues {
        signature.push_str(&format!(
            "{}|{}|{}|{};",
            issue.zone_id, issue.hostname, issue.target, issue.message
        ));
    }
    for err in &report.errors {
        signature.push_str(err);
        signature.push(';');
    }
    if settings::setting_value(state, "forward_check_last_notified")
        .await
        .as_deref()
        == Some(signature.as_str())
    {
        return;
    }

    let mut message = format!(
        "🔍 <b>转发规则定时检查</b>\n\n时间: {}\n检查域名: {}，规则: {}\n发现问题: {}，自动修复: {}",
        escape_telegram_html(&report.checked_at),
        report.checked_zones,
        report.checked_rules,
        report.issues.len(),
        report.fixed
    );

    if !report.errors.is_empty() {
        message.push_str(&format!("\n\n⚠️ <b>检查错误 ({})</b>", report.errors.len()));
        for err in report.errors.iter().take(5) {
            message.push_str(&format!("\n• {}", escape_telegram_html(err)));
        }
        if report.errors.len() > 5 {
            message.push_str(&format!("\n… 其余 {} 条", report.errors.len() - 5));
        }
    }

    if report.issues.is_empty() {
        if report.fixed > 0 {
            message.push_str("\n\n✅ 发现的问题已全部自动修复");
        }
    } else {
        message.push_str("\n\n<b>未修复问题</b>");
        for issue in report.issues.iter().take(15) {
            message.push_str(&format!(
                "\n• {} {} [{}] {}",
                escape_telegram_html(&issue.zone_name),
                escape_telegram_html(&issue.hostname),
                escape_telegram_html(&issue.target),
                escape_telegram_html(&issue.message)
            ));
        }
        if report.issues.len() > 15 {
            message.push_str(&format!("\n… 其余 {} 条", report.issues.len() - 15));
        }
    }

    // 仅在成功发送后记录签名；未配置 Telegram 时下次仍会尝试推送。
    if state.manager.send_telegram(&message).await {
        let _ = settings::save_setting(state, "forward_check_last_notified", &signature).await;
    }
}
/// 执行一次全量检查（定时任务与手动检查共用）。
pub async fn run_forward_health_check(state: &Arc<AppState>) -> ForwardCheckReport {
    let config = forward_check_config(state).await;
    let mut report = ForwardCheckReport {
        checked_at: chrono::Local::now().to_rfc3339(),
        ..Default::default()
    };

    let zone_ids = match sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT zone_id FROM forward_rules WHERE zone_id != '' ORDER BY zone_id ASC",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(ids) => ids,
        Err(err) => {
            report.errors.push(format!("查询待检查域名失败: {err}"));
            return report;
        }
    };

    for zone_id in zone_ids {
        let rows = match sqlx::query_as::<_, ForwardRule>(
            "SELECT * FROM forward_rules WHERE zone_id = ? ORDER BY id ASC",
        )
        .bind(&zone_id)
        .fetch_all(&state.db)
        .await
        {
            Ok(rows) => rows,
            Err(err) => {
                report.errors.push(format!("{zone_id}: 读取本地规则失败: {err}"));
                continue;
            }
        };
        if rows.is_empty() {
            continue;
        }

        report.checked_zones += 1;
        report.checked_rules += rows.len();

        let client = match state.cf_client_for_zone(&zone_id).await {
            Ok(client) => client,
            Err(err) => {
                report.errors.push(format!("{zone_id}: {}", err.message));
                continue;
            }
        };

        let (dns_records, rulesets) =
            match fetch_zone_check_snapshot(&client, &zone_id, &rows).await {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    report.errors.push(format!("{zone_id}: {}", err.message));
                    continue;
                }
            };

        let mut issues = inspect_zone_forward_rules(&rows, &dns_records, &rulesets);

        if config.auto_fix && !issues.is_empty() {
            let errors = repair_zone_forward_rules(state, &client, &zone_id).await;
            report.errors.extend(errors);

            // 修复后重新检查，只把仍然不一致的问题上报。
            let refreshed_rows = sqlx::query_as::<_, ForwardRule>(
                "SELECT * FROM forward_rules WHERE zone_id = ? ORDER BY id ASC",
            )
            .bind(&zone_id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
            if let Ok((dns_records, rulesets)) =
                fetch_zone_check_snapshot(&client, &zone_id, &refreshed_rows).await
            {
                let remaining =
                    inspect_zone_forward_rules(&refreshed_rows, &dns_records, &rulesets);
                report.fixed += issues.len().saturating_sub(remaining.len());
                issues = remaining;
            }
        }

        if !issues.is_empty() {
            tracing::warn!(
                zone_id = %zone_id,
                count = issues.len(),
                "[ForwardCheck] 发现与面板不一致的 DNS / Origin Rules"
            );
        }
        report.issues.extend(issues);
    }

    // 持久化最近一次检查结果。
    if let Ok(serialized) = serde_json::to_string(&report) {
        let _ = settings::save_setting(state, "forward_check_last_report", &serialized).await;
    }
    let _ = settings::save_setting(state, "forward_check_last_run", &now_db()).await;

    notify_forward_check(state, &report).await;

    tracing::info!(
        zones = report.checked_zones,
        rules = report.checked_rules,
        issues = report.issues.len(),
        fixed = report.fixed,
        errors = report.errors.len(),
        "[ForwardCheck] 检查完成"
    );

    report
}

/// 手动触发一次检查（管理员）。
pub async fn check_forward_rules(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let report = run_forward_health_check(&state).await;
    Ok(ok_json(json!({ "success": true, "result": report })))
}

/// 启动后台定时检查任务。每 60 秒唤醒一次，按配置的间隔执行。
pub fn spawn_forward_check_scheduler(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // interval 的第一次 tick 立即返回，这里先消耗掉，避免启动即检查。
        ticker.tick().await;

        loop {
            ticker.tick().await;

            let config = forward_check_config(&state).await;
            if !config.enabled {
                continue;
            }

            let last_run = settings::setting_value(&state, "forward_check_last_run")
                .await
                .and_then(|value| crate::db::parse_db_time(&value))
                .map(|dt| dt.with_timezone(&chrono::Utc));
            let due = match last_run {
                Some(last_run) => chrono::Utc::now()
                    .signed_duration_since(last_run)
                    .num_seconds()
                    >= config.interval_minutes * 60,
                None => true,
            };
            if !due {
                continue;
            }

            run_forward_health_check(&state).await;
        }
    });
}

// ---------------------------------------------------------------------------
// 账号封禁迁移
// ---------------------------------------------------------------------------

pub async fn migrate_blocked_accounts(state: &Arc<AppState>) {
    let blocked_ids: Vec<i64> =
        sqlx::query_scalar::<_, i64>("SELECT id FROM cf_accounts WHERE is_blocked = ?")
            .bind(true)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    for id in blocked_ids {
        let _ = sqlx::query("UPDATE forward_rules SET enabled = ? WHERE account_id = ?")
            .bind(true)
            .bind(id)
            .execute(&state.db)
            .await;
        migrate_account_rules(state, id).await;
        let _ = sqlx::query("UPDATE forward_rules SET enabled = ? WHERE account_id = ?")
            .bind(false)
            .bind(id)
            .execute(&state.db)
            .await;
    }
}

/// 账号被封禁后，自动将其名下转发规则迁移到其他可用账号。
pub async fn migrate_account_rules(state: &Arc<AppState>, blocked_account_id: i64) {
    tracing::info!(blocked_account_id, "[Migrate] 开始迁移账号的转发规则");

    let target_account = sqlx::query_as::<_, CfAccount>(
        "SELECT * FROM cf_accounts WHERE is_active = ? AND is_blocked = ? AND id != ? ORDER BY id ASC LIMIT 1",
    )
    .bind(true)
    .bind(false)
    .bind(blocked_account_id)
    .fetch_optional(&state.db)
    .await;

    let Ok(Some(target_account)) = target_account else {
        tracing::warn!(blocked_account_id, "[Migrate] 无其他可用账号，规则保持停用");
        return;
    };

    let rules =
        sqlx::query_as::<_, ForwardRule>("SELECT * FROM forward_rules WHERE account_id = ?")
            .bind(blocked_account_id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    if rules.is_empty() {
        tracing::info!(blocked_account_id, "[Migrate] 账号无规则需迁移");
        return;
    }

    let target_client = match state.cf_client_for_account(target_account.id).await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(
                account_id = target_account.id,
                error = %err.message,
                "[Migrate] 获取目标账号客户端失败"
            );
            return;
        }
    };

    let target_zones = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE account_id = ?")
        .bind(target_account.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    if target_zones.is_empty() {
        tracing::warn!(
            account_id = target_account.id,
            "[Migrate] 目标账号无可用 Zone，规则保持停用"
        );
        return;
    }

    // 按端口分组迁移（同端口复用一条 Origin Rule）。
    let mut port_groups: BTreeMap<i64, Vec<ForwardRule>> = BTreeMap::new();
    for rule in rules {
        port_groups.entry(rule.origin_port).or_default().push(rule);
    }

    let mut success_count = 0;
    let mut fail_count = 0;
    for (port, group) in port_groups {
        if let Err(err) = migrate_port_group(
            state,
            &target_client,
            &target_zones,
            &target_account,
            port,
            &group,
        )
        .await
        {
            tracing::warn!(port, error = %err.message, "[Migrate] 迁移端口失败");
            fail_count += 1;
        } else {
            success_count += 1;
        }
    }

    tracing::info!(
        blocked_account_id,
        success_count,
        fail_count,
        "[Migrate] 账号迁移完成"
    );
}

async fn migrate_port_group(
    state: &Arc<AppState>,
    client: &Client,
    zones: &[Zone],
    account: &CfAccount,
    port: i64,
    group: &[ForwardRule],
) -> FResult<()> {
    // 仅允许迁移到「该端口下所有规则所有者都被分配」的域名。
    let mut allowed_zones = Vec::new();
    for zone in zones {
        let mut allowed = true;
        for rule in group {
            if rule.user_id != 0 && !user_can_use_zone(state, rule.user_id, zone.id).await? {
                allowed = false;
                break;
            }
        }
        if allowed {
            allowed_zones.push(zone.clone());
        }
    }
    if allowed_zones.is_empty() {
        return Err(ApiError::internal(
            "目标账号下没有分配给规则所有者的域名，暂不迁移",
        ));
    }

    // 挑选规则最少的 Zone（以 CF 侧真实规则数为准）。
    let mut best_zone = allowed_zones[0].clone();
    let mut min_count: Option<usize> = None;
    for zone in &allowed_zones {
        let count = match client.count_origin_rules(&zone.cf_id).await {
            Ok(count) => count,
            Err(err) => {
                tracing::warn!(zone = %zone.name, %err, "[Migrate] 查询 CF 规则数失败，按 0 处理");
                0
            }
        };
        if min_count.map(|min| count < min).unwrap_or(true) {
            min_count = Some(count);
            best_zone = zone.clone();
        }
    }

    struct HostEntry {
        hostname: String,
        dns_id: String,
        rule: ForwardRule,
    }

    let mut hosts = Vec::new();
    let mut all_enabled = false;
    for rule in group {
        let hostname = format!("{}.{}", generate_random_string(8), best_zone.name);
        let created = client
            .create_dns_record(
                &best_zone.cf_id,
                &DnsRecord {
                    zone_id: best_zone.cf_id.clone(),
                    name: hostname.clone(),
                    record_type: detect_dns_record_type(&rule.origin_host).to_string(),
                    content: rule.origin_host.clone(),
                    ttl: 1,
                    proxied: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| ApiError::internal(format!("创建 DNS 失败: {e}")))?;
        if rule.enabled {
            all_enabled = true;
        }
        hosts.push(HostEntry {
            hostname,
            dns_id: created.id,
            rule: rule.clone(),
        });
    }

    let enabled_hostnames: Vec<String> = hosts
        .iter()
        .filter(|h| h.rule.enabled)
        .map(|h| h.hostname.clone())
        .collect();
    let mut expression = build_host_expression(&enabled_hostnames);
    let mut rule_enabled = all_enabled;
    if enabled_hostnames.is_empty() {
        expression = build_host_expression(&[hosts[0].hostname.clone()]);
        rule_enabled = false;
    }

    let ruleset = new_forward_ruleset(vec![new_origin_rule(port, expression, rule_enabled)]);
    let (created, _) = match ensure_origin_ruleset(client, &best_zone.cf_id, &ruleset).await {
        Ok(result) => result,
        Err(err) => {
            for host in &hosts {
                let _ = client
                    .delete_dns_record(&best_zone.cf_id, &host.dns_id)
                    .await;
            }
            return Err(ApiError::internal(format!(
                "创建 Origin Rule 失败: {}",
                err.message
            )));
        }
    };

    let mut new_rule_id = find_rule_id_by_port(&created.rules, port);
    if new_rule_id.is_empty() && created.rules.len() == 1 {
        new_rule_id = created.rules[0].id.clone();
    }

    enable_zone_forwarding_settings(client, &best_zone.cf_id).await;

    for host in &hosts {
        let _ = sqlx::query(
            "UPDATE forward_rules SET account_id = ?, zone_id = ?, zone_name = ?, hostname = ?, \
             dns_record_id = ?, cf_rule_set_id = ?, cf_rule_id = ?, updated_at = ? WHERE id = ?",
        )
        .bind(account.id)
        .bind(&best_zone.cf_id)
        .bind(&best_zone.name)
        .bind(&host.hostname)
        .bind(&host.dns_id)
        .bind(&created.id)
        .bind(&new_rule_id)
        .bind(now_db())
        .bind(host.rule.id)
        .execute(&state.db)
        .await;
    }

    Ok(())
}

async fn pause_expired_subscriptions(state: &AppState) {
    let users = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE subscription IS NOT NULL AND datetime(subscription) < datetime('now')",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for user in users {
        let rules = sqlx::query_as::<_, ForwardRule>(
            "SELECT * FROM forward_rules WHERE user_id = ? AND enabled = ?",
        )
        .bind(user.id)
        .bind(true)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        if rules.is_empty() {
            continue;
        }

        let _ = sqlx::query(
            "UPDATE forward_rules SET enabled = ?, updated_at = ? WHERE user_id = ? AND enabled = ?",
        )
        .bind(false)
        .bind(now_db())
        .bind(user.id)
        .bind(true)
        .execute(&state.db)
        .await;

        // 同一端口共享同一 cf_rule 无需重复同步。
        let mut seen = HashSet::new();
        for rule in &rules {
            let key = (
                rule.account_id,
                rule.cf_rule_set_id.clone(),
                rule.cf_rule_id.clone(),
            );
            if !seen.insert(key) {
                continue;
            }
            let client = match state.cf_client_for_account(rule.account_id).await {
                Ok(client) => client,
                Err(err) => {
                    tracing::warn!(
                        account_id = rule.account_id,
                        error = %err.message,
                        "[Subscription] 获取账号客户端失败，CF 侧规则未同步"
                    );
                    continue;
                }
            };
            if let Err(err) = sync_rule_expression(state, &client, rule).await {
                tracing::warn!(
                    ruleset = %rule.cf_rule_set_id,
                    rule = %rule.cf_rule_id,
                    error = %err.message,
                    "[Subscription] 同步 CF 规则失败"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_host() {
        assert_eq!(
            parse_hostname_list(r#"(http.host eq "a.example.com")"#),
            vec!["a.example.com"]
        );
    }

    #[test]
    fn parse_multiple_hosts() {
        assert_eq!(
            parse_hostname_list(
                r#"((http.host eq "a.example.com") or (http.host eq "b.example.com"))"#
            ),
            vec!["a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn parse_legacy_comma_list() {
        assert_eq!(
            parse_hostname_list("a.example.com, b.example.com"),
            vec!["a.example.com", "b.example.com"]
        );
        assert!(parse_hostname_list("").is_empty());
    }

    #[test]
    fn build_expression_round_trip() {
        let expr = build_host_expression(&[
            "b.example.com".to_string(),
            "a.example.com".to_string(),
            "a.example.com".to_string(),
        ]);
        assert_eq!(
            expr,
            r#"((http.host eq "a.example.com") or (http.host eq "b.example.com"))"#
        );
        assert_eq!(
            parse_hostname_list(&expr),
            vec!["a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn detect_record_types() {
        assert_eq!(detect_dns_record_type("192.0.2.1"), "A");
        assert_eq!(detect_dns_record_type("2001:db8::1"), "AAAA");
        assert_eq!(detect_dns_record_type("origin.example.com"), "CNAME");
    }

    #[test]
    fn random_string_is_expected_shape() {
        let value = generate_random_string(8);
        assert_eq!(value.len(), 8);
        assert!(value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    fn sample_rule(hostname: &str, port: i64, origin_host: &str) -> ForwardRule {
        ForwardRule {
            id: 1,
            user_id: 1,
            account_id: 1,
            zone_id: "zone-1".to_string(),
            zone_name: "example.com".to_string(),
            hostname: hostname.to_string(),
            origin_port: port,
            origin_host: origin_host.to_string(),
            enabled: true,
            cf_rule_set_id: "rs-1".to_string(),
            cf_rule_id: "rule-1".to_string(),
            dns_record_id: "dns-1".to_string(),
            created_at: None,
            updated_at: None,
        }
    }

    fn sample_snapshot(
        rule: &ForwardRule,
        dns: DnsRecord,
        rule_port: i64,
        expression: &str,
        enabled: bool,
    ) -> (Vec<DnsRecord>, HashMap<String, OriginRuleset>) {
        let origin_rule = new_origin_rule(rule_port, expression.to_string(), enabled);
        let mut origin_rule = origin_rule;
        origin_rule.id = rule.cf_rule_id.clone();
        let ruleset = OriginRuleset {
            id: rule.cf_rule_set_id.clone(),
            rules: vec![origin_rule],
            ..Default::default()
        };
        (
            vec![dns],
            HashMap::from([(rule.cf_rule_set_id.clone(), ruleset)]),
        )
    }

    #[test]
    fn inspect_detects_no_issue_when_panel_and_cf_match() {
        let rule = sample_rule("a.example.com", 8080, "192.0.2.1");
        let dns = DnsRecord {
            id: "dns-1".to_string(),
            name: "a.example.com".to_string(),
            record_type: "A".to_string(),
            content: "192.0.2.1".to_string(),
            proxied: true,
            ..Default::default()
        };
        let (dns, rulesets) = sample_snapshot(
            &rule,
            dns,
            8080,
            r#"(http.host eq "a.example.com")"#,
            true,
        );

        let issues = inspect_zone_forward_rules(&[rule], &dns, &rulesets);
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    #[test]
    fn inspect_detects_dns_and_origin_mismatch() {
        let rule = sample_rule("a.example.com", 8080, "192.0.2.1");
        let dns = DnsRecord {
            id: "dns-1".to_string(),
            name: "a.example.com".to_string(),
            record_type: "A".to_string(),
            content: "192.0.2.99".to_string(),
            proxied: true,
            ..Default::default()
        };
        let (dns, rulesets) = sample_snapshot(
            &rule,
            dns,
            9090,
            r#"(http.host eq "b.example.com")"#,
            true,
        );

        let issues = inspect_zone_forward_rules(&[rule], &dns, &rulesets);
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().any(|i| i.target == "DNS"));
        assert!(issues.iter().any(|i| i.target == "Origin Rules"));
    }

    #[test]
    fn inspect_detects_disabled_hostname_still_enabled() {
        let mut rule = sample_rule("a.example.com", 8080, "192.0.2.1");
        rule.enabled = false;
        let dns = DnsRecord {
            id: "dns-1".to_string(),
            name: "a.example.com".to_string(),
            record_type: "A".to_string(),
            content: "192.0.2.1".to_string(),
            proxied: true,
            ..Default::default()
        };
        let (dns, rulesets) = sample_snapshot(
            &rule,
            dns,
            8080,
            r#"(http.host eq "a.example.com")"#,
            true,
        );

        let issues = inspect_zone_forward_rules(&[rule], &dns, &rulesets);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].target, "Origin Rules");
    }

    #[test]
    fn dns_content_comparison_normalizes_ips_and_cnames() {
        assert!(dns_content_matches("A", "192.0.2.1", "192.0.2.1"));
        assert!(dns_content_matches("AAAA", "2001:db8::1", "2001:0db8::1"));
        assert!(dns_content_matches(
            "CNAME",
            "Origin.Example.com.",
            "origin.example.com"
        ));
        assert!(!dns_content_matches("A", "192.0.2.1", "192.0.2.2"));
    }
}
