use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::extractors::{AdminUser, ApiResult};
use crate::api::settings::{save_setting, setting_value};
use crate::api::{ok_json, AppState};
use crate::db::now_db;

/// 一次批量开启 ECH 的结果摘要。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EchReport {
    pub checked_at: String,
    pub checked_zones: usize,
    pub enabled: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct EchConfig {
    auto_enable: bool,
    interval_minutes: i64,
}

async fn ech_config(state: &Arc<AppState>) -> EchConfig {
    let auto_enable = setting_value(state, "ech_auto_enable")
        .await
        .map(|v| v != "false")
        .unwrap_or(true);
    let interval_minutes = setting_value(state, "ech_check_interval")
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(360)
        .clamp(30, 10080);
    EchConfig {
        auto_enable,
        interval_minutes,
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ZoneRef {
    cf_id: String,
    name: String,
}

/// 尽力为单个 Zone 开启 ECH；失败只记录日志，不影响主流程。
pub async fn enable_ech_for_zone(state: &Arc<AppState>, zone_id: &str) {
    let client = match state.cf_client_for_zone(zone_id).await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(zone_id, error = %err.message, "[ECH] 获取 CF 客户端失败");
            return;
        }
    };
    match client.set_ech(zone_id, "on").await {
        Ok(_) => tracing::info!(zone_id, "[ECH] 已开启"),
        Err(err) => tracing::warn!(zone_id, %err, "[ECH] 开启失败"),
    }
}

/// 遍历本地已同步的全部域名，逐个开启 ECH。
async fn run_ech_enable_all(state: &Arc<AppState>) -> EchReport {
    let mut report = EchReport {
        checked_at: chrono::Local::now().to_rfc3339(),
        ..Default::default()
    };

    let zones = match sqlx::query_as::<_, ZoneRef>(
        "SELECT cf_id, name FROM zones WHERE cf_id != '' ORDER BY name ASC",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(zones) => zones,
        Err(err) => {
            report.errors.push(format!("查询域名失败: {err}"));
            return report;
        }
    };

    // 多账号同步可能产生重复记录，按 cf_id 去重。
    let mut seen = HashSet::new();
    for zone in zones {
        if !seen.insert(zone.cf_id.clone()) {
            continue;
        }
        report.checked_zones += 1;
        let client = match state.cf_client_for_zone(&zone.cf_id).await {
            Ok(client) => client,
            Err(err) => {
                report.errors.push(format!("{}: {}", zone.name, err.message));
                continue;
            }
        };
        match client.set_ech(&zone.cf_id, "on").await {
            Ok(_) => report.enabled += 1,
            Err(err) => report.errors.push(format!("{}: {err}", zone.name)),
        }
    }

    if let Ok(serialized) = serde_json::to_string(&report) {
        let _ = save_setting(state, "ech_last_report", &serialized).await;
    }
    let _ = save_setting(state, "ech_last_run", &now_db()).await;

    tracing::info!(
        zones = report.checked_zones,
        enabled = report.enabled,
        errors = report.errors.len(),
        "[ECH] 批量开启完成"
    );

    report
}

/// 在后台启动一次批量开启；已有任务在运行则返回 false。
/// 锁在触发时即被占用，确保前端随后查询状态时不会误判为“尚未开始”。
fn spawn_ech_enable_all(state: &Arc<AppState>) -> bool {
    let Ok(guard) = state.ech_lock.clone().try_lock_owned() else {
        return false;
    };
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = guard;
        run_ech_enable_all(&state).await;
    });
    true
}

/// 手动触发一次批量开启（管理员）。立即返回，由前端轮询进度。
pub async fn enable_ech_all(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let started = spawn_ech_enable_all(&state);
    Ok(ok_json(json!({
        "success": true,
        "result": { "started": started, "running": true }
    })))
}

/// 查询运行状态与最近一次结果（管理员）。
pub async fn ech_status(
    State(state): State<Arc<AppState>>,
    AdminUser(_claims): AdminUser,
) -> ApiResult<Response> {
    let running = state.ech_lock.try_lock().is_err();
    let last_report = setting_value(&state, "ech_last_report")
        .await
        .and_then(|value| serde_json::from_str::<Value>(&value).ok())
        .unwrap_or(Value::Null);
    let last_run = setting_value(&state, "ech_last_run").await;

    Ok(ok_json(json!({
        "success": true,
        "result": {
            "running": running,
            "last_report": last_report,
            "last_run": last_run,
        }
    })))
}

/// 启动后台定时巡检任务。每 60 秒唤醒一次，按配置的间隔执行。
pub fn spawn_ech_scheduler(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // interval 的第一次 tick 立即返回，这里先消耗掉，避免启动即执行。
        ticker.tick().await;

        loop {
            ticker.tick().await;

            let config = ech_config(&state).await;
            if !config.auto_enable {
                continue;
            }

            let last_run = setting_value(&state, "ech_last_run")
                .await
                .and_then(|value| crate::db::parse_db_time(&value))
                .map(|dt| dt.with_timezone(&chrono::Utc));
            let due = match last_run {
                Some(last_run) => {
                    chrono::Utc::now()
                        .signed_duration_since(last_run)
                        .num_seconds()
                        >= config.interval_minutes * 60
                }
                None => true,
            };
            if !due {
                continue;
            }

            // 已有任务（例如管理员手动触发）在运行时跳过本次，等待下个周期。
            let Ok(_guard) = state.ech_lock.clone().try_lock_owned() else {
                continue;
            };
            run_ech_enable_all(&state).await;
        }
    });
}
