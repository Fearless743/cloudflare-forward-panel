use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use serde_json::{json, Value};
use sqlx::SqlitePool;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::RwLock;

use crate::cfclient::{CfZone, Client};
use crate::db::{db_time_to_rfc3339, now_db};
use crate::models::CfAccount;
use crate::telegram::TelegramClient;

pub struct ReportEvent {
    pub account_id: i64,
    pub error: String,
}

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
pub type BlockedCallback = Arc<dyn Fn(i64) -> BoxFuture + Send + Sync>;

/// 多账号管理器：轮询可用账号，账号异常时自动切换 / 封禁。
pub struct Manager {
    db: SqlitePool,
    clients: RwLock<Vec<Arc<Client>>>,
    current_index: AtomicUsize,
    telegram: Arc<TelegramClient>,
    on_account_blocked: RwLock<Option<BlockedCallback>>,
    report_tx: UnboundedSender<ReportEvent>,
}

impl Manager {
    pub fn new(db: SqlitePool, telegram: Arc<TelegramClient>) -> Arc<Self> {
        let (tx, mut rx) = unbounded_channel::<ReportEvent>();
        let manager = Arc::new(Self {
            db,
            clients: RwLock::new(Vec::new()),
            current_index: AtomicUsize::new(0),
            telegram,
            on_account_blocked: RwLock::new(None),
            report_tx: tx,
        });

        // 错误上报使用独立任务处理，避免在 CF 请求路径上同步阻塞。
        let weak: Weak<Manager> = Arc::downgrade(&manager);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Some(m) = weak.upgrade() {
                    m.handle_report(event.account_id, event.error).await;
                }
            }
        });

        manager
    }

    /// 启动时加载账号并同步本地 Zone 表。
    pub async fn init(self: &Arc<Self>) {
        self.load_accounts().await;
        self.sync_local_zones().await;
    }

    async fn load_accounts(&self) {
        let accounts = sqlx::query_as::<_, CfAccount>(
            "SELECT * FROM cf_accounts WHERE is_active = ? AND is_blocked = ? ORDER BY id ASC",
        )
        .bind(true)
        .bind(false)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        let clients =
            accounts
                .into_iter()
                .map(|acc| {
                    Arc::new(
                        Client::new(acc.api_key, acc.email, Some(self.report_tx.clone()))
                            .with_account(acc.id, acc.name, acc.account_id)
                            .with_auth_type(acc.auth_type),
                    )
                })
                .collect::<Vec<_>>();

        tracing::info!(count = clients.len(), "[CF Manager] 加载了可用账号");
        *self.clients.write().await = clients;
    }

    pub async fn reload_accounts(&self) {
        self.load_accounts().await;
    }

    pub async fn get_client(&self) -> Result<Arc<Client>, String> {
        let client = {
            let clients = self.clients.read().await;
            if clients.is_empty() {
                return Err("没有可用的 Cloudflare 账号".to_string());
            }
            let mut index = self.current_index.load(Ordering::SeqCst);
            if index >= clients.len() {
                index = 0;
                self.current_index.store(0, Ordering::SeqCst);
            }
            clients[index].clone()
        };
        self.mark_used(&client).await;
        Ok(client)
    }

    async fn mark_used(&self, client: &Client) {
        if client.account_id == 0 {
            return;
        }
        let result = sqlx::query("UPDATE cf_accounts SET last_used = ? WHERE id = ?")
            .bind(now_db())
            .bind(client.account_id)
            .execute(&self.db)
            .await;
        if let Err(err) = result {
            tracing::warn!(account_id = client.account_id, %err, "[CF Manager] 更新最后使用时间失败");
        }
    }

    async fn handle_report(&self, account_id: i64, err_msg: String) {
        let _ = sqlx::query("UPDATE cf_accounts SET error_msg = ? WHERE id = ?")
            .bind(&err_msg)
            .bind(account_id)
            .execute(&self.db)
            .await;

        if self.telegram.is_configured() {
            let msg = format!(
                "⚠️ <b>CF 账号异常</b>\n\n账号 ID: {}\n错误信息: {}\n时间: {}",
                account_id,
                err_msg,
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            );
            let tg = self.telegram.clone();
            tokio::spawn(async move {
                if let Err(err) = tg.send_message(&msg).await {
                    tracing::warn!(%err, "发送 Telegram 通知失败");
                }
            });
        }

        // 9106=无效 token/权限，10000=认证失败；10001（资源不存在）不是封禁。
        if err_msg.contains("[9106]") || err_msg.contains("[10000]") {
            tracing::warn!(account_id, "[CF Manager] 账号被标记为封禁");
            let _ = sqlx::query("UPDATE cf_accounts SET is_blocked = ? WHERE id = ?")
                .bind(true)
                .bind(account_id)
                .execute(&self.db)
                .await;
            self.load_accounts().await;

            // 先执行迁移回调：此时规则仍保留原始 enabled 状态。
            let callback = self.on_account_blocked.read().await.clone();
            if let Some(cb) = callback {
                cb(account_id).await;
            }

            // 迁移失败的规则仍归属封禁账号：停用本地与 CF 侧规则。
            self.deactivate_account_rules_local(account_id).await;
            self.deactivate_account_rules_remote(account_id).await;
            return;
        }

        self.switch_to_next().await;
    }

    async fn deactivate_account_rules_local(&self, account_id: i64) {
        let result = sqlx::query(
            "UPDATE forward_rules SET enabled = ?, updated_at = ? WHERE account_id = ? AND enabled = ?",
        )
        .bind(false)
        .bind(now_db())
        .bind(account_id)
        .bind(true)
        .execute(&self.db)
        .await;
        match result {
            Ok(res) if res.rows_affected() > 0 => {
                tracing::warn!(
                    account_id,
                    count = res.rows_affected(),
                    "[CF Manager] 账号封禁，已停用本地转发规则"
                );
            }
            Err(err) => tracing::warn!(account_id, %err, "[CF Manager] 停用本地规则失败"),
            _ => {}
        }
    }

    async fn deactivate_account_rules_remote(&self, account_id: i64) {
        let rules = match sqlx::query_as::<_, crate::models::ForwardRule>(
            "SELECT * FROM forward_rules WHERE account_id = ? AND cf_rule_set_id != ''",
        )
        .bind(account_id)
        .fetch_all(&self.db)
        .await
        {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(account_id, %err, "[CF Manager] 查询账号转发规则失败");
                return;
            }
        };
        if rules.is_empty() {
            return;
        }

        let Some(client) = self.client_by_account_id(account_id).await else {
            return;
        };
        for rule in &rules {
            if let Err(err) = client
                .disable_origin_rule(&rule.zone_id, &rule.cf_rule_set_id)
                .await
            {
                tracing::warn!(rule_id = rule.id, %err, "[CF Manager] 停用 CF 规则失败");
            }
        }
        tracing::warn!(
            account_id,
            count = rules.len(),
            "[CF Manager] 已尽力停用 CF 侧规则"
        );
    }

    /// 返回指定账号的客户端；账号不在活跃列表时从数据库临时构造（不上报错误，避免递归）。
    async fn client_by_account_id(&self, account_id: i64) -> Option<Arc<Client>> {
        {
            let clients = self.clients.read().await;
            if let Some(client) = clients.iter().find(|c| c.account_id == account_id) {
                return Some(client.clone());
            }
        }
        let account = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts WHERE id = ?")
            .bind(account_id)
            .fetch_optional(&self.db)
            .await
            .ok()?;
        let account = account?;
        Some(Arc::new(
            Client::new(account.api_key, account.email, None)
                .with_account(account.id, account.name, account.account_id)
                .with_auth_type(account.auth_type),
        ))
    }

    pub async fn get_client_by_account_id(&self, account_id: i64) -> Result<Arc<Client>, String> {
        if account_id == 0 {
            return Err("账号未指定".to_string());
        }
        let client = self
            .client_by_account_id(account_id)
            .await
            .ok_or_else(|| format!("账号 {account_id} 不存在"))?;
        self.mark_used(&client).await;
        Ok(client)
    }

    pub async fn set_on_account_blocked(&self, cb: BlockedCallback) {
        *self.on_account_blocked.write().await = Some(cb);
    }

    async fn switch_to_next(&self) {
        let len = self.clients.read().await.len();
        if len == 0 {
            return;
        }
        let old = self.current_index.load(Ordering::SeqCst);
        let new = (old + 1) % len;
        self.current_index.store(new, Ordering::SeqCst);
        if old != new && len > 1 {
            let name = self.clients.read().await[new].account_name.clone();
            tracing::info!(from = old, to = new, name, "[CF Manager] 切换账号");
        }
    }

    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// 发送 Telegram 通知；返回是否成功发送（未配置时返回 false）。
    pub async fn send_telegram(&self, text: &str) -> bool {
        if !self.telegram.is_configured() {
            return false;
        }
        match self.telegram.send_message(text).await {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(%err, "发送 Telegram 通知失败");
                false
            }
        }
    }

    /// 返回全部账号下的所有 Zone。
    pub async fn list_all_zones(&self) -> Vec<CfZone> {
        let clients = self.clients.read().await.clone();
        let mut all = Vec::new();
        for client in clients {
            match client.list_all_zones().await {
                Ok(zones) => all.extend(zones),
                Err(err) => tracing::warn!(
                    account_id = client.account_id,
                    %err,
                    "[CF Manager] 拉取 Zone 失败"
                ),
            }
        }
        all
    }

    /// 从所有 CF 账号拉取全部 Zone，写入本地 zones 表。
    pub async fn sync_local_zones(&self) {
        let clients = self.clients.read().await.clone();
        for client in clients {
            let zones = match client.list_all_zones().await {
                Ok(zones) => zones,
                Err(err) => {
                    tracing::warn!(
                        account_id = client.account_id,
                        %err,
                        "[CF Manager] 同步 Zone 失败"
                    );
                    continue;
                }
            };
            for zone in zones {
                let result = sqlx::query(
                    "INSERT INTO zones (cf_id, account_id, name, status, name_servers, plan, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT(cf_id) DO UPDATE SET account_id = excluded.account_id",
                )
                .bind(&zone.id)
                .bind(client.account_id)
                .bind(&zone.name)
                .bind(&zone.status)
                .bind(zone.name_servers.join(","))
                .bind(&zone.plan.name)
                .bind(now_db())
                .bind(now_db())
                .execute(&self.db)
                .await;
                if let Err(err) = result {
                    tracing::warn!(cf_id = %zone.id, %err, "[CF Manager] 写入本地 Zone 失败");
                }
            }
        }
        tracing::info!("[CF Manager] 本地 Zone 同步完成");
    }

    /// 账号状态列表（供 /api/accounts/status）。
    pub async fn get_status(&self) -> Vec<Value> {
        let accounts = sqlx::query_as::<_, CfAccount>("SELECT * FROM cf_accounts")
            .fetch_all(&self.db)
            .await
            .unwrap_or_default();

        let clients = self.clients.read().await.clone();
        let current_index = self.current_index.load(Ordering::SeqCst);

        accounts
            .into_iter()
            .map(|acc| {
                let status = if !acc.is_active {
                    "disabled"
                } else if acc.is_blocked {
                    "blocked"
                } else {
                    "available"
                };
                let is_current = clients
                    .iter()
                    .enumerate()
                    .any(|(i, c)| c.account_id == acc.id && i == current_index);
                json!({
                    "id": acc.id,
                    "name": acc.name,
                    "status": status,
                    "is_current": is_current,
                    "error_msg": acc.error_msg,
                    "last_used": acc.last_used.as_deref().and_then(db_time_to_rfc3339),
                })
            })
            .collect()
    }
}
