mod api;
mod auth;
mod cfclient;
mod config;
mod db;
mod models;
mod telegram;

use std::sync::Arc;

use sqlx::SqlitePool;
use tracing_subscriber::EnvFilter;

use crate::api::AppState;
use crate::cfclient::manager::Manager;
use crate::config::Config;
use crate::telegram::TelegramClient;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::load();

    // 确保数据目录存在
    if let Some(parent) = std::path::Path::new(&cfg.db_path).parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            tracing::error!(%err, "创建数据目录失败");
            std::process::exit(1);
        }
    }

    let pool = match db::connect(&cfg.db_path).await {
        Ok(pool) => pool,
        Err(err) => {
            tracing::error!(%err, "连接数据库失败");
            std::process::exit(1);
        }
    };

    if let Err(err) = db::migrate(&pool).await {
        tracing::error!(%err, "数据库迁移失败");
        std::process::exit(1);
    }

    init_admin_account(&pool).await;

    let telegram_client = Arc::new(init_telegram_client(&pool).await);
    let manager = Manager::new(pool.clone(), telegram_client.clone());
    manager.init().await;

    let state = Arc::new(AppState {
        db: pool.clone(),
        manager: manager.clone(),
        jwt_secret: auth::generate_secret(),
    });

    // 账号被封禁时，自动迁移其名下转发规则到其他账号（弱引用避免循环）。
    let weak_state = Arc::downgrade(&state);
    manager
        .set_on_account_blocked(Arc::new(move |account_id| {
            let weak_state = weak_state.clone();
            Box::pin(async move {
                if let Some(state) = weak_state.upgrade() {
                    api::forward::migrate_account_rules(&state, account_id).await;
                }
            })
        }))
        .await;

    let app = api::router(state.clone());

    // 定时检查 DNS / Origin Rules 是否与面板一致（间隔与自动修复可在系统设置中调整）。
    api::forward::spawn_forward_check_scheduler(state.clone());

    let addr = format!("0.0.0.0:{}", cfg.server_port);
    tracing::info!(%addr, "Server starting");
    tracing::info!(count = manager.client_count().await, "可用 CF 账号数量");
    if telegram_client.is_configured() {
        tracing::info!("Telegram 通知已配置");
    }

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(%err, "监听端口失败");
            std::process::exit(1);
        }
    };

    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(%err, "Server failed");
        std::process::exit(1);
    }
}

/// 初始化默认管理员账号（admin / admin123，首次登录强制修改密码）。
async fn init_admin_account(pool: &SqlitePool) {
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    if count > 0 {
        return;
    }

    let hash = match auth::hash_password("admin123") {
        Ok(hash) => hash,
        Err(err) => {
            tracing::error!(%err, "生成管理员密码失败");
            std::process::exit(1);
        }
    };

    let now = db::now_db();
    let result = sqlx::query(
        "INSERT INTO users (username, password, role, is_active, must_change_password, subscription, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
    )
    .bind("admin")
    .bind(hash)
    .bind("admin")
    .bind(true)
    .bind(true)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            tracing::info!("Created default admin account, must change password on first login")
        }
        Err(err) => {
            tracing::error!(%err, "创建管理员账号失败");
            std::process::exit(1);
        }
    }
}

/// 从数据库读取 Telegram 配置。
async fn init_telegram_client(pool: &SqlitePool) -> TelegramClient {
    let token = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind("telegram_bot_token")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    let chat_id = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind("telegram_chat_id")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    TelegramClient::new(token, chat_id)
}
