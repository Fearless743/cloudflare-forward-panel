use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// 打开 SQLite 连接池。
///
/// 保持与 GORM（glebarez/sqlite）一致的数据库文件结构，方便直接复用旧数据：
/// - 不开启外键约束（GORM 默认不启用）
/// - 开启 busy_timeout，避免导入调度器与 HTTP 请求并发写时直接报 locked
pub async fn connect(path: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(path)?
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(10))
        .foreign_keys(false);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
}

/// 自动迁移：创建缺失的表/索引/列。
/// 与 Go 版 `db.AutoMigrate(...)` + 手工列补齐保持等价。
pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let ddl = r#"
CREATE TABLE IF NOT EXISTS `settings` (
    `key` text,
    `value` text,
    `updated_at` datetime,
    PRIMARY KEY (`key`)
);

CREATE TABLE IF NOT EXISTS `users` (
    `id` integer PRIMARY KEY AUTOINCREMENT,
    `username` text,
    `password` text,
    `role` text DEFAULT "user",
    `is_active` numeric DEFAULT true,
    `must_change_password` numeric DEFAULT false,
    `subscription` datetime,
    `created_at` datetime,
    `updated_at` datetime
);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_users_username` ON `users`(`username`);

CREATE TABLE IF NOT EXISTS `cf_accounts` (
    `id` integer PRIMARY KEY AUTOINCREMENT,
    `name` text,
    `email` text,
    `api_key` text,
    `auth_type` text DEFAULT "global_key",
    `account_id` text,
    `is_active` numeric DEFAULT true,
    `is_blocked` numeric DEFAULT false,
    `error_msg` text,
    `last_used` datetime,
    `created_at` datetime,
    `updated_at` datetime
);

CREATE TABLE IF NOT EXISTS `zones` (
    `id` integer PRIMARY KEY AUTOINCREMENT,
    `cf_id` text,
    `account_id` integer,
    `name` text,
    `status` text,
    `name_servers` text,
    `plan` text,
    `created_at` datetime,
    `updated_at` datetime
);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_zones_cf_id` ON `zones`(`cf_id`);
CREATE INDEX IF NOT EXISTS `idx_zones_account_id` ON `zones`(`account_id`);

CREATE TABLE IF NOT EXISTS `zone_users` (
    `id` integer PRIMARY KEY AUTOINCREMENT,
    `zone_id` integer,
    `user_id` integer,
    `created_at` datetime
);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_zone_user` ON `zone_users`(`zone_id`, `user_id`);

CREATE TABLE IF NOT EXISTS `forward_rules` (
    `id` integer PRIMARY KEY AUTOINCREMENT,
    `user_id` integer,
    `account_id` integer,
    `zone_id` text,
    `zone_name` text,
    `hostname` text,
    `origin_port` integer,
    `origin_host` text,
    `enabled` numeric DEFAULT true,
    `cf_rule_set_id` text,
    `cf_rule_id` text,
    `dns_record_id` text,
    `created_at` datetime,
    `updated_at` datetime
);
CREATE INDEX IF NOT EXISTS `idx_forward_rules_zone_id` ON `forward_rules`(`zone_id`);
CREATE INDEX IF NOT EXISTS `idx_forward_rules_user_id` ON `forward_rules`(`user_id`);
CREATE INDEX IF NOT EXISTS `idx_forward_rules_account_id` ON `forward_rules`(`account_id`);

CREATE TABLE IF NOT EXISTS `origin_certificates` (
    `id` integer PRIMARY KEY AUTOINCREMENT,
    `zone_id` text,
    `zone_name` text,
    `hostnames` text,
    `hostnames_key` text,
    `cf_cert_id` text,
    `certificate` text,
    `private_key` text,
    `csr` text,
    `issuer` text,
    `expires_on` text,
    `request_type` text,
    `status` text,
    `created_at` datetime,
    `updated_at` datetime
);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_origin_cert_zone_hostnames` ON `origin_certificates`(`zone_id`, `hostnames_key`);
"#;

    for statement in split_sql(ddl) {
        sqlx::query(&statement).execute(pool).await?;
    }

    // 旧版本表缺失的列：GORM AutoMigrate 会自动补齐，这里显式补齐。
    let legacy_columns: &[(&str, &str, &str)] = &[
        ("users", "must_change_password", "numeric DEFAULT false"),
        ("cf_accounts", "email", "text"),
        ("cf_accounts", "api_key", "text"),
        ("cf_accounts", "auth_type", "text DEFAULT 'global_key'"),
        ("cf_accounts", "account_id", "text"),
        ("zones", "account_id", "integer"),
        ("forward_rules", "user_id", "integer"),
        ("forward_rules", "account_id", "integer"),
        ("forward_rules", "dns_record_id", "text"),
    ];
    for (table, column, decl) in legacy_columns {
        ensure_column(pool, table, column, decl).await?;
    }

    // 旧索引可能尚未创建（列是后来补的）
    for statement in [
        "CREATE INDEX IF NOT EXISTS `idx_forward_rules_user_id` ON `forward_rules`(`user_id`)",
        "CREATE INDEX IF NOT EXISTS `idx_forward_rules_account_id` ON `forward_rules`(`account_id`)",
        "CREATE INDEX IF NOT EXISTS `idx_zones_account_id` ON `zones`(`account_id`)",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }

    Ok(())
}

async fn ensure_column(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    decl: &str,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(&format!("PRAGMA table_info(`{table}`)"))
        .fetch_all(pool)
        .await?;
    let exists = rows.iter().any(|row| {
        row.try_get::<String, _>("name")
            .map(|n| n == column)
            .unwrap_or(false)
    });
    if !exists {
        sqlx::query(&format!(
            "ALTER TABLE `{table}` ADD COLUMN `{column}` {decl}"
        ))
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// 粗略按分号拆分 SQL（DDL 中不含字符串内分号）。
fn split_sql(sql: &str) -> Vec<String> {
    sql.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// 生成与 Go 版一致的数据库时间字符串（本地时区 + 纳秒）。
pub fn now_db() -> String {
    let now = chrono::Local::now();
    now.format("%Y-%m-%d %H:%M:%S%.9f%:z").to_string()
}

/// 解析数据库里的时间字符串（兼容 GORM 写入的多种格式）。
pub fn parse_db_time(raw: &str) -> Option<DateTime<FixedOffset>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // 形如 2026-08-12 04:44:35.686702315+08:00
    if let Ok(dt) = DateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f%:z") {
        return Some(dt);
    }
    // 形如 2026-08-12T04:44:35.686702315+08:00
    if let Ok(dt) = DateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f%:z") {
        return Some(dt);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt);
    }
    // 无时区：按 UTC 处理
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Some(Utc.from_utc_datetime(&naive).fixed_offset());
        }
    }
    None
}

/// 把数据库时间规范化为 RFC3339（与 Go time.Time 的 JSON 输出一致）。
pub fn db_time_to_rfc3339(raw: &str) -> Option<String> {
    parse_db_time(raw).map(|dt| dt.to_rfc3339_opts(SecondsFormat::AutoSi, false))
}

/// 判断订阅时间是否已过期（None 表示永久有效）。
pub fn is_subscription_expired(subscription: Option<&str>) -> bool {
    match subscription {
        None => false,
        Some(raw) => match parse_db_time(raw) {
            Some(expires) => Utc::now() > expires.with_timezone(&Utc),
            // 无法解析时按「未过期」处理，避免误封用户
            None => false,
        },
    }
}

/// 生成 `?, ?, ?` 形式的占位符串。
pub fn placeholders(count: usize) -> String {
    std::iter::repeat_n("?", count)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gorm_time_with_offset() {
        let raw = "2026-08-12 04:44:35.686702315+08:00";
        let normalized = db_time_to_rfc3339(raw).expect("time parses");
        assert!(normalized.starts_with("2026-08-12T04:44:35.686702315+08:00"));
    }

    #[test]
    fn parses_utc_time_without_offset() {
        assert!(parse_db_time("2026-08-12 04:44:35").is_some());
    }

    #[test]
    fn expired_subscription_detection() {
        assert!(!is_subscription_expired(None));
        assert!(is_subscription_expired(Some("2020-01-01 00:00:00+00:00")));
        assert!(!is_subscription_expired(Some("2999-01-01 00:00:00+00:00")));
        // 无法解析时按未过期处理
        assert!(!is_subscription_expired(Some("not-a-date")));
    }

    #[test]
    fn placeholders_string() {
        assert_eq!(placeholders(0), "");
        assert_eq!(placeholders(3), "?,?,?");
    }

    #[tokio::test]
    async fn migrate_backfills_auth_type_for_legacy_accounts() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("legacy.db");
        let pool = connect(&db_path.to_string_lossy()).await.expect("connect");

        sqlx::query(
            "CREATE TABLE cf_accounts (\
             `id` integer PRIMARY KEY AUTOINCREMENT, `name` text, `email` text, `api_key` text, \
             `account_id` text, `is_active` numeric DEFAULT true, `is_blocked` numeric DEFAULT false, \
             `error_msg` text, `last_used` datetime, `created_at` datetime, `updated_at` datetime)",
        )
        .execute(&pool)
        .await
        .expect("create legacy table");

        sqlx::query(
            "INSERT INTO cf_accounts (name, email, api_key, account_id, is_active, is_blocked, error_msg) \
             VALUES ('legacy', 'a@b.com', 'key', 'acc', 1, 0, '')",
        )
        .execute(&pool)
        .await
        .expect("insert legacy account");

        migrate(&pool).await.expect("migrate");

        // 旧数据默认按 Global API Key 处理，新账号由接口显式写入 token。
        let auth_type: String = sqlx::query_scalar("SELECT auth_type FROM cf_accounts LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("read auth_type");
        assert_eq!(auth_type, "global_key");
    }
}
