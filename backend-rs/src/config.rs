use std::env;

/// 服务配置：仅读取 DB_PATH 与 SERVER_PORT 两个环境变量。
/// Cloudflare 凭证、Telegram 配置都存放在数据库里，不读环境变量。
#[derive(Debug, Clone)]
pub struct Config {
    pub db_path: String,
    pub server_port: String,
}

impl Config {
    pub fn load() -> Self {
        Self {
            db_path: get_env("DB_PATH", "./data/cloudflare.db"),
            server_port: get_env("SERVER_PORT", "8080"),
        }
    }
}

fn get_env(key: &str, fallback: &str) -> String {
    env::var(key).unwrap_or_else(|_| fallback.to_string())
}
