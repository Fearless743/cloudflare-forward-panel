use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

/// Telegram 通知客户端。
#[derive(Clone)]
pub struct TelegramClient {
    bot_token: String,
    chat_id: String,
    http: reqwest::Client,
}

impl TelegramClient {
    pub fn new(bot_token: impl Into<String>, chat_id: impl Into<String>) -> Self {
        Self {
            bot_token: bot_token.into(),
            chat_id: chat_id.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.bot_token.is_empty() && !self.chat_id.is_empty()
    }

    /// 发送 HTML 格式消息。未配置时直接返回 Ok（与 Go 版一致）。
    pub async fn send_message(&self, text: &str) -> Result<(), String> {
        if !self.is_configured() {
            return Ok(());
        }

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("chat_id", self.chat_id.as_str()),
                ("text", text),
                ("parse_mode", "HTML"),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().as_u16() != 200 {
            return Err(format!(
                "telegram API error: HTTP {}",
                resp.status().as_u16()
            ));
        }

        // Telegram 错误也返回 HTTP 200，需要解析 body 中的 ok 字段。
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("解析 telegram 响应失败: {e}"))?;
        let parsed: TelegramResult =
            serde_json::from_value(body).map_err(|e| format!("解析 telegram 响应失败: {e}"))?;
        if !parsed.ok {
            return Err(format!("telegram API error: {}", parsed.description));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct TelegramResult {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    description: String,
}
