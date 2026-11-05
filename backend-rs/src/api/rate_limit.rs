use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Mutex;

use crate::api::AppState;

#[derive(Clone)]
struct Entry {
    count: u32,
    window_start: Instant,
}

#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Entry>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn check(&self, key: &str, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        // 简单清理：表过大时移除过期项，避免无限增长
        if map.len() > 10_000 {
            map.retain(|_, e| now.duration_since(e.window_start) <= window);
        }
        let entry = map.entry(key.to_string()).or_insert(Entry {
            count: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) > window {
            entry.count = 0;
            entry.window_start = now;
        }
        if entry.count >= limit {
            return false;
        }
        entry.count += 1;
        true
    }
}

fn client_ip(headers: &axum::http::HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = value.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = value.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    peer.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn limit_auth(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(req.headers(), peer);
    let path = req.uri().path().to_string();
    let key = format!("{ip}:{path}");
    let (limit, window) = if path.ends_with("/auth/login") {
        (10u32, Duration::from_secs(60))
    } else {
        (20u32, Duration::from_secs(60))
    };
    if !state.rate_limiter.check(&key, limit, window).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({"error": "请求过于频繁，请稍后再试"})),
        )
            .into_response();
    }
    next.run(req).await
}
