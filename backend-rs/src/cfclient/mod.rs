pub mod manager;

use std::time::Duration;

use rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedSender;

use crate::cfclient::manager::ReportEvent;

pub const BASE_URL: &str = "https://api.cloudflare.com/client/v4";

/// CF API 基址；可通过 `CF_API_BASE_URL` 覆盖（测试/代理场景）。
fn api_base_url() -> &'static str {
    static BASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        std::env::var("CF_API_BASE_URL")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| BASE_URL.to_string())
    })
}

#[derive(Debug, thiserror::Error)]
pub enum CfError {
    #[error("cloudflare error: {0}")]
    Api(String),
    #[error("request failed: {0}")]
    Http(String),
    #[error("parse response failed: {0}")]
    Parse(String),
    #[error("{0}")]
    Other(String),
}
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CfResponse {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub errors: Vec<CfErrorItem>,
    #[serde(default)]
    pub result: Value,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CfErrorItem {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CfPlan {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CfZone {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub name_servers: Vec<String>,
    #[serde(default)]
    pub plan: CfPlan,
}

fn de_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DnsRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub zone_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub record_type: String,
    #[serde(default)]
    pub content: String,
    #[serde(default, deserialize_with = "de_null_default")]
    pub ttl: i64,
    #[serde(default, deserialize_with = "de_null_default")]
    pub proxied: bool,
    #[serde(default, deserialize_with = "de_null_default")]
    pub comment: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OriginRuleset {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default)]
    pub rules: Vec<OriginRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OriginRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub expression: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub action_parameters: Option<ActionParams>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ActionParams {
    #[serde(default)]
    pub origin: Option<OriginParams>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_header: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OriginParams {
    #[serde(default)]
    pub port: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<Sni>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Sni {
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SslSetting {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub editable: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OriginCertificateResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub certificate: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub csr: String,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub expires_on: String,
    #[serde(default)]
    pub request_type: String,
    #[serde(default)]
    pub status: String,
}

/// 单个 Cloudflare 账号的 API 客户端。
/// 支持 Account API Token（Bearer）与旧版 Global API Key 两种认证方式。
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    pub api_key: String,
    pub email: String,
    pub auth_type: String,
    pub account_id: i64,
    pub account_identifier: String,
    pub account_name: String,
    reporter: Option<UnboundedSender<ReportEvent>>,
    base_url: &'static str,
}

impl Client {
    pub fn new(
        api_key: impl Into<String>,
        email: impl Into<String>,
        reporter: Option<UnboundedSender<ReportEvent>>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            api_key: api_key.into(),
            email: email.into(),
            auth_type: "global_key".to_string(),
            account_id: 0,
            account_identifier: String::new(),
            account_name: String::new(),
            reporter,
            base_url: api_base_url(),
        }
    }

    pub fn with_account(
        mut self,
        account_id: i64,
        account_name: impl Into<String>,
        account_identifier: impl Into<String>,
    ) -> Self {
        self.account_id = account_id;
        self.account_name = account_name.into();
        self.account_identifier = account_identifier.into();
        self
    }

    /// 设置认证方式，兼容数据库里的空值/历史值（未知值按 Global API Key 处理）。
    pub fn with_auth_type(mut self, auth_type: impl Into<String>) -> Self {
        let auth_type = auth_type.into();
        self.auth_type = if auth_type.eq_ignore_ascii_case("token") {
            "token".to_string()
        } else {
            "global_key".to_string()
        };
        self
    }

    fn uses_token(&self) -> bool {
        self.auth_type.eq_ignore_ascii_case("token")
    }

    /// 分页拉取 Zone 的路径；Account API Token 模式下按账号过滤。
    fn zones_path(&self, per_page: usize, page: usize) -> String {
        let mut path = format!("/zones?per_page={per_page}&page={page}");
        if self.uses_token() && !self.account_identifier.is_empty() {
            path.push_str("&account.id=");
            path.push_str(&self.account_identifier);
        }
        path
    }

    async fn do_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, CfError> {
        let url = format!("{}{path}", self.base_url);
        let key_prefix = if self.api_key.len() > 4 {
            format!("{}...", &self.api_key[..4])
        } else {
            self.api_key.clone()
        };
        tracing::info!(
            method = %method,
            path,
            auth_type = %self.auth_type,
            email = %self.email,
            key_prefix,
            "[CF API]"
        );

        let mut request = self
            .http
            .request(method, &url)
            .header("Content-Type", "application/json");

        if self.uses_token() {
            request = request.header("Authorization", format!("Bearer {}", self.api_key));
        } else {
            request = request
                .header("X-Auth-Key", &self.api_key)
                .header("X-Auth-Email", &self.email);
        }

        if let Some(body) = body {
            request = request.json(&body);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| CfError::Http(format!("do request: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| CfError::Http(format!("read body: {e}")))?;

        if text.is_empty() {
            if status.is_success() {
                return Ok(Value::Null);
            }
            return Err(CfError::Api(format!(
                "cloudflare error: HTTP {} (empty response)",
                status.as_u16()
            )));
        }

        let cf: CfResponse = serde_json::from_str(&text)
            .map_err(|e| CfError::Parse(format!("unmarshal response: {e}")))?;

        if !cf.success {
            let err_msg: String = cf
                .errors
                .iter()
                .map(|e| format!("[{}] {} ", e.code, e.message))
                .collect();
            if self.account_id > 0 {
                if let Some(tx) = &self.reporter {
                    let _ = tx.send(ReportEvent {
                        account_id: self.account_id,
                        error: err_msg.clone(),
                    });
                }
            }
            return Err(CfError::Api(err_msg));
        }

        Ok(cf.result)
    }

    // ---------------- Zones ----------------

    pub async fn list_zones(&self) -> Result<Vec<CfZone>, CfError> {
        let value = self
            .do_request(reqwest::Method::GET, &self.zones_path(50, 1), None)
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn get_zone(&self, zone_id: &str) -> Result<CfZone, CfError> {
        let value = self
            .do_request(reqwest::Method::GET, &format!("/zones/{zone_id}"), None)
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    /// 分页拉取全部 Zone。
    pub async fn list_all_zones(&self) -> Result<Vec<CfZone>, CfError> {
        let mut all = Vec::new();
        let mut page = 1;
        loop {
            let value = self
                .do_request(reqwest::Method::GET, &self.zones_path(100, page), None)
                .await?;
            let zones: Vec<CfZone> =
                serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))?;
            let count = zones.len();
            all.extend(zones);
            if count < 100 {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    /// 创建 Zone（接入域名）。成功时 `name_servers` 为 CF 分配的 NS。
    pub async fn create_zone(&self, domain: &str) -> Result<CfZone, CfError> {
        let mut body = json!({ "name": domain, "type": "full" });
        if !self.account_identifier.is_empty() {
            body["account"] = json!({ "id": self.account_identifier });
        }
        let value = self
            .do_request(reqwest::Method::POST, "/zones", Some(body))
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    // ---------------- DNS ----------------

    /// 分页拉取 DNS 记录（单页上限 100，超过时必须翻页）。
    pub async fn list_dns_records(
        &self,
        zone_id: &str,
        record_type: &str,
    ) -> Result<Vec<DnsRecord>, CfError> {
        let mut all = Vec::new();
        let mut page = 1;
        loop {
            let mut path = format!("/zones/{zone_id}/dns_records?per_page=100&page={page}");
            if !record_type.is_empty() {
                path.push_str("&type=");
                path.push_str(record_type);
            }
            let value = self.do_request(reqwest::Method::GET, &path, None).await?;
            let records: Vec<DnsRecord> =
                serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))?;
            let count = records.len();
            all.extend(records);
            if count < 100 {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    pub async fn create_dns_record(
        &self,
        zone_id: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, CfError> {
        let value = self
            .do_request(
                reqwest::Method::POST,
                &format!("/zones/{zone_id}/dns_records"),
                Some(serde_json::to_value(record).unwrap_or(Value::Null)),
            )
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn update_dns_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, CfError> {
        let value = self
            .do_request(
                reqwest::Method::PATCH,
                &format!("/zones/{zone_id}/dns_records/{record_id}"),
                Some(serde_json::to_value(record).unwrap_or(Value::Null)),
            )
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<(), CfError> {
        self.do_request(
            reqwest::Method::DELETE,
            &format!("/zones/{zone_id}/dns_records/{record_id}"),
            None,
        )
        .await?;
        Ok(())
    }

    // ---------------- Origin Rules ----------------

    pub async fn list_origin_rulesets(&self, zone_id: &str) -> Result<Vec<OriginRuleset>, CfError> {
        let value = self
            .do_request(
                reqwest::Method::GET,
                &format!("/zones/{zone_id}/rulesets?phase=http_request_origin&kind=zone"),
                None,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn get_origin_ruleset(
        &self,
        zone_id: &str,
        ruleset_id: &str,
    ) -> Result<OriginRuleset, CfError> {
        let value = self
            .do_request(
                reqwest::Method::GET,
                &format!("/zones/{zone_id}/rulesets/{ruleset_id}"),
                None,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn create_origin_ruleset(
        &self,
        zone_id: &str,
        ruleset: &OriginRuleset,
    ) -> Result<OriginRuleset, CfError> {
        let value = self
            .do_request(
                reqwest::Method::POST,
                &format!("/zones/{zone_id}/rulesets"),
                Some(serde_json::to_value(ruleset).unwrap_or(Value::Null)),
            )
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn update_origin_ruleset(
        &self,
        zone_id: &str,
        ruleset_id: &str,
        ruleset: &OriginRuleset,
    ) -> Result<OriginRuleset, CfError> {
        let value = self
            .do_request(
                reqwest::Method::PUT,
                &format!("/zones/{zone_id}/rulesets/{ruleset_id}"),
                Some(serde_json::to_value(ruleset).unwrap_or(Value::Null)),
            )
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn delete_origin_ruleset(
        &self,
        zone_id: &str,
        ruleset_id: &str,
    ) -> Result<(), CfError> {
        self.do_request(
            reqwest::Method::DELETE,
            &format!("/zones/{zone_id}/rulesets/{ruleset_id}"),
            None,
        )
        .await?;
        Ok(())
    }

    /// 返回指定 zone 的 http_request_origin 规则总数（含面板外手工规则）。
    pub async fn count_origin_rules(&self, zone_id: &str) -> Result<usize, CfError> {
        let rulesets = self.list_origin_rulesets(zone_id).await?;
        let mut total = 0;
        for ruleset in &rulesets {
            if ruleset.id.is_empty() {
                continue;
            }
            match self.get_origin_ruleset(zone_id, &ruleset.id).await {
                Ok(full) => total += full.rules.len(),
                Err(_) => continue,
            }
        }
        Ok(total)
    }

    /// 停用 ruleset 中的所有规则（封禁账号时尽力停用 CF 侧规则）。
    pub async fn disable_origin_rule(
        &self,
        zone_id: &str,
        ruleset_id: &str,
    ) -> Result<(), CfError> {
        let mut ruleset = self.get_origin_ruleset(zone_id, ruleset_id).await?;
        for rule in &mut ruleset.rules {
            rule.enabled = false;
        }
        self.update_origin_ruleset(zone_id, ruleset_id, &ruleset)
            .await?;
        Ok(())
    }

    // ---------------- SSL/TLS ----------------

    pub async fn get_ssl_settings(&self, zone_id: &str) -> Result<SslSetting, CfError> {
        let value = self
            .do_request(
                reqwest::Method::GET,
                &format!("/zones/{zone_id}/settings/ssl"),
                None,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn update_ssl_settings(
        &self,
        zone_id: &str,
        value: &str,
    ) -> Result<SslSetting, CfError> {
        let result = self
            .do_request(
                reqwest::Method::PATCH,
                &format!("/zones/{zone_id}/settings/ssl"),
                Some(json!({ "value": value })),
            )
            .await?;
        serde_json::from_value(result).map_err(|e| CfError::Parse(e.to_string()))
    }

    pub async fn enable_websockets(&self, zone_id: &str) -> Result<(), CfError> {
        self.do_request(
            reqwest::Method::PATCH,
            &format!("/zones/{zone_id}/settings/websockets"),
            Some(json!({ "value": "on" })),
        )
        .await?;
        Ok(())
    }

    pub async fn enable_grpc(&self, zone_id: &str) -> Result<(), CfError> {
        self.do_request(
            reqwest::Method::PATCH,
            &format!("/zones/{zone_id}/settings/grpc"),
            Some(json!({ "value": "on" })),
        )
        .await?;
        Ok(())
    }

    // ---------------- Origin Certificate ----------------

    /// 生成 Cloudflare Origin 证书：本地生成 RSA 私钥 + CSR，CF 只负责签发。
    pub async fn generate_origin_certificate(
        &self,
        hostnames: &[String],
        validity_days: i64,
    ) -> Result<OriginCertificateResponse, CfError> {
        let (csr_pem, key_pem) = generate_csr(hostnames)?;
        let body = json!({
            "hostnames": hostnames,
            "requested_validity": validity_days,
            "request_type": "origin-rsa",
            "csr": csr_pem,
        });
        let value = self
            .do_request(reqwest::Method::POST, "/certificates", Some(body))
            .await?;
        let mut cert: OriginCertificateResponse =
            serde_json::from_value(value).map_err(|e| CfError::Parse(e.to_string()))?;
        cert.private_key = key_pem;
        cert.csr = csr_pem;
        Ok(cert)
    }
}

/// 生成 RSA 私钥与 CSR（PEM）。
fn generate_csr(hostnames: &[String]) -> Result<(String, String), CfError> {
    if hostnames.is_empty() {
        return Err(CfError::Other("hostnames 不能为空".to_string()));
    }
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| CfError::Other(format!("生成 CSR 失败: {e}")))?;

    let pkcs8_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| CfError::Other(format!("生成 CSR 失败: {e}")))?;
    let key_pem = private_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| CfError::Other(format!("生成 CSR 失败: {e}")))?
        .to_string();

    let key_pair =
        rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(pkcs8_pem.as_str(), &rcgen::PKCS_RSA_SHA256)
            .map_err(|e| CfError::Other(format!("生成 CSR 失败: {e}")))?;

    let mut params = rcgen::CertificateParams::new(hostnames.to_vec())
        .map_err(|e| CfError::Other(format!("生成 CSR 失败: {e}")))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, hostnames[0].clone());
    params.distinguished_name = dn;

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| CfError::Other(format!("生成 CSR 失败: {e}")))?;
    let csr_pem = csr
        .pem()
        .map_err(|e| CfError::Other(format!("生成 CSR 失败: {e}")))?;

    Ok((csr_pem, key_pem))
}
