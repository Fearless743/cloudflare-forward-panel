use serde::{Serialize, Serializer};

// ---------------------------------------------------------------------------
// 时间字段序列化：数据库存的是文本，JSON 输出规范化为 RFC3339（与 Go 版一致）
// ---------------------------------------------------------------------------

pub fn ser_ts_opt<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(raw) => match crate::db::db_time_to_rfc3339(raw) {
            Some(normalized) => serializer.serialize_some(&normalized),
            None => serializer.serialize_some(raw),
        },
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub role: String,
    pub is_active: bool,
    pub must_change_password: bool,
    #[serde(serialize_with = "ser_ts_opt")]
    pub subscription: Option<String>,
    #[serde(serialize_with = "ser_ts_opt")]
    pub created_at: Option<String>,
    #[serde(serialize_with = "ser_ts_opt")]
    pub updated_at: Option<String>,
}

impl User {
    /// 检查订阅是否有效：None 表示永久订阅。
    pub fn subscription_valid(&self) -> bool {
        !crate::db::is_subscription_expired(self.subscription.as_deref())
    }
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Setting {
    pub key: String,
    pub value: String,
    #[serde(serialize_with = "ser_ts_opt")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct CfAccount {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub api_key: String,
    /// token = Account API Token（Authorization: Bearer）
    /// global_key = 旧版 Global API Key（X-Auth-Key + X-Auth-Email）
    #[sqlx(default)]
    pub auth_type: String,
    pub account_id: String,
    pub is_active: bool,
    pub is_blocked: bool,
    pub error_msg: String,
    #[serde(serialize_with = "ser_ts_opt")]
    pub last_used: Option<String>,
    #[serde(serialize_with = "ser_ts_opt")]
    pub created_at: Option<String>,
    #[serde(serialize_with = "ser_ts_opt")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Default, sqlx::FromRow, Serialize)]
pub struct Zone {
    pub id: i64,
    pub cf_id: String,
    pub account_id: i64,
    pub name: String,
    pub status: String,
    pub name_servers: String,
    pub plan: String,
    #[serde(serialize_with = "ser_ts_opt")]
    pub created_at: Option<String>,
    #[serde(serialize_with = "ser_ts_opt")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct ZoneUser {
    pub id: i64,
    pub zone_id: i64,
    pub user_id: i64,
    #[serde(serialize_with = "ser_ts_opt")]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct ForwardRule {
    pub id: i64,
    pub user_id: i64,
    pub account_id: i64,
    pub zone_id: String,
    pub zone_name: String,
    pub hostname: String,
    pub origin_port: i64,
    pub origin_host: String,
    pub enabled: bool,
    #[sqlx(rename = "cf_rule_set_id")]
    #[serde(rename = "cf_ruleset_id")]
    pub cf_rule_set_id: String,
    pub cf_rule_id: String,
    pub dns_record_id: String,
    #[serde(serialize_with = "ser_ts_opt")]
    pub created_at: Option<String>,
    #[serde(serialize_with = "ser_ts_opt")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct OriginCertificate {
    pub id: i64,
    pub zone_id: String,
    pub zone_name: String,
    pub hostnames: String,
    #[serde(skip_serializing)]
    pub hostnames_key: String,
    pub cf_cert_id: String,
    pub certificate: String,
    pub private_key: String,
    pub csr: String,
    pub issuer: String,
    pub expires_on: String,
    pub request_type: String,
    pub status: String,
    #[serde(serialize_with = "ser_ts_opt")]
    pub created_at: Option<String>,
    #[serde(serialize_with = "ser_ts_opt")]
    pub updated_at: Option<String>,
}
