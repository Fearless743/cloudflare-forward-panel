use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// JWT Claims（与 Go 版字段保持一致）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub must_change_password: bool,
    pub exp: usize,
    pub iat: usize,
}

/// 每次启动随机生成 32 字节签名密钥：重启后已签发 token 全部失效。
pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    // Go 版使用 bcrypt.DefaultCost(10)，这里保持一致
    bcrypt::hash(password, 10)
}

pub fn check_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

pub fn generate_token(
    secret: &[u8],
    user_id: i64,
    username: &str,
    role: &str,
    must_change_password: bool,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        user_id,
        username: username.to_string(),
        role: role.to_string(),
        must_change_password,
        exp: (now + 24 * 60 * 60) as usize,
        iat: now as usize,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

pub fn parse_token(secret: &[u8], token: &str) -> Option<Claims> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .ok()
        .map(|data| data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcrypt_hash_round_trip() {
        let hash = hash_password("admin123").unwrap();
        assert!(check_password("admin123", &hash));
        assert!(!check_password("wrong", &hash));
        // Go bcrypt（$2a$）生成的哈希同样可验证：兼容旧数据库中的密码
        assert!(check_password(
            "go-compat-test",
            "$2a$10$CcTgYUIXqeMPREvnSAD71ObS2yrmWlVaauMuTb86hm52c1GuDb88i"
        ));
    }

    #[test]
    fn jwt_round_trip() {
        let secret = generate_secret();
        let token = generate_token(&secret, 7, "alice", "admin", true).unwrap();
        let claims = parse_token(&secret, &token).expect("token parses");
        assert_eq!(claims.user_id, 7);
        assert_eq!(claims.username, "alice");
        assert_eq!(claims.role, "admin");
        assert!(claims.must_change_password);

        let other = generate_secret();
        assert!(parse_token(&other, &token).is_none());
    }
}
