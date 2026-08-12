package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("用户名或密码错误")
	ErrUserInactive       = errors.New("账号已禁用")
	ErrTokenExpired       = errors.New("登录已过期，请重新登录")
)

// JWT 配置
// secret 在每次启动时随机生成：重启后所有已签发的 token 都会失效，用户需重新登录
var jwtSecret = generateJWTSecret()

// generateJWTSecret 生成随机的 JWT 签名密钥（32 字节）
func generateJWTSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 加密随机源失败时使用时间戳兜底（几乎不会发生）
		return []byte(fmt.Sprintf("cf-panel-fallback-%d", time.Now().UnixNano()))
	}
	return b
}

// Claims JWT Claims
type Claims struct {
	UserID            uint   `json:"user_id"`
	Username          string `json:"username"`
	Role              string `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
	jwt.RegisteredClaims
}

// HashPassword 哈希密码
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword 验证密码
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken 生成 JWT Token
func GenerateToken(userID uint, username, role string, mustChangePassword bool) (string, error) {
	claims := Claims{
		UserID:             userID,
		Username:           username,
		Role:               role,
		MustChangePassword: mustChangePassword,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ParseToken 解析 JWT Token
func ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrTokenExpired
}
