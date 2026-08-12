package auth

import (
	"context"
	"net/http"
	"strings"
)

// Context key 类型
type contextKey string

const UserContextKey contextKey = "user"

// Middleware 认证中间件
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取 Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"未提供认证信息"}`, http.StatusUnauthorized)
			return
		}

		// 检查 Bearer token 格式
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, `{"error":"认证格式错误"}`, http.StatusUnauthorized)
			return
		}

		// 解析 token
		claims, err := ParseToken(parts[1])
		if err != nil {
			http.Error(w, `{"error":"登录已过期，请重新登录"}`, http.StatusUnauthorized)
			return
		}

		// 将用户信息存入 context
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware 管理员权限中间件
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(UserContextKey).(*Claims)
		if !ok {
			http.Error(w, `{"error":"未授权"}`, http.StatusUnauthorized)
			return
		}

		if claims.Role != "admin" {
			http.Error(w, `{"error":"需要管理员权限"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetUserFromContext 从 context 获取用户信息
func GetUserFromContext(r *http.Request) *Claims {
	claims, _ := r.Context().Value(UserContextKey).(*Claims)
	return claims
}
