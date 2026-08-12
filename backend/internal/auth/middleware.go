package auth

import (
	"context"
	"net/http"
	"strings"
)

// Context key 类型
type contextKey string

const UserContextKey contextKey = "user"

// UserInfo 用户在数据库中的实时状态，用于每次请求时校验
type UserInfo struct {
	Role              string
	IsActive          bool
	MustChangePassword bool
}

// UserValidator 校验用户是否仍有效（存在且启用）。
// 返回 nil 时请求将被拒绝；否则返回实时用户信息用于覆盖 token 中的快照。
type UserValidator func(userID uint) *UserInfo

// Middleware 认证中间件
// validate 可选：用于在每次请求时校验用户状态，避免禁用/删除用户后旧 token 仍有效，
// 并用数据库中的实时角色覆盖 token 中的角色快照（防止降级后旧 token 仍保有 admin 权限）。
func Middleware(validate UserValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
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

			// 校验用户状态（存在且启用），并用实时信息覆盖 token 快照
			if validate != nil {
				info := validate(claims.UserID)
				if info == nil || !info.IsActive {
					http.Error(w, `{"error":"账号已禁用或不存在"}`, http.StatusUnauthorized)
					return
				}
				claims.Role = info.Role
				claims.MustChangePassword = info.MustChangePassword
			}

			// 需要强制修改密码时，仅允许访问修改密码接口
			if claims.MustChangePassword && !strings.HasSuffix(r.URL.Path, "/auth/change-password") {
				http.Error(w, `{"error":"首次登录需修改密码"}`, http.StatusForbidden)
				return
			}

			// 将用户信息存入 context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
