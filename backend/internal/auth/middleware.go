package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Context key 类型
type contextKey string

const UserContextKey contextKey = "user"

// UserInfo 用户在数据库中的实时状态，用于每次请求时校验
type UserInfo struct {
	Role               string
	IsActive           bool
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
				writeJSONError(w, http.StatusUnauthorized, "未提供认证信息")
				return
			}

			// 检查 Bearer token 格式
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				writeJSONError(w, http.StatusUnauthorized, "认证格式错误")
				return
			}

			// 解析 token
			claims, err := ParseToken(parts[1])
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "登录已过期，请重新登录")
				return
			}

			// 校验用户状态（存在且启用），并用实时信息覆盖 token 快照
			if validate != nil {
				info := validate(claims.UserID)
				if info == nil || !info.IsActive {
					writeJSONError(w, http.StatusUnauthorized, "账号已禁用或不存在")
					return
				}
				claims.Role = info.Role
				claims.MustChangePassword = info.MustChangePassword
			}

			// 需要强制修改密码时，仅允许访问修改密码接口
			if claims.MustChangePassword && !strings.HasSuffix(r.URL.Path, "/auth/change-password") {
				writeJSONError(w, http.StatusForbidden, "首次登录需修改密码")
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
			writeJSONError(w, http.StatusUnauthorized, "未授权")
			return
		}

		if claims.Role != "admin" {
			writeJSONError(w, http.StatusForbidden, "需要管理员权限")
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

// writeJSONError 以 JSON 返回认证/权限错误。
// 不能用 http.Error：它会把 Content-Type 设为 text/plain，
// 前端 axios 拿到的 data 是字符串而不是对象，无法读取 error 字段（如首次改密跳转）。
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
