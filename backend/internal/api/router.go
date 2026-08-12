package api

import (
	"cloudflare-forward-panel/internal/auth"
	"cloudflare-forward-panel/internal/cfclient"
	"cloudflare-forward-panel/internal/config"
	"cloudflare-forward-panel/internal/models"
	registrarPkg "cloudflare-forward-panel/internal/registrar"
	"cloudflare-forward-panel/internal/telegram"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
)

type Handler struct {
	db        *gorm.DB
	manager   *cfclient.Manager
	config    *config.Config
	scheduler *ImportScheduler
}

func NewHandler(db *gorm.DB, manager *cfclient.Manager, cfg *config.Config) *Handler {
	h := &Handler{db: db, manager: manager, config: cfg}
	h.scheduler = NewImportScheduler(db, manager)
	return h
}

// StartImportScheduler 启动导入调度器
func (h *Handler) StartImportScheduler() {
	h.scheduler.Start()
}

// getCFClient 获取当前可用的 CF 客户端
func (h *Handler) getCFClient() (*cfclient.Client, error) {
	return h.manager.GetClient()
}

func (h *Handler) Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)

	r.Route("/api", func(r chi.Router) {
		// 公开路由 - 不需要认证
		r.Post("/auth/login", h.login)

		// 需要认证的路由
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware)

			// 用户信息
			r.Get("/auth/me", h.getCurrentUser)

			// 设置
			r.Get("/settings", h.getSettings)
			r.Put("/settings", h.updateSettings)
			r.Post("/settings/test", h.testConnection)
			r.Post("/settings/test-telegram", h.testTelegram)

			// 账号管理 - 仅管理员
			r.Group(func(r chi.Router) {
				r.Use(auth.AdminMiddleware)
				r.Route("/accounts", func(r chi.Router) {
					r.Get("/", h.listAccounts)
					r.Post("/", h.createAccount)
					r.Put("/{accountID}", h.updateAccount)
					r.Delete("/{accountID}", h.deleteAccount)
					r.Post("/{accountID}/toggle", h.toggleAccount)
					r.Post("/{accountID}/unblock", h.unblockAccount)
					r.Get("/status", h.getAccountStatus)
				})
			})

			r.Route("/zones", func(r chi.Router) {
				r.Get("/", h.listZones)
				r.Get("/{zoneID}", h.getZone)

				r.Route("/{zoneID}/dns", func(r chi.Router) {
					r.Get("/", h.listDNSRecords)
					r.Post("/", h.createDNSRecord)
				})

				r.Route("/{zoneID}/ssl", func(r chi.Router) {
					r.Get("/", h.getSSLSettings)
					r.Patch("/", h.updateSSLSettings)
				})
			})

			r.Route("/dns", func(r chi.Router) {
				r.Put("/{recordID}", h.updateDNSRecord)
				r.Delete("/{recordID}", h.deleteDNSRecord)
			})

			// 全局端口转发规则
			r.Route("/forward-rules", func(r chi.Router) {
				r.Get("/", h.listForwardRules)
				r.Post("/", h.createForwardRule)
				r.Put("/{ruleID}", h.updateForwardRule)
				r.Delete("/{ruleID}", h.deleteForwardRule)
				r.Post("/{ruleID}/toggle", h.toggleForwardRule)
			})

			// Origin 证书
			r.Post("/origin-certificates", h.generateOriginCertificate)

			// 用户管理 - 仅管理员
			r.Group(func(r chi.Router) {
				r.Use(auth.AdminMiddleware)
				r.Get("/users", h.listUsers)
				r.Post("/users", h.createUser)
				r.Put("/users/{userID}", h.updateUser)
				r.Delete("/users/{userID}", h.deleteUser)
				r.Post("/users/{userID}/toggle", h.toggleUser)
			})

			// 域名注册商管理 - 仅管理员
			r.Group(func(r chi.Router) {
				r.Use(auth.AdminMiddleware)
				r.Route("/registrars", func(r chi.Router) {
					r.Get("/", h.listRegistrars)
					r.Post("/", h.createRegistrar)
					r.Put("/{registrarID}", h.updateRegistrar)
					r.Delete("/{registrarID}", h.deleteRegistrar)
					r.Post("/{registrarID}/toggle", h.toggleRegistrar)
					r.Post("/{registrarID}/test", h.testRegistrarConnection)
					r.Get("/{registrarID}/domains", h.listRegistrarDomains)
					r.Get("/{registrarID}/available-domains", h.listAvailableRegistrarDomains)
					r.Post("/{registrarID}/domains/import", h.importRegistrarDomains)
					r.Delete("/{registrarID}/domains/{domainID}", h.deleteRegistrarDomain)
					r.Get("/{registrarID}/tasks", h.listImportTasks)
					r.Post("/{registrarID}/tasks/retry", h.retryImportTasks)
				})
			})
		})
	})

	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   msg,
	})
}

// Settings

func (h *Handler) getSettings(w http.ResponseWriter, r *http.Request) {
	var tokenSetting, telegramTokenSetting, telegramChatIDSetting models.Setting
	h.db.Where("key = ?", "cf_api_token").First(&tokenSetting)
	h.db.Where("key = ?", "telegram_bot_token").First(&telegramTokenSetting)
	h.db.Where("key = ?", "telegram_chat_id").First(&telegramChatIDSetting)

	// 隐藏 token 的中间部分
	maskedToken := tokenSetting.Value
	if len(maskedToken) > 8 {
		maskedToken = maskedToken[:4] + "****" + maskedToken[len(maskedToken)-4:]
	}

	maskedTelegramToken := telegramTokenSetting.Value
	if len(maskedTelegramToken) > 8 {
		maskedTelegramToken = maskedTelegramToken[:4] + "****" + maskedTelegramToken[len(maskedTelegramToken)-4:]
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result": map[string]string{
			"cf_api_token":       maskedToken,
			"telegram_bot_token": maskedTelegramToken,
			"telegram_chat_id":   telegramChatIDSetting.Value,
		},
	})
}

func (h *Handler) updateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CFToken          string `json:"cf_api_token"`
		TelegramBotToken string `json:"telegram_bot_token"`
		TelegramChatID   string `json:"telegram_chat_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 保存 CF Token（只在 token 非空且不是掩码时更新，去除首尾空格）
	token := strings.TrimSpace(req.CFToken)
	if token != "" && token != "****" {
		h.db.Save(&models.Setting{Key: "cf_api_token", Value: token})
	}

	// 保存 Telegram Bot Token
	telegramToken := strings.TrimSpace(req.TelegramBotToken)
	if telegramToken != "" && telegramToken != "****" {
		h.db.Save(&models.Setting{Key: "telegram_bot_token", Value: telegramToken})
	}

	// 保存 Telegram Chat ID
	telegramChatID := strings.TrimSpace(req.TelegramChatID)
	h.db.Save(&models.Setting{Key: "telegram_chat_id", Value: telegramChatID})

	// 重新加载账号列表（CF Token 可能已更新）
	h.manager.ReloadAccounts()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "设置已保存",
	})
}

func (h *Handler) testConnection(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	zones, err := client.ListZones()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "连接失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result": map[string]interface{}{
			"status":      "ok",
			"zones_count": len(zones),
		},
	})
}

func (h *Handler) testTelegram(w http.ResponseWriter, r *http.Request) {
	var tokenSetting, chatIDSetting models.Setting
	h.db.Where("key = ?", "telegram_bot_token").First(&tokenSetting)
	h.db.Where("key = ?", "telegram_chat_id").First(&chatIDSetting)

	if tokenSetting.Value == "" || chatIDSetting.Value == "" {
		respondError(w, http.StatusBadRequest, "请先配置 Telegram Bot Token 和 Chat ID")
		return
	}

	client := telegram.NewClient(tokenSetting.Value, chatIDSetting.Value)
	err := client.SendMessage("✅ <b>测试通知</b>\n\nCloudflare 转发面板 Telegram 通知配置成功！")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "发送测试通知失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "测试通知已发送",
	})
}

// Auth

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var user models.User
	if err := h.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		respondError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	if !user.IsActive {
		respondError(w, http.StatusForbidden, "账号已禁用")
		return
	}

	if !auth.CheckPassword(req.Password, user.Password) {
		respondError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "生成token失败")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result": map[string]interface{}{
			"token":    token,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 6 {
		respondError(w, http.StatusBadRequest, "用户名至少3位，密码至少6位")
		return
	}

	// 检查用户名是否已存在
	var existing models.User
	if err := h.db.Where("username = ?", req.Username).First(&existing).Error; err == nil {
		respondError(w, http.StatusConflict, "用户名已存在")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	user := models.User{
		Username: req.Username,
		Password: hash,
		Role:     "user",
		IsActive: true,
	}

	if err := h.db.Create(&user).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "创建用户失败")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "注册成功",
	})
}

func (h *Handler) getCurrentUser(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result": map[string]interface{}{
			"user_id":  claims.UserID,
			"username": claims.Username,
			"role":     claims.Role,
		},
	})
}

// Users

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	var users []models.User
	h.db.Find(&users)

	// 隐藏密码
	for i := range users {
		users[i].Password = ""
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  users,
	})
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username     string  `json:"username"`
		Password     string  `json:"password"`
		Role         string  `json:"role"`
		Subscription *string `json:"subscription"`  // 订阅过期时间，格式：2024-12-31 或 30d/1y
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 6 {
		respondError(w, http.StatusBadRequest, "用户名至少3位，密码至少6位")
		return
	}

	// 检查用户名是否已存在
	var existing models.User
	if err := h.db.Where("username = ?", req.Username).First(&existing).Error; err == nil {
		respondError(w, http.StatusConflict, "用户名已存在")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	// 验证角色
	role := req.Role
	if role != "admin" && role != "user" {
		role = "user"
	}

	// 解析订阅时间
	var subscription *time.Time
	if req.Subscription != nil && *req.Subscription != "" {
		sub, err := parseSubscription(*req.Subscription)
		if err != nil {
			respondError(w, http.StatusBadRequest, "订阅时间格式错误")
			return
		}
		subscription = &sub
	}

	user := models.User{
		Username:     req.Username,
		Password:     hash,
		Role:         role,
		IsActive:     true,
		Subscription: subscription,
	}

	if err := h.db.Create(&user).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "创建用户失败")
		return
	}

	user.Password = ""
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  user,
	})
}

func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "userID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	var req struct {
		Password     *string `json:"password"`
		Role         *string `json:"role"`
		Subscription *string `json:"subscription"`  // 订阅过期时间，格式：2024-12-31 或 30d/1y，空字符串表示清除订阅
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var user models.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		respondError(w, http.StatusNotFound, "用户不存在")
		return
	}

	if req.Password != nil && *req.Password != "" {
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "密码加密失败")
			return
		}
		user.Password = hash
	}

	if req.Role != nil && (*req.Role == "admin" || *req.Role == "user") {
		user.Role = *req.Role
	}

	// 处理订阅时间
	if req.Subscription != nil {
		if *req.Subscription == "" {
			// 清除订阅时间
			user.Subscription = nil
		} else {
			sub, err := parseSubscription(*req.Subscription)
			if err != nil {
				respondError(w, http.StatusBadRequest, "订阅时间格式错误")
				return
			}
			user.Subscription = &sub
		}
	}

	h.db.Save(&user)

	user.Password = ""
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  user,
	})
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "userID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	// 不允许删除自己
	claims := auth.GetUserFromContext(r)
	if claims != nil && uint(userID) == claims.UserID {
		respondError(w, http.StatusBadRequest, "不能删除自己")
		return
	}

	if err := h.db.Where("id = ?", userID).Delete(&models.User{}).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "删除失败")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "用户已删除",
	})
}

func (h *Handler) toggleUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "userID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	var user models.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		respondError(w, http.StatusNotFound, "用户不存在")
		return
	}

	// 不允许禁用自己
	claims := auth.GetUserFromContext(r)
	if claims != nil && uint(userID) == claims.UserID {
		respondError(w, http.StatusBadRequest, "不能禁用自己")
		return
	}

	user.IsActive = !user.IsActive
	h.db.Save(&user)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  user,
	})
}

// Accounts

func (h *Handler) listAccounts(w http.ResponseWriter, r *http.Request) {
	var accounts []models.CFAccount
	h.db.Find(&accounts)

	// 隐藏 API Key 的中间部分
	for i := range accounts {
		if len(accounts[i].APIKey) > 8 {
			accounts[i].APIKey = accounts[i].APIKey[:4] + "****" + accounts[i].APIKey[len(accounts[i].APIKey)-4:]
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  accounts,
	})
}

func (h *Handler) createAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email     string `json:"email"`
		APIKey    string `json:"api_key"`
		AccountID string `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		respondError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.APIKey == "" {
		respondError(w, http.StatusBadRequest, "api_key is required")
		return
	}

	// 自动生成账号名称
	var count int64
	h.db.Model(&models.CFAccount{}).Count(&count)
	name := fmt.Sprintf("账号%d", count+1)

	account := models.CFAccount{
		Name:      name,
		Email:     strings.TrimSpace(req.Email),
		APIKey:    strings.TrimSpace(req.APIKey),
		AccountID: strings.TrimSpace(req.AccountID),
		IsActive:  true,
	}

	if err := h.db.Create(&account).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "创建账号失败: "+err.Error())
		return
	}

	// 刷新管理器
	h.manager.ReloadAccounts()

	// 新账号可用，立即尝试处理等待中的导入任务
	h.scheduler.Trigger()

	// 隐藏 API Key
	account.APIKey = account.APIKey[:4] + "****" + account.APIKey[len(account.APIKey)-4:]

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  account,
	})
}

func (h *Handler) updateAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := strconv.ParseUint(chi.URLParam(r, "accountID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	var req struct {
		Email     string `json:"email"`
		APIKey    string `json:"api_key"`
		AccountID string `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var account models.CFAccount
	if err := h.db.Where("id = ?", accountID).First(&account).Error; err != nil {
		respondError(w, http.StatusNotFound, "账号不存在")
		return
	}

	if req.Email != "" {
		account.Email = strings.TrimSpace(req.Email)
	}
	if req.APIKey != "" && !strings.Contains(req.APIKey, "****") {
		account.APIKey = strings.TrimSpace(req.APIKey)
	}
	if req.AccountID != "" {
		account.AccountID = strings.TrimSpace(req.AccountID)
	}

	h.db.Save(&account)
	h.manager.ReloadAccounts()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "账号已更新",
	})
}

func (h *Handler) deleteAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := strconv.ParseUint(chi.URLParam(r, "accountID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	if err := h.db.Where("id = ?", accountID).Delete(&models.CFAccount{}).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}

	h.manager.ReloadAccounts()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "账号已删除",
	})
}

func (h *Handler) toggleAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := strconv.ParseUint(chi.URLParam(r, "accountID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	var account models.CFAccount
	if err := h.db.Where("id = ?", accountID).First(&account).Error; err != nil {
		respondError(w, http.StatusNotFound, "账号不存在")
		return
	}

	account.IsActive = !account.IsActive
	h.db.Save(&account)
	h.manager.ReloadAccounts()

	// 启用账号时触发导入调度
	if account.IsActive {
		h.scheduler.Trigger()
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  account,
	})
}

func (h *Handler) unblockAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := strconv.ParseUint(chi.URLParam(r, "accountID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	h.db.Model(&models.CFAccount{}).Where("id = ?", accountID).Updates(map[string]interface{}{
		"is_blocked": false,
		"error_msg":  "",
	})

	h.manager.ReloadAccounts()

	// 解除封禁后立即处理等待中的导入任务
	h.scheduler.Trigger()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "账号已解除封禁",
	})
}

func (h *Handler) getAccountStatus(w http.ResponseWriter, r *http.Request) {
	status := h.manager.GetStatus()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  status,
	})
}

// Zones

func (h *Handler) listZones(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	zones, err := client.ListZones()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  zones,
	})
}

func (h *Handler) getZone(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	zoneID := chi.URLParam(r, "zoneID")
	zone, err := client.GetZone(zoneID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  zone,
	})
}

// DNS Records

func (h *Handler) listDNSRecords(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	zoneID := chi.URLParam(r, "zoneID")
	recordType := r.URL.Query().Get("type")

	records, err := client.ListDNSRecords(zoneID, recordType)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  records,
	})
}

func (h *Handler) createDNSRecord(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	zoneID := chi.URLParam(r, "zoneID")

	var record cfclient.DNSRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	created, err := client.CreateDNSRecord(zoneID, &record)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  created,
	})
}

func (h *Handler) updateDNSRecord(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	recordID := chi.URLParam(r, "recordID")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		respondError(w, http.StatusBadRequest, "zone_id query parameter required")
		return
	}

	var record cfclient.DNSRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	updated, err := client.UpdateDNSRecord(zoneID, recordID, &record)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  updated,
	})
}

func (h *Handler) deleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	recordID := chi.URLParam(r, "recordID")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		respondError(w, http.StatusBadRequest, "zone_id query parameter required")
		return
	}

	if err := client.DeleteDNSRecord(zoneID, recordID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// SSL/TLS

func (h *Handler) getSSLSettings(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	zoneID := chi.URLParam(r, "zoneID")

	setting, err := client.GetSSLSettings(zoneID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  setting,
	})
}

func (h *Handler) updateSSLSettings(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	zoneID := chi.URLParam(r, "zoneID")

	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validModes := map[string]bool{
		"off": true, "flexible": true, "full": true,
		"strict": true, "origin_pull": true,
	}
	if !validModes[req.Value] {
		respondError(w, http.StatusBadRequest, "invalid ssl mode")
		return
	}

	setting, err := client.UpdateSSLSettings(zoneID, req.Value)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  setting,
	})
}

// Forward Rules (全局端口转发)

func (h *Handler) listForwardRules(w http.ResponseWriter, r *http.Request) {
	// 先暂停过期用户的转发规则
	h.pauseExpiredSubscriptions()

	var rules []models.ForwardRule
	h.db.Order("zone_name, hostname").Find(&rules)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  rules,
	})
}

func (h *Handler) createForwardRule(w http.ResponseWriter, r *http.Request) {
	// 获取当前用户
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	// 检查用户订阅状态
	var user models.User
	if err := h.db.Where("id = ?", claims.UserID).First(&user).Error; err != nil {
		respondError(w, http.StatusNotFound, "用户不存在")
		return
	}
	if !isSubscriptionValid(&user) {
		respondError(w, http.StatusForbidden, "订阅已过期，无法创建转发规则")
		return
	}

	var req struct {
		OriginPort int    `json:"origin_port"`
		OriginHost string `json:"origin_host"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 验证必填字段
	if req.OriginPort == 0 || req.OriginHost == "" {
		respondError(w, http.StatusBadRequest, "origin_port, origin_host are required")
		return
	}

	// 自动选择可用的域名（选择规则最少的域名）
	var zones []models.Zone
	h.db.Find(&zones)
	if len(zones) == 0 {
		respondError(w, http.StatusBadRequest, "没有可用的域名，请先在域名管理中添加")
		return
	}

	// 找到规则最少的域名
	var bestZone models.Zone
	minRules := int64(999999)
	for _, zone := range zones {
		var count int64
		h.db.Model(&models.ForwardRule{}).Where("zone_id = ?", zone.CFID).Count(&count)
		if count < minRules {
			minRules = count
			bestZone = zone
		}
	}

	// 检查该域名是否已满10条规则
	if minRules >= 10 {
		respondError(w, http.StatusBadRequest, "所有域名的转发规则已满，请联系管理员添加更多域名")
		return
	}

	// 自动生成子域名（使用随机字符串）
	randomStr := generateRandomString(8)
	hostname := fmt.Sprintf("%s.%s", randomStr, bestZone.Name)

	// 检查端口是否已被使用（同一子域名+端口不允许重复）
	var existing models.ForwardRule
	if err := h.db.Where("zone_id = ? AND hostname = ? AND origin_port = ?", bestZone.CFID, hostname, req.OriginPort).First(&existing).Error; err == nil {
		respondError(w, http.StatusBadRequest, "该子域名的端口转发规则已存在")
		return
	}

	// 在 Cloudflare 创建 Origin Rule（仅指定目标端口，host 由 DNS 记录决定）
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	expression := fmt.Sprintf("(http.host eq %q)", hostname)
	ruleset := &cfclient.OriginRuleset{
		Name:        "CF Panel Port Forwarding",
		Description: "Port forwarding rules managed by CF Panel",
		Kind:        "zone",
		Phase:       "http_request_origin",
		Rules: []cfclient.OriginRule{
			{
				Description: fmt.Sprintf("Forward %s to port %d", hostname, req.OriginPort),
				Expression:  expression,
				Action:      "route",
				ActionParameters: &cfclient.ActionParams{
					Origin: &cfclient.OriginParams{
						Port: req.OriginPort,
					},
				},
				Enabled: req.Enabled,
			},
		},
	}

	created, err := client.CreateOriginRuleset(bestZone.CFID, ruleset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "创建 Cloudflare 规则失败: "+err.Error())
		return
	}

	// 创建 DNS 记录（根据目标地址类型自动选择 A / AAAA / CNAME）
	// IPv4 → A，IPv6 → AAAA，域名 → CNAME（均 proxied 走 CF 代理）
	recordType := detectDNSRecordType(req.OriginHost)
	dnsRecord := &cfclient.DNSRecord{
		ZoneID:  bestZone.CFID,
		Name:    hostname,
		Type:    recordType,
		Content: req.OriginHost,
		TTL:     1, // 自动 TTL
		Proxied: true,
	}
	createdDNS, err := client.CreateDNSRecord(bestZone.CFID, dnsRecord)
	if err != nil {
		// DNS 记录创建失败，回滚已创建的 Origin 规则
		client.DeleteOriginRuleset(bestZone.CFID, created.ID)
		respondError(w, http.StatusInternalServerError, "创建 DNS 记录失败: "+err.Error())
		return
	}

	// 保存到本地数据库
	localRule := models.ForwardRule{
		ZoneID:      bestZone.CFID,
		ZoneName:    bestZone.Name,
		Hostname:    hostname,
		OriginPort:  req.OriginPort,
		OriginHost:  req.OriginHost,
		Enabled:     req.Enabled,
		CFRuleSetID: created.ID,
		DNSRecordID: createdDNS.ID,
	}
	if len(created.Rules) > 0 {
		localRule.CFRuleID = created.Rules[0].ID
	}
	h.db.Create(&localRule)

	// 自动设置 SSL 为 Full 模式（忽略错误，不影响规则创建）
	_, _ = client.UpdateSSLSettings(bestZone.CFID, "full")

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  localRule,
	})
}

func (h *Handler) updateForwardRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "ruleID")

	var req struct {
		OriginPort int    `json:"origin_port"`
		OriginHost string `json:"origin_host"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 获取本地规则
	var localRule models.ForwardRule
	if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
		respondError(w, http.StatusNotFound, "规则不存在")
		return
	}

	// 检查端口是否被其他规则使用（同一子域名+端口不允许重复）
	var existing models.ForwardRule
	if err := h.db.Where("zone_id = ? AND hostname = ? AND origin_port = ? AND id != ?", localRule.ZoneID, localRule.Hostname, req.OriginPort, ruleID).First(&existing).Error; err == nil {
		respondError(w, http.StatusBadRequest, "该子域名的端口转发规则已存在")
		return
	}

	// 更新 Cloudflare 规则
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 获取现有的 ruleset
	fullRuleset, err := client.GetOriginRuleset(localRule.ZoneID, localRule.CFRuleSetID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "获取 Cloudflare 规则失败: "+err.Error())
		return
	}

	// 更新规则
	if len(fullRuleset.Rules) > 0 {
		fullRuleset.Rules[0].Description = fmt.Sprintf("Forward %s to port %d", localRule.Hostname, req.OriginPort)
		fullRuleset.Rules[0].Enabled = req.Enabled
		if fullRuleset.Rules[0].ActionParameters == nil {
			fullRuleset.Rules[0].ActionParameters = &cfclient.ActionParams{}
		}
		if fullRuleset.Rules[0].ActionParameters.Origin == nil {
			fullRuleset.Rules[0].ActionParameters.Origin = &cfclient.OriginParams{}
		}
		fullRuleset.Rules[0].ActionParameters.Origin.Port = req.OriginPort
		fullRuleset.Rules[0].ActionParameters.Origin.Host = req.OriginHost
	}

	_, err = client.UpdateOriginRuleset(localRule.ZoneID, localRule.CFRuleSetID, fullRuleset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "更新 Cloudflare 规则失败: "+err.Error())
		return
	}

	// 更新本地数据库
	localRule.OriginPort = req.OriginPort
	localRule.OriginHost = req.OriginHost
	localRule.Enabled = req.Enabled
	h.db.Save(&localRule)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  localRule,
	})
}

func (h *Handler) deleteForwardRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "ruleID")

	// 获取本地规则
	var localRule models.ForwardRule
	if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
		respondError(w, http.StatusNotFound, "规则不存在")
		return
	}

	// 删除 Cloudflare 规则
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 删除 Cloudflare 规则（若 CF 中已不存在，忽略错误继续清理本地）
	if err := client.DeleteOriginRuleset(localRule.ZoneID, localRule.CFRuleSetID); err != nil {
		// 10001 = ruleset 不存在，说明 CF 中已被删除，无需报错
		if !strings.Contains(err.Error(), "[10001]") {
			respondError(w, http.StatusInternalServerError, "删除 Cloudflare 规则失败: "+err.Error())
			return
		}
	}

	// 删除关联的 DNS 记录
	if localRule.DNSRecordID != "" {
		client.DeleteDNSRecord(localRule.ZoneID, localRule.DNSRecordID)
	}

	// 删除本地记录
	h.db.Delete(&localRule)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) toggleForwardRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "ruleID")

	var localRule models.ForwardRule
	if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
		respondError(w, http.StatusNotFound, "规则不存在")
		return
	}

	// 切换状态
	newEnabled := !localRule.Enabled

	// 更新 Cloudflare 规则
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	fullRuleset, err := client.GetOriginRuleset(localRule.ZoneID, localRule.CFRuleSetID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "获取 Cloudflare 规则失败: "+err.Error())
		return
	}

	if len(fullRuleset.Rules) > 0 {
		fullRuleset.Rules[0].Enabled = newEnabled
	}

	_, err = client.UpdateOriginRuleset(localRule.ZoneID, localRule.CFRuleSetID, fullRuleset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "更新 Cloudflare 规则失败: "+err.Error())
		return
	}

	localRule.Enabled = newEnabled
	h.db.Save(&localRule)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  localRule,
	})
}

// helper

func parseQueryInt(r *http.Request, key string, fallback int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return fallback
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return i
}

// parseSubscription 解析订阅时间
// 支持格式：
//   - 日期格式：如 "2024-12-31"
//   - 相对时间格式：如 "30d"（30天）、"1y"（1年）
func parseSubscription(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty subscription")
	}

	// 尝试解析日期格式 (YYYY-MM-DD)
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}

	// 尝试解析相对时间格式
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("invalid format")
	}

	valueStr := s[:len(s)-1]
	unit := s[len(s)-1:]

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid number: %s", valueStr)
	}

	now := time.Now()
	switch unit {
	case "d": // 天
		return now.AddDate(0, 0, value), nil
	case "M": // 月
		return now.AddDate(0, value, 0), nil
	case "y": // 年
		return now.AddDate(value, 0, 0), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported unit: %s (use d/M/y)", unit)
	}
}

// isSubscriptionValid 检查用户订阅是否有效
// 返回 true 表示订阅有效（未过期或永久订阅）
func isSubscriptionValid(user *models.User) bool {
	// 永久订阅（未设置订阅时间）
	if user.Subscription == nil {
		return true
	}
	// 订阅未过期
	return time.Now().Before(*user.Subscription)
}

// pauseExpiredSubscriptions 暂停过期用户的转发规则
func (h *Handler) pauseExpiredSubscriptions() {
	var users []models.User
	h.db.Where("subscription IS NOT NULL AND subscription < ?", time.Now()).Find(&users)

	for _, user := range users {
		// 暂停该用户的所有转发规则
		h.db.Model(&models.ForwardRule{}).
			Where("user_id = ? AND enabled = ?", user.ID, true).
			Update("enabled", false)
	}
}

// detectDNSRecordType 根据目标地址类型返回 DNS 记录类型
// IPv4 → A，IPv6 → AAAA，域名 → CNAME
func detectDNSRecordType(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, ":") {
			return "AAAA"
		}
		return "A"
	}
	return "CNAME"
}

// generateRandomString 生成指定长度的随机字符串（小写字母和数字）
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

// generateOriginCertificate 生成 Cloudflare Origin 证书
func (h *Handler) generateOriginCertificate(w http.ResponseWriter, r *http.Request) {
	client, err := h.getCFClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		ZoneID    string   `json:"zone_id"`
		Hostnames []string `json:"hostnames"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ZoneID == "" || len(req.Hostnames) == 0 {
		respondError(w, http.StatusBadRequest, "zone_id and hostnames are required")
		return
	}

	// 生成 15 年有效期的 Origin 证书
	cert, err := client.GenerateOriginCertificate(req.Hostnames, 5475)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "生成 Origin 证书失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  cert,
	})
}

// listRegistrars 列出所有注册商
func (h *Handler) listRegistrars(w http.ResponseWriter, r *http.Request) {
	var registrars []models.DomainRegistrar
	h.db.Find(&registrars)

	// 隐藏 API Secret
	for i := range registrars {
		if len(registrars[i].APISecret) > 4 {
			registrars[i].APISecret = registrars[i].APISecret[:4] + "****"
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  registrars,
	})
}

// createRegistrar 创建注册商
func (h *Handler) createRegistrar(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		APIKey    string `json:"api_key"`
		APISecret string `json:"api_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.Type == "" || req.APIKey == "" || req.APISecret == "" {
		respondError(w, http.StatusBadRequest, "name, type, api_key and api_secret are required")
		return
	}

	if req.Type != "porkbun" && req.Type != "spaceship" {
		respondError(w, http.StatusBadRequest, "type must be porkbun or spaceship")
		return
	}

	registrar := models.DomainRegistrar{
		Name:      req.Name,
		Type:      req.Type,
		APIKey:    req.APIKey,
		APISecret: req.APISecret,
		IsActive:  true,
	}

	if err := h.db.Create(&registrar).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "创建注册商失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  registrar,
	})
}

// updateRegistrar 更新注册商
func (h *Handler) updateRegistrar(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}

	var registrar models.DomainRegistrar
	if err := h.db.First(&registrar, registrarID).Error; err != nil {
		respondError(w, http.StatusNotFound, "注册商不存在")
		return
	}

	var req struct {
		Name      string `json:"name"`
		APIKey    string `json:"api_key"`
		APISecret string `json:"api_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != "" {
		registrar.Name = req.Name
	}
	if req.APIKey != "" {
		registrar.APIKey = req.APIKey
	}
	if req.APISecret != "" {
		registrar.APISecret = req.APISecret
	}

	if err := h.db.Save(&registrar).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "更新注册商失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  registrar,
	})
}

// deleteRegistrar 删除注册商
func (h *Handler) deleteRegistrar(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}

	if err := h.db.Delete(&models.DomainRegistrar{}, registrarID).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "删除注册商失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "删除成功",
	})
}

// toggleRegistrar 切换注册商状态
func (h *Handler) toggleRegistrar(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}

	var registrar models.DomainRegistrar
	if err := h.db.First(&registrar, registrarID).Error; err != nil {
		respondError(w, http.StatusNotFound, "注册商不存在")
		return
	}

	registrar.IsActive = !registrar.IsActive
	if err := h.db.Save(&registrar).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "切换状态失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  registrar,
	})
}

// testRegistrarConnection 测试注册商连接
func (h *Handler) testRegistrarConnection(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}

	var registrar models.DomainRegistrar
	if err := h.db.First(&registrar, registrarID).Error; err != nil {
		respondError(w, http.StatusNotFound, "注册商不存在")
		return
	}

	client := registrarPkg.GetClient(registrar.Type, registrar.APIKey, registrar.APISecret)
	if client == nil {
		respondError(w, http.StatusBadRequest, "不支持的注册商类型")
		return
	}

	if testErr := client.TestConnection(); testErr != nil {
		respondError(w, http.StatusInternalServerError, "连接测试失败: "+testErr.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "连接测试成功",
	})
}

// listRegistrarDomains 列出注册商下已添加的域名（来自数据库表，非注册商 API）
func (h *Handler) listRegistrarDomains(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}

	// 只返回该注册商下手动添加过的域名
	var domains []models.RegistrarDomain
	if err := h.db.Where("registrar_id = ?", registrarID).Order("id DESC").Find(&domains).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "查询失败: "+err.Error())
		return
	}

	// 收集所有 CF 账号下已存在的域名，标记是否已接入
	existing := h.manager.ListAllZoneNames()
	existingSet := make(map[string]bool)
	for _, name := range existing {
		existingSet[strings.ToLower(name)] = true
	}

	result := make([]map[string]interface{}, 0, len(domains))
	for _, d := range domains {
		lower := strings.ToLower(d.Domain)
		result = append(result, map[string]interface{}{
			"id":         d.ID,
			"domain":     d.Domain,
			"status":     d.Status,
			"error_msg":  d.ErrorMsg,
			"exists":     existingSet[lower],
			"queued":     d.Status == "pending" || d.Status == "processing",
			"registrar_id": d.RegistrarID,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  result,
	})
}

// deleteRegistrarDomain 删除注册商下已添加的域名记录（仅删除本地记录，不操作 CF/注册商）
func (h *Handler) deleteRegistrarDomain(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}
	domainID, err := strconv.ParseUint(chi.URLParam(r, "domainID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	result := h.db.Where("id = ? AND registrar_id = ?", domainID, registrarID).Delete(&models.RegistrarDomain{})
	if result.Error != nil {
		respondError(w, http.StatusInternalServerError, "删除失败: "+result.Error.Error())
		return
	}
	if result.RowsAffected == 0 {
		respondError(w, http.StatusNotFound, "域名记录不存在")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "删除成功",
	})
}

// listAvailableRegistrarDomains 从注册商 API 拉取全部域名，
// 并标记每个域名是否已添加/已接入，供勾选添加
func (h *Handler) listAvailableRegistrarDomains(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}

	var registrar models.DomainRegistrar
	if err := h.db.First(&registrar, registrarID).Error; err != nil {
		respondError(w, http.StatusNotFound, "注册商不存在")
		return
	}

	client := registrarPkg.GetClient(registrar.Type, registrar.APIKey, registrar.APISecret)
	if client == nil {
		respondError(w, http.StatusBadRequest, "不支持的注册商类型")
		return
	}

	domains, err := client.ListDomains()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "拉取域名失败: "+err.Error())
		return
	}

	// 已添加过（在数据库表中）
	var added []models.RegistrarDomain
	h.db.Find(&added)
	addedSet := make(map[string]bool)
	for _, a := range added {
		addedSet[strings.ToLower(a.Domain)] = true
	}

	// 已接入 CF
	existing := h.manager.ListAllZoneNames()
	existingSet := make(map[string]bool)
	for _, name := range existing {
		existingSet[strings.ToLower(name)] = true
	}

	result := make([]map[string]interface{}, 0, len(domains))
	for _, d := range domains {
		lower := strings.ToLower(d)
		result = append(result, map[string]interface{}{
			"domain":       d,
			"added":        addedSet[lower],
			"exists":       existingSet[lower],
			"registrar_id": registrar.ID,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  result,
	})
}

// importRegistrarDomains 批量导入域名到 CF 队列
// 请求体: {"domains": ["example.com", ...]}
// 域名会先写入导入队列，由后台调度器异步处理
func (h *Handler) importRegistrarDomains(w http.ResponseWriter, r *http.Request) {
	registrarID, err := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid registrar ID")
		return
	}

	var registrar models.DomainRegistrar
	if err := h.db.First(&registrar, registrarID).Error; err != nil {
		respondError(w, http.StatusNotFound, "注册商不存在")
		return
	}

	var req struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Domains) == 0 {
		respondError(w, http.StatusBadRequest, "domains is required")
		return
	}

	// 收集所有 CF 已有域名
	existingSet := make(map[string]bool)
	for _, name := range h.manager.ListAllZoneNames() {
		existingSet[strings.ToLower(name)] = true
	}

	results := make([]map[string]interface{}, 0, len(req.Domains))
	successCount := 0
	skipCount := 0
	failCount := 0

	for _, domain := range req.Domains {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain == "" {
			continue
		}

		// 已存在的跳过
		if existingSet[domain] {
			results = append(results, map[string]interface{}{
				"domain":  domain,
				"status":  "skipped",
				"message": "已在 CF 中",
			})
			skipCount++
			continue
		}

		// 入队（唯一约束防重复）
		task := models.RegistrarDomain{
			Domain:      domain,
			RegistrarID: uint(registrarID),
			Status:      "pending",
		}
		if err := h.db.Create(&task).Error; err != nil {
			results = append(results, map[string]interface{}{
				"domain":  domain,
				"status":  "skipped",
				"message": "已在排队中",
			})
			skipCount++
			continue
		}

		results = append(results, map[string]interface{}{
			"domain": domain,
			"status": "queued",
			"message": "已加入导入队列",
		})
		successCount++
	}

	// 触发调度器立即处理
	h.scheduler.Trigger()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result": map[string]interface{}{
			"results": results,
			"success": successCount,
			"skipped": skipCount,
			"failed":  failCount,
		},
	})
}

// listImportTasks 查询导入任务列表
func (h *Handler) listImportTasks(w http.ResponseWriter, r *http.Request) {
	registrarID := r.URL.Query().Get("registrar_id")
	var tasks []models.RegistrarDomain
	query := h.db.Order("created_at DESC").Limit(200)
	if registrarID != "" {
		query = query.Where("registrar_id = ?", registrarID)
	}
	if err := query.Find(&tasks).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "查询失败: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  tasks,
	})
}

// retryImportTasks 重置失败/跳过/部分成功的导入任务回队列重新处理
func (h *Handler) retryImportTasks(w http.ResponseWriter, r *http.Request) {
	count := h.scheduler.RetryFailed()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("已将 %d 个任务重新加入队列", count),
	})
}
