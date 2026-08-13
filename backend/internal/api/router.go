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
	"log"
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

// maskSecret 掩码敏感字段，保留首尾各4位；过短则整体返回。
func maskSecret(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// getCFClientForAccount 获取指定账号的客户端。
// 用于对特定账号名下的 Zone/规则执行操作，避免误用轮询到的其他账号凭证。
// accountID 为 0（历史数据无归属）时回退到轮询客户端。
func (h *Handler) getCFClientForAccount(accountID uint) (*cfclient.Client, error) {
	if accountID == 0 {
		return h.getCFClient()
	}
	return h.manager.GetClientByAccountID(accountID)
}

// migrateBlockedAccounts 遍历所有被封禁账号，尝试把其遗留规则迁移到可用账号。
// 用于「后续添加新账号」时，把之前因无可用账号而停用的规则补齐迁移。
func (h *Handler) migrateBlockedAccounts() {
	var blockedIDs []uint
	h.db.Model(&models.CFAccount{}).Where("is_blocked = ?", true).Pluck("id", &blockedIDs)
	for _, id := range blockedIDs {
		h.MigrateAccountRules(id)
	}
}

// MigrateAccountRules 账号被封禁后，自动将其名下转发规则迁移到其他可用账号。
// 迁移策略：按「端口」分组，每个端口在目标账号挑选一个可用 Zone，重建 Origin Rule + DNS 记录。
// 无可用账号或无可用 Zone 时，规则保持停用状态（由 deactivateAccountRulesLocal 已处理）。
func (h *Handler) MigrateAccountRules(blockedAccountID uint) {
	log.Printf("[Migrate] 开始迁移账号 %d 的转发规则", blockedAccountID)

	// 找到其他可用账号（排除被封禁账号）
	var targetAccount models.CFAccount
	if err := h.db.Where("is_active = ? AND is_blocked = ? AND id != ?", true, false, blockedAccountID).
		Order("id ASC").First(&targetAccount).Error; err != nil {
		log.Printf("[Migrate] 无其他可用账号，账号 %d 规则保持停用", blockedAccountID)
		return
	}

	// 收集封禁账号名下的规则
	var rules []models.ForwardRule
	if err := h.db.Where("account_id = ?", blockedAccountID).Find(&rules).Error; err != nil {
		log.Printf("[Migrate] 查询账号 %d 规则失败: %v", blockedAccountID, err)
		return
	}
	if len(rules) == 0 {
		log.Printf("[Migrate] 账号 %d 无规则需迁移", blockedAccountID)
		return
	}

	targetClient, err := h.manager.GetClientByAccountID(targetAccount.ID)
	if err != nil {
		log.Printf("[Migrate] 获取目标账号 %d 客户端失败: %v", targetAccount.ID, err)
		return
	}

	// 目标账号下的可用 Zone
	var targetZones []models.Zone
	h.db.Where("account_id = ?", targetAccount.ID).Find(&targetZones)
	if len(targetZones) == 0 {
		log.Printf("[Migrate] 目标账号 %d 无可用 Zone，规则保持停用", targetAccount.ID)
		return
	}

	// 按端口分组迁移（同端口复用一条 Origin Rule）
	portGroups := make(map[int][]*models.ForwardRule)
	for i := range rules {
		portGroups[rules[i].OriginPort] = append(portGroups[rules[i].OriginPort], &rules[i])
	}

	successCount := 0
	failCount := 0
	for port, group := range portGroups {
		if err := h.migratePortGroup(targetClient, targetZones, &targetAccount, port, group); err != nil {
			log.Printf("[Migrate] 迁移端口 %d 失败: %v", port, err)
			failCount++
		} else {
			successCount++
		}
	}

	log.Printf("[Migrate] 账号 %d 迁移完成：成功 %d 个端口，失败 %d 个端口", blockedAccountID, successCount, failCount)
}

// migratePortGroup 迁移某个端口下的所有目标到目标账号（重建 Origin Rule + DNS）。
func (h *Handler) migratePortGroup(client *cfclient.Client, zones []models.Zone, account *models.CFAccount, port int, group []*models.ForwardRule) error {
	// 挑选规则最少的 Zone
	bestZone := zones[0]
	minCount := int64(999999)
	for _, z := range zones {
		var c int64
		h.db.Model(&models.ForwardRule{}).Where("zone_id = ?", z.CFID).Count(&c)
		if c < minCount {
			minCount = c
			bestZone = z
		}
	}

	// 每个目标生成新子域名，建 DNS
	type hostEntry struct {
		hostname string
		dnsID    string
		originHost string
		rule     *models.ForwardRule
	}
	var hosts []hostEntry
	allEnabled := false
	for _, r := range group {
		hostname := fmt.Sprintf("%s.%s", generateRandomString(8), bestZone.Name)
		recordType := detectDNSRecordType(r.OriginHost)
		dnsRecord := &cfclient.DNSRecord{
			ZoneID:  bestZone.CFID,
			Name:    hostname,
			Type:    recordType,
			Content: r.OriginHost,
			TTL:     1,
			Proxied: true,
		}
		createdDNS, err := client.CreateDNSRecord(bestZone.CFID, dnsRecord)
		if err != nil {
			return fmt.Errorf("创建 DNS 失败: %w", err)
		}
		hosts = append(hosts, hostEntry{hostname: hostname, dnsID: createdDNS.ID, originHost: r.OriginHost, rule: r})
		if r.Enabled {
			allEnabled = true
		}
	}

	// 构建表达式（只含启用目标；若全禁用则占位一个 hostname 并禁用 rule）
	enabledHosts := make([]string, 0, len(hosts))
	for _, he := range hosts {
		if he.rule.Enabled {
			enabledHosts = append(enabledHosts, he.hostname)
		}
	}
	expression := buildHostExpression(enabledHosts)
	ruleEnabled := allEnabled
	if len(enabledHosts) == 0 {
		expression = buildHostExpression([]string{hosts[0].hostname})
		ruleEnabled = false
	}

	// 创建 Origin Ruleset
	ruleset := &cfclient.OriginRuleset{
		Name:        "CF Panel Port Forwarding",
		Description: "Port forwarding rules managed by CF Panel",
		Kind:        "zone",
		Phase:       "http_request_origin",
		Rules: []cfclient.OriginRule{
			{
				Description: fmt.Sprintf("Forward to port %d", port),
				Expression:  expression,
				Action:      "route",
				ActionParameters: &cfclient.ActionParams{
					Origin: &cfclient.OriginParams{Port: port},
				},
				Enabled: ruleEnabled,
			},
		},
	}
	created, err := h.ensureOriginRuleset(client, bestZone.CFID, ruleset)
	if err != nil {
		// 回滚已创建的 DNS
		for _, he := range hosts {
			_ = client.DeleteDNSRecord(bestZone.CFID, he.dnsID)
		}
		return fmt.Errorf("创建 Origin Rule 失败: %w", err)
	}

	var newRuleID string
	if len(created.Rules) > 0 {
		newRuleID = created.Rules[len(created.Rules)-1].ID
	}

	// 目标 Zone 同样开启 SSL Full + WebSockets + gRPC（忽略错误）
	_, _ = client.UpdateSSLSettings(bestZone.CFID, "full")
	_ = client.EnableWebSockets(bestZone.CFID)
	_ = client.EnableGRPC(bestZone.CFID)

	// 更新本地规则行指向新账号/新 zone/新 CF 资源，并启用状态
	for _, he := range hosts {
		updates := map[string]interface{}{
			"account_id":     account.ID,
			"zone_id":        bestZone.CFID,
			"zone_name":      bestZone.Name,
			"hostname":       he.hostname,
			"dns_record_id":  he.dnsID,
			"cf_rule_set_id": created.ID,
			"cf_rule_id":     newRuleID,
		}
		h.db.Model(&models.ForwardRule{}).Where("id = ?", he.rule.ID).Updates(updates)
	}

	return nil
}

// validateUser 校验用户是否存在且启用，返回实时用户信息用于覆盖 token 快照
func (h *Handler) validateUser(userID uint) *auth.UserInfo {
	var user models.User
	if err := h.db.Select("role", "is_active", "must_change_password").
		Where("id = ?", userID).First(&user).Error; err != nil {
		return nil
	}
	return &auth.UserInfo{
		Role:              user.Role,
		IsActive:          user.IsActive,
		MustChangePassword: user.MustChangePassword,
	}
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
			r.Use(auth.Middleware(h.validateUser))

			// 所有登录用户可用
			r.Get("/auth/me", h.getCurrentUser)
			// 修改当前用户密码（首次登录强制修改）
			r.Post("/auth/change-password", h.changePassword)

			// 端口转发规则（普通用户仅能查看/管理自己的规则，管理员可见全部）
			r.Route("/forward-rules", func(r chi.Router) {
				r.Get("/", h.listForwardRules)
				r.Post("/", h.createForwardRule)
				r.Put("/{ruleID}", h.updateForwardRule)
				r.Delete("/{ruleID}", h.deleteForwardRule)
				r.Post("/{ruleID}/toggle", h.toggleForwardRule)
			})

			// 以下均为管理员级功能
			r.Group(func(r chi.Router) {
				r.Use(auth.AdminMiddleware)

				// 系统设置
				r.Get("/settings", h.getSettings)
				r.Put("/settings", h.updateSettings)
				r.Post("/settings/test", h.testConnection)
				r.Post("/settings/test-telegram", h.testTelegram)

				// 账号管理
				r.Route("/accounts", func(r chi.Router) {
					r.Get("/", h.listAccounts)
					r.Post("/", h.createAccount)
					r.Put("/{accountID}", h.updateAccount)
					r.Delete("/{accountID}", h.deleteAccount)
					r.Post("/{accountID}/toggle", h.toggleAccount)
					r.Post("/{accountID}/unblock", h.unblockAccount)
					r.Get("/status", h.getAccountStatus)
				})

				// 域名管理
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

				// DNS 记录
				r.Route("/dns", func(r chi.Router) {
					r.Put("/{recordID}", h.updateDNSRecord)
					r.Delete("/{recordID}", h.deleteDNSRecord)
				})

				// Origin 证书
				r.Post("/origin-certificates", h.generateOriginCertificate)

				// 用户管理
				r.Get("/users", h.listUsers)
				r.Post("/users", h.createUser)
				r.Put("/users/{userID}", h.updateUser)
				r.Delete("/users/{userID}", h.deleteUser)
				r.Post("/users/{userID}/toggle", h.toggleUser)

				// 域名注册商管理
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
	maskedToken := maskSecret(tokenSetting.Value)
	maskedTelegramToken := maskSecret(telegramTokenSetting.Value)

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

	// 保存 CF Token（只在 token 非空且不含掩码时更新，去除首尾空格）
	token := strings.TrimSpace(req.CFToken)
	if token != "" && !strings.Contains(token, "****") {
		h.db.Save(&models.Setting{Key: "cf_api_token", Value: token})
	}

	// 保存 Telegram Bot Token
	telegramToken := strings.TrimSpace(req.TelegramBotToken)
	if telegramToken != "" && !strings.Contains(telegramToken, "****") {
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

	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, user.MustChangePassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "生成token失败")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result": map[string]interface{}{
			"token":                token,
			"username":             user.Username,
			"role":                 user.Role,
			"must_change_password": user.MustChangePassword,
		},
	})
}

// changePassword 修改当前用户密码（首次登录强制修改）
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.NewPassword) < 6 {
		respondError(w, http.StatusBadRequest, "新密码至少6位")
		return
	}

	var user models.User
	if err := h.db.Where("id = ?", claims.UserID).First(&user).Error; err != nil {
		respondError(w, http.StatusNotFound, "用户不存在")
		return
	}

	if !auth.CheckPassword(req.OldPassword, user.Password) {
		respondError(w, http.StatusBadRequest, "原密码错误")
		return
	}

	// 禁止新旧密码相同
	if req.NewPassword == req.OldPassword {
		respondError(w, http.StatusBadRequest, "新密码不能与原密码相同")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	user.Password = hash
	user.MustChangePassword = false
	h.db.Save(&user)

	// 重新签发 token，清除强制改密标志
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, false)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "生成token失败")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result": map[string]interface{}{
			"token": token,
		},
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
		accounts[i].APIKey = maskSecret(accounts[i].APIKey)
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

	// 若有被封禁账号遗留的规则，立即尝试迁移到新账号
	h.migrateBlockedAccounts()

	// 隐藏 API Key
	account.APIKey = maskSecret(account.APIKey)

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

	// 删除账号时同步删除其本地 Zone 镜像（避免转发规则创建时选中已删除账号的域名）
	h.db.Where("account_id = ?", accountID).Delete(&models.Zone{})

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
	// 重新同步该账号的 Zone 归属（解封后重新拉取，确保本地 Zone 的 account_id 正确）
	h.manager.SyncLocalZones()

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

	claims := auth.GetUserFromContext(r)

	query := h.db.Order("zone_name, hostname")
	// 普通用户仅能查看自己的规则，管理员可见全部
	if claims == nil || claims.Role != "admin" {
		if claims == nil {
			respondError(w, http.StatusUnauthorized, "未授权")
			return
		}
		query = query.Where("user_id = ?", claims.UserID)
	}

	var rules []models.ForwardRule
	query.Find(&rules)

	// 附加创建者用户名
	userNames := make(map[uint]string)
	var users []models.User
	h.db.Select("id", "username").Find(&users)
	for _, u := range users {
		userNames[u.ID] = u.Username
	}

	type ruleWithUser struct {
		models.ForwardRule
		Username string `json:"username"`
	}
	result := make([]ruleWithUser, 0, len(rules))
	for _, r := range rules {
		result = append(result, ruleWithUser{ForwardRule: r, Username: userNames[r.UserID]})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  result,
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

	// 端口相同则复用已有的 Origin Rule：把新主机名并入该规则的表达式，
	// 并为这个新目标插入一行独立的 ForwardRule（共享同一 CF 规则）。
	// 端口全局唯一：任意用户创建已存在的端口都复用同一条规则。
	if existing := h.findExistingRuleForPort(req.OriginPort); existing != nil {
		newHostname, dnsRecordID, err := h.addHostnameToRule(existing, req.OriginHost)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		newRow := models.ForwardRule{
			UserID:      claims.UserID,
			AccountID:   existing.AccountID,
			ZoneID:      existing.ZoneID,
			ZoneName:    existing.ZoneName,
			Hostname:    newHostname,
			OriginPort:  req.OriginPort,
			OriginHost:  req.OriginHost,
			Enabled:     req.Enabled,
			CFRuleSetID: existing.CFRuleSetID,
			CFRuleID:    existing.CFRuleID,
			DNSRecordID: dnsRecordID,
		}
		h.db.Create(&newRow)

		// 按所有「启用行」统一重建共享规则表达式（禁用行不进入表达式）
		client, err := h.getCFClientForAccount(existing.AccountID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := h.syncRuleExpression(client, &newRow); err != nil {
			// 同步失败：删除刚插入的本地行与 DNS 记录
			h.db.Delete(&newRow)
			_ = client.DeleteDNSRecord(newRow.ZoneID, newRow.DNSRecordID)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"result":  newRow,
		})
		return
	}

	// 自动选择可用的域名（优先填满一个域名）
	var zones []models.Zone
	h.db.Order("id ASC").Find(&zones)

	// 收集封禁账号，挑选域名时排除
	var blockedAccountIDs []uint
	h.db.Model(&models.CFAccount{}).Where("is_blocked = ?", true).Pluck("id", &blockedAccountIDs)
	blockedSet := make(map[uint]bool, len(blockedAccountIDs))
	for _, id := range blockedAccountIDs {
		blockedSet[id] = true
	}

	// 过滤掉封禁账号的域名（无归属的旧数据保留，仅排除明确被封禁的账号）
	var availableZones []models.Zone
	for _, zone := range zones {
		if zone.AccountID != 0 && blockedSet[zone.AccountID] {
			continue
		}
		availableZones = append(availableZones, zone)
	}
	if len(availableZones) == 0 {
		respondError(w, http.StatusBadRequest, "没有可用的域名，请先在域名管理中添加或解除账号封禁")
		return
	}

	// 选择域名策略：优先填满一个域名，避免规则在多个域名间均匀散开。
	type zoneCount struct {
		zone  models.Zone
		count int64
	}
	var used []zoneCount
	var empty models.Zone
	hasEmpty := false
	for _, zone := range availableZones {
		var count int64
		h.db.Model(&models.ForwardRule{}).Where("zone_id = ?", zone.CFID).Count(&count)
		if count >= 10 {
			continue // 已满，跳过
		}
		if count > 0 {
			used = append(used, zoneCount{zone: zone, count: count})
		} else if !hasEmpty {
			empty = zone
			hasEmpty = true
		}
	}

	var bestZone models.Zone
	switch {
	case len(used) > 0:
		best := used[0]
		for _, uc := range used[1:] {
			if uc.count < best.count {
				best = uc
			}
		}
		bestZone = best.zone
	case hasEmpty:
		bestZone = empty
	default:
		respondError(w, http.StatusBadRequest, "所有域名的转发规则已满，请联系管理员添加更多域名")
		return
	}

	// 自动生成子域名（使用随机字符串）
	randomStr := generateRandomString(8)
	hostname := fmt.Sprintf("%s.%s", randomStr, bestZone.Name)

	// 在 Cloudflare 创建 Origin Rule（仅指定目标端口，host 由 DNS 记录决定）
	client, err := h.getCFClientForAccount(bestZone.AccountID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	expression := buildHostExpression([]string{hostname})
	ruleset := &cfclient.OriginRuleset{
		Name:        "CF Panel Port Forwarding",
		Description: "Port forwarding rules managed by CF Panel",
		Kind:        "zone",
		Phase:       "http_request_origin",
		Rules: []cfclient.OriginRule{
			{
				Description: fmt.Sprintf("Forward to port %d", req.OriginPort),
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

	created, err := h.ensureOriginRuleset(client, bestZone.CFID, ruleset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "创建 Cloudflare 规则失败: "+err.Error())
		return
	}

	// 创建 DNS 记录（根据目标地址类型自动选择 A / AAAA / CNAME）
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
		client.DeleteOriginRuleset(bestZone.CFID, created.ID)
		respondError(w, http.StatusInternalServerError, "创建 DNS 记录失败: "+err.Error())
		return
	}

	// 保存到本地数据库
	localRule := models.ForwardRule{
		UserID:      claims.UserID,
		AccountID:   bestZone.AccountID,
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
		localRule.CFRuleID = created.Rules[len(created.Rules)-1].ID
	}
	h.db.Create(&localRule)

	// 自动设置 SSL 为 Full 模式，并开启 WebSockets / gRPC（忽略错误，不影响规则创建）
	_, _ = client.UpdateSSLSettings(bestZone.CFID, "full")
	_ = client.EnableWebSockets(bestZone.CFID)
	_ = client.EnableGRPC(bestZone.CFID)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  localRule,
	})
}

// addHostnameToRule 为「同端口复用」场景创建新目标：
// 1) 生成随机子域名；
// 2) 为该子域名创建 DNS 记录。
// 返回新主机名与新 DNS 记录 ID，由调用方插入一行独立的 ForwardRule，
// 表达式统一由调用方通过 syncRuleExpression 按「启用行」重建（禁用行不进入表达式）。
func (h *Handler) addHostnameToRule(rule *models.ForwardRule, originHost string) (string, string, error) {
	client, err := h.getCFClientForAccount(rule.AccountID)
	if err != nil {
		return "", "", err
	}

	// 生成新的随机子域名（复用规则所在 Zone）
	hostname := fmt.Sprintf("%s.%s", generateRandomString(8), rule.ZoneName)

	// 创建 DNS 记录
	recordType := detectDNSRecordType(originHost)
	dnsRecord := &cfclient.DNSRecord{
		ZoneID:  rule.ZoneID,
		Name:    hostname,
		Type:    recordType,
		Content: originHost,
		TTL:     1,
		Proxied: true,
	}
	createdDNS, err := client.CreateDNSRecord(rule.ZoneID, dnsRecord)
	if err != nil {
		return "", "", fmt.Errorf("创建 DNS 记录失败: %w", err)
	}

	return hostname, createdDNS.ID, nil
}

// removeRuleFromRuleset 从共享 ruleset 中删除指定 rule（CF 侧）。
// 若 ruleset 里只剩这一条 rule，则删除整个 ruleset；否则仅移除该条 rule。
// 用于「每个端口一条 rule、同 zone 共享一个 ruleset」场景下删除某端口时。
func (h *Handler) removeRuleFromRuleset(client *cfclient.Client, rule *models.ForwardRule) {
	if rule.CFRuleSetID == "" {
		return
	}
	full, err := client.GetOriginRuleset(rule.ZoneID, rule.CFRuleSetID)
	if err != nil {
		if strings.Contains(err.Error(), "[10001]") {
			return // ruleset 已不存在
		}
		log.Printf("[ForwardRule] 获取 ruleset %s 失败: %v", rule.CFRuleSetID, err)
		return
	}

	// 若本规则已是该 ruleset 唯一 rule（或找不到 CFRuleID），删除整个 ruleset
	idx := findRuleIndex(full.Rules, rule.CFRuleID)
	if len(full.Rules) <= 1 {
		if err := client.DeleteOriginRuleset(rule.ZoneID, rule.CFRuleSetID); err != nil {
			log.Printf("[ForwardRule] 删除 ruleset %s 失败: %v", rule.CFRuleSetID, err)
		}
		return
	}

	// 多条 rule：移除目标 rule 后 PUT 更新
	if idx == -1 {
		return
	}
	full.Rules = append(full.Rules[:idx], full.Rules[idx+1:]...)
	if _, err := client.UpdateOriginRuleset(rule.ZoneID, rule.CFRuleSetID, full); err != nil {
		log.Printf("[ForwardRule] 更新 ruleset %s 失败: %v", rule.CFRuleSetID, err)
	}
}

// removeHostnameFromRule 从共享的 Origin Rule 表达式中移除指定主机名。
func (h *Handler) removeHostnameFromRule(client *cfclient.Client, rule *models.ForwardRule) error {
	// 剩余仍引用该 CF 规则的行（不含当前行）
	var remaining []models.ForwardRule
	h.db.Where("cf_rule_set_id = ? AND cf_rule_id = ? AND id != ?",
		rule.CFRuleSetID, rule.CFRuleID, rule.ID).Find(&remaining)

	if len(remaining) == 0 {
		return nil
	}

	hosts := make([]string, 0, len(remaining))
	for _, r := range remaining {
		hosts = append(hosts, r.Hostname)
	}

	full, err := client.GetOriginRuleset(rule.ZoneID, rule.CFRuleSetID)
	if err != nil {
		return fmt.Errorf("获取 Cloudflare 规则失败: %w", err)
	}
	idx := findRuleIndex(full.Rules, rule.CFRuleID)
	if idx == -1 {
		return fmt.Errorf("Cloudflare 规则不存在")
	}
	full.Rules[idx].Expression = buildHostExpression(hosts)
	if _, err := client.UpdateOriginRuleset(rule.ZoneID, rule.CFRuleSetID, full); err != nil {
		return fmt.Errorf("更新 Cloudflare 规则失败: %w", err)
	}
	return nil
}

func (h *Handler) updateForwardRule(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	ruleID := chi.URLParam(r, "ruleID")

	var req struct {
		OriginPort int  `json:"origin_port"`
		OriginHost string `json:"origin_host"`
		Enabled    bool `json:"enabled"`
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

	// 获取本地规则
	var localRule models.ForwardRule
	if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
		respondError(w, http.StatusNotFound, "规则不存在")
		return
	}

	// 普通用户仅能管理自己的规则
	if claims.Role != "admin" && localRule.UserID != claims.UserID {
		respondError(w, http.StatusForbidden, "无权操作该规则")
		return
	}

	// 检查订阅是否有效（管理员操作不限制）
	if claims.Role != "admin" {
		var owner models.User
		if err := h.db.Where("id = ?", localRule.UserID).First(&owner).Error; err != nil {
			respondError(w, http.StatusNotFound, "用户不存在")
			return
		}
		if !isSubscriptionValid(&owner) {
			respondError(w, http.StatusForbidden, "订阅已过期，无法修改转发规则")
			return
		}
	}

	// 检查端口是否被其他规则使用（同一子域名+端口不允许重复）
	var existing models.ForwardRule
	if err := h.db.Where("zone_id = ? AND hostname = ? AND origin_port = ? AND id != ?", localRule.ZoneID, localRule.Hostname, req.OriginPort, ruleID).First(&existing).Error; err == nil {
		respondError(w, http.StatusBadRequest, "该子域名的端口转发规则已存在")
		return
	}

	client, err := h.getCFClientForAccount(localRule.AccountID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 目标地址变化时同步更新 DNS 记录（先改 DNS，再改本地）
	originHostChanged := req.OriginHost != localRule.OriginHost
	if originHostChanged && localRule.DNSRecordID != "" {
		oldType := detectDNSRecordType(localRule.OriginHost)
		newType := detectDNSRecordType(req.OriginHost)
		if oldType == newType {
			updateRecord := &cfclient.DNSRecord{
				Name:    localRule.Hostname,
				Type:    newType,
				Content: req.OriginHost,
				TTL:     1,
				Proxied: true,
			}
			if _, err := client.UpdateDNSRecord(localRule.ZoneID, localRule.DNSRecordID, updateRecord); err != nil {
				respondError(w, http.StatusInternalServerError, "更新 DNS 记录失败: "+err.Error())
				return
			}
		} else {
			_ = client.DeleteDNSRecord(localRule.ZoneID, localRule.DNSRecordID)
			newRecord := &cfclient.DNSRecord{
				ZoneID:  localRule.ZoneID,
				Name:    localRule.Hostname,
				Type:    newType,
				Content: req.OriginHost,
				TTL:     1,
				Proxied: true,
			}
			createdDNS, err := client.CreateDNSRecord(localRule.ZoneID, newRecord)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "更新 DNS 记录失败: "+err.Error())
				return
			}
			localRule.DNSRecordID = createdDNS.ID
		}
	}

	// 更新本地数据库
	localRule.OriginPort = req.OriginPort
	localRule.OriginHost = req.OriginHost
	localRule.Enabled = req.Enabled
	h.db.Save(&localRule)

	// 编辑弹窗里的开关会改变 enabled：按「启用行」重建共享规则表达式
	if err := h.syncRuleExpression(client, &localRule); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  localRule,
	})
}

func (h *Handler) deleteForwardRule(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	ruleID := chi.URLParam(r, "ruleID")

	// 获取本地规则
	var localRule models.ForwardRule
	if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
		respondError(w, http.StatusNotFound, "规则不存在")
		return
	}

	// 普通用户仅能管理自己的规则
	if claims.Role != "admin" && localRule.UserID != claims.UserID {
		respondError(w, http.StatusForbidden, "无权操作该规则")
		return
	}

	// 检查订阅是否有效（管理员删除自己规则时不限制）
	if claims.Role != "admin" {
		var owner models.User
		if err := h.db.Where("id = ?", localRule.UserID).First(&owner).Error; err != nil {
			respondError(w, http.StatusNotFound, "用户不存在")
			return
		}
		if !isSubscriptionValid(&owner) {
			respondError(w, http.StatusForbidden, "订阅已过期，无法修改转发规则")
			return
		}
	}

	// 删除 Cloudflare 规则（使用规则所属账号的客户端）
	client, err := h.getCFClientForAccount(localRule.AccountID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 统计还有多少本地行共享这条 CF 规则（含当前行）
	var sharedCount int64
	h.db.Model(&models.ForwardRule{}).
		Where("cf_rule_set_id = ? AND cf_rule_id = ?", localRule.CFRuleSetID, localRule.CFRuleID).
		Count(&sharedCount)

	if sharedCount <= 1 {
		// 只有这一行引用该 CF 规则：从共享 ruleset 中删除该条 rule（ruleset 可能还含其他端口的规则）
		h.removeRuleFromRuleset(client, &localRule)
	} else {
		// 多行共享：从 Origin Rule 表达式中移除本主机名
		if err := h.removeHostnameFromRule(client, &localRule); err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
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
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	ruleID := chi.URLParam(r, "ruleID")

	var localRule models.ForwardRule
	if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
		respondError(w, http.StatusNotFound, "规则不存在")
		return
	}

	// 普通用户仅能管理自己的规则
	if claims.Role != "admin" && localRule.UserID != claims.UserID {
		respondError(w, http.StatusForbidden, "无权操作该规则")
		return
	}

	// 检查订阅是否有效（管理员操作不限制）
	if claims.Role != "admin" {
		var owner models.User
		if err := h.db.Where("id = ?", localRule.UserID).First(&owner).Error; err != nil {
			respondError(w, http.StatusNotFound, "用户不存在")
			return
		}
		if !isSubscriptionValid(&owner) {
			respondError(w, http.StatusForbidden, "订阅已过期，无法修改转发规则")
			return
		}
	}

	// 切换状态
	newEnabled := !localRule.Enabled

	// 更新 Cloudflare 规则（使用规则所属账号的客户端）
	client, err := h.getCFClientForAccount(localRule.AccountID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 先落库本行状态，再按「所有启用行」重建共享规则的表达式
	localRule.Enabled = newEnabled
	h.db.Save(&localRule)

	if err := h.syncRuleExpression(client, &localRule); err != nil {
		// 同步失败：回滚本地状态
		localRule.Enabled = !newEnabled
		h.db.Save(&localRule)
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  localRule,
	})
}

// syncRuleExpression 根据数据库里所有引用该 CF rule 的「启用行」重建规则表达式。
// 同端口多目标共享一条 rule 时：禁用某目标 = 从表达式移除其 hostname，
// 而非禁用整条 rule（避免影响其他目标）。
func (h *Handler) syncRuleExpression(client *cfclient.Client, rule *models.ForwardRule) error {
	var rows []models.ForwardRule
	h.db.Where("cf_rule_set_id = ? AND cf_rule_id = ?", rule.CFRuleSetID, rule.CFRuleID).Find(&rows)

	var hosts []string
	for _, r := range rows {
		if r.Enabled {
			hosts = append(hosts, r.Hostname)
		}
	}

	full, err := client.GetOriginRuleset(rule.ZoneID, rule.CFRuleSetID)
	if err != nil {
		if strings.Contains(err.Error(), "[10001]") {
			return fmt.Errorf("Cloudflare 规则不存在")
		}
		return fmt.Errorf("获取 Cloudflare 规则失败: %w", err)
	}
	idx := findRuleIndex(full.Rules, rule.CFRuleID)
	if idx == -1 {
		return fmt.Errorf("Cloudflare 规则不存在")
	}

	if len(hosts) == 0 {
		// 没有启用的目标：整条 rule 禁用，表达式保留最后一个 hostname 占位
		full.Rules[idx].Enabled = false
	} else {
		full.Rules[idx].Enabled = true
		full.Rules[idx].Expression = buildHostExpression(hosts)
	}

	if _, err := client.UpdateOriginRuleset(rule.ZoneID, rule.CFRuleSetID, full); err != nil {
		return fmt.Errorf("更新 Cloudflare 规则失败: %w", err)
	}
	return nil
}

// helper

// findRuleIndex 在 ruleset 的规则列表中按 ruleID 定位规则，找不到返回 -1
func findRuleIndex(rules []cfclient.OriginRule, ruleID string) int {
	if ruleID == "" {
		return -1
	}
	for i := range rules {
		if rules[i].ID == ruleID {
			return i
		}
	}
	return -1
}

// parseHostnameList 将逗号分隔的 hostnames 字符串转为去重后的字符串切片
func parseHostnameList(s string) []string {
	parts := strings.Split(s, ",")
	seen := make(map[string]bool)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// buildHostExpression 根据多个主机名构建 http.host 匹配表达式（单个用 eq，多个用 or 连接）
func buildHostExpression(hostnames []string) string {
	if len(hostnames) == 1 {
		return fmt.Sprintf("(http.host eq %q)", hostnames[0])
	}
	parts := make([]string, 0, len(hostnames))
	for _, h := range hostnames {
		parts = append(parts, fmt.Sprintf("(http.host eq %q)", h))
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// findExistingRuleForPort 按端口查找已存在的规则（端口全局唯一，同端口复用）
func (h *Handler) findExistingRuleForPort(port int) *models.ForwardRule {
	var rule models.ForwardRule
	if err := h.db.Where("origin_port = ?", port).First(&rule).Error; err != nil {
		return nil
	}
	return &rule
}

// ensureOriginRuleset 创建 Origin Ruleset；若该 zone 已达 ruleset 数量上限（错误码 20217），
// 则复用现有的 zone 级 http_request_origin ruleset，把新规则追加进去（合并方案）。
func (h *Handler) ensureOriginRuleset(client *cfclient.Client, zoneID string, newRuleset *cfclient.OriginRuleset) (*cfclient.OriginRuleset, error) {
	created, err := client.CreateOriginRuleset(zoneID, newRuleset)
	if err == nil {
		return created, nil
	}

	// 只有“数量超限”才走合并；其他错误直接返回
	if !strings.Contains(err.Error(), "[20217]") {
		return nil, err
	}

	existingList, listErr := client.ListOriginRulesets(zoneID)
	if listErr != nil {
		return nil, fmt.Errorf("创建失败(%v)且无法列出已有 ruleset(%v)", err, listErr)
	}

	// 选一个 zone 级（kind=zone）的 ruleset 来追加；没有则用返回的第一个
	var target *cfclient.OriginRuleset
	for i := range existingList {
		rs := &existingList[i]
		if rs.Kind == "zone" {
			target = rs
			break
		}
	}
	if target == nil {
		if len(existingList) == 0 {
			return nil, err
		}
		target = &existingList[0]
	}

	// 拉取完整 ruleset（含 rules），追加新规则后 PUT 更新
	full, getErr := client.GetOriginRuleset(zoneID, target.ID)
	if getErr != nil {
		return nil, fmt.Errorf("创建失败(%v)且获取 ruleset %s 失败(%v)", err, target.ID, getErr)
	}
	full.Rules = append(full.Rules, newRuleset.Rules...)
	updated, updateErr := client.UpdateOriginRuleset(zoneID, full.ID, full)
	if updateErr != nil {
		return nil, fmt.Errorf("创建失败(%v)且合并到 ruleset %s 失败(%v)", err, full.ID, updateErr)
	}
	return updated, nil
}

// reconcileForwardRuleCloudflare 校验本地规则与 Cloudflare 侧资源是否一致，
// 修复不一致（清理/重建 Origin Rule 与 DNS 记录）。返回 client 供后续操作复用。
func (h *Handler) reconcileForwardRuleCloudflare(localRule *models.ForwardRule) (*cfclient.Client, error) {
	client, err := h.getCFClientForAccount(localRule.AccountID)
	if err != nil {
		return nil, err
	}

	// 1) Origin Rule 侧
	if localRule.CFRuleSetID != "" {
		if _, err := client.GetOriginRuleset(localRule.ZoneID, localRule.CFRuleSetID); err != nil {
			if strings.Contains(err.Error(), "[10001]") {
				// ruleset 不存在：重建
				expression := fmt.Sprintf("(http.host eq %q)", localRule.Hostname)
				recreated, createErr := h.ensureOriginRuleset(client, localRule.ZoneID, &cfclient.OriginRuleset{
					Name:        "CF Panel Port Forwarding",
					Description: "Port forwarding rules managed by CF Panel",
					Kind:        "zone",
					Phase:       "http_request_origin",
					Rules: []cfclient.OriginRule{
						{
							Description: fmt.Sprintf("Forward %s to port %d", localRule.Hostname, localRule.OriginPort),
							Expression:  expression,
							Action:      "route",
							ActionParameters: &cfclient.ActionParams{
								Origin: &cfclient.OriginParams{Port: localRule.OriginPort},
							},
							Enabled: localRule.Enabled,
						},
					},
				})
				if createErr != nil {
					return nil, fmt.Errorf("重建 Cloudflare 规则失败: %w", createErr)
				}
				localRule.CFRuleSetID = recreated.ID
				if len(recreated.Rules) > 0 {
					localRule.CFRuleID = recreated.Rules[len(recreated.Rules)-1].ID
				}
			} else {
				return nil, fmt.Errorf("获取 Cloudflare 规则失败: %w", err)
			}
		}
	}

	// 2) DNS 侧
	if localRule.DNSRecordID != "" {
		// 用 DNS ID 查询记录是否存在（通过列表匹配）
		records, listErr := client.ListDNSRecords(localRule.ZoneID, "")
		if listErr == nil {
			found := false
			for _, rec := range records {
				if rec.ID == localRule.DNSRecordID {
					found = true
					break
				}
			}
			if !found {
				// DNS 记录不存在：重建
				recordType := detectDNSRecordType(localRule.OriginHost)
				newRecord := &cfclient.DNSRecord{
					ZoneID:  localRule.ZoneID,
					Name:    localRule.Hostname,
					Type:    recordType,
					Content: localRule.OriginHost,
					TTL:     1,
					Proxied: true,
				}
				createdDNS, createErr := client.CreateDNSRecord(localRule.ZoneID, newRecord)
				if createErr != nil {
					return nil, fmt.Errorf("重建 DNS 记录失败: %w", createErr)
				}
				localRule.DNSRecordID = createdDNS.ID
			}
		}
	}

	h.db.Save(localRule)
	return client, nil
}

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
		registrars[i].APISecret = maskSecret(registrars[i].APISecret)
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

	// 掩码敏感字段后再返回
	registrar.APISecret = maskSecret(registrar.APISecret)

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
	if req.APIKey != "" && !strings.Contains(req.APIKey, "****") {
		registrar.APIKey = req.APIKey
	}
	if req.APISecret != "" && !strings.Contains(req.APISecret, "****") {
		registrar.APISecret = req.APISecret
	}

	if err := h.db.Save(&registrar).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "更新注册商失败: "+err.Error())
		return
	}

	// 掩码敏感字段后再返回
	registrar.APISecret = maskSecret(registrar.APISecret)

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
	if !registrar.IsActive {
		respondError(w, http.StatusBadRequest, "注册商已禁用")
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
	registrarID, _ := strconv.ParseUint(chi.URLParam(r, "registrarID"), 10, 32)
	count := h.scheduler.RetryFailed(uint(registrarID))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("已将 %d 个任务重新加入队列", count),
	})
}
