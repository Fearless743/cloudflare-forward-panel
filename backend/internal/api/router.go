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
	"regexp"
	"sort"
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

// maskSecret 掩码敏感字段，保留首尾各4位；过短则整体隐藏。
// 注意：短密钥不能原样返回，否则「掩码」等于泄露。
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
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

// getCFClientForZone 根据本地 Zone 镜像找到其所属账号，用对应账号的凭证操作。
// 多账号场景下，若用轮询到的其他账号访问 Zone，会返回鉴权错误甚至误判账号被封禁。
// 本地无该 Zone 的归属信息时回退到轮询客户端（兼容历史数据）。
func (h *Handler) getCFClientForZone(zoneID string) (*cfclient.Client, error) {
	var zone models.Zone
	if err := h.db.Select("account_id").Where("cf_id = ?", zoneID).First(&zone).Error; err == nil && zone.AccountID != 0 {
		return h.getCFClientForAccount(zone.AccountID)
	}
	return h.getCFClient()
}

// migrateBlockedAccounts 遍历所有被封禁账号，尝试把其遗留规则迁移到可用账号。
// 用于「后续添加新账号」时，把之前因无可用账号而停用的规则补齐迁移。
func (h *Handler) migrateBlockedAccounts() {
	var blockedIDs []uint
	h.db.Model(&models.CFAccount{}).Where("is_blocked = ?", true).Pluck("id", &blockedIDs)
	for _, id := range blockedIDs {
		// 这些规则当初因账号封禁被自动停用（本地 enabled=false），
		// 迁移时按「启用」重建到新账号；迁移后仍归属封禁账号的行再恢复停用。
		h.db.Model(&models.ForwardRule{}).Where("account_id = ?", id).Update("enabled", true)
		h.MigrateAccountRules(id)
		h.db.Model(&models.ForwardRule{}).Where("account_id = ?", id).Update("enabled", false)
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
	// 仅允许迁移到「该端口下所有规则所有者都被分配」的域名，避免自动迁移到未授权域名。
	// 无归属（UserID==0）的历史规则不受限制，保持旧行为。
	allowedZones := make([]models.Zone, 0, len(zones))
	for _, z := range zones {
		allowed := true
		for _, r := range group {
			if r.UserID != 0 && !h.userCanUseZone(r.UserID, z.ID) {
				allowed = false
				break
			}
		}
		if allowed {
			allowedZones = append(allowedZones, z)
		}
	}
	if len(allowedZones) == 0 {
		return fmt.Errorf("目标账号下没有分配给规则所有者的域名，暂不迁移")
	}
	zones = allowedZones

	// 挑选规则最少的 Zone：以 CF 侧 http_request_origin 真实规则数为准（含外部手工规则）。
	// 同端口多目标共享一条 CF 规则，本地行数会虚高，故不能用本地 ForwardRule 行数排名。
	bestZone := zones[0]
	minCount := int(^uint(0) >> 1) // MaxInt
	bestFound := false
	for _, z := range zones {
		count, err := client.CountOriginRules(z.CFID)
		if err != nil {
			log.Printf("[Migrate] 查询域名 %s 的 CF 规则数失败: %v，按 0 处理", z.Name, err)
			count = 0
		}
		if !bestFound || count < minCount {
			minCount = count
			bestZone = z
			bestFound = true
		}
	}

	// 每个目标生成新子域名，建 DNS
	type hostEntry struct {
		hostname   string
		dnsID      string
		originHost string
		rule       *models.ForwardRule
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
	created, _, err := h.ensureOriginRuleset(client, bestZone.CFID, ruleset)
	if err != nil {
		// 回滚已创建的 DNS
		for _, he := range hosts {
			_ = client.DeleteDNSRecord(bestZone.CFID, he.dnsID)
		}
		return fmt.Errorf("创建 Origin Rule 失败: %w", err)
	}

	var newRuleID string
	if len(created.Rules) > 0 {
		newRuleID = findRuleIDByPort(created.Rules, port)
		if newRuleID == "" && len(created.Rules) == 1 {
			newRuleID = created.Rules[0].ID
		}
	}

	// 目标 Zone 同样开启转发所需设置（SSL Full + WebSockets + gRPC，忽略错误）
	enableZoneForwardingSettings(client, bestZone.CFID)

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
		Role:               user.Role,
		IsActive:           user.IsActive,
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
				r.Get("/zones", h.listLocalZones) // 本地可用域名列表（所有登录用户可用）
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
					r.Put("/{zoneID}/users", h.updateZoneUsers) // 分配域名给用户

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

// isUniqueConstraintErr 判断是否为数据库唯一约束冲突。
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate")
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
		Subscription *string `json:"subscription"` // 订阅过期时间，格式：2024-12-31 或 30d/1y
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
		Subscription *string `json:"subscription"` // 订阅过期时间，格式：2024-12-31 或 30d/1y，空字符串表示清除订阅
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
		if len(*req.Password) < 6 {
			respondError(w, http.StatusBadRequest, "密码至少6位")
			return
		}
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "密码加密失败")
			return
		}
		user.Password = hash
	}

	if req.Role != nil && (*req.Role == "admin" || *req.Role == "user") {
		// 防止管理员把自己降级后失去所有管理入口
		claims := auth.GetUserFromContext(r)
		if *req.Role == "user" && user.Role == "admin" && claims != nil && claims.UserID == user.ID {
			respondError(w, http.StatusBadRequest, "不能取消自己的管理员权限")
			return
		}
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

	// 检查该用户是否有转发规则，阻止删除避免产生孤儿规则
	var ruleCount int64
	h.db.Model(&models.ForwardRule{}).Where("user_id = ?", userID).Count(&ruleCount)
	if ruleCount > 0 {
		respondError(w, http.StatusBadRequest,
			fmt.Sprintf("该用户下有 %d 条转发规则，请先删除所有规则后再删除用户", ruleCount))
		return
	}

	// 删除用户时同步清理域名分配关系
	if err := h.db.Where("user_id = ?", userID).Delete(&models.ZoneUser{}).Error; err != nil {
		respondError(w, http.StatusInternalServerError, "清理域名分配失败")
		return
	}

	result := h.db.Where("id = ?", userID).Delete(&models.User{})
	if result.Error != nil {
		respondError(w, http.StatusInternalServerError, "删除失败")
		return
	}
	if result.RowsAffected == 0 {
		respondError(w, http.StatusNotFound, "用户不存在")
		return
	}

	log.Printf("[Admin] 管理员 %s(role=%s) 删除了用户 ID %d", claims.Username, claims.Role, userID)

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
	// 同步新账号的 Zone 到本地表，否则新增账号的域名要重启后才能用于转发/迁移
	h.manager.SyncLocalZones()

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
		Email     *string `json:"email"`
		APIKey    *string `json:"api_key"`
		AccountID *string `json:"account_id"`
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

	if req.Email != nil && strings.TrimSpace(*req.Email) != "" {
		account.Email = strings.TrimSpace(*req.Email)
	}
	if req.APIKey != nil && *req.APIKey != "" && !strings.Contains(*req.APIKey, "****") {
		account.APIKey = strings.TrimSpace(*req.APIKey)
	}
	// 使用指针区分「未传」与「传空字符串」：允许清空 CF 账号 ID
	if req.AccountID != nil {
		account.AccountID = strings.TrimSpace(*req.AccountID)
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

	claims := auth.GetUserFromContext(r)

	// 检查该账号下是否有转发规则，阻止删除避免产生无法清理的孤儿规则
	var ruleCount int64
	h.db.Model(&models.ForwardRule{}).Where("account_id = ?", accountID).Count(&ruleCount)
	if ruleCount > 0 {
		respondError(w, http.StatusBadRequest,
			fmt.Sprintf("该账号下有 %d 条转发规则，请先删除所有规则后再删除账号", ruleCount))
		return
	}

	// 事务保护：删除账号 + 删除 Zone 镜像原子完成
	tx := h.db.Begin()

	if err := tx.Where("id = ?", accountID).Delete(&models.CFAccount{}).Error; err != nil {
		tx.Rollback()
		respondError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}

	// 删除账号时同步删除其本地 Zone 镜像（避免转发规则创建时选中已删除账号的域名）
	// 以及这些域名的用户分配关系
	var zoneIDs []uint
	if err := tx.Model(&models.Zone{}).Where("account_id = ?", accountID).Pluck("id", &zoneIDs).Error; err != nil {
		tx.Rollback()
		respondError(w, http.StatusInternalServerError, "查询 Zone 镜像失败: "+err.Error())
		return
	}
	if len(zoneIDs) > 0 {
		if err := tx.Where("zone_id IN ?", zoneIDs).Delete(&models.ZoneUser{}).Error; err != nil {
			tx.Rollback()
			respondError(w, http.StatusInternalServerError, "删除域名分配失败: "+err.Error())
			return
		}
	}
	if err := tx.Where("account_id = ?", accountID).Delete(&models.Zone{}).Error; err != nil {
		tx.Rollback()
		respondError(w, http.StatusInternalServerError, "删除 Zone 镜像失败: "+err.Error())
		return
	}

	tx.Commit()

	h.manager.ReloadAccounts()

	log.Printf("[Admin] 管理员 %s(role=%s) 删除了 CF 账号 %d", claims.Username, claims.Role, accountID)

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

	// 启用账号时触发导入调度，并同步该账号的 Zone
	if account.IsActive {
		h.manager.SyncLocalZones()
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
	// 汇总所有账号的 Zone，避免多账号场景下只看到当前轮询账号的域名
	if h.manager.GetClientCount() == 0 {
		respondError(w, http.StatusBadRequest, "没有可用的 Cloudflare 账号")
		return
	}

	zones := h.manager.ListAllZones()

	// 附加域名已分配的用户，供管理页面展示与编辑
	type zoneWithUsers struct {
		cfclient.Zone
		UserIDs   []uint   `json:"user_ids"`
		Usernames []string `json:"usernames"`
	}

	cfIDs := make([]string, 0, len(zones))
	for _, z := range zones {
		cfIDs = append(cfIDs, z.ID)
	}

	var localZones []models.Zone
	if len(cfIDs) > 0 {
		h.db.Where("cf_id IN ?", cfIDs).Find(&localZones)
	}
	cfIDToLocalID := make(map[string]uint, len(localZones))
	localIDs := make([]uint, 0, len(localZones))
	for _, z := range localZones {
		cfIDToLocalID[z.CFID] = z.ID
		localIDs = append(localIDs, z.ID)
	}

	assignmentsByZone := make(map[uint][]uint)
	if len(localIDs) > 0 {
		var assignments []models.ZoneUser
		h.db.Where("zone_id IN ?", localIDs).Order("id ASC").Find(&assignments)
		for _, a := range assignments {
			assignmentsByZone[a.ZoneID] = append(assignmentsByZone[a.ZoneID], a.UserID)
		}
	}

	var users []models.User
	h.db.Select("id", "username").Find(&users)
	usernameByID := make(map[uint]string, len(users))
	for _, u := range users {
		usernameByID[u.ID] = u.Username
	}

	result := make([]zoneWithUsers, 0, len(zones))
	for _, z := range zones {
		item := zoneWithUsers{Zone: z, UserIDs: []uint{}, Usernames: []string{}}
		if localID, ok := cfIDToLocalID[z.ID]; ok {
			for _, uid := range assignmentsByZone[localID] {
				item.UserIDs = append(item.UserIDs, uid)
				item.Usernames = append(item.Usernames, usernameByID[uid])
			}
		}
		result = append(result, item)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  result,
	})
}

// updateZoneUsers 覆盖式设置某个域名的授权用户列表（仅管理员）。
func (h *Handler) updateZoneUsers(w http.ResponseWriter, r *http.Request) {
	zoneCFID := chi.URLParam(r, "zoneID")

	var req struct {
		UserIDs []uint `json:"user_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var zone models.Zone
	if err := h.db.Where("cf_id = ?", zoneCFID).First(&zone).Error; err != nil {
		respondError(w, http.StatusNotFound, "域名不存在或尚未同步到本地")
		return
	}

	// 校验用户存在并去重
	seen := make(map[uint]bool, len(req.UserIDs))
	userIDs := make([]uint, 0, len(req.UserIDs))
	for _, uid := range req.UserIDs {
		if seen[uid] {
			continue
		}
		var user models.User
		if err := h.db.Where("id = ?", uid).First(&user).Error; err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("用户 %d 不存在", uid))
			return
		}
		seen[uid] = true
		userIDs = append(userIDs, uid)
	}

	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("zone_id = ?", zone.ID).Delete(&models.ZoneUser{}).Error; err != nil {
			return err
		}
		for _, uid := range userIDs {
			if err := tx.Create(&models.ZoneUser{ZoneID: zone.ID, UserID: uid}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "保存域名分配失败: "+err.Error())
		return
	}

	claims := auth.GetUserFromContext(r)
	if claims != nil {
		log.Printf("[Admin] 管理员 %s 将域名 %s 分配给用户 %v", claims.Username, zone.Name, userIDs)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  map[string]interface{}{"user_ids": userIDs},
	})
}

// listLocalZones 返回当前用户可用的本地域名列表（排除被封禁账号），供转发规则表单下拉选择。
// 所有用户（包括管理员）只能使用被分配的域名。
func (h *Handler) listLocalZones(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  h.availableLocalZonesForUser(claims.UserID),
	})
}

func (h *Handler) getZone(w http.ResponseWriter, r *http.Request) {
	zoneID := chi.URLParam(r, "zoneID")
	client, err := h.getCFClientForZone(zoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

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
	zoneID := chi.URLParam(r, "zoneID")
	client, err := h.getCFClientForZone(zoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

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
	zoneID := chi.URLParam(r, "zoneID")
	client, err := h.getCFClientForZone(zoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

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
	recordID := chi.URLParam(r, "recordID")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		respondError(w, http.StatusBadRequest, "zone_id query parameter required")
		return
	}

	client, err := h.getCFClientForZone(zoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
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
	recordID := chi.URLParam(r, "recordID")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		respondError(w, http.StatusBadRequest, "zone_id query parameter required")
		return
	}

	client, err := h.getCFClientForZone(zoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 检查该 DNS 记录是否被转发规则引用，阻止误删
	var ruleCount int64
	h.db.Model(&models.ForwardRule{}).Where("zone_id = ? AND dns_record_id = ?", zoneID, recordID).Count(&ruleCount)
	if ruleCount > 0 {
		respondError(w, http.StatusBadRequest,
			fmt.Sprintf("该 DNS 记录被 %d 条转发规则引用，请先删除相关规则后再删除 DNS 记录", ruleCount))
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
	zoneID := chi.URLParam(r, "zoneID")
	client, err := h.getCFClientForZone(zoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

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
	zoneID := chi.URLParam(r, "zoneID")
	client, err := h.getCFClientForZone(zoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

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
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	// 所有用户（包括管理员）都只能查看自己创建的规则，避免跨用户看到他人记录
	var rules []models.ForwardRule
	h.db.Where("user_id = ?", claims.UserID).
		Order("zone_name, hostname").
		Find(&rules)

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

// availableLocalZones 返回本地 zones 表中排除被封禁账号的域名。
// 过滤口径与 createForwardRule 的自动选择逻辑保持一致：
// 无归属（AccountID==0）的旧数据保留，仅排除明确被封禁的账号。
func (h *Handler) availableLocalZones() []models.Zone {
	var zones []models.Zone
	h.db.Order("id ASC").Find(&zones)

	var blockedAccountIDs []uint
	h.db.Model(&models.CFAccount{}).Where("is_blocked = ?", true).Pluck("id", &blockedAccountIDs)
	blockedSet := make(map[uint]bool, len(blockedAccountIDs))
	for _, id := range blockedAccountIDs {
		blockedSet[id] = true
	}

	available := make([]models.Zone, 0, len(zones))
	for _, z := range zones {
		if z.AccountID != 0 && blockedSet[z.AccountID] {
			continue
		}
		available = append(available, z)
	}
	return available
}

// findAvailableZoneByCFID 按 CFID 查找可用（未封禁账号）的本地 zone。
func (h *Handler) findAvailableZoneByCFID(cfid string) (*models.Zone, error) {
	zones := h.availableLocalZones()
	for i := range zones {
		if zones[i].CFID == cfid {
			return &zones[i], nil
		}
	}
	return nil, fmt.Errorf("指定的域名不存在或所属账号已被封禁")
}

// authorizedZoneIDs 返回用户被授权的本地 Zone 主键。
func (h *Handler) authorizedZoneIDs(userID uint) []uint {
	var ids []uint
	h.db.Model(&models.ZoneUser{}).Where("user_id = ?", userID).Pluck("zone_id", &ids)
	return ids
}

// availableLocalZonesForUser 返回用户可用的域名。
// 所有用户（包括管理员）都只能使用被分配的域名；未分配域名不可用。
func (h *Handler) availableLocalZonesForUser(userID uint) []models.Zone {
	zones := h.availableLocalZones()

	ids := h.authorizedZoneIDs(userID)
	if len(ids) == 0 {
		return []models.Zone{}
	}
	allowed := make(map[uint]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}

	filtered := make([]models.Zone, 0, len(zones))
	for _, z := range zones {
		if allowed[z.ID] {
			filtered = append(filtered, z)
		}
	}
	return filtered
}

// userCanUseZone 判断用户是否可使用某个本地 Zone（包括管理员也需被分配）。
func (h *Handler) userCanUseZone(userID uint, zoneID uint) bool {
	var count int64
	h.db.Model(&models.ZoneUser{}).Where("zone_id = ? AND user_id = ?", zoneID, userID).Count(&count)
	return count > 0
}

// userCanUseZoneCFID 按 Cloudflare Zone ID 判断用户的域名使用权限。
// 本地不存在的 Zone 视为无权使用。
func (h *Handler) userCanUseZoneCFID(userID uint, cfid string) bool {
	var zone models.Zone
	if err := h.db.Where("cf_id = ?", cfid).First(&zone).Error; err != nil {
		return false
	}
	return h.userCanUseZone(userID, zone.ID)
}

// enableZoneForwardingSettings 开启转发所需的 Zone 设置：SSL Full、WebSockets、gRPC。
// 均为幂等操作，忽略错误（不阻断规则创建）。
func enableZoneForwardingSettings(client *cfclient.Client, zoneID string) {
	_, _ = client.UpdateSSLSettings(zoneID, "full")
	_ = client.EnableWebSockets(zoneID)
	_ = client.EnableGRPC(zoneID)
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
	if claims.Role != "admin" && !isSubscriptionValid(&user) {
		respondError(w, http.StatusForbidden, "订阅已过期，无法创建转发规则")
		return
	}

	var req struct {
		OriginPort int    `json:"origin_port"`
		OriginHost string `json:"origin_host"`
		Enabled    bool   `json:"enabled"`
		ZoneID     string `json:"zone_id"` // 可选：指定域名（本地 Zone 的 CFID）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 验证必填字段
	if req.OriginPort < 1 || req.OriginPort > 65535 || req.OriginHost == "" {
		respondError(w, http.StatusBadRequest, "origin_port 必须在 1-65535 之间，origin_host 不能为空")
		return
	}

	// 指定域名时先解析并验证可用性
	var selectedZone *models.Zone
	if req.ZoneID != "" {
		z, err := h.findAvailableZoneByCFID(req.ZoneID)
		if err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !h.userCanUseZone(claims.UserID, z.ID) {
			respondError(w, http.StatusForbidden, "无权使用该域名，请联系管理员分配")
			return
		}
		selectedZone = z
	}

	// 端口相同则复用已有的 Origin Rule：把新主机名并入该规则的表达式，
	// 并为这个新目标插入一行独立的 ForwardRule（共享同一 CF 规则）。
	// 端口全局唯一：任意用户创建已存在的端口都复用同一条规则。
	if existing := h.findExistingRuleForPort(req.OriginPort); existing != nil {
		// 所有用户（包括管理员）都不能借用未分配给自己的域名
		if !h.userCanUseZoneCFID(claims.UserID, existing.ZoneID) {
			respondError(w, http.StatusForbidden, "该端口已绑定域名 "+existing.ZoneName+"，无权使用该域名")
			return
		}
		// 用户显式指定域名但端口已绑定到其他域名 → 报错
		if selectedZone != nil && selectedZone.CFID != existing.ZoneID {
			respondError(w, http.StatusBadRequest, "该端口已绑定域名 "+existing.ZoneName+"，无法指定其他域名")
			return
		}
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
		if err := h.db.Create(&newRow).Error; err != nil {
			if c, cerr := h.getCFClientForAccount(newRow.AccountID); cerr == nil {
				_ = c.DeleteDNSRecord(newRow.ZoneID, newRow.DNSRecordID)
			}
			respondError(w, http.StatusInternalServerError, "保存规则失败: "+err.Error())
			return
		}

		// 按所有「启用行」统一重建共享规则表达式（禁用行不进入表达式）
		client, err := h.getCFClientForAccount(existing.AccountID)
		if err != nil {
			h.db.Delete(&newRow)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := h.syncRuleExpression(client, &newRow); err != nil {
			if !forwardRuleMissingErr(err) {
				// 同步失败：删除刚插入的本地行与 DNS 记录
				h.db.Delete(&newRow)
				_ = client.DeleteDNSRecord(newRow.ZoneID, newRow.DNSRecordID)
				respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			// CF 侧规则丢失：全量对账补全后重试
			if _, rerr := h.reconcileZoneForwardRules(client, newRow.ZoneID); rerr != nil {
				h.db.Delete(&newRow)
				_ = client.DeleteDNSRecord(newRow.ZoneID, newRow.DNSRecordID)
				respondError(w, http.StatusInternalServerError, "自动修复规则失败: "+rerr.Error())
				return
			}
			if err := h.syncRuleExpression(client, &newRow); err != nil {
				h.db.Delete(&newRow)
				_ = client.DeleteDNSRecord(newRow.ZoneID, newRow.DNSRecordID)
				respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		// 复用端口也要确保 Zone 已开启转发所需设置（旧规则/旧数据可能未开过）
		enableZoneForwardingSettings(client, existing.ZoneID)

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"result":  newRow,
		})
		return
	}

	// 选择域名：用户指定时直接使用，否则按「填满策略」自动选择
	var bestZone models.Zone
	if selectedZone != nil {
		bestZone = *selectedZone
	} else {
		// 自动选择可用的域名（优先填满一个域名）
		availableZones := h.availableLocalZonesForUser(claims.UserID)
		if len(availableZones) == 0 {
			respondError(w, http.StatusBadRequest, "没有可用的域名，请联系管理员分配域名或解除账号封禁")
			return
		}

		// 选择域名策略：优先填满一个域名，避免规则在多个域名间均匀散开。
		// 计数口径为 Cloudflare 侧 http_request_origin 的真实规则数（含面板外手工规则），
		// 而非本地 ForwardRule 行数——同端口多目标共享一条 CF 规则，行数会虚高。
		// 域名不设「已满」上限：始终在所有 zone 中挑选 CF 规则数最少的（作用于空域时规则更集中）。
		type zoneCount struct {
			zone  models.Zone
			count int
		}
		// 每个 zone 的规则数必须用该 zone 所属账号的 client 查询（跨账号 zone 不能共用轮询凭证）。
		clientByAccount := make(map[uint]*cfclient.Client)
		clientForZone := func(zone *models.Zone) (*cfclient.Client, error) {
			if c, ok := clientByAccount[zone.AccountID]; ok {
				return c, nil
			}
			c, err := h.getCFClientForAccount(zone.AccountID)
			if err != nil {
				return nil, err
			}
			clientByAccount[zone.AccountID] = c
			return c, nil
		}

		counted := make([]zoneCount, 0, len(availableZones))
		for i := range availableZones {
			zone := &availableZones[i]
			client, err := clientForZone(zone)
			if err != nil {
				log.Printf("[ForwardRule] 获取域名 %s 所属账号客户端失败: %v，跳过", zone.Name, err)
				continue
			}
			count, err := client.CountOriginRules(zone.CFID)
			if err != nil {
				log.Printf("[ForwardRule] 查询域名 %s 的 CF 规则数失败: %v，跳过", zone.Name, err)
				continue
			}
			counted = append(counted, zoneCount{zone: *zone, count: count})
		}
		if len(counted) == 0 {
			respondError(w, http.StatusBadRequest, "无法获取任何域名的规则数，请联系管理员排查 Cloudflare 账号状态")
			return
		}

		// 填满策略：优先使用「已有规则（CF 侧 count>0）但最少」的域名；没有则用规则数为 0 的域名。
		// 均不设上限。
		var used []zoneCount
		var empty zoneCount
		hasEmpty := false
		for _, zc := range counted {
			if zc.count > 0 {
				used = append(used, zc)
			} else if !hasEmpty {
				empty = zc
				hasEmpty = true
			}
		}

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
			bestZone = empty.zone
		default:
			respondError(w, http.StatusBadRequest, "没有可用的域名，请联系管理员分配域名或解除账号封禁")
			return
		}
	}

	// 兜底校验：无论显式指定还是自动选择，都必须使用分配给当前用户的域名。
	// 防止后续逻辑调整（如自动选域、迁移）绕过授权过滤。
	if !h.userCanUseZone(claims.UserID, bestZone.ID) {
		respondError(w, http.StatusForbidden, "无权使用该域名，请联系管理员分配")
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

	created, isNew, err := h.ensureOriginRuleset(client, bestZone.CFID, ruleset)
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
		// 仅当本次新建了 ruleset 时才回滚删除；合并路径下 created.ID 是共享 ruleset，
		// 删除会连带清掉该 Zone 下其他端口的转发规则。
		if isNew {
			client.DeleteOriginRuleset(bestZone.CFID, created.ID)
		}
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
		localRule.CFRuleID = findRuleIDByPort(created.Rules, req.OriginPort)
		if localRule.CFRuleID == "" && len(created.Rules) == 1 {
			localRule.CFRuleID = created.Rules[0].ID
		}
	}
	if err := h.db.Create(&localRule).Error; err != nil {
		// 本地保存失败：回滚刚创建的 DNS（ruleset 仅在本次新建时删除，避免误删共享规则）
		_ = client.DeleteDNSRecord(bestZone.CFID, createdDNS.ID)
		if isNew {
			_ = client.DeleteOriginRuleset(bestZone.CFID, created.ID)
		}
		respondError(w, http.StatusInternalServerError, "保存规则失败: "+err.Error())
		return
	}

	// 自动开启转发所需设置（SSL Full + WebSockets + gRPC，忽略错误，不影响规则创建）
	enableZoneForwardingSettings(client, bestZone.CFID)

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

// removeRuleFromRuleset 从共享 ruleset 中移除指定 rule（CF 侧），保留 ruleset 本身。
// 是否删除整个 ruleset 由调用方基于「该 ruleset 是否还有其他本地行引用」决定。
func (h *Handler) removeRuleFromRuleset(client *cfclient.Client, rule *models.ForwardRule) error {
	if rule.CFRuleSetID == "" {
		return nil
	}
	full, err := client.GetOriginRuleset(rule.ZoneID, rule.CFRuleSetID)
	if err != nil {
		if strings.Contains(err.Error(), "[10001]") {
			return nil // ruleset 已不存在
		}
		return fmt.Errorf("获取 ruleset %s 失败: %w", rule.CFRuleSetID, err)
	}

	idx := findRuleIndex(full.Rules, rule.CFRuleID)
	if idx == -1 {
		// 目标 rule 在 CF 侧已不存在（对账后仍未恢复）：无需操作
		return nil
	}

	// CF 侧只剩这一条 rule，但本地仍引用该 ruleset（数据不一致）：
	// 保守处理，不删除 ruleset（避免其他本地行失效），交由对账修复。
	if len(full.Rules) <= 1 {
		log.Printf("[ForwardRule] ruleset %s 仅剩一条 rule 但本地仍引用，跳过删除", rule.CFRuleSetID)
		return nil
	}

	full.Rules = append(full.Rules[:idx], full.Rules[idx+1:]...)
	if _, err := client.UpdateOriginRuleset(rule.ZoneID, rule.CFRuleSetID, full); err != nil {
		return fmt.Errorf("更新 ruleset %s 失败: %w", rule.CFRuleSetID, err)
	}
	return nil
}

// deleteRuleset 删除整个 ruleset（仅当没有其他本地行引用该 ruleset 时由调用方调用）。
func (h *Handler) deleteRuleset(client *cfclient.Client, rule *models.ForwardRule) error {
	if rule.CFRuleSetID == "" {
		return nil
	}
	if err := client.DeleteOriginRuleset(rule.ZoneID, rule.CFRuleSetID); err != nil {
		if strings.Contains(err.Error(), "[10001]") {
			return nil // 已不存在，无需处理
		}
		return fmt.Errorf("删除 ruleset %s 失败: %w", rule.CFRuleSetID, err)
	}
	return nil
}

// removeHostnameFromRule 从共享的 Origin Rule 表达式中移除指定主机名。
// 注意：只收集剩余行中启用（r.Enabled）的 hostname，与 syncRuleExpression 保持一致。
// 禁用目标的 hostname 不应进入表达式，避免误将已禁用的转发重新激活。
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
		if r.Enabled {
			hosts = append(hosts, r.Hostname)
		}
	}

	full, err := client.GetOriginRuleset(rule.ZoneID, rule.CFRuleSetID)
	if err != nil {
		return fmt.Errorf("获取 Cloudflare 规则失败: %w", err)
	}
	idx := findRuleIndex(full.Rules, rule.CFRuleID)
	if idx == -1 {
		return fmt.Errorf("Cloudflare 规则不存在")
	}
	// 保留 CF 表达式中属于面板外手工添加的主机名
	hosts = append(hosts, h.externalHostnames(rule, full.Rules[idx].Expression)...)
	if len(hosts) == 0 {
		// 剩余行全部禁用：整条 rule 禁用（与 syncRuleExpression 一致，避免空表达式）
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

// externalHostnames 返回 CF 规则表达式中不属于任何本地 ForwardRule 的主机名
// （通常是用户直接在 Cloudflare 面板手工添加的规则）。
// 重建表达式时必须保留它们，否则切换/删除一条面板规则会误删手工规则。
func (h *Handler) externalHostnames(rule *models.ForwardRule, expression string) []string {
	if rule.CFRuleSetID == "" || rule.CFRuleID == "" {
		return nil
	}
	var rows []models.ForwardRule
	h.db.Select("hostname").
		Where("cf_rule_set_id = ? AND cf_rule_id = ?", rule.CFRuleSetID, rule.CFRuleID).
		Find(&rows)

	managed := make(map[string]bool, len(rows))
	for _, r := range rows {
		managed[strings.ToLower(r.Hostname)] = true
	}

	out := make([]string, 0)
	for _, host := range parseHostnameList(expression) {
		// 当前操作涉及的主机名必须被移除，不能当作「外部主机」保留
		if strings.EqualFold(host, rule.Hostname) {
			continue
		}
		if !managed[strings.ToLower(host)] {
			out = append(out, host)
		}
	}
	return out
}

func (h *Handler) updateForwardRule(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "未授权")
		return
	}

	ruleID := chi.URLParam(r, "ruleID")

	var req struct {
		OriginPort int    `json:"origin_port"`
		OriginHost string `json:"origin_host"`
		Enabled    bool   `json:"enabled"`
		ZoneID     string `json:"zone_id"` // 可选：指定新域名（本地 Zone 的 CFID）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 验证必填字段
	if req.OriginPort < 1 || req.OriginPort > 65535 || req.OriginHost == "" {
		respondError(w, http.StatusBadRequest, "origin_port 必须在 1-65535 之间，origin_host 不能为空")
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

	// 所有用户（包括管理员）只能使用被分配的域名：
	// 迁移规则到其它域名、或改端口复用其它域名的共享规则时都需校验权限。
	if req.ZoneID != "" && req.ZoneID != localRule.ZoneID && !h.userCanUseZoneCFID(claims.UserID, req.ZoneID) {
		respondError(w, http.StatusForbidden, "无权使用该域名，请联系管理员分配")
		return
	}
	if req.OriginPort != localRule.OriginPort {
		if existing := h.findExistingRuleForPortExcluding(req.OriginPort, localRule.ID); existing != nil && existing.CFRuleSetID != "" {
			if !h.userCanUseZoneCFID(claims.UserID, existing.ZoneID) {
				respondError(w, http.StatusForbidden, "该端口已绑定域名 "+existing.ZoneName+"，无权使用该域名")
				return
			}
		}
	}

	// 端口/域名变更需要重建或迁移 CF 资源；仅改目标地址时才走原地更新。
	// 注意：此前实现只改了本地 origin_port，CF 侧 Origin Rule 的端口不会变化，
	// 导致面板显示已修改但实际流量仍转发到旧端口。
	portChanged := req.OriginPort != localRule.OriginPort
	zoneChanged := req.ZoneID != "" && req.ZoneID != localRule.ZoneID
	if portChanged || zoneChanged {
		if err := h.reconfigureForwardRule(&localRule, req.OriginPort, req.OriginHost, req.Enabled, req.ZoneID); err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// 重新读取，返回迁移/对账后的最新数据
		if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"result":  localRule,
		})
		return
	}

	client, err := h.getCFClientForAccount(localRule.AccountID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 目标地址变化时同步更新 DNS 记录（先改 DNS，再改本地）
	if req.OriginHost != localRule.OriginHost {
		newDNSID, err := h.updateRuleDNSRecord(client, &localRule, req.OriginHost)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "更新 DNS 记录失败: "+err.Error())
			return
		}
		if newDNSID != "" {
			localRule.DNSRecordID = newDNSID
		}
	}

	// 更新本地数据库
	localRule.OriginPort = req.OriginPort
	localRule.OriginHost = req.OriginHost
	localRule.Enabled = req.Enabled
	h.db.Save(&localRule)

	// 编辑弹窗里的开关会改变 enabled：按「启用行」重建共享规则表达式
	if err := h.syncRuleExpressionWithReconcile(client, &localRule); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  localRule,
	})
}

// reconfigureForwardRule 处理规则的端口/域名变更。
// 端口在面板内是「共享维度」：同端口的多条目标共享一条 CF Origin Rule。
// 因此改端口时优先并入该端口已有的规则；独占旧规则时可直接改端口；
// 旧规则被多个目标共享时则为新端口拆出一条独立规则。
func (h *Handler) reconfigureForwardRule(rule *models.ForwardRule, newPort int, newHost string, enabled bool, requestedZoneID string) error {
	old := *rule
	oldClient, err := h.getCFClientForAccount(old.AccountID)
	if err != nil {
		return err
	}

	// 1) 新端口已有其他本地规则：并入该端口的共享规则（必要时跟随其 zone）
	if existing := h.findExistingRuleForPortExcluding(newPort, old.ID); existing != nil && existing.CFRuleSetID != "" {
		if requestedZoneID != "" && requestedZoneID != existing.ZoneID {
			return fmt.Errorf("该端口已绑定域名 %s，无法指定其他域名", existing.ZoneName)
		}
		return h.mergeRuleIntoExistingPort(&old, existing, newHost, enabled)
	}

	// 2) 解析目标 zone
	targetZone := models.Zone{CFID: old.ZoneID, Name: old.ZoneName, AccountID: old.AccountID}
	if requestedZoneID != "" && requestedZoneID != old.ZoneID {
		z, err := h.findAvailableZoneByCFID(requestedZoneID)
		if err != nil {
			return err
		}
		targetZone = *z
	}

	// 3) 同 zone：原地改端口或从共享规则中拆分
	if targetZone.CFID == old.ZoneID {
		return h.changeRulePortInSameZone(oldClient, &old, newPort, newHost, enabled)
	}

	// 4) 跨 zone：复用迁移逻辑（按 rule 上最新的端口/目标重建资源）
	rule.OriginPort = newPort
	rule.OriginHost = newHost
	rule.Enabled = enabled
	return h.migrateRuleToZone(rule, &targetZone)
}

// changeRulePortInSameZone 在同一个 Zone 内修改端口：
// - 旧规则独占：直接修改 CF 规则的 origin port；
// - 旧规则被多个目标共享：为新端口创建独立规则，再从旧共享规则移除本主机名。
func (h *Handler) changeRulePortInSameZone(client *cfclient.Client, rule *models.ForwardRule, newPort int, newHost string, enabled bool) error {
	var sharedCount int64
	h.db.Model(&models.ForwardRule{}).
		Where("cf_rule_set_id = ? AND cf_rule_id = ?", rule.CFRuleSetID, rule.CFRuleID).
		Count(&sharedCount)

	if rule.CFRuleSetID != "" && rule.CFRuleID != "" && sharedCount <= 1 {
		// 独占：先改 CF 端口，再同步目标地址与表达式
		if err := h.updateRulePort(client, rule, newPort); err != nil {
			return fmt.Errorf("修改 Cloudflare 规则端口失败: %w", err)
		}
		newDNSID, err := h.updateRuleDNSRecord(client, rule, newHost)
		if err != nil {
			return fmt.Errorf("更新 DNS 记录失败: %w", err)
		}
		rule.OriginPort = newPort
		rule.OriginHost = newHost
		rule.Enabled = enabled
		if newDNSID != "" {
			rule.DNSRecordID = newDNSID
		}
		if err := h.db.Save(rule).Error; err != nil {
			return err
		}
		return h.syncRuleExpressionWithReconcile(client, rule)
	}

	// 共享：为新端口创建独立规则（本行独占），保留原 hostname/DNS
	old := *rule
	ruleset := &cfclient.OriginRuleset{
		Name:        "CF Panel Port Forwarding",
		Description: "Port forwarding rules managed by CF Panel",
		Kind:        "zone",
		Phase:       "http_request_origin",
		Rules: []cfclient.OriginRule{{
			Description: fmt.Sprintf("Forward to port %d", newPort),
			Expression:  buildHostExpression([]string{old.Hostname}),
			Action:      "route",
			ActionParameters: &cfclient.ActionParams{
				Origin: &cfclient.OriginParams{Port: newPort},
			},
			Enabled: enabled,
		}},
	}
	created, _, err := h.ensureOriginRuleset(client, old.ZoneID, ruleset)
	if err != nil {
		return fmt.Errorf("为新端口创建 Cloudflare 规则失败: %w", err)
	}
	newRuleID := findRuleIDByPort(created.Rules, newPort)
	if newRuleID == "" && len(created.Rules) == 1 {
		newRuleID = created.Rules[0].ID
	}
	if newRuleID == "" {
		return fmt.Errorf("未能定位新建的 Cloudflare 规则")
	}

	newDNSID, err := h.updateRuleDNSRecord(client, &old, newHost)
	if err != nil {
		return fmt.Errorf("更新 DNS 记录失败: %w", err)
	}
	rule.CFRuleSetID = created.ID
	rule.CFRuleID = newRuleID
	rule.OriginPort = newPort
	rule.OriginHost = newHost
	rule.Enabled = enabled
	if newDNSID != "" {
		rule.DNSRecordID = newDNSID
	}
	if err := h.db.Save(rule).Error; err != nil {
		return err
	}

	// 本行已指向新规则，此处只清理旧规则中的本机名（DNS 复用，不删除）
	old.DNSRecordID = ""
	if err := h.detachRuleFromCF(client, &old); err != nil {
		log.Printf("[ForwardRule] 拆分端口后清理旧规则失败: %v", err)
	}
	return nil
}

// mergeRuleIntoExistingPort 把本行并入「新端口已有」的共享规则。
// 同 zone 复用 hostname/DNS；跨 zone 时在目标 zone 新建随机 hostname 与 DNS。
func (h *Handler) mergeRuleIntoExistingPort(old *models.ForwardRule, existing *models.ForwardRule, newHost string, enabled bool) error {
	oldSnapshot := *old
	oldClient, err := h.getCFClientForAccount(oldSnapshot.AccountID)
	if err != nil {
		return err
	}
	targetClient, err := h.getCFClientForAccount(existing.AccountID)
	if err != nil {
		return err
	}

	sameZone := oldSnapshot.ZoneID == existing.ZoneID
	newHostname := oldSnapshot.Hostname
	newDNSID := oldSnapshot.DNSRecordID

	if !sameZone {
		hostname := fmt.Sprintf("%s.%s", generateRandomString(8), existing.ZoneName)
		createdDNS, err := targetClient.CreateDNSRecord(existing.ZoneID, &cfclient.DNSRecord{
			ZoneID:  existing.ZoneID,
			Name:    hostname,
			Type:    detectDNSRecordType(newHost),
			Content: newHost,
			TTL:     1,
			Proxied: true,
		})
		if err != nil {
			return fmt.Errorf("在新域名创建 DNS 记录失败: %w", err)
		}
		newHostname = hostname
		newDNSID = createdDNS.ID
	}

	// 指向目标共享规则
	old.AccountID = existing.AccountID
	old.ZoneID = existing.ZoneID
	old.ZoneName = existing.ZoneName
	old.Hostname = newHostname
	old.DNSRecordID = newDNSID
	old.CFRuleSetID = existing.CFRuleSetID
	old.CFRuleID = existing.CFRuleID
	old.OriginPort = existing.OriginPort
	old.OriginHost = newHost
	old.Enabled = enabled
	if err := h.db.Save(old).Error; err != nil {
		if !sameZone {
			_ = targetClient.DeleteDNSRecord(existing.ZoneID, newDNSID)
		}
		return err
	}

	// 把新 hostname 并入目标规则表达式（本行此时已被查询到）
	if err := h.syncRuleExpression(targetClient, old); err != nil {
		// 回滚本地行指向；跨 zone 时清理刚建的 DNS
		*old = oldSnapshot
		_ = h.db.Save(old)
		if !sameZone {
			_ = targetClient.DeleteDNSRecord(existing.ZoneID, newDNSID)
		}
		return fmt.Errorf("同步目标规则失败: %w", err)
	}

	// 同 zone 时 DNS 记录仍是旧的，需要把内容更新为新目标地址
	if sameZone {
		newDNSID, err = h.updateRuleDNSRecord(targetClient, old, newHost)
		if err != nil {
			return fmt.Errorf("更新 DNS 记录失败: %w", err)
		}
		if newDNSID != "" {
			old.DNSRecordID = newDNSID
			_ = h.db.Save(old)
		}
	}

	// 清理旧规则中的本机名；同 zone 复用 DNS，不删除
	cleanupOld := oldSnapshot
	if sameZone {
		cleanupOld.DNSRecordID = ""
	}
	if err := h.detachRuleFromCF(oldClient, &cleanupOld); err != nil {
		log.Printf("[ForwardRule] 并入共享端口后清理旧规则失败: %v", err)
	}
	if !sameZone && oldSnapshot.DNSRecordID != "" {
		if err := oldClient.DeleteDNSRecord(oldSnapshot.ZoneID, oldSnapshot.DNSRecordID); err != nil &&
			!strings.Contains(err.Error(), "[10001]") {
			log.Printf("[ForwardRule] 删除旧 DNS 记录 %s 失败: %v", oldSnapshot.DNSRecordID, err)
		}
	}

	enableZoneForwardingSettings(targetClient, existing.ZoneID)
	return nil
}

// updateRulePort 原地修改一条 CF Origin Rule 的目标端口。
func (h *Handler) updateRulePort(client *cfclient.Client, rule *models.ForwardRule, newPort int) error {
	if rule.CFRuleSetID == "" {
		return nil
	}
	full, err := client.GetOriginRuleset(rule.ZoneID, rule.CFRuleSetID)
	if err != nil {
		return err
	}
	idx := findRuleIndex(full.Rules, rule.CFRuleID)
	if idx == -1 {
		return fmt.Errorf("Cloudflare 规则不存在")
	}
	if full.Rules[idx].ActionParameters == nil {
		full.Rules[idx].ActionParameters = &cfclient.ActionParams{}
	}
	if full.Rules[idx].ActionParameters.Origin == nil {
		full.Rules[idx].ActionParameters.Origin = &cfclient.OriginParams{}
	}
	full.Rules[idx].ActionParameters.Origin.Port = newPort
	full.Rules[idx].Description = fmt.Sprintf("Forward to port %d", newPort)
	_, err = client.UpdateOriginRuleset(rule.ZoneID, rule.CFRuleSetID, full)
	return err
}

// updateRuleDNSRecord 更新规则对应 DNS 记录的内容。类型不变时原地 PATCH；
// 类型变化（A/AAAA/CNAME）时新建记录并删除旧记录。返回新的 DNS 记录 ID。
func (h *Handler) updateRuleDNSRecord(client *cfclient.Client, rule *models.ForwardRule, newHost string) (string, error) {
	if rule.DNSRecordID == "" {
		return "", nil
	}
	oldType := detectDNSRecordType(rule.OriginHost)
	newType := detectDNSRecordType(newHost)
	if oldType == newType {
		record := &cfclient.DNSRecord{
			Name:    rule.Hostname,
			Type:    newType,
			Content: newHost,
			TTL:     1,
			Proxied: true,
		}
		if _, err := client.UpdateDNSRecord(rule.ZoneID, rule.DNSRecordID, record); err != nil {
			return "", err
		}
		return rule.DNSRecordID, nil
	}

	oldID := rule.DNSRecordID
	created, err := client.CreateDNSRecord(rule.ZoneID, &cfclient.DNSRecord{
		ZoneID:  rule.ZoneID,
		Name:    rule.Hostname,
		Type:    newType,
		Content: newHost,
		TTL:     1,
		Proxied: true,
	})
	if err != nil {
		return "", err
	}
	if err := client.DeleteDNSRecord(rule.ZoneID, oldID); err != nil {
		log.Printf("[ForwardRule] 删除旧 DNS 记录 %s 失败: %v", oldID, err)
	}
	return created.ID, nil
}

// detachRuleFromCF 从旧 CF 资源中移除一条本地规则对应的 hostname/rule。
// 与 cleanupRuleFromZone 不同：本函数基于「排除当前行后」的本地引用和 CF 侧真实规则数判断，
// 不会因为「同端口只剩另一条共享行」而误删仍被引用的规则。
func (h *Handler) detachRuleFromCF(client *cfclient.Client, rule *models.ForwardRule) error {
	if rule.CFRuleSetID == "" {
		return nil
	}
	full, err := client.GetOriginRuleset(rule.ZoneID, rule.CFRuleSetID)
	if err != nil {
		if strings.Contains(err.Error(), "[10001]") {
			return nil
		}
		return err
	}
	idx := findRuleIndex(full.Rules, rule.CFRuleID)
	if idx == -1 {
		return nil
	}

	var remainingSameRule int64
	h.db.Model(&models.ForwardRule{}).
		Where("cf_rule_set_id = ? AND cf_rule_id = ? AND id != ?", rule.CFRuleSetID, rule.CFRuleID, rule.ID).
		Count(&remainingSameRule)
	if remainingSameRule > 0 {
		return h.removeHostnameFromRule(client, rule)
	}

	// 没有其他本地行共享该规则，但 CF 表达式里可能还有面板外手工添加的主机名：
	// 此时只移除本行 hostname，绝不能删除整条规则/ ruleset。
	remainingExprHosts := make([]string, 0)
	for _, h := range parseHostnameList(full.Rules[idx].Expression) {
		if !strings.EqualFold(h, rule.Hostname) {
			remainingExprHosts = append(remainingExprHosts, h)
		}
	}
	if len(remainingExprHosts) > 0 {
		full.Rules[idx].Expression = buildHostExpression(remainingExprHosts)
		_, err := client.UpdateOriginRuleset(rule.ZoneID, rule.CFRuleSetID, full)
		return err
	}

	var remainingSet int64
	h.db.Model(&models.ForwardRule{}).
		Where("cf_rule_set_id = ? AND id != ?", rule.CFRuleSetID, rule.ID).
		Count(&remainingSet)
	if len(full.Rules) <= 1 && remainingSet == 0 {
		return h.deleteRuleset(client, rule)
	}
	return h.removeRuleFromRuleset(client, rule)
}

// syncRuleExpressionWithReconcile 先尝试同步表达式；CF 侧规则丢失时自动对账补全后重试。
func (h *Handler) syncRuleExpressionWithReconcile(client *cfclient.Client, rule *models.ForwardRule) error {
	if err := h.syncRuleExpression(client, rule); err != nil {
		if !forwardRuleMissingErr(err) {
			return err
		}
		if _, rerr := h.reconcileZoneForwardRules(client, rule.ZoneID); rerr != nil {
			return fmt.Errorf("自动修复规则失败: %w", rerr)
		}
		// 对账可能更新了本地行的 CF ID，重新读取后重试
		if err := h.db.Where("id = ?", rule.ID).First(rule).Error; err != nil {
			return err
		}
		return h.syncRuleExpression(client, rule)
	}
	return nil
}

// migrateRuleToZone 将单条规则迁移到新 zone：
// 1) 在新 zone 创建 DNS 记录 + Origin Rule（复用 ensureOriginRuleset 合并逻辑）；
// 2) 清理旧 zone 中该规则的 CF 资源；
// 3) 更新本地行指向新 zone。
// 规则为「同端口多目标共享一条 CF rule」的成员时，仅从旧共享表达式移除本行 hostname，不删除共享规则。
func (h *Handler) migrateRuleToZone(rule *models.ForwardRule, newZone *models.Zone) error {
	oldClient, err := h.getCFClientForAccount(rule.AccountID)
	if err != nil {
		return err
	}
	newClient, err := h.getCFClientForAccount(newZone.AccountID)
	if err != nil {
		return err
	}

	// 1) 新 zone 建 DNS（随机子域名）
	newHostname := fmt.Sprintf("%s.%s", generateRandomString(8), newZone.Name)
	createdDNS, err := newClient.CreateDNSRecord(newZone.CFID, &cfclient.DNSRecord{
		ZoneID:  newZone.CFID,
		Name:    newHostname,
		Type:    detectDNSRecordType(rule.OriginHost),
		Content: rule.OriginHost,
		TTL:     1,
		Proxied: true,
	})
	if err != nil {
		return fmt.Errorf("在新域名创建 DNS 记录失败: %w", err)
	}

	// 2) 新 zone 建/合并 Origin Rule
	ruleset := &cfclient.OriginRuleset{
		Name:        "CF Panel Port Forwarding",
		Description: "Port forwarding rules managed by CF Panel",
		Kind:        "zone",
		Phase:       "http_request_origin",
		Rules: []cfclient.OriginRule{{
			Description: fmt.Sprintf("Forward to port %d", rule.OriginPort),
			Expression:  buildHostExpression([]string{newHostname}),
			Action:      "route",
			ActionParameters: &cfclient.ActionParams{
				Origin: &cfclient.OriginParams{Port: rule.OriginPort},
			},
			Enabled: rule.Enabled,
		}},
	}
	created, isNew, err := h.ensureOriginRuleset(newClient, newZone.CFID, ruleset)
	if err != nil {
		_ = newClient.DeleteDNSRecord(newZone.CFID, createdDNS.ID)
		return fmt.Errorf("在新域名创建规则失败: %w", err)
	}
	newRuleID := ""
	if len(created.Rules) > 0 {
		newRuleID = findRuleIDByPort(created.Rules, rule.OriginPort)
		if newRuleID == "" && len(created.Rules) == 1 {
			newRuleID = created.Rules[0].ID
		}
	}

	// 3) 清理旧 zone（成功建好新资源后再拆旧资源）
	if err := h.cleanupRuleFromZone(oldClient, rule); err != nil {
		// 回滚新资源：DNS 必删；ruleset 仅在本次新建时删除（合并路径共享，不可删）
		_ = newClient.DeleteDNSRecord(newZone.CFID, createdDNS.ID)
		if isNew {
			_ = newClient.DeleteOriginRuleset(newZone.CFID, created.ID)
		}
		return fmt.Errorf("清理旧域名资源失败: %w", err)
	}

	// 4) 新 zone 开启转发所需设置（幂等，忽略错误）
	enableZoneForwardingSettings(newClient, newZone.CFID)

	// 5) 更新本地行指向新 zone
	rule.AccountID = newZone.AccountID
	rule.ZoneID = newZone.CFID
	rule.ZoneName = newZone.Name
	rule.Hostname = newHostname
	rule.DNSRecordID = createdDNS.ID
	rule.CFRuleSetID = created.ID
	rule.CFRuleID = newRuleID
	return h.db.Save(rule).Error
}

// cleanupRuleFromZone 清理某条规则在 CF 侧的独占资源（rule/ruleset/DNS），但不删除本地行。
// 同端口多目标共享一条 CF rule 时，仅移除本行 hostname，保留其他目标；
// 判断是否删除整个 ruleset 时以 CF 侧真实规则数为准，避免误删面板外手工创建的规则。
func (h *Handler) cleanupRuleFromZone(client *cfclient.Client, rule *models.ForwardRule) error {
	if err := h.detachRuleFromCF(client, rule); err != nil {
		if !forwardRuleMissingErr(err) {
			return err
		}
		log.Printf("[ForwardRule] 迁移清理时 CF 侧规则已不存在，跳过")
	}

	if rule.DNSRecordID != "" {
		if err := client.DeleteDNSRecord(rule.ZoneID, rule.DNSRecordID); err != nil {
			if !strings.Contains(err.Error(), "[10001]") {
				return fmt.Errorf("删除旧 DNS 记录失败: %w", err)
			}
		}
	}
	return nil
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

	// 删除前先对账：补齐 CF 侧缺失的规则/DNS、修复本地 CF ID 不一致，
	// 保证下面的删除决策（是否删整个 ruleset）基于准确的数据，避免误删同端口共享规则。
	// 对账幂等：规则完整时只做读取比对，开销可接受。
	_, _ = h.reconcileZoneForwardRules(client, localRule.ZoneID)
	if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 从 CF 侧移除本行对应资源：
	// - 同端口多目标共享：只从表达式移除本主机名；
	// - 独占：按 CF 侧真实规则数决定删除单条规则还是整个 ruleset（避免误删面板外规则）。
	if err := h.detachRuleFromCF(client, &localRule); err != nil {
		if !forwardRuleMissingErr(err) {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		log.Printf("[ForwardRule] 删除规则 %s 时 CF 侧已不存在，跳过 CF 侧清理", localRule.Hostname)
	}

	// 删除关联的 DNS 记录（仅当 CF 侧删除成功后才执行，避免 DB 记录已删但 CF 资源残留）
	if localRule.DNSRecordID != "" {
		if err := client.DeleteDNSRecord(localRule.ZoneID, localRule.DNSRecordID); err != nil {
			if !strings.Contains(err.Error(), "[10001]") {
				log.Printf("[ForwardRule] 删除 DNS 记录 %s 失败: %v，本地记录保留", localRule.DNSRecordID, err)
				respondError(w, http.StatusInternalServerError, "删除 DNS 记录失败，本地记录已保留: "+err.Error())
				return
			}
			// DNS 记录已不存在，可以继续
		}
	}

	// 删除本地记录
	h.db.Delete(&localRule)

	log.Printf("[ForwardRule] 管理员 %s(role=%s) 删除了转发规则 %s (%s:%d)",
		claims.Username, claims.Role, localRule.Hostname, localRule.OriginHost, localRule.OriginPort)

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
		if !forwardRuleMissingErr(err) {
			// 同步失败：回滚本地状态
			localRule.Enabled = !newEnabled
			h.db.Save(&localRule)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// CF 侧规则丢失：全量对账补全后重试
		if _, rerr := h.reconcileZoneForwardRules(client, localRule.ZoneID); rerr != nil {
			localRule.Enabled = !newEnabled
			h.db.Save(&localRule)
			respondError(w, http.StatusInternalServerError, "自动修复规则失败: "+rerr.Error())
			return
		}
		// 对账可能已更新本地行的 CF ID，重新读取后重试
		if err := h.db.Where("id = ?", ruleID).First(&localRule).Error; err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := h.syncRuleExpression(client, &localRule); err != nil {
			localRule.Enabled = !newEnabled
			h.db.Save(&localRule)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
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

	// 保留面板外手工添加到同一 CF 规则的主机名
	hosts = append(hosts, h.externalHostnames(rule, full.Rules[idx].Expression)...)

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

// findRuleIDByPort 在 ruleset 的规则列表中按目标端口查找 rule ID。
// 合并写入（ensureOriginRuleset）时，新规则可能被合并进已有规则，位置不一定是最后一条，
// 因此不能用 Rules[len-1] 兜底。
func findRuleIDByPort(rules []cfclient.OriginRule, port int) string {
	for i := range rules {
		r := &rules[i]
		if r.ActionParameters != nil && r.ActionParameters.Origin != nil &&
			r.ActionParameters.Origin.Port == port {
			return r.ID
		}
	}
	return ""
}

// hostEqRegexp 从 Cloudflare Origin Rule 表达式中提取 http.host eq 的主机名。
// 表达式形如：(http.host eq "a.example.com") 或
// ((http.host eq "a.example.com") or (http.host eq "b.example.com"))
var hostEqRegexp = regexp.MustCompile(`http\.host\s+eq\s+"((?:[^"\\]|\\.)*)"`)

// parseHostnameList 从 Cloudflare 规则表达式中解析出全部主机名。
// 历史数据可能保存的是逗号分隔的纯 host 列表，此时回退到逗号切分。
func parseHostnameList(expr string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)

	matches := hostEqRegexp.FindAllStringSubmatch(expr, -1)
	if len(matches) > 0 {
		for _, m := range matches {
			h := m[1]
			// 还原表达式中的转义字符（如 \. / \"）
			if unquoted, err := strconv.Unquote(`"` + m[1] + `"`); err == nil {
				h = unquoted
			}
			h = strings.TrimSpace(h)
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
		return out
	}

	for _, p := range strings.Split(expr, ",") {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// buildHostExpression 根据多个主机名构建 http.host 匹配表达式（单个用 eq，多个用 or 连接）。
// 排序保证同一组主机名生成稳定的表达式，避免无意义更新。
func buildHostExpression(hostnames []string) string {
	uniq := make([]string, 0, len(hostnames))
	seen := make(map[string]bool, len(hostnames))
	for _, h := range hostnames {
		if h != "" && !seen[h] {
			seen[h] = true
			uniq = append(uniq, h)
		}
	}
	sort.Strings(uniq)

	if len(uniq) == 0 {
		return ""
	}
	if len(uniq) == 1 {
		return fmt.Sprintf("(http.host eq %q)", uniq[0])
	}
	parts := make([]string, 0, len(uniq))
	for _, h := range uniq {
		parts = append(parts, fmt.Sprintf("(http.host eq %q)", h))
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// findExistingRuleForPort 按端口查找已存在的规则（端口全局唯一，同端口复用）
func (h *Handler) findExistingRuleForPort(port int) *models.ForwardRule {
	return h.findExistingRuleForPortExcluding(port, 0)
}

// findExistingRuleForPortExcluding 按端口查找规则，可排除指定本地行（用于编辑时忽略自身）。
func (h *Handler) findExistingRuleForPortExcluding(port int, excludeID uint) *models.ForwardRule {
	var rule models.ForwardRule
	query := h.db.Where("origin_port = ?", port)
	if excludeID != 0 {
		query = query.Where("id != ?", excludeID)
	}
	if err := query.Order("id ASC").First(&rule).Error; err != nil {
		return nil
	}
	return &rule
}

// ensureOriginRuleset 创建 Origin Ruleset；若该 zone 已达 ruleset 数量上限（错误码 20217），
// 则复用现有的 zone 级 http_request_origin ruleset，把新规则追加进去（合并方案）。
// 返回 (ruleset, isNewlyCreated, error)：isNewlyCreated 为 true 表示本次新建了 ruleset，
// 调用方在回滚时应仅对新建的 ruleset 执行删除，避免误删共享的已有 ruleset。
func (h *Handler) ensureOriginRuleset(client *cfclient.Client, zoneID string, newRuleset *cfclient.OriginRuleset) (*cfclient.OriginRuleset, bool, error) {
	created, err := client.CreateOriginRuleset(zoneID, newRuleset)
	if err == nil {
		return created, true, nil
	}

	// 只有"数量超限"才走合并；其他错误直接返回
	if !strings.Contains(err.Error(), "[20217]") {
		return nil, false, err
	}

	existingList, listErr := client.ListOriginRulesets(zoneID)
	if listErr != nil {
		return nil, false, fmt.Errorf("创建失败(%v)且无法列出已有 ruleset(%v)", err, listErr)
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
			return nil, false, err
		}
		target = &existingList[0]
	}

	// 拉取完整 ruleset（含 rules），检查目标端口是否已存在规则
	// 若已存在，更新其表达式合并 hostname，而非追加重复规则
	full, getErr := client.GetOriginRuleset(zoneID, target.ID)
	if getErr != nil {
		return nil, false, fmt.Errorf("创建失败(%v)且获取 ruleset %s 失败(%v)", err, target.ID, getErr)
	}
	for i := range newRuleset.Rules {
		newRule := &newRuleset.Rules[i]
		merged := false
		if newRule.ActionParameters != nil && newRule.ActionParameters.Origin != nil {
			newPort := newRule.ActionParameters.Origin.Port
			for j := range full.Rules {
				existing := &full.Rules[j]
				if existing.ActionParameters != nil && existing.ActionParameters.Origin != nil &&
					existing.ActionParameters.Origin.Port == newPort {
					// 禁用的新目标不能并入现有表达式，否则会意外激活该主机名；
					// 仍标记 merged，避免为同一端口追加重复规则。
					if newRule.Enabled {
						existingHosts := parseHostnameList(existing.Expression)
						newHosts := parseHostnameList(newRule.Expression)
						mergedSet := make(map[string]bool, len(existingHosts)+len(newHosts))
						for _, h := range existingHosts {
							mergedSet[h] = true
						}
						for _, h := range newHosts {
							mergedSet[h] = true
						}
						mergedList := make([]string, 0, len(mergedSet))
						for h := range mergedSet {
							mergedList = append(mergedList, h)
						}
						existing.Expression = buildHostExpression(mergedList)
						existing.Enabled = true
					}
					merged = true
					break
				}
			}
		}
		if !merged {
			full.Rules = append(full.Rules, *newRule)
		}
	}
	updated, updateErr := client.UpdateOriginRuleset(zoneID, full.ID, full)
	if updateErr != nil {
		return nil, false, fmt.Errorf("创建失败(%v)且合并到 ruleset %s 失败(%v)", err, full.ID, updateErr)
	}
	return updated, false, nil // isNewlyCreated=false，回滚时不能删除此共享 ruleset
}

// forwardRuleMissingErr 判断错误是否为「CF 规则/规则集不存在」类错误（资源已被 CF 侧删除）。
// 这类错误触发全量对账补全，而不是直接向用户报错。
func forwardRuleMissingErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "[10001]") || strings.Contains(msg, "Cloudflare 规则不存在")
}

// ruleGroup 一组本地行共享同一条 CF rule（同端口多目标：各目标为一行，表达式含全部 hostname）。
type ruleGroup struct {
	rows []*models.ForwardRule
	port int
}

// enabledHosts 返回组内启用行的 hostname 列表（禁用行不进入表达式）。
func enabledHosts(rows []*models.ForwardRule) []string {
	hosts := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Enabled {
			hosts = append(hosts, r.Hostname)
		}
	}
	return hosts
}

// reconcileZoneForwardRules 对指定 Zone 做全量对账：把本地所有引用 CF 资源的转发规则
// 与 Cloudflare 侧对齐，重建任何在 CF 侧丢失的 ruleset / rule / DNS 记录。
// 同端口多目标共享一条 rule：整条 ruleset 丢失时按「rule-group」整体重建，
// 单条 rule 丢失时追加回原 ruleset。返回被修复的规则数。
func (h *Handler) reconcileZoneForwardRules(client *cfclient.Client, zoneID string) (int, error) {
	// 1) 收集本地所有行（含禁用行，禁用行仍共享同一 CF rule）
	var rows []models.ForwardRule
	h.db.Where("zone_id = ?", zoneID).Order("id ASC").Find(&rows)
	if len(rows) == 0 {
		return 0, nil
	}

	// 2) 拉取 CF 侧该 zone 全部 ruleset（含完整 rules）与 DNS 记录
	existingList, err := client.ListOriginRulesets(zoneID)
	if err != nil {
		return 0, fmt.Errorf("列出 Cloudflare 规则失败: %w", err)
	}
	rulesetMap := make(map[string]*cfclient.OriginRuleset, len(existingList))
	for i := range existingList {
		rs := &existingList[i]
		full, getErr := client.GetOriginRuleset(zoneID, rs.ID)
		if getErr != nil {
			continue // 单个 ruleset 拉取失败不阻塞整体对账
		}
		rulesetMap[full.ID] = full
	}

	dnsRecords, dnsErr := client.ListDNSRecords(zoneID, "")
	dnsIDSet := make(map[string]bool, len(dnsRecords))
	if dnsErr == nil {
		for _, rec := range dnsRecords {
			dnsIDSet[rec.ID] = true
		}
	}

	// 3) 按 ruleset -> rule 分组（同端口多目标共享一条 CF rule）
	groupsBySet := make(map[string][]*ruleGroup)
	groupByKey := make(map[string]*ruleGroup) // setID + "\x00" + ruleID
	for i := range rows {
		r := &rows[i]
		if r.CFRuleSetID == "" || r.CFRuleID == "" {
			continue // 无 CF 关联的旧数据，跳过
		}
		key := r.CFRuleSetID + "\x00" + r.CFRuleID
		g, ok := groupByKey[key]
		if !ok {
			g = &ruleGroup{port: r.OriginPort}
			groupByKey[key] = g
			groupsBySet[r.CFRuleSetID] = append(groupsBySet[r.CFRuleSetID], g)
		}
		g.rows = append(g.rows, r)
	}

	fixed := 0

	for setID, groups := range groupsBySet {
		full, ok := rulesetMap[setID]
		if !ok {
			// 整个 ruleset 丢失：按 rule-group 整体重建（每条 CF rule 对应一个组）
			recreated, createErr := h.rebuildZoneRuleset(client, zoneID, groups)
			if createErr != nil {
				log.Printf("[ForwardRule] 重建 ruleset %s 失败: %v", setID, createErr)
				continue
			}
			h.updateGroupCFIDs(groups, recreated)
			for _, g := range groups {
				fixed += len(g.rows)
			}
			continue
		}

		// ruleset 还在：逐条检查 rule 是否丢失
		for _, g := range groups {
			if findRuleIndex(full.Rules, g.rows[0].CFRuleID) != -1 {
				continue
			}
			// 该 rule 丢失：先在 ruleset 中按端口查找，避免创建重复规则
			hosts := enabledHosts(g.rows)
			if len(hosts) == 0 {
				continue
			}
			existingIdx := -1
			for j := range full.Rules {
				r := &full.Rules[j]
				if r.ActionParameters != nil && r.ActionParameters.Origin != nil &&
					r.ActionParameters.Origin.Port == g.port {
					existingIdx = j
					break
				}
			}
			if existingIdx != -1 {
				// 同端口规则已存在：合并新 hostname 到现有规则表达式
				existing := &full.Rules[existingIdx]
				existingHosts := parseHostnameList(existing.Expression)
				mergedSet := make(map[string]bool, len(existingHosts)+len(hosts))
				for _, h := range existingHosts {
					mergedSet[h] = true
				}
				for _, h := range hosts {
					mergedSet[h] = true
				}
				mergedList := make([]string, 0, len(mergedSet))
				for h := range mergedSet {
					mergedList = append(mergedList, h)
				}
				existing.Expression = buildHostExpression(mergedList)
				existing.Enabled = true
				_, updateErr := client.UpdateOriginRuleset(zoneID, full.ID, full)
				if updateErr != nil {
					log.Printf("[ForwardRule] 合并缺失 rule 到现有规则失败 (%s): %v", full.ID, updateErr)
					continue
				}
				// 更新本地行的 cf_rule_id 指向现有规则的 ID
				for _, r := range g.rows {
					h.db.Model(r).Update("cf_rule_id", existing.ID)
				}
				fixed += len(g.rows)
				continue
			}
			// ruleset 中无同端口规则：追加新规则
			full.Rules = append(full.Rules, cfclient.OriginRule{
				Description: fmt.Sprintf("Forward to port %d", g.port),
				Expression:  buildHostExpression(hosts),
				Action:      "route",
				ActionParameters: &cfclient.ActionParams{
					Origin: &cfclient.OriginParams{Port: g.port},
				},
				Enabled: true,
			})
			updated, updateErr := client.UpdateOriginRuleset(zoneID, full.ID, full)
			if updateErr != nil {
				log.Printf("[ForwardRule] 补回缺失 rule 失败 (%s): %v", full.ID, updateErr)
				continue
			}
			newRuleID := findRuleIDByPort(updated.Rules, g.port)
			if newRuleID == "" && len(updated.Rules) == 1 {
				newRuleID = updated.Rules[0].ID
			}
			for _, r := range g.rows {
				h.db.Model(r).Update("cf_rule_id", newRuleID)
			}
			fixed += len(g.rows)
		}
	}

	// 4) DNS 对账
	for i := range rows {
		r := &rows[i]
		if r.DNSRecordID == "" || dnsIDSet[r.DNSRecordID] {
			continue
		}
		created, createErr := client.CreateDNSRecord(zoneID, &cfclient.DNSRecord{
			ZoneID:  zoneID,
			Name:    r.Hostname,
			Type:    detectDNSRecordType(r.OriginHost),
			Content: r.OriginHost,
			TTL:     1,
			Proxied: true,
		})
		if createErr != nil {
			log.Printf("[ForwardRule] 重建 DNS 记录失败 (%s): %v", r.Hostname, createErr)
			continue
		}
		h.db.Model(r).Update("dns_record_id", created.ID)
		fixed++
	}

	if fixed > 0 {
		log.Printf("[ForwardRule] Zone %s 对账完成，修复 %d 项", zoneID, fixed)
	}
	return fixed, nil
}

// rebuildZoneRuleset 用本地 rule-group 重建一个丢失的 ruleset（每条 CF rule 对应一个组）。
func (h *Handler) rebuildZoneRuleset(client *cfclient.Client, zoneID string, groups []*ruleGroup) (*cfclient.OriginRuleset, error) {
	rules := make([]cfclient.OriginRule, 0, len(groups))
	for _, g := range groups {
		hosts := enabledHosts(g.rows)
		if len(hosts) == 0 {
			continue
		}
		rules = append(rules, cfclient.OriginRule{
			Description: fmt.Sprintf("Forward to port %d", g.port),
			Expression:  buildHostExpression(hosts),
			Action:      "route",
			ActionParameters: &cfclient.ActionParams{
				Origin: &cfclient.OriginParams{Port: g.port},
			},
			Enabled: true,
		})
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("没有可重建的启用规则")
	}
	recreated, _, err := h.ensureOriginRuleset(client, zoneID, &cfclient.OriginRuleset{
		Name:        "CF Panel Port Forwarding",
		Description: "Port forwarding rules managed by CF Panel",
		Kind:        "zone",
		Phase:       "http_request_origin",
		Rules:       rules,
	})
	return recreated, err
}

// updateGroupCFIDs 重建 ruleset 后，把组内所有本地行的 CF ID 更新为新值。
// 新规则按目标端口映射到对应 rule-group。
func (h *Handler) updateGroupCFIDs(groups []*ruleGroup, recreated *cfclient.OriginRuleset) {
	ruleIDByPort := make(map[int]string, len(recreated.Rules))
	for _, rule := range recreated.Rules {
		if rule.ActionParameters != nil && rule.ActionParameters.Origin != nil {
			ruleIDByPort[rule.ActionParameters.Origin.Port] = rule.ID
		}
	}
	for _, g := range groups {
		ruleID := ruleIDByPort[g.port]
		if ruleID == "" && len(recreated.Rules) == 1 {
			ruleID = recreated.Rules[0].ID // 兜底：仅一条规则时无需按端口匹配
		}
		for _, r := range g.rows {
			h.db.Model(r).Updates(map[string]interface{}{
				"cf_rule_set_id": recreated.ID,
				"cf_rule_id":     ruleID,
			})
		}
	}
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
	// 按本地时区解析，并视为「当天结束前有效」：用户选择 2024-12-31 时，
	// 到期时间应为 12-31 23:59:59，而不是当天 00:00（否则当天就被判定过期）。
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t.AddDate(0, 0, 1).Add(-time.Second), nil
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

// pauseExpiredSubscriptions 暂停过期用户的转发规则，并同步到 CF 侧
func (h *Handler) pauseExpiredSubscriptions() {
	var users []models.User
	h.db.Where("subscription IS NOT NULL AND subscription < ?", time.Now()).Find(&users)

	for _, user := range users {
		// 查找该用户所有已启用的转发规则
		var rules []models.ForwardRule
		h.db.Where("user_id = ? AND enabled = ?", user.ID, true).Find(&rules)

		if len(rules) == 0 {
			continue
		}

		// 先在 DB 中禁用
		h.db.Model(&models.ForwardRule{}).
			Where("user_id = ? AND enabled = ?", user.ID, true).
			Update("enabled", false)

		// 收集需要同步的 CF 规则对（同一端口共享同一 cf_rule 无需重复同步）
		type cfRuleKey struct {
			accountID   uint
			cfRuleSetID string
			cfRuleID    string
		}
		seen := make(map[cfRuleKey]bool)
		for _, rule := range rules {
			key := cfRuleKey{accountID: rule.AccountID, cfRuleSetID: rule.CFRuleSetID, cfRuleID: rule.CFRuleID}
			if seen[key] {
				continue
			}
			seen[key] = true

			client, err := h.getCFClientForAccount(rule.AccountID)
			if err != nil {
				log.Printf("[Subscription] 获取账号 %d 客户端失败: %v，CF 侧规则未同步", rule.AccountID, err)
				continue
			}
			if err := h.syncRuleExpression(client, &rule); err != nil {
				log.Printf("[Subscription] 同步 CF 规则 %s/%s 失败: %v", rule.CFRuleSetID, rule.CFRuleID, err)
			}
		}
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

	client, err := h.getCFClientForZone(req.ZoneID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
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

	var registrar models.DomainRegistrar
	if err := h.db.First(&registrar, registrarID).Error; err != nil {
		respondError(w, http.StatusNotFound, "注册商不存在")
		return
	}

	// 检查该注册商下是否有域名任务，阻止删除避免产生孤儿队列记录
	var domainCount int64
	h.db.Model(&models.RegistrarDomain{}).Where("registrar_id = ?", registrarID).Count(&domainCount)
	if domainCount > 0 {
		respondError(w, http.StatusBadRequest,
			fmt.Sprintf("该注册商下有 %d 个域名记录，请先删除所有域名记录后再删除注册商", domainCount))
		return
	}

	tx := h.db.Begin()
	if err := tx.Delete(&models.DomainRegistrar{}, registrarID).Error; err != nil {
		tx.Rollback()
		respondError(w, http.StatusInternalServerError, "删除注册商失败: "+err.Error())
		return
	}
	tx.Commit()

	claims := auth.GetUserFromContext(r)
	if claims != nil {
		log.Printf("[Admin] 管理员 %s(role=%s) 删除了注册商 %s", claims.Username, claims.Role, registrar.Name)
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
			"id":           d.ID,
			"domain":       d.Domain,
			"status":       d.Status,
			"error_msg":    d.ErrorMsg,
			"retry_count":  d.RetryCount,
			"exists":       existingSet[lower],
			"queued":       d.Status == "pending" || d.Status == "processing",
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

	// 先查询域名记录状态，processing 中的任务禁止删除（避免与调度器竞态）
	var domain models.RegistrarDomain
	if err := h.db.Where("id = ? AND registrar_id = ?", domainID, registrarID).First(&domain).Error; err != nil {
		respondError(w, http.StatusNotFound, "域名记录不存在")
		return
	}
	if domain.Status == "processing" {
		respondError(w, http.StatusBadRequest, "该域名正在导入中，请稍后再试")
		return
	}

	// 已成功导入的域名删除后，CF Zone 不会自动清理，需提醒用户
	if domain.Status == "success" || domain.Status == "partial" {
		log.Printf("[Registrar] 警告：删除已成功导入的域名 %s，CF Zone 仍保留在 Cloudflare 中，需手动清理", domain.Domain)
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
			if isUniqueConstraintErr(err) {
				results = append(results, map[string]interface{}{
					"domain":  domain,
					"status":  "skipped",
					"message": "已在排队中",
				})
				skipCount++
			} else {
				results = append(results, map[string]interface{}{
					"domain":  domain,
					"status":  "failed",
					"message": "入队失败: " + err.Error(),
				})
				failCount++
			}
			continue
		}

		results = append(results, map[string]interface{}{
			"domain":  domain,
			"status":  "queued",
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
	// 路由位于 /registrars/{registrarID}/tasks，优先使用路径参数
	registrarID := chi.URLParam(r, "registrarID")
	if registrarID == "" {
		registrarID = r.URL.Query().Get("registrar_id")
	}
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
	message := fmt.Sprintf("已将 %d 个任务重新加入队列", count)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": message,
		"result":  map[string]string{"message": message},
	})
}
