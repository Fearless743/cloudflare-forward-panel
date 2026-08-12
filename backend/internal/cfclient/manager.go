package cfclient

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"cloudflare-forward-panel/internal/models"
	"cloudflare-forward-panel/internal/telegram"
	"gorm.io/gorm"
)

// Manager 管理多个 CF 账号，支持自动切换
type Manager struct {
	db             *gorm.DB
	clients        []*Client
	currentIndex   int
	mu             sync.RWMutex
	telegramClient *telegram.Client
	// onAccountBlocked 账号被封禁时的回调（用于自动迁移规则等上层逻辑）
	onAccountBlocked func(accountID uint)
}

// NewManager 创建多账号管理器
func NewManager(db *gorm.DB, telegramClient *telegram.Client) *Manager {
	m := &Manager{
		db:             db,
		clients:        make([]*Client, 0),
		currentIndex:   0,
		telegramClient: telegramClient,
	}
	m.loadAccounts()
	// 启动时同步一次本地 Zone 表（供转发规则使用）
	m.SyncLocalZones()
	return m
}

// loadAccounts 从数据库加载所有启用的账号
func (m *Manager) loadAccounts() {
	var accounts []models.CFAccount
	m.db.Where("is_active = ? AND is_blocked = ?", true, false).Order("id ASC").Find(&accounts)

	m.clients = make([]*Client, 0)
	for _, acc := range accounts {
		client := NewClient(acc.APIKey, acc.Email)
		client.accountID = acc.ID
		client.accountName = acc.Name
		client.accountIdentifier = acc.AccountID // CF 账号 ID
		client.SetManager(m)                     // 设置管理器引用
		m.clients = append(m.clients, client)
	}
	log.Printf("[CF Manager] 加载了 %d 个可用账号", len(m.clients))
}

// ReloadAccounts 重新加载账号列表（用于配置变更后刷新）
func (m *Manager) ReloadAccounts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadAccounts()
}

// GetClient 获取当前可用的客户端
func (m *Manager) GetClient() (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.clients) == 0 {
		return nil, fmt.Errorf("没有可用的 Cloudflare 账号")
	}

	// 确保索引有效
	if m.currentIndex >= len(m.clients) {
		m.currentIndex = 0
	}

	c := m.clients[m.currentIndex]
	m.markUsed(c)
	return c, nil
}

// markUsed 更新账号的最后使用时间（需持有写锁，由 GetClient/GetClientByAccountID 调用）
func (m *Manager) markUsed(c *Client) {
	if c == nil || c.accountID == 0 {
		return
	}
	now := time.Now()
	if err := m.db.Model(&models.CFAccount{}).Where("id = ?", c.accountID).Update("last_used", &now).Error; err != nil {
		log.Printf("[CF Manager] 更新账号 %d 最后使用时间失败: %v", c.accountID, err)
	}
}

// ReportError 报告账号错误，可能触发切换
// 注意：本方法通过 client.doRequest 的 goroutine 异步调用（见 client.go），
// 不要持有锁做耗时/网络操作，锁内只做内存与轻量 DB 操作。
func (m *Manager) ReportError(accountID uint, errMsg string) {
	m.mu.Lock()

	// 更新数据库中的错误信息
	m.db.Model(&models.CFAccount{}).Where("id = ?", accountID).Updates(map[string]interface{}{
		"error_msg": errMsg,
	})

	// 发送 Telegram 通知
	if m.telegramClient != nil && m.telegramClient.IsConfigured() {
		msg := fmt.Sprintf("⚠️ <b>CF 账号异常</b>\n\n账号 ID: %d\n错误信息: %s\n时间: %s",
			accountID, errMsg, time.Now().Format("2006-01-02 15:04:05"))
		go m.telegramClient.SendMessage(msg)
	}

	// 检查是否是封禁相关的错误（9106=无效token/权限，10000=认证失败）
	// 注意：10001 是"资源不存在"（如 ruleset not found），不是账号封禁，不能封账号
	blockedErrors := []int{9106, 10000}
	for _, code := range blockedErrors {
		if strings.Contains(errMsg, fmt.Sprintf("[%d]", code)) {
			log.Printf("[CF Manager] 账号 %d 被标记为封禁", accountID)
			m.db.Model(&models.CFAccount{}).Where("id = ?", accountID).Update("is_blocked", true)
			// 停用本地规则并更新内存客户端列表（耗时短，锁内完成）
			m.deactivateAccountRulesLocal(accountID)
			m.loadAccounts()
			cb := m.onAccountBlocked
			m.mu.Unlock()
			// 封号回调（自动迁移规则）放到锁外执行，避免网络操作持锁
			if cb != nil {
				go cb(accountID)
			}
			// 停用 CF 侧规则是网络操作，放到锁外执行
			m.deactivateAccountRulesRemote(accountID)
			return
		}
	}

	// 如果不是封禁错误，切换到下一个账号
	m.switchToNext()
	m.mu.Unlock()
}

// deactivateAccountRulesLocal 停用指定账号名下的本地转发规则（仅 DB 更新，锁内调用）
func (m *Manager) deactivateAccountRulesLocal(accountID uint) {
	res := m.db.Model(&models.ForwardRule{}).
		Where("account_id = ? AND enabled = ?", accountID, true).
		Update("enabled", false)
	if res.RowsAffected > 0 {
		log.Printf("[CF Manager] 账号 %d 封禁，已停用 %d 条本地转发规则", accountID, res.RowsAffected)
	}
}

// deactivateAccountRulesRemote 尽力停用该账号名下 CF 侧 Origin Rule（网络操作，锁外调用）
func (m *Manager) deactivateAccountRulesRemote(accountID uint) {
	var rules []models.ForwardRule
	if err := m.db.Where("account_id = ? AND cf_ruleset_id != ?", accountID, "").Find(&rules).Error; err != nil {
		log.Printf("[CF Manager] 查询账号 %d 的转发规则失败: %v", accountID, err)
		return
	}
	if len(rules) == 0 {
		return
	}

	client := m.clientByAccountID(accountID)
	if client == nil {
		return
	}
	for i := range rules {
		if err := client.DisableOriginRule(rules[i].ZoneID, rules[i].CFRuleSetID); err != nil {
			log.Printf("[CF Manager] 停用 CF 规则 %d 失败: %v", rules[i].ID, err)
		}
	}
	log.Printf("[CF Manager] 账号 %d 封禁，已尽力停用 %d 条 CF 侧规则", accountID, len(rules))
}

// clientByAccountID 返回指定账号的客户端（用于封禁后对其名下的 Zone 执行清理操作）
// 自身加锁，线程安全。
func (m *Manager) clientByAccountID(accountID uint) *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.clients {
		if c.accountID == accountID {
			return c
		}
	}
	// 不在活跃列表（可能因封禁已剔除），从数据库取凭证临时构造客户端
	var acc models.CFAccount
	if err := m.db.Where("id = ?", accountID).First(&acc).Error; err != nil {
		return nil
	}
	return NewClient(acc.APIKey, acc.Email)
}

// GetClientByAccountID 返回指定账号的客户端。
// 用于对特定账号名下的 Zone/规则执行操作，避免误用轮询到的其他账号凭证。
// 账号不在活跃列表（如被封禁/禁用）时，从数据库取凭证临时构造（无错误上报，避免递归）。
func (m *Manager) GetClientByAccountID(accountID uint) (*Client, error) {
	if accountID == 0 {
		return nil, fmt.Errorf("账号未指定")
	}
	c := m.clientByAccountID(accountID)
	if c == nil {
		return nil, fmt.Errorf("账号 %d 不存在", accountID)
	}
	m.mu.Lock()
	m.markUsed(c)
	m.mu.Unlock()
	return c, nil
}

// SetOnAccountBlocked 设置账号被封禁时的回调（自动迁移规则等）
func (m *Manager) SetOnAccountBlocked(cb func(accountID uint)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onAccountBlocked = cb
}

// switchToNext 切换到下一个账号
func (m *Manager) switchToNext() {
	if len(m.clients) == 0 {
		return
	}

	oldIndex := m.currentIndex
	m.currentIndex = (m.currentIndex + 1) % len(m.clients)

	if oldIndex != m.currentIndex && len(m.clients) > 1 {
		log.Printf("[CF Manager] 切换账号: %d -> %d (%s)",
			oldIndex, m.currentIndex, m.clients[m.currentIndex].accountName)
	}
}

// GetNextClient 获取下一个可用的客户端（用于重试）
func (m *Manager) GetNextClient() (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.clients) == 0 {
		return nil, fmt.Errorf("没有可用的 Cloudflare 账号")
	}

	m.switchToNext()
	return m.clients[m.currentIndex], nil
}

// GetClientCount 获取可用账号数量
func (m *Manager) GetClientCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

// ListAllZoneNames 遍历所有账号，收集全部已接入的域名（zone 名称）
// 用于检查某个域名是否已存在于任一 CF 账号中
func (m *Manager) ListAllZoneNames() []string {
	m.mu.RLock()
	clients := make([]*Client, len(m.clients))
	copy(clients, m.clients)
	m.mu.RUnlock()

	names := make([]string, 0)
	seen := make(map[string]bool)

	// 优先使用本地 Zone 表（快速、免请求）
	var localZones []models.Zone
	m.db.Find(&localZones)
	for _, z := range localZones {
		if !seen[z.Name] {
			seen[z.Name] = true
			names = append(names, z.Name)
		}
	}

	// 再从 CF API 拉取补充（含手动接入的域名）
	for _, c := range clients {
		zones, err := c.ListAllZones()
		if err != nil {
			// 单个账号失败不影响其他账号（跨账号去重场景）
			log.Printf("[CF Manager] 账号 %d 拉取 Zone 失败: %v", c.accountID, err)
			continue
		}
		for _, z := range zones {
			if !seen[z.Name] {
				seen[z.Name] = true
				names = append(names, z.Name)
			}
		}
	}
	return names
}

// SyncLocalZones 从所有 CF 账号拉取全部 Zone，写入本地 zones 表
// 用于启动时同步，让转发规则能使用已接入的域名
func (m *Manager) SyncLocalZones() {
	m.mu.RLock()
	clients := make([]*Client, len(m.clients))
	copy(clients, m.clients)
	m.mu.RUnlock()

	for _, c := range clients {
		zones, err := c.ListAllZones()
		if err != nil {
			log.Printf("[CF Manager] 账号 %d 同步 Zone 失败: %v", c.accountID, err)
			continue
		}
		for _, z := range zones {
			localZone := models.Zone{
				CFID:        z.ID,
				AccountID:   c.accountID,
				Name:        z.Name,
				Status:      z.Status,
				NameServers: strings.Join(z.NameServers, ","),
				Plan:        z.Plan.Name,
			}
			if err := m.db.Where("cf_id = ?", z.ID).FirstOrCreate(&localZone).Error; err != nil {
				log.Printf("[CF Manager] 写入本地 Zone 失败: %v", err)
				continue
			}
			// 回填账号归属（FirstOrCreate 命中原有行时不会更新该行的 account_id，
			// 因此无论首次创建还是已存在，都强制覆盖为当前账号）
			if err := m.db.Model(&models.Zone{}).Where("cf_id = ?", z.ID).Update("account_id", c.accountID).Error; err != nil {
				log.Printf("[CF Manager] 回填 Zone %s 账号归属失败: %v", z.Name, err)
			}
		}
	}
	log.Printf("[CF Manager] 本地 Zone 同步完成")
}

// GetStatus 获取所有账号状态
func (m *Manager) GetStatus() []map[string]interface{} {
	var accounts []models.CFAccount
	m.db.Find(&accounts)

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]map[string]interface{}, 0)
	for _, acc := range accounts {
		status := "available"
		if acc.IsBlocked {
			status = "blocked"
		}
		if !acc.IsActive {
			status = "disabled"
		}

		// 检查是否是当前使用的账号
		isCurrent := false
		for i, c := range m.clients {
			if c.accountID == acc.ID && i == m.currentIndex {
				isCurrent = true
				break
			}
		}

		result = append(result, map[string]interface{}{
			"id":         acc.ID,
			"name":       acc.Name,
			"status":     status,
			"is_current": isCurrent,
			"error_msg":  acc.ErrorMsg,
			"last_used":  acc.LastUsed,
		})
	}

	return result
}

// SetAccountInfo 设置账号信息
func (c *Client) SetAccountInfo(id uint, name string) {
	c.accountID = id
	c.accountName = name
}

// GetAccountID 获取账号 ID
func (c *Client) GetAccountID() uint {
	return c.accountID
}

// GetAccountName 获取账号名称
func (c *Client) GetAccountName() string {
	return c.accountName
}
