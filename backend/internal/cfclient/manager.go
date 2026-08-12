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
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.clients) == 0 {
		return nil, fmt.Errorf("没有可用的 Cloudflare 账号")
	}

	// 确保索引有效
	if m.currentIndex >= len(m.clients) {
		m.currentIndex = 0
	}

	return m.clients[m.currentIndex], nil
}

// ReportError 报告账号错误，可能触发切换
func (m *Manager) ReportError(accountID uint, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

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
		if contains(errMsg, fmt.Sprintf("[%d]", code)) {
			log.Printf("[CF Manager] 账号 %d 被标记为封禁", accountID)
			m.db.Model(&models.CFAccount{}).Where("id = ?", accountID).Update("is_blocked", true)
			m.ReloadAccounts()
			return
		}
	}

	// 如果不是封禁错误，切换到下一个账号
	m.switchToNext()
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
				Name:        z.Name,
				Status:      z.Status,
				NameServers: strings.Join(z.NameServers, ","),
				Plan:        z.Plan.Name,
			}
			if err := m.db.Where("cf_id = ?", z.ID).FirstOrCreate(&localZone).Error; err != nil {
				log.Printf("[CF Manager] 写入本地 Zone 失败: %v", err)
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// 扩展 Client 结构以包含账号信息
type accountInfo struct {
	accountID   uint
	accountName string
}

func init() {
	// 给 Client 添加账号信息字段
}

// 延迟初始化 accountInfo 字段
func (c *Client) SetAccountInfo(id uint, name string) {
	c.accountID = id
	c.accountName = name
}

func (c *Client) GetAccountID() uint {
	return c.accountID
}

func (c *Client) GetAccountName() string {
	return c.accountName
}
