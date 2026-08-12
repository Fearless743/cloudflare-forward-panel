package models

import (
	"time"
)

// User 用户模型
type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Username     string     `gorm:"uniqueIndex" json:"username"`
	Password     string     `json:"-"`  // 不返回密码
	Role         string     `gorm:"default:user" json:"role"`  // admin 或 user
	IsActive     bool       `gorm:"default:true" json:"is_active"`
	Subscription *time.Time `json:"subscription"`  // 订阅过期时间，nil 表示永久
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Setting 存储配置项（键值对）
type Setting struct {
	Key       string `gorm:"primaryKey" json:"key"`
	Value     string `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CFAccount 存储多个 Cloudflare 账号凭证（Global API Key）
type CFAccount struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`                     // 账号名称（便于识别）
	Email     string    `json:"email"`                    // 登录邮箱
	APIKey    string    `json:"api_key"`                  // Global API Key
	AccountID string    `json:"account_id"`               // CF 账号 ID（创建 Zone 时指定）
	IsActive  bool      `json:"is_active" gorm:"default:true"`  // 是否启用
	IsBlocked bool      `json:"is_blocked" gorm:"default:false"` // 是否被封禁
	ErrorMsg  string    `json:"error_msg"`                // 最后错误信息
	LastUsed  *time.Time `json:"last_used"`               // 最后使用时间
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Zone struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CFID        string    `gorm:"uniqueIndex" json:"cf_id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	NameServers string    `json:"name_servers"`
	Plan        string    `json:"plan"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ForwardRule 全局端口转发规则
type ForwardRule struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	UserID      uint   `gorm:"index" json:"user_id"`        // 关联用户
	ZoneID      string `gorm:"index" json:"zone_id"`       // Cloudflare Zone ID
	ZoneName    string `json:"zone_name"`                    // 域名（便于显示）
	Hostname    string `json:"hostname"`                     // 主机名（子域名）
	OriginPort  int    `json:"origin_port"`                  // 转发到的源站端口
	OriginHost  string `json:"origin_host"`                  // 目标 IP（DNS A 记录的解析值）
	Enabled     bool   `json:"enabled" gorm:"default:true"`
	CFRuleSetID string `json:"cf_ruleset_id"`                // Cloudflare Ruleset ID
	CFRuleID    string `json:"cf_rule_id"`                   // Cloudflare Rule ID
	DNSRecordID string `json:"dns_record_id"`                // DNS A 记录 ID
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DomainRegistrar 域名注册商配置
type DomainRegistrar struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`                    // 注册商名称（便于识别）
	Type      string    `json:"type"`                    // porkbun 或 spaceship
	APIKey    string    `json:"api_key"`                 // API Key（Porkbun 和 Spaceship 都需要）
	APISecret string    `json:"api_secret"`              // API Secret（两个注册商都需要）
	IsActive  bool      `json:"is_active" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RegistrarDomain 注册商下添加的域名
// 只有手动勾选并加入的域名才会出现在这里，后台调度器据此接入 CF
type RegistrarDomain struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Domain      string    `gorm:"uniqueIndex" json:"domain"` // 域名（唯一）
	RegistrarID uint      `json:"registrar_id"`              // 来源注册商
	Status      string    `gorm:"default:pending" json:"status"` // pending/processing/success/failed/skipped/partial
	ErrorMsg    string    `json:"error_msg"`                 // 错误信息
	RetryCount  int       `gorm:"default:0" json:"retry_count"`  // 重试次数
	AccountID   uint      `json:"account_id"`                // 处理该域名的 CF 账号
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
