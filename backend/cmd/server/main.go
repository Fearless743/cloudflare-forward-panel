package main

import (
	"cloudflare-forward-panel/internal/api"
	"cloudflare-forward-panel/internal/auth"
	"cloudflare-forward-panel/internal/cfclient"
	"cloudflare-forward-panel/internal/config"
	"cloudflare-forward-panel/internal/models"
	"cloudflare-forward-panel/internal/telegram"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	cfg := config.Load()

	// 确保数据目录存在
	dbDir := filepath.Dir(cfg.DBPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// 初始化数据库
	db, err := gorm.Open(sqlite.Open(cfg.DBPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect database: %v", err)
	}

	// 自动迁移
	if err := db.AutoMigrate(&models.User{}, &models.Setting{}, &models.CFAccount{}, &models.Zone{}, &models.ForwardRule{}, &models.DomainRegistrar{}, &models.RegistrarDomain{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// 旧表数据迁移：domain_import_tasks -> registrar_domains
	if db.Migrator().HasTable("domain_import_tasks") {
		if err := db.Exec("INSERT OR IGNORE INTO registrar_domains (id, domain, registrar_id, status, error_msg, retry_count, account_id, created_at, updated_at) SELECT id, domain, registrar_id, status, error_msg, retry_count, account_id, created_at, updated_at FROM domain_import_tasks").Error; err != nil {
			log.Printf("迁移 domain_import_tasks 数据失败: %v", err)
		} else {
			db.Migrator().DropTable("domain_import_tasks")
			log.Println("已迁移旧导入任务表数据")
		}
	}

	// 创建默认管理员账号（如果不存在）
	initAdminAccount(db)

	// 加载 Telegram 配置并初始化客户端
	telegramClient := initTelegramClient(db)

	// 创建多账号管理器
	cfManager := cfclient.NewManager(db, telegramClient)

	// 创建路由
	handler := api.NewHandler(db, cfManager, cfg)
	router := handler.Router()

	// 账号被封禁时，自动迁移其名下转发规则到其他账号
	cfManager.SetOnAccountBlocked(handler.MigrateAccountRules)

	// 启动导入调度器
	handler.StartImportScheduler()

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Server starting on %s", addr)
	log.Printf("Frontend: http://localhost:%s", cfg.ServerPort)
	log.Printf("可用 CF 账号数量: %d", cfManager.GetClientCount())
	if telegramClient.IsConfigured() {
		log.Printf("Telegram 通知已配置")
	}

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// initAdminAccount 初始化默认管理员账号
func initAdminAccount(db *gorm.DB) {
	var count int64
	db.Model(&models.User{}).Count(&count)

	if count == 0 {
		hash, err := auth.HashPassword("admin123")
		if err != nil {
			log.Fatalf("Failed to hash admin password: %v", err)
		}

		admin := models.User{
			Username:           "admin",
			Password:           hash,
			Role:               "admin",
			IsActive:           true,
			MustChangePassword: true, // 首次登录强制修改密码
		}

		if err := db.Create(&admin).Error; err != nil {
			log.Fatalf("Failed to create admin account: %v", err)
		}
		log.Println("Created default admin account, must change password on first login")
	}
}

// initTelegramClient 初始化 Telegram 客户端
func initTelegramClient(db *gorm.DB) *telegram.Client {
	var tokenSetting, chatIDSetting models.Setting
	db.Where("key = ?", "telegram_bot_token").First(&tokenSetting)
	db.Where("key = ?", "telegram_chat_id").First(&chatIDSetting)

	return telegram.NewClient(tokenSetting.Value, chatIDSetting.Value)
}
