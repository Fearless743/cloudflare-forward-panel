package main

import (
	"cloudflare-forward-panel/internal/api"
	"cloudflare-forward-panel/internal/auth"
	"cloudflare-forward-panel/internal/cfclient"
	"cloudflare-forward-panel/internal/config"
	"cloudflare-forward-panel/internal/models"
	"cloudflare-forward-panel/internal/telegram"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed all:frontend/dist
var embeddedFrontend embed.FS

// buildFrontend 占位：本地开发时用 `go run` 需要先把前端构建产物放到 cmd/server/frontend/dist 下。
// CI/Docker 构建时由 Dockerfile 先把 frontend/dist 拷贝到该路径，再执行 go build 完成内嵌。

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
	log.Printf("可用 CF 账号数量: %d", cfManager.GetClientCount())
	if telegramClient.IsConfigured() {
		log.Printf("Telegram 通知已配置")
	}

	// 挂载前端静态资源（SPA：找不到文件时回退到 index.html）
	router.Mount("/", spaHandler())

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// spaHandler 返回内嵌前端静态文件的处理器，支持 SPA 路由回退到 index.html
func spaHandler() http.Handler {
	distFS, err := fs.Sub(embeddedFrontend, "frontend/dist")
	if err != nil {
		log.Printf("[前端] 内嵌静态资源加载失败: %v（将以纯 API 模式运行）", err)
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(distFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Clean(r.URL.Path)
		// 已存在的文件直接返回
		if f, err := distFS.Open(strings.TrimPrefix(path, "/")); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// 非文件路径（SPA 路由）回退到 index.html
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
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
