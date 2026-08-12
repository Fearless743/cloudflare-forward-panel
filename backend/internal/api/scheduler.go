package api

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"cloudflare-forward-panel/internal/cfclient"
	"cloudflare-forward-panel/internal/models"
	registrarPkg "cloudflare-forward-panel/internal/registrar"

	"gorm.io/gorm"
)

// ImportScheduler 域名导入队列调度器
// 定时扫描 pending 任务，自动选择 CF 账号处理（创建 Zone + 更新 NS）
// 没有可用账号时等待，有账号时自动处理
type ImportScheduler struct {
	db       *gorm.DB
	manager  *cfclient.Manager
	mu       sync.Mutex // 防止并发处理同一批任务
	interval time.Duration
}

func NewImportScheduler(db *gorm.DB, manager *cfclient.Manager) *ImportScheduler {
	return &ImportScheduler{
		db:       db,
		manager:  manager,
		interval: 5 * time.Second,
	}
}

// Start 启动后台轮询
func (s *ImportScheduler) Start() {
	// 启动时将上次遗留的 processing 任务重置为 pending
	// （进程异常退出时可能残留处理中的任务）
	s.db.Model(&models.RegistrarDomain{}).
		Where("status = ?", "processing").
		Update("status", "pending")

	go func() {
		for {
			s.Trigger()
			time.Sleep(s.interval)
		}
	}()
	log.Printf("[ImportScheduler] 已启动，轮询间隔 %v", s.interval)
}

// RetryFailed 将失败/跳过/部分成功的任务重置回 pending，重新处理。
// registrarID 为 0 时重试所有注册商，否则只重试指定注册商。
func (s *ImportScheduler) RetryFailed(registrarID uint) int {
	query := s.db.Model(&models.RegistrarDomain{}).
		Where("status IN ?", []string{"failed", "skipped", "partial"})
	if registrarID != 0 {
		query = query.Where("registrar_id = ?", registrarID)
	}
	result := query.Updates(map[string]interface{}{
		"status":      "pending",
		"error_msg":   "",
		"retry_count": 0,
	})
	s.Trigger()
	return int(result.RowsAffected)
}

// Trigger 立即触发一次处理（账号变更时可调用）
// 使用 TryLock 避免与正在进行的批次冲突
func (s *ImportScheduler) Trigger() {
	if s.mu.TryLock() {
		defer s.mu.Unlock()
		s.processPending()
	}
}

// processPending 处理队列中待导入的域名
func (s *ImportScheduler) processPending() {
	// 没有可用账号则等待
	if s.manager.GetClientCount() == 0 {
		return
	}

	// 取一批待处理任务
	var tasks []models.RegistrarDomain
	if err := s.db.Where("status = ?", "pending").Order("id ASC").Limit(10).Find(&tasks).Error; err != nil {
		log.Printf("[ImportScheduler] 查询任务失败: %v", err)
		return
	}
	if len(tasks) == 0 {
		return
	}

	// 批次开始时拉取一次所有 CF 账号下已存在的域名
	existingSet := make(map[string]bool)
	for _, name := range s.manager.ListAllZoneNames() {
		existingSet[strings.ToLower(name)] = true
	}

	for i := range tasks {
		task := &tasks[i]
		domain := strings.ToLower(strings.TrimSpace(task.Domain))
		if domain == "" {
			s.finishTask(task, "skipped", "空域名", 0)
			continue
		}

		// 标记处理中
		s.db.Model(task).Update("status", "processing")

		// 已存在则跳过
		if existingSet[domain] {
			s.finishTask(task, "skipped", "已在 CF 中", 0)
			continue
		}

		// 获取当前 CF 客户端（优先填满当前账号）
		client, err := s.manager.GetClient()
		if err != nil {
			// 没有可用账号，重置回 pending，等待下次
			log.Printf("[ImportScheduler] 无可用账号，暂停处理")
			s.db.Model(&models.RegistrarDomain{}).
				Where("status = ?", "processing").
				Update("status", "pending")
			return
		}

		// 创建 Zone
		zone, err := client.CreateZone(domain)
		if err != nil {
			// 当前账号失败（可能被封禁），切换到下一个账号重试
			// 封禁时 ReportError 会自动从账号列表移除该账号
			if nextClient, err2 := s.manager.GetNextClient(); err2 == nil && nextClient != client {
				zone, err = nextClient.CreateZone(domain)
				client = nextClient
			}
		}
		if err != nil {
			s.failTask(task, "创建 Zone 失败: "+err.Error())
			continue
		}

		// 更新注册商 NS 为 CF 分配的 NS
		regClient, err := s.getRegistrarClient(task.RegistrarID)
		if err != nil {
			s.finishTask(task, "partial", "Zone 已创建，但获取注册商失败: "+err.Error(), client.GetAccountID())
			continue
		}
		if len(zone.NameServers) >= 2 {
			if err := regClient.UpdateNameservers(domain, zone.NameServers[0], zone.NameServers[1]); err != nil {
				s.finishTask(task, "partial", "Zone 已创建，但 NS 更新失败: "+err.Error(), client.GetAccountID())
				continue
			}
		}

		// 成功：写入本地 Zone 表，供转发规则使用
		localZone := models.Zone{
			CFID:        zone.ID,
			AccountID:   client.GetAccountID(),
			Name:        zone.Name,
			Status:      zone.Status,
			NameServers: strings.Join(zone.NameServers, ","),
			Plan:        zone.Plan.Name,
		}
		if err := s.db.Where("cf_id = ?", zone.ID).FirstOrCreate(&localZone).Error; err != nil {
			log.Printf("[ImportScheduler] 写入本地 Zone 失败: %v", err)
		}

		s.finishTask(task, "success", "", client.GetAccountID())
		// 记录已存在，避免同批次内重复
		existingSet[domain] = true
	}
}

// getRegistrarClient 根据任务关联的注册商创建客户端
func (s *ImportScheduler) getRegistrarClient(registrarID uint) (registrarPkg.Registrar, error) {
	var registrar models.DomainRegistrar
	if err := s.db.First(&registrar, registrarID).Error; err != nil {
		return nil, err
	}
	if !registrar.IsActive {
		return nil, fmt.Errorf("注册商已禁用")
	}
	client := registrarPkg.GetClient(registrar.Type, registrar.APIKey, registrar.APISecret)
	if client == nil {
		return nil, fmt.Errorf("不支持的注册商类型: %s", registrar.Type)
	}
	return client, nil
}

// finishTask 完成任务（成功/跳过/部分成功）
func (s *ImportScheduler) finishTask(task *models.RegistrarDomain, status, errMsg string, accountID uint) {
	s.db.Model(task).Updates(map[string]interface{}{
		"status":     status,
		"error_msg":  errMsg,
		"account_id": accountID,
	})
}

// failTask 处理失败，超过重试上限则标记 failed
func (s *ImportScheduler) failTask(task *models.RegistrarDomain, errMsg string) {
	newCount := task.RetryCount + 1
	if newCount >= 3 {
		s.db.Model(task).Updates(map[string]interface{}{
			"status":      "failed",
			"error_msg":   errMsg,
			"retry_count": newCount,
		})
	} else {
		s.db.Model(task).Updates(map[string]interface{}{
			"status":      "pending",
			"error_msg":   errMsg,
			"retry_count": newCount,
		})
	}
}
