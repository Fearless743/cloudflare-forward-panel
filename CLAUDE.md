# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

基于 React + Go 的 Cloudflare 管理面板。核心能力：域名管理、DNS 记录、端口转发（Origin Rules）、SSL/TLS 配置，以及通过 Porkbun/Spaceship 注册商批量导入域名并接入 Cloudflare。

## 常用命令

```bash
# 后端（Go，需在 backend/ 目录下）
cd backend
go run ./cmd/server                 # 开发运行（默认 8080 端口）
go build -o ../bin/server ./cmd/server   # 构建
go mod tidy                         # 安装依赖

# 前端（Vite + React，需在 frontend/ 目录下）
cd frontend
bun install                         # 安装依赖（项目用 bun，存在 bun.lock；npm 亦可）
npm run dev                         # 开发服务器（3000 端口，代理 /api 到 8080）
npm run build                       # 生产构建（= tsc -b && vite build）
```

根目录 `Makefile` 提供 `make build` / `make run` / `make dev-backend` / `make dev-frontend` / `make clean` 快捷命令。

**没有自动化测试**：后端无 `_test.go` 文件，前端 `package.json` 无 test 脚本。验证改动需手动启动前后端联调。

## 架构

### 目录结构与数据流

```
frontend (Vite/React18/AntD5, TS)  ——HTTP /api——>  backend (Go/chi)
                                                       ├── internal/api/router.go   所有 HTTP handler
                                                       ├── internal/cfclient/       Cloudflare API 客户端
                                                       ├── internal/registrar/      注册商客户端 (porkbun/spaceship)
                                                       ├── internal/telegram/       通知
                                                       ├── internal/auth/           JWT 认证
                                                       ├── internal/config/         配置加载
                                                       └── internal/models/         GORM 模型
                                                              ↓ SQLite (GORM)
```

- **后端所有 HTTP handler 都写在 `internal/api/router.go` 一个文件里**（1800+ 行），不是按资源拆分的典型结构。新增接口在此文件追加，路由注册在 `Router()` 方法内。
- **前端所有 API 调用集中在 `frontend/src/api/client.ts`**，一个函数对应一个后端端点；页面组件在 `src/pages/` 下。

### 关键机制

1. **多 CF 账号轮询（`cfclient/manager.go`）**：`Manager` 持有多个 `Client`（对应 `CFAccount` 表），`GetClient()` 按 `currentIndex` 轮询返回当前账号。CF API 报错时 `ReportError` 会：发 Telegram 通知 → 检测封禁错误码（9106/10000）自动 `is_blocked` 并 reload → 否则切换到下一个账号。**注意 10001（资源不存在）不是封禁，需排除**。

2. **域名导入流水线（异步）**：注册商（Porkbun/Spaceship）下勾选域名 → 写入 `RegistrarDomain` 表（status=pending）→ `ImportScheduler`（`api/scheduler.go`，5 秒轮询）异步处理：对每个域名 `CreateZone` + 更新注册商 NS 为 CF 分配的 NS。失败重试 3 次后标记 failed。任务状态机：pending → processing → success/failed/skipped/partial。

3. **端口转发（`createForwardRule`，业务核心）**：创建 `ForwardRule` 时后端自动完成一组 CF 操作——挑选本地 Zone 表中规则最少的域名 → 生成随机子域名 → 创建 Origin Rule（`http_request_origin` phase，route action 指定 origin port）→ 按目标地址类型创建 DNS 记录（IPv4→A / IPv6→AAAA / 域名→CNAME，均 proxied）→ 设置 SSL 为 Full 模式。删除时反向清理（Origin Rule + DNS 记录）。

4. **认证**：JWT（HS256，`Authorization: Bearer <token>`）。**secret 硬编码**在 `auth/auth.go` 中（`cf-panel-secret-key-change-in-production`）。角色 `admin`/`user`，通过 `auth.Middleware` / `auth.AdminMiddleware` 区分。默认管理员 `admin / admin123`（首次启动自动创建）。

5. **配置来源**：`config.Load()` 只读两个环境变量 `DB_PATH`、`SERVER_PORT`（见 `.env.example`）。**CF 凭证和 Telegram 配置不读 `.env`**——CF 账号存在 `CFAccount` 表（Global API Key + email，通过 `X-Auth-Key`/`X-Auth-Email` 头认证），Telegram bot token 存在 `Setting` 键值表。

### 数据模型（`internal/models/models.go`）

`User`（含订阅过期时间 `subscription`，nil 表永久）、`Setting`（KV 配置）、`CFAccount`（多账号凭证）、`Zone`（本地镜像 CF Zone，供转发规则用）、`ForwardRule`（转发规则，关联 CF ruleset/dns ID）、`DomainRegistrar`（注册商配置）、`RegistrarDomain`（导入队列）。启动时 `AutoMigrate` 全部模型。

## 注意事项

- **README.md 已过时**：其技术栈（写的是 npm、`CF_API_EMAIL/CF_API_KEY` 环境变量）、API 端点表与实际代码不符。以代码为准——实际用 bun、CF 凭证存数据库、端点见 `router.go`。
- CF API 用 **Global API Key**（`X-Auth-Key` + `X-Auth-Email`），非 API Token。错误码字符串形如 `[9106] message`，manager 依赖此格式解析封禁。
- 敏感字段（API key、secret）在返回前会在 handler 中做掩码处理；更新时跳过含 `****` 的值。
