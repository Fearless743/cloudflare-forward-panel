# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Cloudflare 管理面板。核心能力：域名管理、DNS 记录、端口转发（Origin Rules）、SSL/TLS 配置。

**后端已用 Rust 重写，位于 `backend-rs/`，是当前唯一默认构建/部署的后端。**
`backend/` 下的 Go 实现仅作为对照保留（不再被 Makefile/Dockerfile 使用），除非明确要求，不要修改或删除它。

## 常用命令

```bash
# 后端（Rust，需在 backend-rs/ 目录下）
cd backend-rs
cargo run                     # 开发运行（默认 8080 端口）
cargo test                    # 单元测试
cargo build                   # 构建（前端需先放到 backend-rs/frontend/dist）
cargo clippy --all-targets    # 静态检查
python3 tests/e2e_mock.py     # 端到端测试（需先 cargo build，使用 mock CF API）

# 前端（Vite + React，需在 frontend/ 目录下）
cd frontend
bun install                   # 安装依赖（项目用 bun，存在 bun.lock）
bun run dev                   # 开发服务器（3000 端口，代理 /api 到 8080）
bun run build                 # 生产构建（= tsc -b && vite build）

# 根目录快捷命令
make build          # 前端 + 内嵌资源 + Rust release 构建 → bin/server
make run            # 构建并运行
make dev-backend    # cargo run
make dev-frontend   # bun run dev
make build-go       # 构建旧的 Go 后端 → bin/server-go
make clean
```

## 架构

### 目录结构与数据流

```
frontend (Vite/React18/AntD5, TS)  ——HTTP /api——>  backend-rs (Rust/axum)
                                                        ├── src/api/             路由与 handler
                                                        │   ├── mod.rs           路由注册、CORS、静态资源、AppState
                                                        │   ├── forward.rs       端口转发核心
                                                        │   ├── zones.rs         域名 / DNS / SSL
                                                        │   ├── accounts.rs      CF 账号
                                                        │   ├── users.rs         用户 / 订阅
                                                        │   ├── settings.rs      系统设置
                                                        │   ├── certs.rs         Origin 证书缓存
                                                        │   └── auth_handlers.rs 登录 / 改密
                                                        ├── src/cfclient/        CF API 客户端 + 多账号管理器
                                                        ├── src/telegram.rs      通知
                                                        ├── src/auth.rs          JWT / bcrypt
                                                        ├── src/db.rs            SQLite 连接 + 自动迁移
                                                        ├── src/models.rs        数据模型
                                                        └── src/config.rs        配置加载
                                                               ↓ SQLite (sqlx)
```

- **前端所有 API 调用集中在 `frontend/src/api/client.ts`**，一个函数对应一个后端端点；页面组件在 `src/pages/` 下。
- 后端 handler 按资源拆分在 `src/api/` 各模块；新增接口时在对应模块添加 handler，并在 `src/api/mod.rs` 的 `router()` 中注册路由。
- **响应格式**：成功 `{"success":true,"result":...}`；错误 `{"error":"..."}`（HTTP 状态码表达错误类型）。认证中间件错误也只含 `error` 字段。

### 关键机制

1. **多 CF 账号轮询（`cfclient/manager.rs`）**：`Manager` 持有多个 `Client`（对应 `cf_accounts` 表），`get_client()` 按 `current_index` 轮询。CF API 报错时 `Client` 通过 channel 上报 `Manager::handle_report`：发 Telegram 通知 → 检测封禁错误码（9106/10000）自动 `is_blocked` 并 reload → 否则切换到下一个账号。**注意 10001（资源不存在）不是封禁**。封禁时会回调 `api::forward::migrate_account_rules` 迁移规则。

2. **端口转发（`api/forward.rs`，业务核心）**：创建规则时后端自动完成一组 CF 操作——挑选本地 Zone 表中 CF 规则最少的域名 → 生成随机子域名 → 创建 Origin Rule（`http_request_origin` phase，route action 指定 origin port）→ 按目标地址类型创建 DNS 记录（IPv4→A / IPv6→AAAA / 域名→CNAME，均 proxied）→ 设置 SSL 为 Full。删除时反向清理。另有全量对账（`reconcile_zone_forward_rules`）修复 CF 侧丢失的 ruleset/rule/DNS，并保留面板外手工创建的主机名。后台定时检查任务（`spawn_forward_check_scheduler`）按系统设置中的间隔对比面板与 CF 的 DNS / Origin Rules，可自动修复并通过 Telegram 通知；管理员也可在设置页手动触发检查。

3. **认证**：JWT（HS256，`Authorization: Bearer <token>`）。**secret 每次启动随机生成**，重启后旧 token 全部失效。角色 `admin`/`user`，通过 `AuthUser` / `AdminUser` axum extractor 区分；每次请求都会从数据库读取实时角色与启用状态，并覆盖 token 快照。默认管理员 `admin / admin123`（首次启动自动创建，`must_change_password=true`，此时仅允许调用改密接口）。

4. **配置来源**：`config.rs` 只读 `DB_PATH`、`SERVER_PORT`。**CF 凭证和 Telegram 配置不读 `.env`**——CF 账号存在 `cf_accounts` 表（`auth_type=token` 时用 `Authorization: Bearer` 的 Account API Token；`auth_type=global_key` 时用 `X-Auth-Key`/`X-Auth-Email`），Telegram 配置存在 `settings` 键值表。

5. **域名分配（`zone_users`）**：管理员在「域名管理」页把域名分配给一个或多个用户（管理员也可分配给自己）。`/api/forward-rules/zones` 与自动选域逻辑只返回当前用户被分配的域名；创建/编辑规则时校验目标域名权限。

6. **数据库兼容**：`db.rs` 的 `migrate()` 生成与 GORM AutoMigrate 等价的表结构，并补齐旧版本缺失的列（`must_change_password`、`cf_accounts.email/api_key/auth_type/account_id`、`zones.account_id`、`forward_rules.user_id/account_id/dns_record_id`）。时间列是 GORM 格式文本；JSON 输出时统一转 RFC3339。密码使用 bcrypt，与 Go 生成的 `$2a$` 哈希兼容。

### 数据模型（`src/models.rs`）

`users`（含订阅过期时间 `subscription`，NULL 表永久）、`settings`（KV 配置）、`cf_accounts`（多账号凭证）、`zones`（本地镜像 CF Zone）、`zone_users`（域名→用户多对多授权）、`forward_rules`（转发规则，关联 CF ruleset/dns ID）、`origin_certificates`（Origin 证书缓存）。注册商管理功能已从 Rust 后端、Go 旧后端与前端完全移除；旧数据库中可能遗留的 `domain_registrars` / `registrar_domains` 表不再被读写，也不会自动删除。

## 注意事项

- **CF API 认证**：默认使用 Account API Token（`Authorization: Bearer <token>`，`cf_accounts.auth_type=token`），同时兼容旧版 Global API Key（`X-Auth-Key` + `X-Auth-Email`）。错误码字符串形如 `[9106] message`，manager 依赖此格式解析封禁。
- **敏感字段**（API key、secret）在返回前会做掩码（保留首尾各 4 位）；更新时跳过含 `****` 的值。
- **`forward_rules.cf_rule_set_id` 是数据库列名，JSON 字段名是 `cf_ruleset_id`**，前端依赖后者。
- 静态资源通过 `rust-embed` 从 `backend-rs/frontend/dist` 内嵌；debug 构建会直接读磁盘，release 构建在编译期内嵌，因此构建顺序很重要。
- 旧的 Go 实现（`backend/`）与 README 中历史描述可能不一致，行为以 `backend-rs/` 为准。
