# Cloudflare 转发面板

基于 React + Go 的 Cloudflare 管理面板，支持多账号管理、域名管理、DNS 记录、端口转发（Origin Rules）、SSL/TLS 配置，以及通过 Porkbun/Spaceship 注册商批量导入域名并接入 Cloudflare。

## 功能特性

- **多账号轮询**：支持多个 Cloudflare 账号（Global API Key），请求失败自动切换；账号封禁时自动迁移其名下转发规则到其他账号
- **域名管理**：查看 Cloudflare 账户下的所有域名、NS 服务器与套餐信息
- **DNS 记录**：A、AAAA、CNAME、MX、TXT 等记录类型的增删改查
- **端口转发**：基于 Cloudflare Origin Rules，自动生成随机子域名 + DNS 记录 + SSL 全量模式；同端口多目标复用同一条规则
- **SSL/TLS**：配置域名的加密模式（关闭、灵活、完全、完全-严格）
- **域名导入**：从 Porkbun / Spaceship 批量拉取域名，异步接入 Cloudflare 并更新注册商 NS
- **用户与订阅**：多用户、角色权限（admin/user）、订阅过期自动停用转发规则
- **Telegram 通知**：账号异常时推送告警

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端 | Go 1.26、Chi Router、GORM、SQLite |
| 前端 | Vite + React 18 + TypeScript、Ant Design 5 |
| 认证 | JWT（首次登录强制修改默认密码） |
| 部署 | 单二进制（前端静态资源内嵌）、Docker、GitHub Actions |

## 快速开始

### 环境变量

后端只读两个环境变量（见 `.env.example`）：

```env
# 数据库文件路径（默认 ./data/cloudflare.db）
DB_PATH=./data/cloudflare.db
# 服务监听端口（默认 8080）
SERVER_PORT=8080
```

> **注意**：Cloudflare 凭证（Global API Key + 邮箱）、Telegram Bot Token 均存在数据库里，通过面板的「账号管理」「系统设置」页面配置，不读 `.env`。

### 本地开发

```bash
# 后端（端口 8080）
cd backend && go run ./cmd/server

# 前端（端口 3000，自动代理 /api 到 8080）
cd frontend && bun install && bun run dev
```

访问 http://localhost:3000

> 首次启动会创建默认管理员 `admin / admin123`，登录后**强制要求修改密码**。

### 生产部署（Docker Compose）

```bash
docker compose up -d
```

默认使用 `ghcr.io/fearless743/cloudflare-forward-panel:latest` 镜像，SQLite 数据持久化在 `./data` 目录。访问 http://localhost:8080

### 本地构建单二进制

```bash
# 1. 构建前端（产物输出到 frontend/dist）
cd frontend && bun run build

# 2. 拷贝前端产物到 embed 路径
cd ../backend && mkdir -p cmd/server/frontend/dist && cp -r ../frontend/dist/* cmd/server/frontend/dist/

# 3. 构建后端（前端已内嵌）
go build -o ../bin/server ./cmd/server

# 4. 运行
./bin/server
```

## 项目结构

```
cloudflare-forward-panel/
├── backend/                    # Go 后端
│   ├── cmd/server/main.go      # 入口（内嵌前端静态资源）
│   ├── internal/
│   │   ├── api/                # HTTP 路由和处理器（router.go 集中全部 handler）
│   │   ├── cfclient/           # Cloudflare API 客户端 + 多账号管理器
│   │   ├── registrar/          # 注册商客户端（porkbun / spaceship）
│   │   ├── telegram/           # Telegram 通知
│   │   ├── auth/               # JWT 认证
│   │   ├── config/             # 配置加载
│   │   └── models/             # GORM 数据模型
│   └── go.mod
├── frontend/                   # React 前端
│   ├── src/
│   │   ├── api/client.ts       # API 客户端（集中全部请求）
│   │   ├── components/         # 组件
│   │   ├── pages/              # 页面
│   │   └── types/              # 类型定义
│   └── package.json
├── .github/workflows/          # GitHub Actions（自动构建推送 Docker 镜像）
├── Dockerfile                  # 多阶段构建
├── docker-compose.yml
├── .env.example
└── Makefile
```

## API 端点

所有 `/api` 路由需 `Authorization: Bearer <token>`；标注「管理员」的接口需要 admin 角色。

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| POST | `/api/auth/login` | 登录，返回 JWT | 公开 |
| GET | `/api/auth/me` | 当前用户信息 | 登录 |
| POST | `/api/auth/change-password` | 修改自己的密码 | 登录 |
| GET | `/api/forward-rules` | 转发规则列表（用户仅自己） | 登录 |
| POST | `/api/forward-rules` | 创建转发规则 | 登录 |
| PUT | `/api/forward-rules/{id}` | 编辑转发规则 | 登录（仅自己） |
| DELETE | `/api/forward-rules/{id}` | 删除转发规则 | 登录（仅自己） |
| POST | `/api/forward-rules/{id}/toggle` | 启用/禁用 | 登录（仅自己） |
| GET | `/api/settings` | 系统设置（掩码） | 管理员 |
| PUT | `/api/settings` | 更新设置 | 管理员 |
| POST | `/api/settings/test` | 测试 CF 连接 | 管理员 |
| POST | `/api/settings/test-telegram` | 测试 Telegram 通知 | 管理员 |
| GET | `/api/accounts` | 账号列表 | 管理员 |
| POST | `/api/accounts` | 添加账号 | 管理员 |
| PUT | `/api/accounts/{id}` | 更新账号 | 管理员 |
| DELETE | `/api/accounts/{id}` | 删除账号 | 管理员 |
| POST | `/api/accounts/{id}/toggle` | 启用/禁用账号 | 管理员 |
| POST | `/api/accounts/{id}/unblock` | 解除账号封禁 | 管理员 |
| GET | `/api/accounts/status` | 账号状态 | 管理员 |
| GET | `/api/zones` | 域名列表 | 管理员 |
| GET | `/api/zones/{id}` | 域名详情 | 管理员 |
| GET | `/api/zones/{id}/dns` | DNS 记录 | 管理员 |
| POST | `/api/zones/{id}/dns` | 创建 DNS 记录 | 管理员 |
| PUT | `/api/dns/{id}` | 更新 DNS 记录 | 管理员 |
| DELETE | `/api/dns/{id}` | 删除 DNS 记录 | 管理员 |
| GET | `/api/zones/{id}/ssl` | SSL 设置 | 管理员 |
| PATCH | `/api/zones/{id}/ssl` | 更新 SSL 设置 | 管理员 |
| POST | `/api/origin-certificates` | 生成 Origin 证书 | 管理员 |
| GET/POST/PUT/DELETE | `/api/users` | 用户管理 | 管理员 |
| GET/POST/PUT/DELETE | `/api/registrars` | 注册商管理 | 管理员 |

## 端口转发说明

端口转发基于 Cloudflare Origin Rules 实现：

1. 在「端口转发」页面点击「添加规则」
2. 输入目标地址（IPv4 → A 记录、IPv6 → AAAA 记录、域名 → CNAME 记录）
3. 输入目标端口
4. 保存后系统自动：挑选规则最少的域名 → 生成随机子域名 → 创建 Origin Rule → 创建 DNS 记录 → 设置 SSL 为 Full 模式

**同端口复用**：同一端口创建多个目标时，复用同一条 Origin Rule，表达式合并为 `http.host eq "a" or http.host eq "b"`。禁用某个目标只从表达式移除其主机名，不影响同端口其他目标。

**封号迁移**：CF 账号被封禁（错误码 9106/10000）时，其名下规则会停用并自动迁移到其他可用账号；后续新增可用账号时也会补齐迁移。

## License

MIT
