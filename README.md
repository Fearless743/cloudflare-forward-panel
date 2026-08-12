# Cloudflare 转发面板

基于 React + Go 的 Cloudflare 管理面板，支持域名管理、DNS 记录配置、端口转发（Origin Rules）和 SSL/TLS 设置。

## 功能特性

- **域名管理**：查看 Cloudflare 账户下的所有域名
- **DNS 记录**：支持 A、AAAA、CNAME、MX、TXT 等记录类型的增删改查
- **端口转发**：基于 Cloudflare Origin Rules 实现端口转发
- **SSL/TLS**：配置域名的加密模式（关闭、灵活、完全、完全-严格）

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端 | Go 1.22+, Chi Router, GORM, SQLite |
| 前端 | Vite + React 18 + TypeScript, Ant Design 5 |
| 认证 | Cloudflare Global API Key |

## 快速开始

### 1. 配置环境变量

复制 `.env.example` 为 `.env` 并填写配置：

```bash
cp .env.example .env
```

编辑 `.env`：

```env
CF_API_EMAIL=your@email.com
CF_API_KEY=your-global-api-key
DB_PATH=./data/cloudflare.db
SERVER_PORT=8080
```

### 2. 安装依赖

```bash
# 安装后端依赖
cd backend && go mod tidy

# 安装前端依赖
cd frontend && npm install
```

### 3. 启动服务

```bash
# 开发模式 - 启动后端（端口 8080）
cd backend && go run ./cmd/server

# 开发模式 - 启动前端（端口 3000，自动代理到后端）
cd frontend && npm run dev
```

访问 http://localhost:3000

### 4. 生产构建

```bash
# 构建前端
cd frontend && npm run build

# 构建后端
cd backend && go build -o ../bin/server ./cmd/server

# 运行
./bin/server
```

## 项目结构

```
cloudflare-forward-panel/
├── backend/                    # Go 后端
│   ├── cmd/server/main.go     # 入口
│   ├── internal/
│   │   ├── api/               # HTTP 路由和处理器
│   │   ├── cfclient/          # Cloudflare API 客户端
│   │   ├── config/            # 配置加载
│   │   └── models/            # 数据模型
│   └── go.mod
├── frontend/                   # React 前端
│   ├── src/
│   │   ├── api/               # API 客户端
│   │   ├── components/        # 组件
│   │   ├── pages/             # 页面
│   │   └── types/             # 类型定义
│   └── package.json
├── .env.example
├── .gitignore
└── Makefile
```

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/zones` | 获取域名列表 |
| GET | `/api/zones/:id` | 获取域名详情 |
| GET | `/api/zones/:id/dns` | 获取 DNS 记录 |
| POST | `/api/zones/:id/dns` | 创建 DNS 记录 |
| PUT | `/api/dns/:id` | 更新 DNS 记录 |
| DELETE | `/api/dns/:id` | 删除 DNS 记录 |
| GET | `/api/zones/:id/origin-rules` | 获取 Origin Rules |
| POST | `/api/zones/:id/origin-rules` | 创建 Origin Rule |
| PUT | `/api/zones/:id/origin-rules/:ruleId` | 更新 Origin Rule |
| DELETE | `/api/zones/:id/origin-rules/:ruleId` | 删除 Origin Rule |
| GET | `/api/zones/:id/ssl` | 获取 SSL 设置 |
| PATCH | `/api/zones/:id/ssl` | 更新 SSL 设置 |

## 端口转发使用说明

端口转发基于 Cloudflare Origin Rules 实现：

1. 在「端口转发」页面点击「添加规则」
2. 输入主机名（如 `example.com`）
3. 输入目标端口（如 `8080`）
4. 保存即可生效

**注意**：Origin Rules 在 Free 计划下最多支持 100 条规则。

## License

MIT
