# syntax=docker/dockerfile:1

# ---------- 阶段 1：构建前端 ----------
FROM oven/bun:1 AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

# ---------- 阶段 2：构建后端 ----------
FROM golang:1.26-alpine AS backend-builder
WORKDIR /app/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
# 把前端构建产物放到 embed 路径（cmd/server/frontend/dist），再编译进单个二进制
COPY --from=frontend-builder /app/frontend/dist ./cmd/server/frontend/dist
# 纯静态编译，避免运行期依赖 glibc
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/server ./cmd/server

# ---------- 阶段 3：运行 ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app

WORKDIR /app

# 后端二进制（前端已内嵌）
COPY --from=backend-builder /app/server /app/server

# 数据持久化目录
RUN mkdir -p /app/data && chown -R app:app /app

USER app
EXPOSE 8080

# 默认数据路径与端口（可用环境变量覆盖：DB_PATH / SERVER_PORT）
ENV DB_PATH=/app/data/cloudflare.db \
    SERVER_PORT=8080

CMD ["/app/server"]
