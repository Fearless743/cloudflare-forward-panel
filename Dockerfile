# syntax=docker/dockerfile:1

# ---------- 阶段 1：构建前端 ----------
FROM oven/bun:1 AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

# ---------- 阶段 2：构建 Rust 后端 ----------
FROM rust:1-slim-bookworm AS backend-builder
WORKDIR /app/backend-rs
# 先只复制依赖清单，充分利用 Docker 层缓存
COPY backend-rs/Cargo.toml backend-rs/Cargo.lock ./
RUN cargo fetch
COPY backend-rs/ ./
# 把前端构建产物放到 embed 路径（rust-embed），再编译进单个二进制
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist
RUN cargo build --release --bin server

# ---------- 阶段 3：运行 ----------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 后端二进制（前端已内嵌）
COPY --from=backend-builder /app/backend-rs/target/release/server /app/server

# 数据持久化目录
RUN mkdir -p /app/data

EXPOSE 8080

# 默认数据路径与端口（可用环境变量覆盖：DB_PATH / SERVER_PORT）
ENV DB_PATH=/app/data/cloudflare.db \
    SERVER_PORT=8080

# 以 root 运行：避免 bind mount 的宿主机 data 目录属主与容器内非 root 用户不一致，
# 导致 SQLite 报 "attempt to write a readonly database"。
# 如需降权运行，请用命名卷（named volume）而非 bind mount，或自行 chown 宿主机 data 目录。
CMD ["/app/server"]
