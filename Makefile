.PHONY: build build-backend build-frontend run dev-backend dev-frontend \
	build-go run-go dev-go install-frontend install-backend clean

# ============================ Rust 后端（默认） ============================

# 完整构建：前端 → 内嵌资源 → Rust 后端
build: build-frontend
	rm -rf backend-rs/frontend/dist
	mkdir -p backend-rs/frontend/dist
	cp -r frontend/dist/. backend-rs/frontend/dist/
	cd backend-rs && cargo build --release
	mkdir -p bin
	cp backend-rs/target/release/server bin/server-rs

# 仅构建后端（前端产物需已位于 backend-rs/frontend/dist）
build-backend:
	cd backend-rs && cargo build --release
	mkdir -p bin
	cp backend-rs/target/release/server bin/server-rs

run: build
	./bin/server-rs

# 开发模式 - Rust 后端（默认 8080 端口）
dev-backend:
	cd backend-rs && cargo run

# ============================ 前端 ============================

build-frontend:
	cd frontend && bun run build

# 开发模式 - 前端（3000 端口，自动代理 /api 到 8080）
dev-frontend:
	cd frontend && bun run dev

install-frontend:
	cd frontend && bun install

# ============================ Go 后端（旧版，保留对照） ============================

build-go:
	cd backend && go build -o ../bin/server-go ./cmd/server

run-go: build-go
	./bin/server-go

dev-go:
	cd backend && go run ./cmd/server

install-backend:
	cd backend-rs && cargo fetch
	cd backend && go mod tidy

# ============================ 清理 ============================

clean:
	rm -rf bin/
	rm -rf frontend/dist/
	rm -rf backend-rs/target/
	rm -rf data/
