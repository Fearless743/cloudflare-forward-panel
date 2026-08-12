.PHONY: build run dev clean

# 构建后端
build:
	cd backend && go build -o ../bin/server ./cmd/server

# 运行后端
run: build
	./bin/server

# 开发模式 - 后端
dev-backend:
	cd backend && go run ./cmd/server

# 开发模式 - 前端
dev-frontend:
	cd frontend && npm run dev

# 安装前端依赖
install-frontend:
	cd frontend && npm install

# 安装后端依赖
install-backend:
	cd backend && go mod tidy

# 清理
clean:
	rm -rf bin/
	rm -rf frontend/dist/
	rm -rf data/

# 构建前端
build-frontend:
	cd frontend && npm run build
