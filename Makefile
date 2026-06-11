# fscan Makefile
# 提供统一的构建、测试、检查命令

.PHONY: help test test-cover build build-web build-ui build-debug build-race lint lint-fix clean ci deps install-tools stress-test

# 默认目标
.DEFAULT_GOAL := help

# 项目配置
BINARY_NAME := fscan
GO := go
GOLANGCI_LINT := golangci-lint

# 颜色输出
BLUE := \033[0;34m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m # No Color

## help: 显示帮助信息
help:
	@echo "$(BLUE)fscan 构建工具$(NC)"
	@echo ""
	@echo "$(GREEN)可用命令:$(NC)"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
	@echo ""

## deps: 下载依赖
deps:
	@echo "$(BLUE)下载依赖...$(NC)"
	$(GO) mod download
	$(GO) mod verify
	@echo "$(GREEN)✓ 依赖下载完成$(NC)"

## test: 运行测试
test:
	@echo "$(BLUE)运行测试...$(NC)"
	# 禁用go test内置的vet检查，因为i18n.GetTextF的间接格式化模式与vet的printf检查冲突
	# golangci-lint会运行完整的vet检查（已在.golangci.yml中禁用printf）
	$(GO) test -vet=off -race -v ./...
	@echo "$(GREEN)✓ 测试通过$(NC)"

## test-cover: 运行测试并生成覆盖率报告
test-cover:
	@echo "$(BLUE)运行测试（带覆盖率）...$(NC)"
	# 禁用go test内置的vet检查，原因同上
	$(GO) test -vet=off -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo ""
	@echo "$(BLUE)覆盖率报告:$(NC)"
	$(GO) tool cover -func=coverage.out | tail -1
	@echo ""
	@echo "$(GREEN)生成 HTML 报告: coverage.html$(NC)"
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ 覆盖率报告生成完成$(NC)"

## build: 构建生产版本（无 pprof，优化体积）
build:
	@echo "$(BLUE)构建生产版本（无 pprof）...$(NC)"
	$(GO) build -ldflags="-s -w" -trimpath -o $(BINARY_NAME) .
	@echo "$(GREEN)✓ 构建完成: $(BINARY_NAME)$(NC)"

## build-web: 构建带Web UI的版本（需要先构建前端）
build-web: build-ui
	@echo "$(BLUE)构建Web版本...$(NC)"
	$(GO) build -tags web -ldflags="-s -w" -trimpath -o $(BINARY_NAME)-web .
	@echo "$(GREEN)✓ 构建完成: $(BINARY_NAME)-web$(NC)"
	@echo "$(BLUE)提示: 运行 ./$(BINARY_NAME)-web 启动Web界面（默认端口 10240）$(NC)"

## build-ui: 构建前端（需要Node.js和npm）
build-ui:
	@echo "$(BLUE)构建前端...$(NC)"
	@if [ ! -d "web-ui" ]; then \
		echo "$(RED)错误: web-ui 目录不存在$(NC)"; \
		echo "请先创建前端项目"; \
		exit 1; \
	fi
	@cd web-ui && npm install && npm run build
	@rm -rf web/dist
	@cp -r web-ui/dist web/dist
	@echo "$(GREEN)✓ 前端构建完成$(NC)"

## build-debug: 构建调试版本（带 pprof）
build-debug:
	@echo "$(BLUE)构建调试版本（带 pprof）...$(NC)"
	$(GO) build -tags=debug -o $(BINARY_NAME)_debug .
	@echo "$(GREEN)✓ 构建完成: $(BINARY_NAME)_debug$(NC)"
	@echo "$(BLUE)提示: 运行后访问 http://localhost:6060/debug/pprof$(NC)"

## build-race: 构建 race 检测版本
build-race:
	@echo "$(BLUE)构建 race 检测版本...$(NC)"
	$(GO) build -race -tags=debug -o $(BINARY_NAME)_race .
	@echo "$(GREEN)✓ 构建完成: $(BINARY_NAME)_race$(NC)"
	@echo "$(BLUE)提示: 运行时会检测数据竞争，性能会降低$(NC)"

## build-all: 构建所有平台的二进制文件
build-all:
	@echo "$(BLUE)构建所有平台...$(NC)"
	@echo "Windows amd64..."
	GOOS=windows GOARCH=amd64 $(GO) build -o dist/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Linux amd64..."
	GOOS=linux GOARCH=amd64 $(GO) build -o dist/$(BINARY_NAME)-linux-amd64 .
	@echo "Darwin amd64..."
	GOOS=darwin GOARCH=amd64 $(GO) build -o dist/$(BINARY_NAME)-darwin-amd64 .
	@echo "$(GREEN)✓ 所有平台构建完成$(NC)"

## lint: 运行代码检查
lint:
	@echo "$(BLUE)运行代码检查...$(NC)"
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || \
		{ echo "$(RED)错误: golangci-lint 未安装$(NC)"; \
		  echo "运行 'make install-tools' 安装"; \
		  exit 1; }
	$(GOLANGCI_LINT) run ./...
	@echo "$(GREEN)✓ 代码检查通过$(NC)"

## lint-fix: 运行代码检查并自动修复
lint-fix:
	@echo "$(BLUE)运行代码检查（自动修复）...$(NC)"
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || \
		{ echo "$(RED)错误: golangci-lint 未安装$(NC)"; \
		  echo "运行 'make install-tools' 安装"; \
		  exit 1; }
	$(GOLANGCI_LINT) run --fix ./...
	@echo "$(GREEN)✓ 代码检查完成（已自动修复）$(NC)"

## clean: 清理构建产物
clean:
	@echo "$(BLUE)清理构建产物...$(NC)"
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f $(BINARY_NAME)_debug $(BINARY_NAME)_debug.exe
	rm -f $(BINARY_NAME)_race $(BINARY_NAME)_race.exe
	rm -f coverage.out coverage.html
	rm -rf dist/ tests/logs/
	@echo "$(GREEN)✓ 清理完成$(NC)"

## stress-test: 压力测试（需要先 build-debug）
stress-test:
	@echo "$(BLUE)压力测试...$(NC)"
	@if [ ! -f $(BINARY_NAME)_debug ] && [ ! -f $(BINARY_NAME)_debug.exe ]; then \
		echo "$(RED)错误: $(BINARY_NAME)_debug 不存在$(NC)"; \
		echo "请先运行 'make build-debug'"; \
		exit 1; \
	fi
	@if [ -f tests/stress_test.sh ]; then \
		bash tests/stress_test.sh; \
	else \
		echo "$(RED)错误: tests/stress_test.sh 不存在$(NC)"; \
		echo "请先创建压力测试脚本"; \
		exit 1; \
	fi

## ci: CI流程（lint + test + build）
ci: lint test build
	@echo "$(GREEN)✓ CI流程完成$(NC)"

## install-tools: 安装开发工具
install-tools:
	@echo "$(BLUE)安装开发工具...$(NC)"
	@echo "检查 golangci-lint..."
	@if command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		echo "$(GREEN)✓ golangci-lint 已安装$(NC)"; \
		$(GOLANGCI_LINT) version; \
	else \
		echo "$(BLUE)安装 golangci-lint...$(NC)"; \
		if command -v go >/dev/null 2>&1; then \
			echo "使用 go install 安装..."; \
			go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
			echo "$(GREEN)✓ golangci-lint 安装成功$(NC)" && \
			$(GOLANGCI_LINT) version || \
			{ echo "$(RED)✗ 安装失败，请手动安装:$(NC)"; \
			  echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
			  echo "或访问: https://golangci-lint.run/welcome/install/"; \
			  exit 1; }; \
		else \
			echo "$(RED)✗ Go 未安装，无法自动安装 golangci-lint$(NC)"; \
			exit 1; \
		fi; \
	fi

## fmt: 格式化代码
fmt:
	@echo "$(BLUE)格式化代码...$(NC)"
	$(GO) fmt ./...
	@echo "$(GREEN)✓ 代码格式化完成$(NC)"

## vet: 运行 go vet（跳过printf检查）
vet:
	@echo "$(BLUE)运行 go vet...$(NC)"
	$(GO) vet -printf=false ./...
	@echo "$(GREEN)✓ go vet 检查通过$(NC)"
