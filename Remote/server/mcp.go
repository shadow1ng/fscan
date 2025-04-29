package server

import (
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Remote/service"
)

func StartMcpServer(transport string) {
	mcpServer := NewFscanMCPServer()

	if transport == "sse" {
		Common.LogSuccess("🚀 启动 MCP SSE 服务器，监听地址: http://localhost:8080")
		sseServer := server.NewSSEServer(mcpServer, server.WithBaseURL("http://localhost:8080"))
		if err := sseServer.Start(":8080"); err != nil {
			Common.LogError(fmt.Sprintf("❌ 启动 SSE 服务器失败: %v", err))
			panic(err)
		}
	} else {
		Common.LogSuccess("🚀 启动 MCP Stdio 服务器（标准输入输出模式）")
		if err := server.ServeStdio(mcpServer); err != nil {
			Common.LogError(fmt.Sprintf("❌ 启动 Stdio 服务器失败: %v", err))
			panic(err)
		}
	}
}

func NewFscanMCPServer() *server.MCPServer {
	s := server.NewMCPServer(
		"Fscan MCP",
		"1.0.0",
	)
	toolHandler := service.NewFscanMCPTool()

	// 添加工具处理器
	s.AddTool(
		mcp.NewTool("StartScan",
			mcp.WithDescription("开始扫描"),
			mcp.WithString("target",
				mcp.Required(),
				mcp.Description("扫描目标"),
			),
		),
		toolHandler.StartScan,
	)
	s.AddTool(
		mcp.NewTool("GetScanResults",
			mcp.WithDescription("获取扫描结果"),
		),
		toolHandler.GetScanResults,
	)
	return s

}
