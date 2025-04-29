package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Core"
)

type FscanMCPTool struct {
	scanMutex     sync.Mutex
	isScanning    int32
	scanStartTime time.Time
}

func NewFscanMCPTool() *FscanMCPTool {
	return &FscanMCPTool{}
}

func (s *FscanMCPTool) StartScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, ok := request.Params.Arguments["target"].(string)
	if !ok {
		return nil, errors.New("name must be a string")
	}
	//构造扫描字符串
	arg := fmt.Sprintf("-h %s", target)

	if !atomic.CompareAndSwapInt32(&s.isScanning, 0, 1) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: "已有扫描任务正在运行，请稍后重试",
				},
			},
		}, nil
	}

	s.scanStartTime = time.Now() // 记录任务开始时间

	go func() {
		defer atomic.StoreInt32(&s.isScanning, 0)

		s.scanMutex.Lock()
		defer s.scanMutex.Unlock()

		Common.LogDebug("异步执行扫描请求，目标: " + arg)

		var info Common.HostInfo
		if err := Common.FlagFromRemote(&info, arg); err != nil {
			return
		}
		if err := Common.Parse(&info); err != nil {
			return
		}
		if err := Common.CloseOutput(); err != nil {
			Common.LogError(fmt.Sprintf("关闭输出系统失败: %v", err))
			return
		}
		if err := Common.InitOutput(); err != nil {
			Common.LogError(fmt.Sprintf("初始化输出系统失败: %v", err))
			return
		}

		Core.Scan(info)

		Common.LogDebug("扫描任务完成")
	}()
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("扫描任务开始，扫描参数: %s", arg),
			},
		},
	}, nil
}

func (s *FscanMCPTool) GetScanResults(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: Common.OutputFormat + Common.Outputfile,
			},
		},
	}, nil
}
