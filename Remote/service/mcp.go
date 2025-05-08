package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	lastSentIndex int
}

func NewFscanMCPTool() *FscanMCPTool {
	return &FscanMCPTool{}
}

func (s *FscanMCPTool) StartScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, ok := request.Params.Arguments["target"].(string)
	if !ok {
		return nil, errors.New("target must be a string")
	}

	arg := fmt.Sprintf("-h %s", target)
	if !atomic.CompareAndSwapInt32(&s.isScanning, 0, 1) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("A scan is already in progress. Progress: %s%%", func() string {
						if Common.Num == 0 || Common.End == 0 {
							return "initializing"
						}
						return fmt.Sprintf("%.2f", (float64(Common.End)/float64(Common.Num))*100)
					}()),
				},
			},
		}, nil
	}

	s.scanStartTime = time.Now()
	s.lastSentIndex = 0

	go func() {
		defer atomic.StoreInt32(&s.isScanning, 0)

		s.scanMutex.Lock()
		defer s.scanMutex.Unlock()

		Common.LogDebug("Starting scan asynchronously: " + arg)

		var info Common.HostInfo
		if err := Common.FlagFromRemote(&info, arg); err != nil {
			return
		}
		if err := Common.Parse(&info); err != nil {
			return
		}
		if err := Common.CloseOutput(); err != nil {
			Common.LogError(fmt.Sprintf("Failed to close output: %v", err))
			return
		}
		if err := Common.InitOutput(); err != nil {
			Common.LogError(fmt.Sprintf("Failed to initialize output: %v", err))
			return
		}

		Core.Scan(info)
		Common.LogDebug("Scan completed.")
	}()

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("Scan started. Parameters: %s", arg),
			},
		},
	}, nil
}

func (s *FscanMCPTool) GetScanResults(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// immediate, _ := request.Params.Arguments["immediate"].(bool)
	// server := server.ServerFromContext(ctx)

	// if !immediate {
	// 	for {
	// 		select {
	// 		case <-ctx.Done():
	// 			return nil, ctx.Err()
	// 		default:
	// 			if atomic.LoadInt32(&s.isScanning) == 0 {
	// 				break
	// 			}
	// 			_ = server.SendNotificationToClient(
	// 				ctx,
	// 				"Fscan/progress",
	// 				map[string]interface{}{
	// 					"end":   Common.End,
	// 					"total": Common.Num,
	// 				},
	// 			)
	// 			time.Sleep(1000 * time.Millisecond)
	// 		}
	// 	}
	// }
	results, err := Common.GetResults()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to read results: %v", err))
		return nil, fmt.Errorf("failed to read results: %w", err)
	}

	var sb strings.Builder
	for _, r := range results {
		detailsJSON, err := json.Marshal(r.Details)
		if err != nil {
			Common.LogError(fmt.Sprintf("Failed to encode result details (Target: %s, Type: %s): %v", r.Target, r.Type, err))
			continue
		}

		sb.WriteString(fmt.Sprintf(
			"--- Result ---\nTime: %s\nType: %s\nTarget: %s\nStatus: %s\nDetails: %s\n\n",
			r.Time.Format(time.RFC3339),
			r.Type,
			r.Target,
			r.Status,
			string(detailsJSON),
		))
	}
	progress := fmt.Sprintf("Scan Progress: %.2f%%\n", func() float64 {
		if Common.Num == 0 || Common.End == 0 {
			return 0
		}
		if s.isScanning == 0 {
			return 100
		}
		return (float64(Common.End) / float64(Common.Num)) * 100
	}())
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: progress,
			},
			mcp.TextContent{
				Type: "text",
				Text: sb.String(),
			},
		},
	}, nil
}
