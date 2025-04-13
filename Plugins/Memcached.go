package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// MemcachedScanResult 表示Memcached扫描结果
type MemcachedScanResult struct {
	Success bool
	Error   error
	Stats   string
}

// MemcachedScan 检测Memcached未授权访问
func MemcachedScan(info *Common.HostInfo) error {
	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 Memcached %s", realhost))

	// 尝试连接并检查未授权访问
	result := tryMemcachedConnection(ctx, info, Common.Timeout)

	if result.Success {
		// 保存成功结果
		scanResult := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":        info.Ports,
				"service":     "memcached",
				"type":        "unauthorized-access",
				"description": "Memcached unauthorized access",
				"stats":       result.Stats,
			},
		}
		Common.SaveResult(scanResult)
		Common.LogSuccess(fmt.Sprintf("Memcached %s 未授权访问", realhost))
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			Common.LogDebug("Memcached扫描全局超时")
			return fmt.Errorf("全局超时")
		}
	default:
	}

	Common.LogDebug(fmt.Sprintf("Memcached扫描完成: %s", realhost))
	return result.Error
}

// tryMemcachedConnection 尝试连接Memcached并检查未授权访问
func tryMemcachedConnection(ctx context.Context, info *Common.HostInfo, timeoutSeconds int64) *MemcachedScanResult {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	timeout := time.Duration(timeoutSeconds) * time.Second

	// 创建结果通道
	resultChan := make(chan *MemcachedScanResult, 1)

	// 创建连接上下文，带超时
	connCtx, connCancel := context.WithTimeout(ctx, timeout)
	defer connCancel()

	// 在协程中尝试连接
	go func() {
		// 构建结果结构
		result := &MemcachedScanResult{
			Success: false,
			Error:   nil,
			Stats:   "",
		}

		// 建立TCP连接
		client, err := Common.WrapperTcpWithTimeout("tcp", realhost, timeout)
		if err != nil {
			result.Error = err
			select {
			case <-connCtx.Done():
			case resultChan <- result:
			}
			return
		}
		defer client.Close()

		// 设置操作截止时间
		if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
			result.Error = err
			select {
			case <-connCtx.Done():
			case resultChan <- result:
			}
			return
		}

		// 发送stats命令
		if _, err := client.Write([]byte("stats\n")); err != nil {
			result.Error = err
			select {
			case <-connCtx.Done():
			case resultChan <- result:
			}
			return
		}

		// 读取响应
		rev := make([]byte, 1024)
		n, err := client.Read(rev)
		if err != nil {
			result.Error = err
			select {
			case <-connCtx.Done():
			case resultChan <- result:
			}
			return
		}

		// 检查响应是否包含统计信息
		response := string(rev[:n])
		if strings.Contains(response, "STAT") {
			result.Success = true
			result.Stats = response
		}

		// 发送结果
		select {
		case <-connCtx.Done():
		case resultChan <- result:
		}
	}()

	// 等待结果或上下文取消
	select {
	case result := <-resultChan:
		return result
	case <-connCtx.Done():
		if ctx.Err() != nil {
			// 全局上下文取消
			return &MemcachedScanResult{
				Success: false,
				Error:   ctx.Err(),
			}
		}
		// 连接超时
		return &MemcachedScanResult{
			Success: false,
			Error:   fmt.Errorf("连接超时"),
		}
	}
}
