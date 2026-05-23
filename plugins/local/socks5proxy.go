//go:build (plugin_socks5proxy || !plugin_selective) && !no_local

package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// Socks5ProxyPlugin SOCKS5代理插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现SOCKS5代理功能
// - 保持原有功能逻辑
type Socks5ProxyPlugin struct {
	plugins.BasePlugin
	listener net.Listener
}

// NewSocks5ProxyPlugin 创建SOCKS5代理插件
func NewSocks5ProxyPlugin() *Socks5ProxyPlugin {
	return &Socks5ProxyPlugin{
		BasePlugin: plugins.NewBasePlugin("socks5proxy"),
	}
}

// Scan 执行SOCKS5代理扫描 - 直接实现
func (p *Socks5ProxyPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	var output strings.Builder

	// 从config获取配置
	port := config.Socks5ProxyPort
	if port <= 0 {
		port = 1080 // 默认端口
	}

	output.WriteString(i18n.GetText("socks5_header") + "\n")
	output.WriteString(i18n.Tr("local_listen_port", port) + "\n")
	output.WriteString(i18n.Tr("local_platform", runtime.GOOS) + "\n\n")

	common.LogInfo(i18n.Tr("socks5_starting", port))

	// 启动SOCKS5代理服务器
	err := p.startSocks5Server(ctx, port, state)
	if err != nil {
		output.WriteString(i18n.Tr("socks5_server_error", err) + "\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(i18n.GetText("socks5_done") + "\n")
	common.LogSuccess(i18n.Tr("socks5_complete", port))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// startSocks5Server 启动SOCKS5代理服务器 - 核心实现
func (p *Socks5ProxyPlugin) startSocks5Server(ctx context.Context, port int, state *common.State) error {
	// 监听指定端口
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.GetText("listen_port_failed"), err)
	}
	defer func() { _ = listener.Close() }()

	p.listener = listener
	common.LogSuccess(i18n.Tr("socks5_started", port))

	// 设置SOCKS5代理为活跃状态，告诉主程序保持运行
	state.SetSocks5ProxyActive(true)
	defer func() {
		// 确保退出时清除活跃状态
		state.SetSocks5ProxyActive(false)
	}()

	// 主循环处理连接
	for {
		select {
		case <-ctx.Done():
			common.LogInfo(i18n.GetText("socks5_cancelled"))
			return ctx.Err()
		default:
		}

		// 设置监听器超时，以便能响应上下文取消
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			// 检查是否是超时错误
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue // 超时继续循环
			}
			common.LogError(i18n.Tr("socks5_accept_failed", err))
			continue
		}

		// 并发处理客户端连接
		go p.handleClient(ctx, conn)
	}
}

// handleClient 处理客户端连接
func (p *Socks5ProxyPlugin) handleClient(ctx context.Context, clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()

	// ctx 取消时关闭连接，解除阻塞的 IO
	go func() {
		<-ctx.Done()
		_ = clientConn.Close()
	}()

	// SOCKS5握手阶段
	if err := p.handleSocks5Handshake(clientConn); err != nil {
		if ctx.Err() == nil {
			common.LogError(i18n.Tr("socks5_handshake_failed", err))
		}
		return
	}

	// SOCKS5请求阶段
	targetConn, _, err := p.handleSocks5Request(clientConn)
	if err != nil {
		if ctx.Err() == nil {
			common.LogError(i18n.Tr("socks5_request_failed", err))
		}
		return
	}
	defer func() { _ = targetConn.Close() }()

	common.LogSuccess(i18n.GetText("socks5_connected"))

	// 双向数据转发
	p.relayData(clientConn, targetConn)
}

// handleSocks5Handshake 处理SOCKS5握手
func (p *Socks5ProxyPlugin) handleSocks5Handshake(conn net.Conn) error {
	// 读取客户端握手请求
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.GetText("socks5_handshake_read_failed"), err)
	}

	if n < 3 || buffer[0] != 0x05 { // SOCKS版本必须是5
		return fmt.Errorf("%s", i18n.GetText("socks5_unsupported_version"))
	}

	// 发送握手响应（无认证）
	response := []byte{0x05, 0x00} // 版本5，无认证
	_, err = conn.Write(response)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.GetText("socks5_handshake_write_failed"), err)
	}

	return nil
}

// handleSocks5Request 处理SOCKS5连接请求
func (p *Socks5ProxyPlugin) handleSocks5Request(clientConn net.Conn) (net.Conn, int, error) {
	// 读取连接请求
	buffer := make([]byte, 256)
	n, err := clientConn.Read(buffer)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.GetText("socks5_request_read_failed"), err)
	}

	if n < 7 || buffer[0] != 0x05 {
		return nil, 0, fmt.Errorf("%s", i18n.GetText("socks5_invalid_request"))
	}

	cmd := buffer[1]
	if cmd != 0x01 { // 只支持CONNECT命令
		// 发送不支持的命令响应
		response := []byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		_, _ = clientConn.Write(response)
		return nil, 0, fmt.Errorf(i18n.GetText("socks5_unsupported_command")+": %d", cmd)
	}

	// 解析目标地址
	addrType := buffer[3]
	var targetHost string
	var targetPort int

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return nil, 0, fmt.Errorf("%s", i18n.GetText("ipv4_address_invalid"))
		}
		targetHost = fmt.Sprintf("%d.%d.%d.%d", buffer[4], buffer[5], buffer[6], buffer[7])
		targetPort = int(buffer[8])<<8 + int(buffer[9])
	case 0x03: // 域名
		if n < 5 {
			return nil, 0, fmt.Errorf("%s", i18n.GetText("domain_format_invalid"))
		}
		domainLen := int(buffer[4])
		if n < 5+domainLen+2 {
			return nil, 0, fmt.Errorf("%s", i18n.GetText("domain_length_invalid"))
		}
		targetHost = string(buffer[5 : 5+domainLen])
		targetPort = int(buffer[5+domainLen])<<8 + int(buffer[5+domainLen+1])
	case 0x04: // IPv6
		if n < 22 {
			return nil, 0, fmt.Errorf("%s", i18n.GetText("ipv6_address_invalid"))
		}
		// IPv6地址解析（简化实现）
		targetHost = net.IP(buffer[4:20]).String()
		targetPort = int(buffer[20])<<8 + int(buffer[21])
	default:
		// 发送不支持的地址类型响应
		response := []byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		_, _ = clientConn.Write(response)
		return nil, 0, fmt.Errorf(i18n.GetText("socks5_unsupported_address_type")+": %d", addrType)
	}

	// 连接目标服务器
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		// 发送连接失败响应
		response := []byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		_, _ = clientConn.Write(response)
		return nil, 0, fmt.Errorf("%s: %w", i18n.GetText("socks5_target_connect_failed"), err)
	}

	// 获取本地监听端口（从targetConn获取）
	localAddr, ok := targetConn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("%s", i18n.GetText("local_address_unavailable"))
	}
	localPort := localAddr.Port

	// 发送成功响应
	response := make([]byte, 10)
	response[0] = 0x05 // SOCKS版本
	response[1] = 0x00 // 成功
	response[2] = 0x00 // 保留
	response[3] = 0x01 // IPv4地址类型
	// 绑定地址和端口（使用127.0.0.1:localPort）
	copy(response[4:8], []byte{127, 0, 0, 1})
	response[8] = byte(localPort >> 8)
	response[9] = byte(localPort & 0xff)

	_, err = clientConn.Write(response)
	if err != nil {
		_ = targetConn.Close()
		return nil, 0, fmt.Errorf("%s: %w", i18n.GetText("socks5_success_response_failed"), err)
	}

	common.LogDebug(i18n.Tr("socks5_proxy_connection_established", targetAddr))
	return targetConn, localPort, nil
}

// relayData 双向数据转发
func (p *Socks5ProxyPlugin) relayData(clientConn, targetConn net.Conn) {
	done := make(chan struct{}, 2)

	// 客户端到目标服务器
	go func() {
		defer func() { done <- struct{}{} }()
		_, _ = io.Copy(targetConn, clientConn)
		_ = targetConn.Close()
	}()

	// 目标服务器到客户端
	go func() {
		defer func() { done <- struct{}{} }()
		_, _ = io.Copy(clientConn, targetConn)
		_ = clientConn.Close()
	}()

	// 等待其中一个方向完成
	<-done
}

// 注册插件
func init() {
	RegisterLocalPlugin("socks5proxy", func() Plugin {
		return NewSocks5ProxyPlugin()
	})
}
