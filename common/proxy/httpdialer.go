package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// httpDialer HTTP代理拨号器
type httpDialer struct {
	config   *ProxyConfig
	stats    *ProxyStats
	baseDial *net.Dialer
}

func (h *httpDialer) Dial(network, address string) (net.Conn, error) {
	return h.DialContext(context.Background(), network, address)
}

func (h *httpDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	start := time.Now()
	atomic.AddInt64(&h.stats.TotalConnections, 1)

	// 连接到HTTP代理服务器
	proxyConn, err := h.baseDial.DialContext(ctx, NetworkTCP, h.config.Address)
	if err != nil {
		atomic.AddInt64(&h.stats.FailedConnections, 1)
		h.stats.mu.Lock()
		h.stats.LastError = err.Error()
		h.stats.mu.Unlock()
		return nil, NewProxyError(ErrTypeConnection, ErrMsgHTTPConnFailed, ErrCodeHTTPConnFailed, err)
	}

	// 发送CONNECT请求
	if err := h.sendConnectRequest(proxyConn, address); err != nil {
		_ = proxyConn.Close() // 错误处理路径，Close错误可忽略
		atomic.AddInt64(&h.stats.FailedConnections, 1)
		h.stats.mu.Lock()
		h.stats.LastError = err.Error()
		h.stats.mu.Unlock()
		return nil, err
	}

	duration := time.Since(start)
	h.stats.mu.Lock()
	h.stats.LastConnectTime = start
	h.stats.mu.Unlock()
	atomic.AddInt64(&h.stats.ActiveConnections, 1)
	h.updateAverageConnectTime(duration)

	return &trackedConn{
		Conn:  proxyConn,
		stats: h.stats,
	}, nil
}

// sendConnectRequest 发送HTTP CONNECT请求
func (h *httpDialer) sendConnectRequest(conn net.Conn, address string) error {
	// 构建CONNECT请求
	req := fmt.Sprintf(HTTPConnectRequestFormat, address, address)

	// 添加认证头
	if h.config.Username != "" {
		auth := base64.StdEncoding.EncodeToString(
			[]byte(h.config.Username + AuthSeparator + h.config.Password))
		req += fmt.Sprintf(HTTPAuthHeaderFormat, auth)
	}

	req += HTTPRequestEndFormat

	// 设置写超时
	if err := conn.SetWriteDeadline(time.Now().Add(h.config.Timeout)); err != nil {
		return NewProxyError(ErrTypeTimeout, ErrMsgHTTPSetWriteTimeout, ErrCodeHTTPSetWriteTimeout, err)
	}

	// 发送请求
	if _, err := conn.Write([]byte(req)); err != nil {
		return NewProxyError(ErrTypeConnection, ErrMsgHTTPSendConnectFail, ErrCodeHTTPSendConnectFail, err)
	}

	// 设置读超时
	if err := conn.SetReadDeadline(time.Now().Add(h.config.Timeout)); err != nil {
		return NewProxyError(ErrTypeTimeout, ErrMsgHTTPSetReadTimeout, ErrCodeHTTPSetReadTimeout, err)
	}

	// 读取响应
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return NewProxyError(ErrTypeProtocol, ErrMsgHTTPReadRespFailed, ErrCodeHTTPReadRespFailed, err)
	}

	// 检查响应状态
	if resp.StatusCode != HTTPStatusOK {
		// 只有在失败时才关闭响应体，避免影响成功的CONNECT隧道
		_ = resp.Body.Close() // 错误处理路径，Close错误可忽略
		return NewProxyError(ErrTypeAuth,
			fmt.Sprintf(ErrMsgHTTPProxyAuthFailed, resp.StatusCode), ErrCodeHTTPProxyAuthFailed, nil)
	}

	// 对于成功的CONNECT隧道，不要关闭resp.Body
	// 因为这会关闭底层TCP连接，导致隧道失效
	// HTTP CONNECT协议要求在200响应后保持连接开放供数据传输

	// 清除deadline
	_ = conn.SetDeadline(time.Time{})

	return nil
}

// updateAverageConnectTime 更新平均连接时间
func (h *httpDialer) updateAverageConnectTime(duration time.Duration) {
	h.stats.mu.Lock()
	defer h.stats.mu.Unlock()
	if h.stats.AverageConnectTime == 0 {
		h.stats.AverageConnectTime = duration
	} else {
		h.stats.AverageConnectTime = (h.stats.AverageConnectTime + duration) / 2
	}
}
