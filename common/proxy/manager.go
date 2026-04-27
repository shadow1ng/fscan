package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// manager 代理管理器实现
type manager struct {
	config *ProxyConfig
	stats  *ProxyStats
	mu     sync.RWMutex

	// 连接池
	dialerCache map[string]Dialer
	cacheExpiry time.Time
	cacheMu     sync.RWMutex
}

// NewProxyManager 创建新的代理管理器
func NewProxyManager(config *ProxyConfig) ProxyManager {
	if config == nil {
		config = DefaultProxyConfig()
	}

	// 自动配置代理行为
	AutoConfigureProxy(config)

	m := &manager{
		config: config,
		stats: &ProxyStats{
			ProxyType:    config.Type.String(),
			ProxyAddress: config.Address,
		},
		dialerCache: make(map[string]Dialer),
		cacheExpiry: time.Now().Add(DefaultCacheExpiry),
	}

	// 对 SOCKS5 代理进行行为探测，检测是否存在"全回显"问题
	// 只探测一次，避免重复输出警告
	if config.Type == ProxyTypeSOCKS5 && !IsProxyProbed() {
		SetProxyProbed(true)
		dialer, err := m.createSOCKS5Dialer()
		if err == nil {
			reliable := ProbeProxyBehavior(dialer, config.Timeout)
			SetProxyReliable(reliable)
		}
	}

	return m
}

// GetDialer 获取普通拨号器
func (m *manager) GetDialer() (Dialer, error) {
	m.mu.RLock()
	config := m.config
	m.mu.RUnlock()

	switch config.Type {
	case ProxyTypeNone:
		return m.createDirectDialer(), nil
	case ProxyTypeSOCKS5:
		return m.createSOCKS5Dialer()
	case ProxyTypeHTTP, ProxyTypeHTTPS:
		return m.createHTTPDialer()
	default:
		return nil, NewProxyError(ErrTypeConfig, ErrMsgUnsupportedProxyType, ErrCodeUnsupportedProxyType, nil)
	}
}

// GetTLSDialer 获取TLS拨号器
func (m *manager) GetTLSDialer() (TLSDialer, error) {
	dialer, err := m.GetDialer()
	if err != nil {
		return nil, err
	}

	return &tlsDialerWrapper{
		dialer: dialer,
		config: m.config,
		stats:  m.stats,
	}, nil
}

// UpdateConfig 更新配置
func (m *manager) UpdateConfig(config *ProxyConfig) error {
	if config == nil {
		return NewProxyError(ErrTypeConfig, ErrMsgEmptyConfig, ErrCodeEmptyConfig, nil)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = config
	m.stats.ProxyType = config.Type.String()
	m.stats.ProxyAddress = config.Address

	// 自动配置代理行为
	AutoConfigureProxy(config)

	// 清理缓存
	m.cacheMu.Lock()
	m.dialerCache = make(map[string]Dialer)
	m.cacheExpiry = time.Now().Add(DefaultCacheExpiry)
	m.cacheMu.Unlock()

	return nil
}

// Close 关闭管理器
func (m *manager) Close() error {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	m.dialerCache = make(map[string]Dialer)
	return nil
}

// Stats 获取统计信息
func (m *manager) Stats() *ProxyStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()

	return &ProxyStats{
		TotalConnections:   atomic.LoadInt64(&m.stats.TotalConnections),
		ActiveConnections:  atomic.LoadInt64(&m.stats.ActiveConnections),
		FailedConnections:  atomic.LoadInt64(&m.stats.FailedConnections),
		AverageConnectTime: m.stats.AverageConnectTime,
		LastConnectTime:    m.stats.LastConnectTime,
		LastError:          m.stats.LastError,
		ProxyType:          m.stats.ProxyType,
		ProxyAddress:       m.stats.ProxyAddress,
	}
}

// createDirectDialer 创建直连拨号器
func (m *manager) createDirectDialer() Dialer {
	return &directDialer{
		timeout:   m.config.Timeout,
		localAddr: m.config.LocalAddr,
		stats:     m.stats,
	}
}

// createSOCKS5Dialer 创建SOCKS5拨号器
func (m *manager) createSOCKS5Dialer() (Dialer, error) {
	// 检查缓存
	cacheKey := fmt.Sprintf(CacheKeySOCKS5, m.config.Address)
	m.cacheMu.RLock()
	if time.Now().Before(m.cacheExpiry) {
		if cached, exists := m.dialerCache[cacheKey]; exists {
			m.cacheMu.RUnlock()
			return cached, nil
		}
	}
	m.cacheMu.RUnlock()

	// 解析代理地址
	proxyURL := fmt.Sprintf(SOCKS5URLFormat, m.config.Address)
	if m.config.Username != "" {
		proxyURL = fmt.Sprintf(SOCKS5URLAuthFormat,
			m.config.Username, m.config.Password, m.config.Address)
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, NewProxyError(ErrTypeConfig, ErrMsgSOCKS5ParseFailed, ErrCodeSOCKS5ParseFailed, err)
	}

	// 创建基础拨号器
	baseDial := &net.Dialer{
		Timeout:   m.config.Timeout,
		KeepAlive: m.config.KeepAlive,
	}

	// 创建SOCKS5拨号器
	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{
			User: u.User.Username(),
		}
		if password, hasPassword := u.User.Password(); hasPassword {
			auth.Password = password
		}
	}

	socksDialer, err := proxy.SOCKS5(NetworkTCP, u.Host, auth, baseDial)
	if err != nil {
		return nil, NewProxyError(ErrTypeConnection, ErrMsgSOCKS5CreateFailed, ErrCodeSOCKS5CreateFailed, err)
	}

	dialer := &socks5Dialer{
		dialer: socksDialer,
		config: m.config,
		stats:  m.stats,
	}

	// 更新缓存
	m.cacheMu.Lock()
	m.dialerCache[cacheKey] = dialer
	m.cacheExpiry = time.Now().Add(DefaultCacheExpiry)
	m.cacheMu.Unlock()

	return dialer, nil
}

// createHTTPDialer 创建HTTP代理拨号器
func (m *manager) createHTTPDialer() (Dialer, error) {
	// 检查缓存
	cacheKey := fmt.Sprintf(CacheKeyHTTP, m.config.Address)
	m.cacheMu.RLock()
	if time.Now().Before(m.cacheExpiry) {
		if cached, exists := m.dialerCache[cacheKey]; exists {
			m.cacheMu.RUnlock()
			return cached, nil
		}
	}
	m.cacheMu.RUnlock()

	dialer := &httpDialer{
		config: m.config,
		stats:  m.stats,
		baseDial: &net.Dialer{
			Timeout:   m.config.Timeout,
			KeepAlive: m.config.KeepAlive,
		},
	}

	// 更新缓存
	m.cacheMu.Lock()
	m.dialerCache[cacheKey] = dialer
	m.cacheExpiry = time.Now().Add(DefaultCacheExpiry)
	m.cacheMu.Unlock()

	return dialer, nil
}

// directDialer 直连拨号器
type directDialer struct {
	timeout   time.Duration
	localAddr string // 本地网卡IP地址
	stats     *ProxyStats
}

func (d *directDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	start := time.Now()
	atomic.AddInt64(&d.stats.TotalConnections, 1)

	dialer := &net.Dialer{
		Timeout: d.timeout,
	}

	// 如果指定了本地地址，绑定 LocalAddr
	if d.localAddr != "" {
		if ip := net.ParseIP(d.localAddr); ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	conn, err := dialer.DialContext(ctx, network, address)

	duration := time.Since(start)

	d.stats.mu.Lock()
	d.stats.LastConnectTime = start
	d.stats.mu.Unlock()

	if err != nil {
		atomic.AddInt64(&d.stats.FailedConnections, 1)
		d.stats.mu.Lock()
		d.stats.LastError = err.Error()
		d.stats.mu.Unlock()
		return nil, NewProxyError(ErrTypeConnection, ErrMsgDirectConnFailed, ErrCodeDirectConnFailed, err)
	}

	atomic.AddInt64(&d.stats.ActiveConnections, 1)
	d.updateAverageConnectTime(duration)

	return &trackedConn{
		Conn:  conn,
		stats: d.stats,
	}, nil
}

// socks5Dialer SOCKS5拨号器
type socks5Dialer struct {
	dialer proxy.Dialer
	config *ProxyConfig
	stats  *ProxyStats
}

func (s *socks5Dialer) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

func (s *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	start := time.Now()
	atomic.AddInt64(&s.stats.TotalConnections, 1)

	// 创建一个带超时的上下文
	dialCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// 使用goroutine处理拨号，以支持取消
	connChan := make(chan struct {
		conn net.Conn
		err  error
	}, 1)

	go func() {
		conn, err := s.dialer.Dial(network, address)
		select {
		case <-dialCtx.Done():
			if conn != nil {
				_ = conn.Close() // context取消路径，Close错误可忽略
			}
		case connChan <- struct {
			conn net.Conn
			err  error
		}{conn, err}:
		}
	}()

	select {
	case <-dialCtx.Done():
		atomic.AddInt64(&s.stats.FailedConnections, 1)
		s.stats.mu.Lock()
		s.stats.LastError = dialCtx.Err().Error()
		s.stats.mu.Unlock()
		return nil, NewProxyError(ErrTypeTimeout, ErrMsgSOCKS5ConnTimeout, ErrCodeSOCKS5ConnTimeout, dialCtx.Err())
	case result := <-connChan:
		duration := time.Since(start)

		s.stats.mu.Lock()
		s.stats.LastConnectTime = start
		s.stats.mu.Unlock()

		if result.err != nil {
			atomic.AddInt64(&s.stats.FailedConnections, 1)
			s.stats.mu.Lock()
			s.stats.LastError = result.err.Error()
			s.stats.mu.Unlock()
			return nil, NewProxyError(ErrTypeConnection, ErrMsgSOCKS5ConnFailed, ErrCodeSOCKS5ConnFailed, result.err)
		}

		atomic.AddInt64(&s.stats.ActiveConnections, 1)
		s.updateAverageConnectTime(duration)

		return &trackedConn{
			Conn:  result.conn,
			stats: s.stats,
		}, nil
	}
}

// updateAverageConnectTime 更新平均连接时间
func (d *directDialer) updateAverageConnectTime(duration time.Duration) {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()
	if d.stats.AverageConnectTime == 0 {
		d.stats.AverageConnectTime = duration
	} else {
		d.stats.AverageConnectTime = (d.stats.AverageConnectTime + duration) / 2
	}
}

func (s *socks5Dialer) updateAverageConnectTime(duration time.Duration) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()
	if s.stats.AverageConnectTime == 0 {
		s.stats.AverageConnectTime = duration
	} else {
		s.stats.AverageConnectTime = (s.stats.AverageConnectTime + duration) / 2
	}
}

// ProbeProxyBehavior 探测代理是否存在"全回显"问题
// 通过连接一个几乎肯定不可达的地址，并尝试发送数据来判断代理行为
// 返回 true 表示代理可靠，false 表示代理存在全回显问题
//
// 判断标准：
// - 连接失败 → 可靠（代理正确拒绝不可达目标）
// - 写入失败 → 可靠（代理在数据传输时报告错误）
// - 读取超时 → 可靠（代理转发了请求，目标没响应是正常的）
// - 读取错误 → 可靠（代理正确报告了目标不可达）
// - 收到数据 → 不可靠（代理伪造了响应）
func ProbeProxyBehavior(dialer Dialer, timeout time.Duration) bool {
	// 使用 RFC 5737 保留的测试 IP (TEST-NET-1) + 高端口
	// 192.0.2.1 是文档专用地址，保证不会路由到真实主机
	testAddr := "192.0.2.1:65533"

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", testAddr)
	if err != nil {
		// 连接失败 = 正常代理行为，代理可靠
		return true
	}
	defer conn.Close()

	// 连接"成功"，进一步验证：尝试发送数据检查是否真的可达
	// 全回显代理会接受连接，但数据无法到达目标

	// 设置短超时
	_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	_, writeErr := conn.Write([]byte("PROBE\r\n"))

	if writeErr != nil {
		// 写入失败 = 连接不可用，但这是预期的（目标不可达）
		// 某些代理会在写入时才报告真实错误
		return true
	}

	// 等待响应或错误
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	n, readErr := conn.Read(buf)

	if readErr != nil {
		// 读取超时或错误 = 目标不可达，代理行为正常
		// 超时说明代理正确转发了请求，目标没有响应是正常的
		// 其他错误（reset, refused等）说明代理正确报告了目标不可达
		return true
	}

	// 收到数据 = 代理伪造了响应，不可靠
	if n > 0 {
		return false
	}

	// 无错误且无数据 = EOF，说明连接被正常关闭，代理行为正常
	return true
}
