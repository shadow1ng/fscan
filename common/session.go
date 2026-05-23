package common

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/output"
	"github.com/shadow1ng/fscan/common/proxy"
)

// ResultSink receives structured scan results for one scan session.
type ResultSink func(result *output.ScanResult) error

// ScanSession 封装单次扫描的全部上下文
// 一次扫描一个 session，并发扫描各自独立
type ScanSession struct {
	Config     *Config    // 不可变，创建后只读
	State      *State     // 可变，原子操作，每会话独立
	Params     *FlagVars  // 原始参数，只读
	ResultSink ResultSink // 可选，覆盖全局输出
	PauseGate  func(ctx context.Context) error

	// 每会话 dialer（按 timeout 懒初始化，取决于代理配置）
	dialerMu   sync.Mutex
	dialers    map[time.Duration]proxy.Dialer
	dialerErrs map[time.Duration]error
}

// NewScanSession 从已构建的 Config、State 和 FlagVars 创建会话
func NewScanSession(config *Config, state *State, params *FlagVars) *ScanSession {
	return &ScanSession{
		Config: config,
		State:  state,
		Params: params,
	}
}

// SaveResult saves a scan result through the session sink if present, otherwise
// falls back to the process-wide output pipeline used by the CLI.
func (s *ScanSession) SaveResult(result *output.ScanResult) error {
	if s != nil && s.ResultSink != nil {
		return s.ResultSink(result)
	}
	return SaveResult(result)
}

func (s *ScanSession) loggingEnabled() bool {
	return s == nil || s.Config == nil || !s.Config.Output.Silent
}

// LogDebug writes through the session's logging policy.
func (s *ScanSession) LogDebug(msg string) {
	if s.loggingEnabled() {
		LogDebug(msg)
	}
}

// LogInfo writes through the session's logging policy.
func (s *ScanSession) LogInfo(msg string) {
	if s.loggingEnabled() {
		LogInfo(msg)
	}
}

// LogSuccess writes through the session's logging policy.
func (s *ScanSession) LogSuccess(result string) {
	if s.loggingEnabled() {
		LogSuccess(result)
	}
}

// LogVuln writes through the session's logging policy.
func (s *ScanSession) LogVuln(result string) {
	if s.loggingEnabled() {
		LogVuln(result)
	}
}

// LogError writes through the session's logging policy.
func (s *ScanSession) LogError(errMsg string) {
	if s.loggingEnabled() {
		LogError(errMsg)
	}
}

// DialTCP 创建 TCP 连接，内含限速检查、代理、计数
func (s *ScanSession) DialTCP(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	// 检查发包限制
	if ok, err := CanSendPacketWith(s.Config, s.State); !ok {
		s.LogError(i18n.Tr("tcp_connection_restricted", address, err.Error()))
		return nil, fmt.Errorf("%s", i18n.Tr("network_rate_limited", err.Error()))
	}

	// 获取 dialer
	dialer, err := s.getDialer(timeout)
	if err != nil {
		s.LogError(i18n.Tr("proxy_dialer_failed", err))
		s.State.IncrementTCPFailedPacketCount()
		return nil, err
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		s.State.IncrementTCPFailedPacketCount()
		s.LogDebug(i18n.Tr("connection_failed", address, err))
		return nil, err
	}

	// SO_LINGER=0: 连接关闭时立即发送 RST，避免 TIME_WAIT 堆积
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}

	s.State.IncrementTCPSuccessPacketCount()
	return conn, nil
}

// DialUDP creates a connected UDP socket with rate limiting and packet counting.
// UDP cannot be proxied; if a proxy is configured the connection is made directly.
func (s *ScanSession) DialUDP(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	if ok, err := CanSendPacketWith(s.Config, s.State); !ok {
		return nil, fmt.Errorf("%s", i18n.Tr("network_rate_limited", err.Error()))
	}

	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		s.State.IncrementUDPPacketCount()
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	s.State.IncrementUDPPacketCount()
	return conn, nil
}

// HTTPDo executes an HTTP request with the session's packet limits and counters.
func (s *ScanSession) HTTPDo(client *http.Client, req *http.Request) (*http.Response, error) {
	if ok, err := CanSendPacketWith(s.Config, s.State); !ok {
		s.LogError(i18n.Tr("http_request_restricted", req.URL.String(), err.Error()))
		return nil, fmt.Errorf("%s", i18n.Tr("network_rate_limited", err.Error()))
	}

	resp, err := client.Do(req)
	if err != nil {
		s.State.IncrementTCPFailedPacketCount()
		return nil, err
	}
	s.State.IncrementTCPSuccessPacketCount()
	return resp, nil
}

// ProxyEnabled reports whether this scan session uses a network proxy.
func (s *ScanSession) ProxyEnabled() bool {
	if s == nil || s.Config == nil {
		return false
	}
	return s.Config.Network.Socks5Proxy != "" || s.Config.Network.HTTPProxy != ""
}

// IsSOCKS5Proxy reports whether this scan session uses SOCKS5.
func (s *ScanSession) IsSOCKS5Proxy() bool {
	return s != nil && s.Config != nil && s.Config.Network.Socks5Proxy != ""
}

// ProxyReliable reports whether the session proxy should be treated as reliable.
func (s *ScanSession) ProxyReliable() bool {
	if !s.ProxyEnabled() || !s.IsSOCKS5Proxy() {
		return true
	}
	return proxy.IsProxyReliable()
}

func (s *ScanSession) getDialer(timeout time.Duration) (proxy.Dialer, error) {
	if timeout <= 0 {
		timeout = s.Config.Timeout
	}

	s.dialerMu.Lock()
	defer s.dialerMu.Unlock()

	if s.dialers == nil {
		s.dialers = make(map[time.Duration]proxy.Dialer)
		s.dialerErrs = make(map[time.Duration]error)
	}
	if dialer, ok := s.dialers[timeout]; ok {
		return dialer, s.dialerErrs[timeout]
	}

	cfg := s.createProxyConfig(timeout)
	manager := proxy.NewProxyManager(cfg)
	dialer, err := manager.GetDialer()
	s.dialers[timeout] = dialer
	s.dialerErrs[timeout] = err
	return dialer, err
}

func (s *ScanSession) createProxyConfig(timeout time.Duration) *proxy.ProxyConfig {
	cfg := proxy.DefaultProxyConfig()
	cfg.Timeout = timeout
	cfg.LocalAddr = s.Config.Network.Iface

	// 优先 SOCKS5
	if s.Config.Network.Socks5Proxy != "" {
		cfg.Type = proxy.ProxyTypeSOCKS5
		socks5URL := s.Config.Network.Socks5Proxy
		if !strings.HasPrefix(socks5URL, "socks5://") {
			socks5URL = "socks5://" + socks5URL
		}
		cfg.Address, cfg.Username, cfg.Password = parseProxyURL(socks5URL, s.Config.Network.Socks5Proxy)
		return cfg
	}

	// 其次 HTTP
	if s.Config.Network.HTTPProxy != "" {
		if strings.HasPrefix(s.Config.Network.HTTPProxy, "https://") {
			cfg.Type = proxy.ProxyTypeHTTPS
		} else {
			cfg.Type = proxy.ProxyTypeHTTP
		}
		cfg.Address, cfg.Username, cfg.Password = parseProxyURL(s.Config.Network.HTTPProxy, s.Config.Network.HTTPProxy)
		return cfg
	}

	cfg.Type = proxy.ProxyTypeNone
	return cfg
}
