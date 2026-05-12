package common

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/proxy"
)

// ScanSession 封装单次扫描的全部上下文
// 一次扫描一个 session，并发扫描各自独立
type ScanSession struct {
	Config *Config   // 不可变，创建后只读
	State  *State    // 可变，原子操作，每会话独立
	Params *FlagVars // 原始参数，只读

	// 每会话 dialer（懒初始化，取决于代理配置）
	dialerOnce sync.Once
	dialer     proxy.Dialer
	dialerErr  error
}

// NewScanSession 从已构建的 Config、State 和 FlagVars 创建会话
func NewScanSession(config *Config, state *State, params *FlagVars) *ScanSession {
	return &ScanSession{
		Config: config,
		State:  state,
		Params: params,
	}
}

// DialTCP 创建 TCP 连接，内含限速检查、代理、计数
func (s *ScanSession) DialTCP(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	// 检查发包限制
	if ok, err := CanSendPacketWith(s.Config, s.State); !ok {
		LogError(fmt.Sprintf("TCP连接 %s 受限: %s", address, err.Error()))
		return nil, fmt.Errorf("发包受限: %s", err.Error())
	}

	// 获取 dialer
	dialer, err := s.getDialer()
	if err != nil {
		LogError(fmt.Sprintf("获取代理拨号器失败: %v", err))
		s.State.IncrementTCPFailedPacketCount()
		return nil, err
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		s.State.IncrementTCPFailedPacketCount()
		LogDebug(fmt.Sprintf("连接 %s 失败: %v", address, err))
		return nil, err
	}

	// SO_LINGER=0: 连接关闭时立即发送 RST，避免 TIME_WAIT 堆积
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}

	s.State.IncrementTCPSuccessPacketCount()
	return conn, nil
}

func (s *ScanSession) getDialer() (proxy.Dialer, error) {
	s.dialerOnce.Do(func() {
		cfg := s.createProxyConfig()
		manager := proxy.NewProxyManager(cfg)
		s.dialer, s.dialerErr = manager.GetDialer()
	})
	return s.dialer, s.dialerErr
}

func (s *ScanSession) createProxyConfig() *proxy.ProxyConfig {
	cfg := proxy.DefaultProxyConfig()
	cfg.Timeout = s.Config.Timeout
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
