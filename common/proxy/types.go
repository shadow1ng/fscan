package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// ProxyType 代理类型
//
//nolint:revive // 保持与现有代码的向后兼容性
type ProxyType int

const (
	// ProxyTypeNone 无代理
	ProxyTypeNone ProxyType = iota
	// ProxyTypeHTTP HTTP代理
	ProxyTypeHTTP
	// ProxyTypeHTTPS HTTPS代理
	ProxyTypeHTTPS
	// ProxyTypeSOCKS5 SOCKS5代理
	ProxyTypeSOCKS5
)

// String 返回代理类型的字符串表示
func (pt ProxyType) String() string {
	switch pt {
	case ProxyTypeNone:
		return ProxyTypeStringNone
	case ProxyTypeHTTP:
		return ProxyTypeStringHTTP
	case ProxyTypeHTTPS:
		return ProxyTypeStringHTTPS
	case ProxyTypeSOCKS5:
		return ProxyTypeStringSOCKS5
	default:
		return ProxyTypeStringUnknown
	}
}

// ProxyConfig 代理配置
//
//nolint:revive // 保持与现有代码的向后兼容性
type ProxyConfig struct {
	Type         ProxyType     `json:"type"`
	Address      string        `json:"address"`
	Username     string        `json:"username,omitempty"`
	Password     string        `json:"password,omitempty"`
	LocalAddr    string        `json:"local_addr,omitempty"` // 本地网卡IP地址（VPN场景）
	Timeout      time.Duration `json:"timeout"`
	MaxRetries   int           `json:"max_retries"`
	KeepAlive    time.Duration `json:"keep_alive"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	MaxIdleConns int           `json:"max_idle_conns"`
}

// DefaultProxyConfig 返回默认代理配置
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		Type:         ProxyTypeNone,
		Timeout:      DefaultProxyTimeout,
		MaxRetries:   DefaultProxyMaxRetries,
		KeepAlive:    DefaultProxyKeepAlive,
		IdleTimeout:  DefaultProxyIdleTimeout,
		MaxIdleConns: DefaultProxyMaxIdleConns,
	}
}

// Dialer 拨号器接口
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TLSDialer TLS拨号器接口
type TLSDialer interface {
	Dialer
	DialTLS(network, address string, config *tls.Config) (net.Conn, error)
	DialTLSContext(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error)
}

// ProxyManager 代理管理器接口
//
//nolint:revive // 保持与现有代码的向后兼容性
type ProxyManager interface {
	GetDialer() (Dialer, error)
	GetTLSDialer() (TLSDialer, error)
	UpdateConfig(config *ProxyConfig) error
	Close() error
	Stats() *ProxyStats // 保留接口但实现为空操作
}

// ProxyStats 代理统计信息（暂时保留以维护编译）
//
//nolint:revive // 保持与现有代码的向后兼容性
type ProxyStats struct {
	TotalConnections   int64  `json:"total_connections"`
	ActiveConnections  int64  `json:"active_connections"`
	FailedConnections  int64  `json:"failed_connections"`
	mu                 sync.Mutex    `json:"-"`
	AverageConnectTime time.Duration `json:"average_connect_time"`
	LastConnectTime    time.Time     `json:"last_connect_time"`
	LastError          string        `json:"last_error,omitempty"`
	ProxyType          string        `json:"proxy_type"`
	ProxyAddress       string        `json:"proxy_address"`
}

// ProxyError 代理错误类型
//
//nolint:revive // 保持与现有代码的向后兼容性
type ProxyError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code"`
	Cause   error  `json:"cause,omitempty"`
}

func (e *ProxyError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// NewProxyError 创建代理错误
func NewProxyError(errType, message string, code int, cause error) *ProxyError {
	return &ProxyError{
		Type:    errType,
		Message: message,
		Code:    code,
		Cause:   cause,
	}
}

// 预定义错误类型已迁移到constants.go
