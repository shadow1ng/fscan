package common

/*
network.go - 统一网络操作包装器

提供便捷的网络连接API，自动处理发包限制检查、代理和统计。
*/

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/proxy"
)

// =============================================================================
// 全局代理管理器（复用连接，避免重复创建）
// =============================================================================

var (
	globalProxyOnce    sync.Once
	globalProxyDialer  proxy.Dialer
	globalProxyInitErr error
)

// getGlobalDialer 获取全局拨号器（线程安全，只初始化一次）
func getGlobalDialer(timeout time.Duration) (proxy.Dialer, error) {
	globalProxyOnce.Do(func() {
		// 创建代理配置
		config := createProxyConfig(timeout)

		// 创建代理管理器
		manager := proxy.NewProxyManager(config)

		// 创建拨号器
		globalProxyDialer, globalProxyInitErr = manager.GetDialer()
	})

	return globalProxyDialer, globalProxyInitErr
}

// =============================================================================
// 代理配置
// =============================================================================

// parseProxyURL 解析代理URL，提取地址和认证信息
func parseProxyURL(proxyURL, fallback string) (host, username, password string) {
	if !strings.Contains(proxyURL, "://") {
		if host, username, password, ok := parseProxyURLCandidate("http://" + proxyURL); ok {
			return host, username, password
		}
	}
	if host, username, password, ok := parseProxyURLCandidate(proxyURL); ok {
		return host, username, password
	}
	return fallback, "", ""
}

func parseProxyURLCandidate(proxyURL string) (host, username, password string, ok bool) {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return "", "", "", false
	}
	host = parsedURL.Host
	if host == "" {
		return "", "", "", false
	}
	if parsedURL.User != nil {
		username = parsedURL.User.Username()
		password, _ = parsedURL.User.Password()
	}
	return host, username, password, true
}

// createProxyConfig 根据全局设置创建代理配置
func createProxyConfig(timeout time.Duration) *proxy.ProxyConfig {
	fv := GetFlagVars()
	config := proxy.DefaultProxyConfig()
	config.Timeout = timeout
	config.LocalAddr = fv.Iface // 设置本地网卡IP地址

	// 优先使用SOCKS5代理
	if fv.Socks5Proxy != "" {
		config.Type = proxy.ProxyTypeSOCKS5
		// 确保有协议前缀以便解析
		socks5URL := fv.Socks5Proxy
		if !strings.HasPrefix(socks5URL, "socks5://") {
			socks5URL = "socks5://" + socks5URL
		}
		config.Address, config.Username, config.Password = parseProxyURL(socks5URL, fv.Socks5Proxy)
		return config
	}

	// 其次使用HTTP代理
	if fv.HTTPProxy != "" {
		if strings.HasPrefix(fv.HTTPProxy, "https://") {
			config.Type = proxy.ProxyTypeHTTPS
		} else {
			config.Type = proxy.ProxyTypeHTTP
		}
		config.Address, config.Username, config.Password = parseProxyURL(fv.HTTPProxy, fv.HTTPProxy)
		return config
	}

	// 无代理配置，使用直连
	config.Type = proxy.ProxyTypeNone
	return config
}

// =============================================================================
// TCP 连接
// =============================================================================

// Deprecated: WrapperTcpWithTimeout 仅供 libs/grdp 兼容使用，新代码请用 ScanSession.DialTCP
//
//nolint:revive
func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	// 检查发包限制 - 在代理连接前进行控制
	if canSend, reason := CanSendPacket(); !canSend {
		LogError(i18n.Tr("tcp_connection_restricted", address, reason))
		return nil, fmt.Errorf("%s", i18n.Tr("network_rate_limited", reason))
	}

	// 获取全局拨号器（复用，避免重复创建）
	dialer, err := getGlobalDialer(timeout)
	if err != nil {
		LogError(i18n.Tr("proxy_dialer_failed", err))
		GetGlobalState().IncrementTCPFailedPacketCount()
		return nil, err
	}

	// 使用代理拨号器连接
	conn, err := dialer.DialContext(context.Background(), network, address)

	// 统计TCP包数量 - 无论是否使用代理都要计数
	if err != nil {
		GetGlobalState().IncrementTCPFailedPacketCount()
		LogDebug(i18n.Tr("connection_failed", address, err))
		return nil, err
	}

	// 连接成功，统计成功包
	GetGlobalState().IncrementTCPSuccessPacketCount()

	return conn, nil
}

// SafeTCPDial TCP连接的便捷封装
// 直接调用WrapperTcpWithTimeout，自动处理发包限制、代理和统计
func SafeTCPDial(address string, timeout time.Duration) (net.Conn, error) {
	return WrapperTcpWithTimeout("tcp", address, timeout)
}

// =============================================================================
// HTTP 请求
// =============================================================================

// IsProxyEnabled 检查是否启用了代理（封装proxy包的函数）
func IsProxyEnabled() bool {
	return proxy.IsProxyEnabled()
}

// IsProxyReliable 检查代理是否可靠（不存在全回显问题）
func IsProxyReliable() bool {
	return proxy.IsProxyReliable()
}

// IsSOCKS5Proxy 检查当前代理是否为SOCKS5类型
func IsSOCKS5Proxy() bool {
	return proxy.IsSOCKS5Proxy()
}

// SafeHTTPDo 带发包控制的HTTP请求
func SafeHTTPDo(client *http.Client, req *http.Request) (*http.Response, error) {
	// 检查发包限制
	if canSend, reason := CanSendPacket(); !canSend {
		LogError(i18n.Tr("http_request_restricted", req.URL.String(), reason))
		return nil, fmt.Errorf("%s", i18n.Tr("network_rate_limited", reason))
	}

	// 执行HTTP请求
	resp, err := client.Do(req)

	// 统计TCP包数量 (HTTP本质上是TCP)
	if err != nil {
		GetGlobalState().IncrementTCPFailedPacketCount()
	} else {
		GetGlobalState().IncrementTCPSuccessPacketCount()
	}

	return resp, err
}
