package proxy

import (
	"sync/atomic"
)

var (
	// proxyEnabled 标记是否启用了代理（全局状态）
	proxyEnabled atomic.Bool

	// socks5Standard 标记是否为标准的SOCKS5代理
	socks5Standard atomic.Bool

	// proxyInitialized 标记代理是否已初始化
	proxyInitialized atomic.Bool

	// proxyReliable 标记代理是否可靠（不存在全回显问题）
	proxyReliable atomic.Bool

	// proxyProbed 标记代理是否已经探测过（避免重复探测）
	proxyProbed atomic.Bool

	// currentProxyType 当前代理类型
	currentProxyType atomic.Int32
)

// SetProxyEnabled 设置代理启用状态
func SetProxyEnabled(enabled bool) {
	proxyEnabled.Store(enabled)
}

// SetSOCKS5Standard 设置SOCKS5是否标准
func SetSOCKS5Standard(standard bool) {
	socks5Standard.Store(standard)
}

// SetProxyInitialized 设置代理初始化状态
func SetProxyInitialized(initialized bool) {
	proxyInitialized.Store(initialized)
}

// IsProxyEnabled 检查是否启用了代理
func IsProxyEnabled() bool {
	return proxyEnabled.Load()
}

// SetProxyReliable 设置代理可靠性状态
func SetProxyReliable(reliable bool) {
	proxyReliable.Store(reliable)
}

// IsProxyReliable 检查代理是否可靠（不存在全回显问题）
func IsProxyReliable() bool {
	return proxyReliable.Load()
}

// SetProxyProbed 设置代理已探测标志
func SetProxyProbed(probed bool) {
	proxyProbed.Store(probed)
}

// IsProxyProbed 检查代理是否已探测过
func IsProxyProbed() bool {
	return proxyProbed.Load()
}

// IsSOCKS5Proxy 检查当前代理是否为SOCKS5类型
func IsSOCKS5Proxy() bool {
	return proxyEnabled.Load() && ProxyType(currentProxyType.Load()) == ProxyTypeSOCKS5
}

// AutoConfigureProxy 自动配置代理相关行为
// 根据代理类型和状态自动调整扫描策略
func AutoConfigureProxy(config *ProxyConfig) {
	if config == nil || config.Type == ProxyTypeNone {
		SetProxyEnabled(false)
		SetSOCKS5Standard(false)
		SetProxyInitialized(false)
		SetProxyReliable(true) // 无代理时默认可靠
		return
	}

	// 启用代理标记
	SetProxyEnabled(true)
	currentProxyType.Store(int32(config.Type))

	// SOCKS5代理默认假设非标准（后续由探测函数验证）
	if config.Type == ProxyTypeSOCKS5 {
		SetSOCKS5Standard(false)
		// 只有未探测过时才设置默认值，避免覆盖探测结果
		if !IsProxyProbed() {
			SetProxyReliable(true) // 默认可靠，后续由 ProbeProxyBehavior 更新
		}
	}

	// HTTP/HTTPS代理视为标准且可靠
	if config.Type == ProxyTypeHTTP || config.Type == ProxyTypeHTTPS {
		SetSOCKS5Standard(true)
		SetProxyReliable(true)
	}
}
