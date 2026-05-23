package proxy

import (
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
)

/*
constants.go - 代理系统常量定义

统一管理common/proxy包中的所有常量，便于查看和编辑。
*/

// =============================================================================
// 代理类型常量 (从Types.go迁移)
// =============================================================================

const (
	// ProxyTypeStringNone 代理类型字符串 - 无代理
	ProxyTypeStringNone = "none"
	// ProxyTypeStringHTTP HTTP代理
	ProxyTypeStringHTTP = "http"
	// ProxyTypeStringHTTPS HTTPS代理
	ProxyTypeStringHTTPS = "https"
	// ProxyTypeStringSOCKS5 SOCKS5代理
	ProxyTypeStringSOCKS5 = "socks5"
	// ProxyTypeStringUnknown 未知代理类型
	ProxyTypeStringUnknown = "unknown"
)

// =============================================================================
// 默认配置常量 (从Types.go迁移)
// =============================================================================

const (
	// DefaultProxyTimeout 默认代理配置值 - 默认超时时间
	DefaultProxyTimeout = 30 * time.Second
	// DefaultProxyMaxRetries 默认最大重试次数
	DefaultProxyMaxRetries = 3
	// DefaultProxyKeepAlive 默认保持连接时间
	DefaultProxyKeepAlive = 30 * time.Second
	// DefaultProxyIdleTimeout 默认空闲超时时间
	DefaultProxyIdleTimeout = 90 * time.Second
	// DefaultProxyMaxIdleConns 默认最大空闲连接数
	DefaultProxyMaxIdleConns = 10
)

// =============================================================================
// 错误类型常量 (从Types.go迁移)
// =============================================================================

const (
	// ErrTypeConfig 预定义错误类型 - 配置错误
	ErrTypeConfig = "config_error"
	// ErrTypeConnection 连接错误
	ErrTypeConnection = "connection_error"
	// ErrTypeAuth 认证错误
	ErrTypeAuth = "auth_error"
	// ErrTypeTimeout 超时错误
	ErrTypeTimeout = "timeout_error"
	// ErrTypeProtocol 协议错误
	ErrTypeProtocol = "protocol_error"
)

// =============================================================================
// 缓存管理常量 (从Manager.go迁移)
// =============================================================================

const (
	// DefaultCacheExpiry 缓存配置 - 默认缓存过期时间
	DefaultCacheExpiry = 5 * time.Minute
)

// =============================================================================
// 错误代码常量 (从Manager.go和其他文件迁移)
// =============================================================================

const (
	// ErrCodeUnsupportedProxyType Manager错误代码 - 不支持的代理类型
	ErrCodeUnsupportedProxyType = 1001
	// ErrCodeEmptyConfig 配置为空
	ErrCodeEmptyConfig = 1002

	// ErrCodeSOCKS5ParseFailed SOCKS5错误代码 - 地址解析失败
	ErrCodeSOCKS5ParseFailed = 2001
	// ErrCodeSOCKS5CreateFailed 拨号器创建失败
	ErrCodeSOCKS5CreateFailed = 2002

	// ErrCodeDirectConnFailed 直连错误代码 - 直连失败
	ErrCodeDirectConnFailed = 3001
	// ErrCodeSOCKS5ConnTimeout SOCKS5连接超时
	ErrCodeSOCKS5ConnTimeout = 3002
	// ErrCodeSOCKS5ConnFailed SOCKS5连接失败
	ErrCodeSOCKS5ConnFailed = 3003

	// ErrCodeHTTPConnFailed HTTP代理错误代码 - 连接失败
	ErrCodeHTTPConnFailed = 4001
	// ErrCodeHTTPSetWriteTimeout 设置写超时失败
	ErrCodeHTTPSetWriteTimeout = 4002
	// ErrCodeHTTPSendConnectFail 发送CONNECT请求失败
	ErrCodeHTTPSendConnectFail = 4003
	// ErrCodeHTTPSetReadTimeout 设置读超时失败
	ErrCodeHTTPSetReadTimeout = 4004
	// ErrCodeHTTPReadRespFailed 读取响应失败
	ErrCodeHTTPReadRespFailed = 4005
	// ErrCodeHTTPProxyAuthFailed 代理认证失败
	ErrCodeHTTPProxyAuthFailed = 4006

	// ErrCodeTLSTCPConnFailed TLS错误代码 - TCP连接失败
	ErrCodeTLSTCPConnFailed = 5001
	// ErrCodeTLSHandshakeFailed TLS握手失败
	ErrCodeTLSHandshakeFailed = 5002
)

// =============================================================================
// HTTP协议常量 (从HTTPDialer.go迁移)
// =============================================================================

const (
	// HTTPStatusOK HTTP响应状态码 - 成功状态码200
	HTTPStatusOK = 200

	// HTTPVersion HTTP协议常量 - HTTP版本
	HTTPVersion = "HTTP/1.1"
	// HTTPMethodConnect CONNECT方法
	HTTPMethodConnect = "CONNECT"

	// HTTPHeaderHost HTTP头部常量 - Host头
	HTTPHeaderHost = "Host"
	// HTTPHeaderProxyAuth Proxy-Authorization头
	HTTPHeaderProxyAuth = "Proxy-Authorization"
	// HTTPHeaderAuthBasic Basic认证方式
	HTTPHeaderAuthBasic = "Basic"
)

// =============================================================================
// 网络协议常量 (从各文件迁移)
// =============================================================================

const (
	// NetworkTCP 网络协议 - TCP协议
	NetworkTCP = "tcp"

	// ProxyProtocolSOCKS5 代理协议前缀 - SOCKS5协议
	ProxyProtocolSOCKS5 = "socks5"

	// AuthSeparator 认证分隔符 - 冒号分隔符
	AuthSeparator = ":"
)

// =============================================================================
// 错误消息常量
// =============================================================================

var (
	// ErrMsgUnsupportedProxyType Manager错误消息 - 不支持的代理类型
	ErrMsgUnsupportedProxyType = i18n.GetText("proxy_unsupported_type")
	// ErrMsgEmptyConfig 配置不能为空
	ErrMsgEmptyConfig = i18n.GetText("proxy_empty_config")

	// ErrMsgSOCKS5ParseFailed SOCKS5错误消息 - 地址解析失败
	ErrMsgSOCKS5ParseFailed = i18n.GetText("proxy_socks5_parse_failed")
	// ErrMsgSOCKS5CreateFailed 拨号器创建失败
	ErrMsgSOCKS5CreateFailed = i18n.GetText("proxy_socks5_create_failed")
	// ErrMsgSOCKS5ConnTimeout 连接超时
	ErrMsgSOCKS5ConnTimeout = i18n.GetText("proxy_socks5_conn_timeout")
	// ErrMsgSOCKS5ConnFailed 连接失败
	ErrMsgSOCKS5ConnFailed = i18n.GetText("proxy_socks5_conn_failed")

	// ErrMsgDirectConnFailed 直连错误消息 - 直连失败
	ErrMsgDirectConnFailed = i18n.GetText("proxy_direct_conn_failed")

	// ErrMsgHTTPConnFailed HTTP代理错误消息 - 连接失败
	ErrMsgHTTPConnFailed = i18n.GetText("proxy_http_conn_failed")
	// ErrMsgHTTPSetWriteTimeout 设置写超时失败
	ErrMsgHTTPSetWriteTimeout = i18n.GetText("proxy_http_set_write_timeout")
	// ErrMsgHTTPSendConnectFail 发送CONNECT请求失败
	ErrMsgHTTPSendConnectFail = i18n.GetText("proxy_http_send_connect_failed")
	// ErrMsgHTTPSetReadTimeout 设置读超时失败
	ErrMsgHTTPSetReadTimeout = i18n.GetText("proxy_http_set_read_timeout")
	// ErrMsgHTTPReadRespFailed 读取响应失败
	ErrMsgHTTPReadRespFailed = i18n.GetText("proxy_http_read_response_failed")
	// ErrMsgHTTPProxyAuthFailed 代理认证失败
	ErrMsgHTTPProxyAuthFailed = i18n.GetText("proxy_http_status_failed")

	// ErrMsgTLSTCPConnFailed TLS错误消息 - TCP连接失败
	ErrMsgTLSTCPConnFailed = i18n.GetText("proxy_tls_tcp_conn_failed")
	// ErrMsgTLSHandshakeFailed TLS握手失败
	ErrMsgTLSHandshakeFailed = i18n.GetText("proxy_tls_handshake_failed")
)

// =============================================================================
// 缓存键前缀常量 (从Manager.go迁移)
// =============================================================================

const (
	// CacheKeySOCKS5 缓存键前缀 - SOCKS5代理缓存键格式
	CacheKeySOCKS5 = "socks5_%s"
	// CacheKeyHTTP HTTP代理缓存键格式
	CacheKeyHTTP = "http_%s"
)

// =============================================================================
// 格式化字符串常量 (从各文件迁移)
// =============================================================================

const (
	// SOCKS5URLFormat SOCKS5 URL格式 - 基本格式
	SOCKS5URLFormat = "socks5://%s"
	// SOCKS5URLAuthFormat 带认证的SOCKS5 URL格式
	SOCKS5URLAuthFormat = "socks5://%s:%s@%s"

	// HTTPConnectRequestFormat HTTP CONNECT请求格式 - CONNECT请求行
	HTTPConnectRequestFormat = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n"
	// HTTPAuthHeaderFormat 认证头格式
	HTTPAuthHeaderFormat = "Proxy-Authorization: Basic %s\r\n"
	// HTTPRequestEndFormat 请求结束标记
	HTTPRequestEndFormat = "\r\n"
)
