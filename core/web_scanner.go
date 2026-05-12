package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
)

// ===============================
// Web服务检测
// ===============================

// 全局共享 HTTP Client，复用连接池减少 TLS 握手和 TCP 建连开销
var (
	sharedHTTPClientOnce sync.Once
	sharedHTTPClient     *http.Client
)

func getSharedHTTPClient(config *common.Config) *http.Client {
	sharedHTTPClientOnce.Do(func() {
		sharedHTTPClient = createHTTPClient(config)
		// 启用 keep-alive 复用连接
		if t, ok := sharedHTTPClient.Transport.(*http.Transport); ok {
			t.DisableKeepAlives = false
			t.MaxIdleConns = 100
			t.MaxIdleConnsPerHost = 2
		}
	})
	return sharedHTTPClient
}

// WebPortDetector 简化的Web检测器 - 保持API兼容
type WebPortDetector struct{}

// GetWebPortDetector 获取检测器实例 - 保持API兼容，删除单例模式
func GetWebPortDetector() *WebPortDetector {
	return &WebPortDetector{}
}

// DetectHTTPScheme 智能检测HTTP/HTTPS协议
// 策略：TLS握手优先（快速且准确），失败后尝试HTTP
// 返回: "https", "http", 或 "" (都不是Web服务)
func DetectHTTPScheme(host string, port int, config *common.Config, session *common.ScanSession) string {
	// 优化：先快速检测 TCP 连通性
	if !isPortReachable(host, port, config, session) {
		return ""
	}

	timeout := config.Network.WebTimeout
	addr := fmt.Sprintf("%s:%d", host, port)

	// 第一步：尝试TLS握手（优先检测HTTPS）
	// 优势：握手失败代价小，不需要发送完整HTTP请求
	tlsDialer := &net.Dialer{Timeout: timeout}
	tlsConn, err := tls.DialWithDialer(
		tlsDialer,
		"tcp", addr,
		&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10, // 兼容老版本TLS
		},
	)

	if err == nil {
		_ = tlsConn.Close()
		return "https"
	}

	// TLS握手失败，记录原因

	// 第二步：尝试HTTP请求（回退检测HTTP）
	client := getSharedHTTPClient(config)

	// 使用HEAD请求（更轻量）
	httpURL := fmt.Sprintf("http://%s", addr)
	resp, err := client.Head(httpURL)
	if err == nil {
		_ = resp.Body.Close()
		return "http"
	}

	// HTTP也失败，记录并返回空
	return ""
}

// createHTTPClient 创建统一的HTTP客户端 - 支持HTTP/HTTPS和代理
func createHTTPClient(config *common.Config) *http.Client {
	timeout := config.Network.WebTimeout

	// 创建基础Transport，配置连接和 TLS 超时
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		// 设置连接超时，避免长时间等待无响应的服务器
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		// TLS 握手超时
		TLSHandshakeTimeout: timeout,
	}

	// 配置代理设置
	networkConfig := config.Network
	if networkConfig.HTTPProxy != "" {
		// 使用HTTP代理
		if proxyURL, err := url.Parse(networkConfig.HTTPProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			common.LogError(i18n.Tr("http_proxy_config_error", err))
		}
	} else if networkConfig.Socks5Proxy != "" {
		// 使用SOCKS5代理 - 需要特殊处理
		if _, err := url.Parse(networkConfig.Socks5Proxy); err == nil {
			// SOCKS5代理需要使用代理管理器
			// 这里先记录警告，建议使用HTTP代理进行Web检测
			common.LogError(i18n.GetText("socks5_not_supported_web"))
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向
		},
	}
}

// DetectHTTPServiceOnly HTTP协议检测 - 保持API兼容，简化实现
func (w *WebPortDetector) DetectHTTPServiceOnly(host string, port int, config *common.Config, session *common.ScanSession) bool {
	// 优化：先快速检测 TCP 连通性，避免在不可达端口上浪费双倍超时时间
	// 对于不存在的端口，这可以将检测时间从 2×timeout 减少到 1×timeout
	if !isPortReachable(host, port, config, session) {
		return false
	}

	client := getSharedHTTPClient(config)

	// 尝试HTTP
	if w.tryHTTP(client, host, port, "http") {
		return true
	}

	// 尝试HTTPS
	if w.tryHTTP(client, host, port, "https") {
		return true
	}

	return false
}

// isPortReachable 快速检测端口是否可达（TCP 连接测试）
// 用于在 HTTP/HTTPS 检测前过滤不可达端口，避免双重超时
func isPortReachable(host string, port int, config *common.Config, session *common.ScanSession) bool {
	timeout := config.Network.WebTimeout
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := session.DialTCP(context.Background(), "tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// tryHTTP 尝试HTTP请求 - 简化的核心逻辑
func (w *WebPortDetector) tryHTTP(client *http.Client, host string, port int, protocol string) bool {
	// 构造URL
	var url string
	if (port == 80 && protocol == "http") || (port == 443 && protocol == "https") {
		url = fmt.Sprintf("%s://%s", protocol, host)
	} else {
		url = fmt.Sprintf("%s://%s:%d", protocol, host, port)
	}

	// 发送HEAD请求
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "fscan-web-detector/2.1")
	req.Header.Set("Accept", "*/*")

	// 使用统一的SafeHTTPDo以确保遵循限速策略和代理设置
	resp, err := common.SafeHTTPDo(client, req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// 简单有效的判断：有HTTP状态码就是Web服务
	return resp.StatusCode > 0 && resp.StatusCode < 600
}

// ===============================
// 基于服务指纹的Web服务识别
// ===============================

// Web服务缓存 - 简化的全局缓存
var (
	webServiceCache = make(map[string]*ServiceInfo)
	webCacheMutex   sync.RWMutex
)

// IsWebServiceByFingerprint 基于服务指纹判断Web服务 - 保持API兼容
// 服务识别规则 - 编译期常量，避免运行时分配
var (
	nonWebKeywords = []string{
		"oracle", "mysql", "postgresql", "redis", "mongodb", "ssh",
		"telnet", "ftp", "smtp", "pop3", "imap", "ldap", "snmp", "vnc", "rdp", "smb",
	}
	webKeywords = []string{
		"http", "https", "ssl", "tls", "nginx", "apache", "iis", "tomcat",
		"jetty", "nodejs", "php", "asp", "jsp",
	}
	bannerKeywords = []string{"server:", "http/", "content-type:"}
)

// IsWebServiceByFingerprint 通过指纹判断是否为Web服务
func IsWebServiceByFingerprint(serviceInfo *ServiceInfo) bool {
	if serviceInfo == nil || serviceInfo.Name == "" {
		return false
	}

	serviceName := strings.ToLower(serviceInfo.Name)

	// 非Web服务优先检查（短路）
	for _, keyword := range nonWebKeywords {
		if strings.Contains(serviceName, keyword) {
			return false
		}
	}

	// Web服务名检查
	for _, keyword := range webKeywords {
		if strings.Contains(serviceName, keyword) {
			return true
		}
	}

	// Banner特征检查
	if serviceInfo.Banner != "" {
		banner := strings.ToLower(serviceInfo.Banner)
		for _, keyword := range bannerKeywords {
			if strings.Contains(banner, keyword) {
				return true
			}
		}
	}

	return false
}

// MarkAsWebService 标记Web服务 - 保持API兼容
func MarkAsWebService(host string, port int, serviceInfo *ServiceInfo) {
	cacheKey := fmt.Sprintf("%s:%d", host, port)

	webCacheMutex.Lock()
	defer webCacheMutex.Unlock()

	webServiceCache[cacheKey] = serviceInfo
}

// GetWebServiceInfo 获取Web服务信息
func GetWebServiceInfo(host string, port int) (*ServiceInfo, bool) {
	cacheKey := fmt.Sprintf("%s:%d", host, port)

	webCacheMutex.RLock()
	defer webCacheMutex.RUnlock()

	serviceInfo, exists := webServiceCache[cacheKey]
	return serviceInfo, exists
}

// IsMarkedWebService 检查是否已标记为Web服务
func IsMarkedWebService(host string, port int) bool {
	_, exists := GetWebServiceInfo(host, port)
	return exists
}

// ===============================
// Web扫描策略
// ===============================

// WebScanStrategy Web扫描策略
type WebScanStrategy struct {
	*BaseScanStrategy
}

// NewWebScanStrategy 创建新的Web扫描策略
func NewWebScanStrategy() *WebScanStrategy {
	return &WebScanStrategy{
		BaseScanStrategy: NewBaseScanStrategy("Web扫描", FilterWeb),
	}
}

// Name 返回策略名称
func (s *WebScanStrategy) Name() string {
	return i18n.GetText("scan_strategy_web_name")
}

// Description 返回策略描述
func (s *WebScanStrategy) Description() string {
	return i18n.GetText("scan_strategy_web_desc")
}

// Execute 执行Web扫描策略
func (s *WebScanStrategy) Execute(ctx context.Context, session *common.ScanSession, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	// 输出扫描开始信息
	s.LogScanStart()

	// 验证插件配置
	if err := s.ValidateConfiguration(); err != nil {
		common.LogError(err.Error())
		return
	}

	// 准备URL目标
	targets := s.PrepareTargets(info, session.State)

	// 输出插件信息
	s.LogPluginInfo(session.Config)

	// 执行扫描任务
	ExecuteScanTasks(ctx, session, targets, s, ch, wg)
}

// PrepareTargets 准备URL目标列表
func (s *WebScanStrategy) PrepareTargets(baseInfo common.HostInfo, state *common.State) []common.HostInfo {
	var targetInfos []common.HostInfo

	// 首先从State获取URL目标
	urls := state.GetURLs()
	for _, urlStr := range urls {
		urlInfo := s.createTargetFromURL(baseInfo, urlStr)
		if urlInfo != nil {
			targetInfos = append(targetInfos, *urlInfo)
		}
	}

	// 如果URLs为空但baseInfo.Url有值，使用baseInfo.URL
	if len(targetInfos) == 0 && baseInfo.URL != "" {
		urlInfo := s.createTargetFromURL(baseInfo, baseInfo.URL)
		if urlInfo != nil {
			targetInfos = append(targetInfos, *urlInfo)
		}
	}

	return targetInfos
}

// createTargetFromURL 从URL创建目标信息
func (s *WebScanStrategy) createTargetFromURL(baseInfo common.HostInfo, urlStr string) *common.HostInfo {
	// 确保URL包含协议头
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
	}

	// 解析URL获取Host和Port信息
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		common.LogError(i18n.Tr("url_parse_failed", urlStr, err))
		return nil
	}

	urlInfo := baseInfo
	urlInfo.URL = urlStr
	urlInfo.Host = parsedURL.Hostname()

	// 设置端口
	portStr := parsedURL.Port()
	if portStr == "" {
		// 根据协议设置默认端口
		if parsedURL.Scheme == "https" {
			urlInfo.Port = 443
		} else {
			urlInfo.Port = 80
		}
	} else {
		// 解析端口字符串为整数
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
			urlInfo.Port = port
		} else {
			// 解析失败时使用默认端口
			if parsedURL.Scheme == "https" {
				urlInfo.Port = 443
			} else {
				urlInfo.Port = 80
			}
		}
	}

	// 标记为Web服务，确保Web插件能识别此目标
	MarkAsWebService(urlInfo.Host, urlInfo.Port, &ServiceInfo{Name: "http"})

	return &urlInfo
}
