//go:build plugin_webtitle || !plugin_selective

package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/core"
	"github.com/shadow1ng/fscan/plugins"
	WebScan "github.com/shadow1ng/fscan/webscan"
	"github.com/shadow1ng/fscan/webscan/fingerprint"
	"github.com/shadow1ng/fscan/webscan/lib"
)

// 预编译正则表达式
var (
	titleRegex      = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	whitespaceRegex = regexp.MustCompile(`\s+`)
)

// WebTitlePlugin Web标题获取插件
type WebTitlePlugin struct {
	plugins.BasePlugin
}

// NewWebTitlePlugin 创建WebTitle插件
func NewWebTitlePlugin() *WebTitlePlugin {
	return &WebTitlePlugin{
		BasePlugin: plugins.NewBasePlugin("webtitle"),
	}
}

// Scan 执行WebTitle扫描
func (p *WebTitlePlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *WebScanResult {
	config := session.Config
	title, status, length, server, fingerprints, url, err := p.getWebTitle(ctx, info, config, session)
	if err != nil {
		return &WebScanResult{
			Success: false,
			Error:   err,
		}
	}

	// 构建输出：URL code:状态码 len:长度 title:标题 server:服务器 [指纹]
	titleDisplay := title
	if titleDisplay == "" {
		titleDisplay = "None"
	}
	msg := fmt.Sprintf("%-30s code:%-3d len:%-5d title:%-20s", url, status, length, titleDisplay)
	if server != "" {
		msg += fmt.Sprintf(" server:%s", server)
	}
	if len(fingerprints) > 0 {
		msg += fmt.Sprintf(" %v", fingerprints)
	}

	// 有指纹用绿色，无指纹用白色
	if len(fingerprints) > 0 {
		common.LogSuccess(msg)
	} else {
		common.LogInfo(msg)
	}

	return &WebScanResult{
		Type:         plugins.ResultTypeWeb,
		Success:      true,
		Output:       url,
		Title:        title,
		Status:       status,
		Server:       server,
		Fingerprints: fingerprints,
	}
}

func (p *WebTitlePlugin) getWebTitle(ctx context.Context, info *common.HostInfo, config *common.Config, session *common.ScanSession) (string, int, int, string, []string, string, error) {
	// 智能协议检测
	protocol := p.detectProtocol(info, config, session)
	baseURL := fmt.Sprintf("%s://%s:%d", protocol, info.Host, info.Port)

	// 构建显示用URL（隐藏标准端口）
	var displayURL string
	if (protocol == "https" && info.Port == 443) || (protocol == "http" && info.Port == 80) {
		displayURL = fmt.Sprintf("%s://%s", protocol, info.Host)
	} else {
		displayURL = baseURL
	}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return "", 0, 0, "", nil, displayURL, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// 先使用不跟随重定向的Client获取原始响应
	resp, err := lib.ClientNoRedirect.Do(req)
	if err != nil {
		return "", 0, 0, "", nil, displayURL, err
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	contentLen := len(body)
	if contentLen <= 0 && err != nil {
		return "", resp.StatusCode, 0, resp.Header.Get("Server"), nil, displayURL, err
	}

	// 收集用于指纹识别的响应数据
	var checkDataList []WebScan.CheckDatas
	checkDataList = append(checkDataList, WebScan.CheckDatas{
		Body:    body,
		Headers: p.formatHeaders(resp.Header),
		Favicon: p.fetchFaviconHash(baseURL),
	})

	title := p.extractTitle(string(body))
	statusCode := resp.StatusCode
	server := resp.Header.Get("Server")

	// 如果是3xx重定向，跟随重定向获取最终页面的指纹
	if statusCode >= 300 && statusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			// 解析重定向URL
			redirectURL := p.resolveRedirectURL(baseURL, location)
			if redirectURL != "" {
				// 发送跟随重定向的请求
				reqRedirect, err := http.NewRequestWithContext(ctx, "GET", redirectURL, nil)
				if err == nil {
					reqRedirect.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
					respRedirect, err := lib.Client.Do(reqRedirect)
					if err == nil {
						bodyRedirect, _ := io.ReadAll(respRedirect.Body)
						_ = respRedirect.Body.Close()

						if len(bodyRedirect) > 0 {
							// 添加跳转后页面的指纹数据
							checkDataList = append(checkDataList, WebScan.CheckDatas{
								Body:    bodyRedirect,
								Headers: p.formatHeaders(respRedirect.Header),
								Favicon: p.fetchFaviconHash(redirectURL),
							})

							// 如果原始页面没有标题，使用跳转后页面的标题
							if title == "" {
								title = p.extractTitle(string(bodyRedirect))
							}
						}
					}
				}
			}
		}
	}

	// 执行指纹识别（合并原始响应和跳转后响应的指纹）
	fingerprints := p.identifyFingerprintsMulti(ctx, info, baseURL, checkDataList, config)

	return title, statusCode, contentLen, server, fingerprints, displayURL, nil
}

// resolveRedirectURL 解析重定向URL，处理相对路径
func (p *WebTitlePlugin) resolveRedirectURL(baseURL, location string) string {
	// 如果是绝对URL，直接返回
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}

	// 解析基础URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	// 解析相对路径
	ref, err := url.Parse(location)
	if err != nil {
		return ""
	}

	// 合并URL
	return base.ResolveReference(ref).String()
}

// identifyFingerprintsMulti 识别多个响应的指纹并合并
func (p *WebTitlePlugin) identifyFingerprintsMulti(ctx context.Context, info *common.HostInfo, baseURL string, checkDataList []WebScan.CheckDatas, config *common.Config) []string {
	// 调用指纹识别
	fingerprints := WebScan.InfoCheck(baseURL, &checkDataList)

	// 非全量模式下，基于指纹触发POC扫描
	if !config.POC.Full && !config.POC.Disabled {
		p.triggerPocScan(ctx, info, fingerprints, config)
	}

	return fingerprints
}

// triggerPocScan 基于指纹触发POC扫描
func (p *WebTitlePlugin) triggerPocScan(ctx context.Context, info *common.HostInfo, fingerprints []string, config *common.Config) {
	target := info.Target()

	// 无指纹，跳过
	if len(fingerprints) == 0 {
		common.LogDebug(fmt.Sprintf("WebTitle %s 无匹配指纹，跳过POC扫描", target))
		return
	}

	// 检测CDN/WAF
	if cdnName := matchCDNorWAF(fingerprints); cdnName != "" {
		common.LogDebug(fmt.Sprintf("WebTitle %s 检测到%s，跳过POC扫描", target, cdnName))
		return
	}

	// 基于指纹执行POC扫描
	common.LogDebug(fmt.Sprintf("WebTitle %s 触发指纹POC扫描: %v", target, fingerprints))
	info.Info = fingerprints
	WebScan.WebScan(ctx, info, config)
}

// formatHeaders 将 HTTP Header 格式化为字符串
func (p *WebTitlePlugin) formatHeaders(headers http.Header) string {
	var builder strings.Builder
	for name, values := range headers {
		for _, value := range values {
			builder.WriteString(fmt.Sprintf("%s: %s\n", name, value))
		}
	}
	return builder.String()
}

// detectProtocol 智能检测HTTP/HTTPS协议（基于服务识别和主动探测）
func (p *WebTitlePlugin) detectProtocol(info *common.HostInfo, config *common.Config, session *common.ScanSession) string {
	host := info.Host
	port := info.Port

	serviceInfo, exists := core.GetWebServiceInfo(host, port)

	if exists {
		// 第一优先级：检查已缓存的协议检测结果
		if protocol, ok := serviceInfo.Extras["protocol"]; ok {
			return protocol
		}

		// 第二优先级：基于服务名称特征判断（仅限服务识别阶段确定的https/ssl/tls）
		// 注意：普通的"http"服务名不直接返回，因为可能是-u模式默认添加的协议
		serviceName := strings.ToLower(serviceInfo.Name)
		if common.ContainsAny(serviceName, "https", "ssl", "tls") {
			// 缓存协议信息到Extras
			if serviceInfo.Extras == nil {
				serviceInfo.Extras = make(map[string]string)
			}
			serviceInfo.Extras["protocol"] = "https"
			return "https"
		}
	}

	// 第三优先级：主动协议检测（TLS握手）
	// 对于-u模式或服务名为普通"http"的情况，进行主动检测确认
	detected := core.DetectHTTPScheme(host, port, config, session)
	if detected != "" {
		// 缓存检测结果（避免重复检测）
		if exists {
			if serviceInfo.Extras == nil {
				serviceInfo.Extras = make(map[string]string)
			}
			serviceInfo.Extras["protocol"] = detected
		}
		return detected
	}

	// 第四优先级：默认HTTP（fallback）
	return "http"
}

func (p *WebTitlePlugin) extractTitle(html string) string {
	matches := titleRegex.FindStringSubmatch(html)

	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		title = whitespaceRegex.ReplaceAllString(title, " ")

		if len(title) > 100 {
			title = title[:100] + "..."
		}

		if utf8.ValidString(title) {
			return title
		}
	}

	return ""
}

// fetchFaviconHash 下载 favicon.ico 并计算 hash
func (p *WebTitlePlugin) fetchFaviconHash(baseURL string) fingerprint.FaviconHashes {
	// 构造 favicon URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return fingerprint.FaviconHashes{}
	}
	faviconURL := fmt.Sprintf("%s://%s/favicon.ico", u.Scheme, u.Host)

	// 请求 favicon
	req, err := http.NewRequest("GET", faviconURL, nil)
	if err != nil {
		return fingerprint.FaviconHashes{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := lib.Client.Do(req)
	if err != nil {
		return fingerprint.FaviconHashes{}
	}
	defer func() { _ = resp.Body.Close() }()

	// 只处理成功响应
	if resp.StatusCode != http.StatusOK {
		return fingerprint.FaviconHashes{}
	}

	// 读取 favicon 数据（限制大小防止恶意文件）
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 最大 1MB
	if err != nil || len(data) == 0 {
		return fingerprint.FaviconHashes{}
	}

	return fingerprint.CalculateFaviconHashes(data)
}

func init() {
	RegisterWebPlugin("webtitle", func() WebPlugin {
		return NewWebTitlePlugin()
	})
}
