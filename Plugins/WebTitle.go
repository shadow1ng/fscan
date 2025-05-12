package Plugins

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// 常量定义
const (
	maxTitleLength     = 100
	defaultProtocol    = "http"
	httpsProtocol      = "https"
	httpProtocol       = "http"
	printerFingerPrint = "打印机"
	emptyTitle         = "\"\""
	noTitleText        = "无标题"

	// HTTP相关常量
	httpPort        = "80"
	httpsPort       = "443"
	contentEncoding = "Content-Encoding"
	gzipEncoding    = "gzip"
	contentLength   = "Content-Length"
)

// 错误定义
var (
	ErrNoTitle        = fmt.Errorf("无法获取标题")
	ErrHTTPClientInit = fmt.Errorf("HTTP客户端未初始化")
	ErrReadRespBody   = fmt.Errorf("读取响应内容失败")
)

// 响应结果
type WebResponse struct {
	Url         string
	StatusCode  int
	Title       string
	Length      string
	Headers     map[string]string
	RedirectUrl string
	Body        []byte
	Error       error
}

// 协议检测结果
type ProtocolResult struct {
	Protocol string
	Success  bool
}

// WebTitle 获取Web标题和指纹信息
func WebTitle(info *Common.HostInfo) error {
	if info == nil {
		return fmt.Errorf("主机信息为空")
	}

	// 初始化Url
	if err := initializeUrl(info); err != nil {
		Common.LogError(fmt.Sprintf("初始化Url失败: %v", err))
		return err
	}

	// 获取网站标题信息
	checkData, err := fetchWebInfo(info)
	if err != nil {
		// 记录错误但继续处理可能获取的数据
		Common.LogError(fmt.Sprintf("获取网站信息失败: %s %v", info.Url, err))
	}

	// 分析指纹
	if len(checkData) > 0 {
		info.Infostr = WebScan.InfoCheck(info.Url, &checkData)

		// 检查是否为打印机，避免意外打印
		for _, v := range info.Infostr {
			if v == printerFingerPrint {
				Common.LogBase("检测到打印机，停止扫描")
				return nil
			}
		}
	}

	return err
}

// 初始化Url：根据主机和端口生成完整Url
func initializeUrl(info *Common.HostInfo) error {
	if info.Url == "" {
		// 根据端口推断Url
		switch info.Ports {
		case httpPort:
			info.Url = fmt.Sprintf("%s://%s", httpProtocol, info.Host)
		case httpsPort:
			info.Url = fmt.Sprintf("%s://%s", httpsProtocol, info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			protocol, err := detectProtocol(host, Common.Timeout)
			if err != nil {
				return fmt.Errorf("协议检测失败: %w", err)
			}
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else if !strings.Contains(info.Url, "://") {
		// 处理未指定协议的Url
		host := strings.Split(info.Url, "/")[0]
		protocol, err := detectProtocol(host, Common.Timeout)
		if err != nil {
			return fmt.Errorf("协议检测失败: %w", err)
		}
		info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
	}

	return nil
}

// 获取Web信息：标题、指纹等
func fetchWebInfo(info *Common.HostInfo) ([]WebScan.CheckDatas, error) {
	var checkData []WebScan.CheckDatas

	// 记录原始Url协议
	originalUrl := info.Url
	isHTTPS := strings.HasPrefix(info.Url, "https://")

	// 第一次尝试访问Url
	resp, err := fetchUrlWithRetry(info, false, &checkData)

	// 处理不同的错误情况
	if err != nil {
		// 如果是HTTPS并失败，尝试降级到HTTP
		if isHTTPS {
			info.Url = strings.Replace(info.Url, "https://", "http://", 1)
			resp, err = fetchUrlWithRetry(info, false, &checkData)

			// 如果HTTP也失败，恢复原始Url并返回错误
			if err != nil {
				info.Url = originalUrl
				return checkData, err
			}
		} else {
			return checkData, err
		}
	}

	// 处理重定向
	if resp != nil && resp.RedirectUrl != "" {
		info.Url = resp.RedirectUrl
		resp, err = fetchUrlWithRetry(info, true, &checkData)

		// 如果重定向后失败，尝试降级协议
		if err != nil && strings.HasPrefix(info.Url, "https://") {
			info.Url = strings.Replace(info.Url, "https://", "http://", 1)
			resp, err = fetchUrlWithRetry(info, true, &checkData)
		}
	}

	// 处理需要升级到HTTPS的情况
	if resp != nil && resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		resp, err = fetchUrlWithRetry(info, false, &checkData)

		// 如果HTTPS升级失败，回退到HTTP
		if err != nil {
			info.Url = strings.Replace(info.Url, "https://", "http://", 1)
			resp, err = fetchUrlWithRetry(info, false, &checkData)
		}

		// 处理升级后的重定向
		if resp != nil && resp.RedirectUrl != "" {
			info.Url = resp.RedirectUrl
			resp, err = fetchUrlWithRetry(info, true, &checkData)
		}
	}

	return checkData, err
}

// 尝试获取Url，支持重试
func fetchUrlWithRetry(info *Common.HostInfo, followRedirect bool, checkData *[]WebScan.CheckDatas) (*WebResponse, error) {
	// 获取页面内容
	resp, err := fetchUrl(info.Url, followRedirect)
	if err != nil {
		return nil, err
	}

	// 保存检查数据
	if resp.Body != nil && len(resp.Body) > 0 {
		headers := fmt.Sprintf("%v", resp.Headers)
		*checkData = append(*checkData, WebScan.CheckDatas{resp.Body, headers})
	}

	// 保存扫描结果
	if resp.StatusCode > 0 {
		saveWebResult(info, resp)
	}

	return resp, nil
}

// 抓取Url内容
func fetchUrl(targetUrl string, followRedirect bool) (*WebResponse, error) {
	// 创建HTTP请求
	req, err := http.NewRequest("GET", targetUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("User-agent", Common.UserAgent)
	req.Header.Set("Accept", Common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if Common.Cookie != "" {
		req.Header.Set("Cookie", Common.Cookie)
	}
	req.Header.Set("Connection", "close")

	// 选择HTTP客户端
	var client *http.Client
	if followRedirect {
		client = lib.Client
	} else {
		client = lib.ClientNoRedirect
	}

	if client == nil {
		return nil, ErrHTTPClientInit
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		// 特殊处理SSL/TLS相关错误
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "tls") || strings.Contains(errMsg, "ssl") ||
			strings.Contains(errMsg, "handshake") || strings.Contains(errMsg, "certificate") {
			return &WebResponse{Error: err}, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	// 准备响应结果
	result := &WebResponse{
		Url:        req.URL.String(),
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
	}

	// 提取响应头
	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	// 获取内容长度
	result.Length = resp.Header.Get(contentLength)

	// 检查重定向
	redirectUrl, err := resp.Location()
	if err == nil {
		result.RedirectUrl = redirectUrl.String()
	}

	// 读取响应内容
	body, err := readResponseBody(resp)
	if err != nil {
		return result, fmt.Errorf("读取响应内容失败: %w", err)
	}
	result.Body = body

	// 提取标题
	if !utf8.Valid(body) {
		body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
	}
	result.Title = extractTitle(body)

	if result.Length == "" {
		result.Length = fmt.Sprintf("%d", len(body))
	}

	return result, nil
}

// 读取HTTP响应体内容
func readResponseBody(resp *http.Response) ([]byte, error) {
	var body []byte
	var reader io.Reader = resp.Body

	// 处理gzip压缩的响应
	if resp.Header.Get(contentEncoding) == gzipEncoding {
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("创建gzip解压器失败: %w", err)
		}
		defer gr.Close()
		reader = gr
	}

	// 读取内容
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("读取响应内容失败: %w", err)
	}

	return body, nil
}

// 提取网页标题
func extractTitle(body []byte) string {
	// 使用正则表达式匹配title标签内容
	re := regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")
	find := re.FindSubmatch(body)

	if len(find) > 1 {
		title := string(find[1])

		// 清理标题内容
		title = strings.TrimSpace(title)
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)

		// 截断过长的标题
		if len(title) > maxTitleLength {
			title = title[:maxTitleLength]
		}

		// 处理空标题
		if title == "" {
			return emptyTitle
		}

		return title
	}

	return noTitleText
}

// 保存Web扫描结果
func saveWebResult(info *Common.HostInfo, resp *WebResponse) {
	// 处理指纹信息
	fingerprints := info.Infostr
	if len(fingerprints) == 1 && fingerprints[0] == "" {
		fingerprints = []string{}
	}

	// 准备服务器信息
	serverInfo := make(map[string]interface{})
	serverInfo["title"] = resp.Title
	serverInfo["length"] = resp.Length
	serverInfo["status_code"] = resp.StatusCode

	// 添加响应头信息
	for k, v := range resp.Headers {
		serverInfo[strings.ToLower(k)] = v
	}

	// 添加重定向信息
	if resp.RedirectUrl != "" {
		serverInfo["redirect_Url"] = resp.RedirectUrl
	}

	// 保存扫描结果
	result := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.SERVICE,
		Target: info.Host,
		Status: "identified",
		Details: map[string]interface{}{
			"port":         info.Ports,
			"service":      "http",
			"title":        resp.Title,
			"Url":          resp.Url,
			"status_code":  resp.StatusCode,
			"length":       resp.Length,
			"server_info":  serverInfo,
			"fingerprints": fingerprints,
		},
	}
	Common.SaveResult(result)

	// 输出控制台日志
	logMsg := fmt.Sprintf("网站标题 %-25v 状态码:%-3v 长度:%-6v 标题:%v",
		resp.Url, resp.StatusCode, resp.Length, resp.Title)

	if resp.RedirectUrl != "" {
		logMsg += fmt.Sprintf(" 重定向地址: %s", resp.RedirectUrl)
	}

	if len(fingerprints) > 0 {
		logMsg += fmt.Sprintf(" 指纹:%v", fingerprints)
	}

	Common.LogInfo(logMsg)
}

// 检测目标主机的协议类型(HTTP/HTTPS)
func detectProtocol(host string, timeout int64) (string, error) {
	// 根据标准端口快速判断协议
	if strings.HasSuffix(host, ":"+httpPort) {
		return httpProtocol, nil
	} else if strings.HasSuffix(host, ":"+httpsPort) {
		return httpsProtocol, nil
	}

	timeoutDuration := time.Duration(timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	// 并发检测HTTP和HTTPS
	resultChan := make(chan ProtocolResult, 2)
	wg := sync.WaitGroup{}
	wg.Add(2)

	// 检测HTTPS
	go func() {
		defer wg.Done()
		success := checkHTTPS(host, timeoutDuration/2)
		select {
		case resultChan <- ProtocolResult{httpsProtocol, success}:
		case <-ctx.Done():
		}
	}()

	// 检测HTTP
	go func() {
		defer wg.Done()
		success := checkHTTP(ctx, host, timeoutDuration/2)
		select {
		case resultChan <- ProtocolResult{httpProtocol, success}:
		case <-ctx.Done():
		}
	}()

	// 确保所有goroutine正常退出
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	var httpsResult, httpResult *ProtocolResult

	for result := range resultChan {
		if result.Protocol == httpsProtocol {
			r := result
			httpsResult = &r
		} else if result.Protocol == httpProtocol {
			r := result
			httpResult = &r
		}
	}

	// 决定使用哪种协议 - 优先使用HTTPS
	if httpsResult != nil && httpsResult.Success {
		return httpsProtocol, nil
	} else if httpResult != nil && httpResult.Success {
		return httpProtocol, nil
	}

	// 默认使用HTTP
	return defaultProtocol, nil
}

// 检测HTTPS协议
func checkHTTPS(host string, timeout time.Duration) bool {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
	if err == nil {
		conn.Close()
		return true
	}

	// 分析TLS错误，某些错误可能表明服务器支持TLS但有其他问题
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "handshake failure") ||
		strings.Contains(errMsg, "certificate") ||
		strings.Contains(errMsg, "tls") ||
		strings.Contains(errMsg, "x509") ||
		strings.Contains(errMsg, "secure")
}

// 检测HTTP协议
func checkHTTP(ctx context.Context, host string, timeout time.Duration) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", fmt.Sprintf("http://%s", host), nil)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向
		},
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		return true
	}

	// 尝试原始TCP连接和简单HTTP请求
	netConn, err := net.DialTimeout("tcp", host, timeout)
	if err == nil {
		defer netConn.Close()
		netConn.SetDeadline(time.Now().Add(timeout))

		// 发送简单HTTP请求
		_, err = netConn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
		if err == nil {
			// 读取响应
			buf := make([]byte, 1024)
			netConn.SetDeadline(time.Now().Add(timeout))
			n, err := netConn.Read(buf)
			if err == nil && n > 0 {
				response := string(buf[:n])
				return strings.Contains(response, "HTTP/")
			}
		}
	}

	return false
}
