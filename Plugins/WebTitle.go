package Plugins

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// WebTitle 获取Web标题和指纹信息
func WebTitle(info *Common.HostInfo) error {
	Common.LogDebug(fmt.Sprintf("开始获取Web标题，初始信息: %+v", info))

	// 获取网站标题信息
	err, CheckData := GOWebTitle(info)
	Common.LogDebug(fmt.Sprintf("GOWebTitle执行完成 - 错误: %v, 检查数据长度: %d", err, len(CheckData)))

	info.Infostr = WebScan.InfoCheck(info.Url, &CheckData)
	Common.LogDebug(fmt.Sprintf("信息检查完成，获得信息: %v", info.Infostr))

	// 检查是否为打印机，避免意外打印
	for _, v := range info.Infostr {
		if v == "打印机" {
			Common.LogDebug("检测到打印机，停止扫描")
			return nil
		}
	}

	// 输出错误信息（如果有）
	if err != nil {
		errlog := fmt.Sprintf("网站标题 %v %v", info.Url, err)
		Common.LogError(errlog)
	}

	return err
}

// GOWebTitle 获取网站标题并处理URL
func GOWebTitle(info *Common.HostInfo) (err error, CheckData []WebScan.CheckDatas) {
	Common.LogDebug(fmt.Sprintf("开始处理URL: %s", info.Url))

	// 如果URL未指定，根据端口生成URL
	if info.Url == "" {
		Common.LogDebug("URL为空，根据端口生成URL")
		switch info.Ports {
		case "80":
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			Common.LogDebug(fmt.Sprintf("正在检测主机协议: %s", host))
			protocol := GetProtocol(host, Common.Timeout)
			Common.LogDebug(fmt.Sprintf("检测到协议: %s", protocol))
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else {
		// 处理未指定协议的URL
		if !strings.Contains(info.Url, "://") {
			Common.LogDebug("URL未包含协议，开始检测")
			host := strings.Split(info.Url, "/")[0]
			protocol := GetProtocol(host, Common.Timeout)
			Common.LogDebug(fmt.Sprintf("检测到协议: %s", protocol))
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}
	Common.LogDebug(fmt.Sprintf("协议检测完成后的URL: %s", info.Url))

	// 第一次获取URL
	Common.LogDebug("第一次尝试访问URL")
	err, result, CheckData := geturl(info, 1, CheckData)
	Common.LogDebug(fmt.Sprintf("第一次访问结果 - 错误: %v, 返回信息: %s", err, result))
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	// 处理URL跳转
	if strings.Contains(result, "://") {
		Common.LogDebug(fmt.Sprintf("检测到重定向到: %s", result))
		info.Url = result
		err, result, CheckData = geturl(info, 3, CheckData)
		Common.LogDebug(fmt.Sprintf("重定向请求结果 - 错误: %v, 返回信息: %s", err, result))
		if err != nil {
			return
		}
	}

	// 处理HTTP到HTTPS的升级
	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		Common.LogDebug("正在升级到HTTPS")
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		Common.LogDebug(fmt.Sprintf("升级后的URL: %s", info.Url))
		err, result, CheckData = geturl(info, 1, CheckData)

		// 处理升级后的跳转
		if strings.Contains(result, "://") {
			Common.LogDebug(fmt.Sprintf("HTTPS升级后发现重定向到: %s", result))
			info.Url = result
			err, _, CheckData = geturl(info, 3, CheckData)
			if err != nil {
				return
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("GOWebTitle执行完成 - 错误: %v", err))
	if err != nil {
		return
	}
	return
}

func geturl(info *Common.HostInfo, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	Common.LogDebug(fmt.Sprintf("geturl开始执行 - URL: %s, 标志位: %d", info.Url, flag))

	// 处理目标URL
	Url := info.Url
	if flag == 2 {
		Common.LogDebug("处理favicon.ico URL")
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
		Common.LogDebug(fmt.Sprintf("favicon URL: %s", Url))
	}

	// 创建HTTP请求
	Common.LogDebug("开始创建HTTP请求")
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("创建HTTP请求失败: %v", err))
		return err, "", CheckData
	}

	// 设置请求头
	req.Header.Set("User-agent", Common.UserAgent)
	req.Header.Set("Accept", Common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if Common.Cookie != "" {
		req.Header.Set("Cookie", Common.Cookie)
	}
	req.Header.Set("Connection", "close")
	Common.LogDebug("已设置请求头")

	// 选择HTTP客户端
	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect
		Common.LogDebug("使用不跟随重定向的客户端")
	} else {
		client = lib.Client
		Common.LogDebug("使用普通客户端")
	}

	// 检查客户端是否为空
	if client == nil {
		Common.LogDebug("错误: HTTP客户端为空")
		return fmt.Errorf("HTTP客户端未初始化"), "", CheckData
	}

	// 发送请求
	Common.LogDebug("开始发送HTTP请求")
	resp, err := client.Do(req)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("HTTP请求失败: %v", err))
		return err, "https", CheckData
	}
	defer resp.Body.Close()
	Common.LogDebug(fmt.Sprintf("收到HTTP响应，状态码: %d", resp.StatusCode))

	// 读取响应内容
	body, err := getRespBody(resp)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应内容失败: %v", err))
		return err, "https", CheckData
	}
	Common.LogDebug(fmt.Sprintf("成功读取响应内容，长度: %d", len(body)))

	// 保存检查数据
	CheckData = append(CheckData, WebScan.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})
	Common.LogDebug("已保存检查数据")

	// 处理非favicon请求
	var reurl string
	if flag != 2 {
		// 处理编码
		if !utf8.Valid(body) {
			body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
		}

		// 获取页面信息
		title := gettitle(body)
		length := resp.Header.Get("Content-Length")
		if length == "" {
			length = fmt.Sprintf("%v", len(body))
		}

		// 收集服务器信息
		serverInfo := make(map[string]interface{})
		serverInfo["title"] = title
		serverInfo["length"] = length
		serverInfo["status_code"] = resp.StatusCode

		// 收集响应头信息
		for k, v := range resp.Header {
			if len(v) > 0 {
				serverInfo[strings.ToLower(k)] = v[0]
			}
		}

		// 检查重定向
		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
			serverInfo["redirect_url"] = reurl
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
				"title":        title,
				"url":          resp.Request.URL.String(),
				"status_code":  resp.StatusCode,
				"length":       length,
				"server_info":  serverInfo,
				"fingerprints": info.Infostr, // 指纹信息
			},
		}
		Common.SaveResult(result)

		// 输出控制台日志
		logMsg := fmt.Sprintf("网站标题 %-25v 状态码:%-3v 长度:%-6v 标题:%v",
			resp.Request.URL, resp.StatusCode, length, title)
		if reurl != "" {
			logMsg += fmt.Sprintf(" 重定向地址: %s", reurl)
		}
		Common.LogSuccess(logMsg)
	}

	// 返回结果
	if reurl != "" {
		Common.LogDebug(fmt.Sprintf("返回重定向URL: %s", reurl))
		return nil, reurl, CheckData
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		Common.LogDebug("返回HTTPS升级标志")
		return nil, "https", CheckData
	}
	Common.LogDebug("geturl执行完成，无特殊返回")
	return nil, "", CheckData
}

// getRespBody 读取HTTP响应体内容
func getRespBody(oResp *http.Response) ([]byte, error) {
	Common.LogDebug("开始读取响应体内容")
	var body []byte

	// 处理gzip压缩的响应
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		Common.LogDebug("检测到gzip压缩，开始解压")
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			Common.LogDebug(fmt.Sprintf("创建gzip解压器失败: %v", err))
			return nil, err
		}
		defer gr.Close()

		// 循环读取解压内容
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				Common.LogDebug(fmt.Sprintf("读取压缩内容失败: %v", err))
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
		Common.LogDebug(fmt.Sprintf("gzip解压完成，内容长度: %d", len(body)))
	} else {
		// 直接读取未压缩的响应
		Common.LogDebug("读取未压缩的响应内容")
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应内容失败: %v", err))
			return nil, err
		}
		body = raw
		Common.LogDebug(fmt.Sprintf("读取完成，内容长度: %d", len(body)))
	}
	return body, nil
}

// gettitle 从HTML内容中提取网页标题
func gettitle(body []byte) (title string) {
	Common.LogDebug("开始提取网页标题")

	// 使用正则表达式匹配title标签内容
	re := regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")
	find := re.FindSubmatch(body)

	if len(find) > 1 {
		title = string(find[1])
		Common.LogDebug(fmt.Sprintf("找到原始标题: %s", title))

		// 清理标题内容
		title = strings.TrimSpace(title)                  // 去除首尾空格
		title = strings.Replace(title, "\n", "", -1)      // 去除换行
		title = strings.Replace(title, "\r", "", -1)      // 去除回车
		title = strings.Replace(title, "&nbsp;", " ", -1) // 替换HTML空格

		// 截断过长的标题
		if len(title) > 100 {
			Common.LogDebug("标题超过100字符，进行截断")
			title = title[:100]
		}

		// 处理空标题
		if title == "" {
			Common.LogDebug("标题为空，使用双引号代替")
			title = "\"\""
		}
	} else {
		Common.LogDebug("未找到标题标签")
		title = "无标题"
	}
	Common.LogDebug(fmt.Sprintf("最终标题: %s", title))
	return
}

// GetProtocol 检测目标主机的协议类型(HTTP/HTTPS)
func GetProtocol(host string, Timeout int64) (protocol string) {
	Common.LogDebug(fmt.Sprintf("开始检测主机协议 - 主机: %s, 超时: %d秒", host, Timeout))
	protocol = "http"

	// 根据标准端口快速判断协议
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		Common.LogDebug("检测到HTTP标准端口或无端口，使用HTTP协议")
		return
	} else if strings.HasSuffix(host, ":443") {
		Common.LogDebug("检测到HTTPS标准端口，使用HTTPS协议")
		protocol = "https"
		return
	}

	// 尝试建立TCP连接
	Common.LogDebug("尝试建立TCP连接")
	socksconn, err := Common.WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("TCP连接失败: %v", err))
		return
	}

	// 尝试TLS握手
	Common.LogDebug("开始TLS握手")
	conn := tls.Client(socksconn, &tls.Config{
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	})

	// 确保连接关闭
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					Common.LogError(fmt.Sprintf("连接关闭时发生错误: %v", err))
				}
			}()
			Common.LogDebug("关闭连接")
			conn.Close()
		}
	}()

	// 设置连接超时
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))

	// 执行TLS握手
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		Common.LogDebug("TLS握手成功或握手失败但确认是HTTPS协议")
		protocol = "https"
	} else {
		Common.LogDebug(fmt.Sprintf("TLS握手失败: %v，使用HTTP协议", err))
	}

	Common.LogDebug(fmt.Sprintf("协议检测完成，使用: %s", protocol))
	return protocol
}
