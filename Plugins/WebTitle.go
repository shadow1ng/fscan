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

// WebTitle 获取Web标题并执行扫描
func WebTitle(info *Common.HostInfo) error {
	// 获取网站标题信息
	err, CheckData := GOWebTitle(info)
	info.Infostr = WebScan.InfoCheck(info.Url, &CheckData)

	// 检查是否为打印机，避免意外打印
	for _, v := range info.Infostr {
		if v == "打印机" {
			return nil
		}
	}

	// 根据配置决定是否执行漏洞扫描
	if !Common.DisablePoc && err == nil {
		WebScan.WebScan(info)
	} else {
		errlog := fmt.Sprintf("[-] 网站标题 %v %v", info.Url, err)
		Common.LogError(errlog)
	}

	return err
}

// GOWebTitle 获取网站标题并处理URL
func GOWebTitle(info *Common.HostInfo) (err error, CheckData []WebScan.CheckDatas) {
	// 如果URL未指定，根据端口生成URL
	if info.Url == "" {
		switch info.Ports {
		case "80":
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			protocol := GetProtocol(host, Common.Timeout)
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else {
		// 处理未指定协议的URL
		if !strings.Contains(info.Url, "://") {
			host := strings.Split(info.Url, "/")[0]
			protocol := GetProtocol(host, Common.Timeout)
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}

	// 第一次获取URL
	err, result, CheckData := geturl(info, 1, CheckData)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	// 处理URL跳转
	if strings.Contains(result, "://") {
		info.Url = result
		err, result, CheckData = geturl(info, 3, CheckData)
		if err != nil {
			return
		}
	}

	// 处理HTTP到HTTPS的升级
	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData = geturl(info, 1, CheckData)

		// 处理升级后的跳转
		if strings.Contains(result, "://") {
			info.Url = result
			err, _, CheckData = geturl(info, 3, CheckData)
			if err != nil {
				return
			}
		}
	}

	if err != nil {
		return
	}
	return
}

// geturl 获取URL响应内容和信息
// 参数：
//   - info: 主机配置信息
//   - flag: 请求类型标志(1:首次尝试 2:获取favicon 3:处理302跳转 4:处理400转https)
//   - CheckData: 检查数据数组
//
// 返回：
//   - error: 错误信息
//   - string: 重定向URL或协议
//   - []WebScan.CheckDatas: 更新后的检查数据
func geturl(info *Common.HostInfo, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	// 处理目标URL
	Url := info.Url
	if flag == 2 {
		// 获取favicon.ico的URL
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}

	// 创建HTTP请求
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
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

	// 选择HTTP客户端
	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect // 不跟随重定向
	} else {
		client = lib.Client // 跟随重定向
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return err, "https", CheckData
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := getRespBody(resp)
	if err != nil {
		return err, "https", CheckData
	}

	// 保存检查数据
	CheckData = append(CheckData, WebScan.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})

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

		// 处理重定向
		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
		}

		// 输出结果
		result := fmt.Sprintf("[*] 网站标题 %-25v 状态码:%-3v 长度:%-6v 标题:%v",
			resp.Request.URL, resp.StatusCode, length, title)
		if reurl != "" {
			result += fmt.Sprintf(" 重定向地址: %s", reurl)
		}
		Common.LogSuccess(result)
	}

	// 返回结果
	if reurl != "" {
		return nil, reurl, CheckData
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		return nil, "https", CheckData
	}
	return nil, "", CheckData
}

// getRespBody 读取HTTP响应体内容
func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte

	// 处理gzip压缩的响应
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()

		// 循环读取解压内容
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		// 直接读取未压缩的响应
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

// gettitle 从HTML内容中提取网页标题
func gettitle(body []byte) (title string) {
	// 使用正则表达式匹配title标签内容
	re := regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")
	find := re.FindSubmatch(body)

	if len(find) > 1 {
		title = string(find[1])

		// 清理标题内容
		title = strings.TrimSpace(title)                  // 去除首尾空格
		title = strings.Replace(title, "\n", "", -1)      // 去除换行
		title = strings.Replace(title, "\r", "", -1)      // 去除回车
		title = strings.Replace(title, "&nbsp;", " ", -1) // 替换HTML空格

		// 截断过长的标题
		if len(title) > 100 {
			title = title[:100]
		}

		// 处理空标题
		if title == "" {
			title = "\"\"" // 空标题显示为双引号
		}
	} else {
		title = "无标题" // 没有找到title标签
	}
	return
}

// GetProtocol 检测目标主机的协议类型(HTTP/HTTPS)
func GetProtocol(host string, Timeout int64) (protocol string) {
	protocol = "http"

	// 根据标准端口快速判断协议
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}

	// 尝试建立TCP连接
	socksconn, err := Common.WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}

	// 尝试TLS握手
	conn := tls.Client(socksconn, &tls.Config{
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	})

	// 确保连接关闭
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					Common.LogError(err)
				}
			}()
			conn.Close()
		}
	}()

	// 设置连接超时
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))

	// 执行TLS握手
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}

	return protocol
}
