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

	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func WebTitle(info common.HostInfo, flags common.Flags) error {
	if flags.Scantype == "webpoc" {
		WebScan.WebScan(info, flags)
		return nil
	}
	err, CheckData := GOWebTitle(info, flags)
	info.Infostr = WebScan.InfoCheck(info.Url, &CheckData)

	if flags.IsWebCan && err == nil {
		WebScan.WebScan(info, flags)
	} else {
		errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		common.LogError(errlog)
	}
	return err
}
func GOWebTitle(info common.HostInfo, flags common.Flags) (err error, CheckData []WebScan.CheckDatas) {
	if info.Url == "" {
		switch info.Ports {
		case "80":
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			protocol := GetProtocol(host, common.Socks5{Address: flags.Socks5Proxy}, flags.Timeout)
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			host := strings.Split(info.Url, "/")[0]
			protocol := GetProtocol(host, common.Socks5{Address: flags.Socks5Proxy}, flags.Timeout)
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}

	err, result, CheckData := geturl(info, flags, 1, CheckData)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	// there is a jump
	if strings.Contains(result, "://") {
		info.Url = result
		err, result, CheckData = geturl(info, flags, 3, CheckData)
		if err != nil {
			return
		}
	}

	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData = geturl(info, flags, 1, CheckData)
		// there is a jump
		if strings.Contains(result, "://") {
			info.Url = result
			err, _, CheckData = geturl(info, flags, 3, CheckData)
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

func geturl(info common.HostInfo, flags common.Flags, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	//flag 1 first try
	//flag 2 /favicon.ico
	//flag 3 302
	//flag 4 400 -> https

	Url := info.Url
	if flag == 2 {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return err, "", CheckData
	}
	req.Header.Set("User-agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}

	req.Header.Set("Connection", "close")
	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect
	} else {
		client = lib.Client
	}

	resp, err := client.Do(req)
	if err != nil {
		return err, "https", CheckData
	}

	defer resp.Body.Close()
	var title string
	body, err := getRespBody(resp)
	if err != nil {
		return err, "https", CheckData
	}
	if !utf8.Valid(body) {
		body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
	}
	CheckData = append(CheckData, WebScan.CheckDatas{Body: body, Headers: fmt.Sprintf("%s", resp.Header)})
	var reurl string
	if flag != 2 {
		title = gettitle(body)
		length := resp.Header.Get("Content-Length")
		if length == "" {
			length = fmt.Sprintf("%v", len(body))
		}
		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
		}
		result := fmt.Sprintf("[*] WebTitle: %-25v code:%-3v len:%-6v title:%v", resp.Request.URL, resp.StatusCode, length, title)
		if reurl != "" {
			result += fmt.Sprintf(" jump url: %s", reurl)
		}
		common.LogSuccess(result)
	}
	if reurl != "" {
		return nil, reurl, CheckData
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		return nil, "https", CheckData
	}
	return nil, "", CheckData
}

func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
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
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

func gettitle(body []byte) (title string) {
	re := regexp.MustCompile("(?ims)<title>(.*?)</title>")
	find := re.FindSubmatch(body)
	if len(find) > 1 {
		title = string(find[1])
		title = strings.TrimSpace(title)
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)
		if len(title) > 100 {
			title = title[:100]
		}
	}
	if title == "" {
		title = "None"
	}
	return
}

func GetProtocol(host string, proxy common.Socks5, Timeout int64) (protocol string) {
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return "http"
	}

	if strings.HasSuffix(host, ":443") {
		return "https"
	}

	socksconn, err := common.WrapperTcpWithTimeout("tcp", host, proxy, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}
	conn := tls.Client(socksconn, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					common.LogError(err)
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
