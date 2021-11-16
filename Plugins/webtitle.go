package Plugins

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"github.com/saintfish/chardet"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	Charsets = []string{"utf-8", "gbk", "gb2312"}
)

func WebTitle(info *common.HostInfo) error {
	err := GOWebTitle(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		common.LogError(errlog)
	}
	return err
}

//flag 1 first try
//flag 2 /favicon.ico
//flag 3 302
//flag 4 400 -> https

func GOWebTitle(info *common.HostInfo) error {
	var CheckData []WebScan.CheckDatas
	if info.Url == "" {
		if info.Ports == "80" {
			info.Url = fmt.Sprintf("http://%s", info.Host)
		} else if info.Ports == "443" {
			info.Url = fmt.Sprintf("https://%s", info.Host)
		} else {
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			protocol := GetProtocol(host, info.Timeout)
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			protocol := GetProtocol(info.Url, info.Timeout)
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}

	err, result, CheckData := geturl(info, 1, CheckData)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return err
	}

	if strings.Contains(result, "://") {
		//有跳转
		redirecturl, err := url.Parse(result)
		if err == nil {
			info.Url = redirecturl.String()
			err, result, CheckData = geturl(info, 3, CheckData)
			if err != nil {
				return err
			}
		}
	}

	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData = geturl(info, 1, CheckData)
		if strings.Contains(result, "://") {
			//有跳转
			redirecturl, err := url.Parse(result)
			if err == nil {
				info.Url = redirecturl.String()
				err, result, CheckData = geturl(info, 3, CheckData)
				if err != nil {
					return err
				}
			}
		} else {
			if err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}

	err, _, CheckData = geturl(info, 2, CheckData)
	if err != nil {
		return err
	}

	info.Infostr = WebScan.InfoCheck(info.Url, CheckData)

	if common.IsWebCan == false {
		WebScan.WebScan(info)
	}
	return err
}

func geturl(info *common.HostInfo, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
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
	if err == nil {
		req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		if common.Pocinfo.Cookie != "" {
			req.Header.Set("Cookie", "rememberMe=1;"+common.Pocinfo.Cookie)
		} else {
			req.Header.Set("Cookie", "rememberMe=1")
		}
		req.Header.Set("Connection", "close")

		var client *http.Client
		if flag == 1 {
			client = lib.ClientNoRedirect
		} else {
			client = lib.Client
		}

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var title string
			var text []byte
			body, err := getRespBody(resp)
			if err != nil {
				return err, "https", CheckData
			}
			if flag != 2 {
				re := regexp.MustCompile("(?ims)<title>(.*)</title>")
				find := re.FindSubmatch(body)
				if len(find) > 1 {
					text = find[1]
					GetEncoding := func() string { // 判断Content-Type
						r1, err := regexp.Compile(`(?im)charset=\s*?([\w-]+)`)
						if err != nil {
							return ""
						}
						headerCharset := r1.FindString(resp.Header.Get("Content-Type"))
						if headerCharset != "" {
							for _, v := range Charsets { // headers 编码优先，所以放在前面
								if strings.Contains(strings.ToLower(headerCharset), v) == true {
									return v
								}
							}
						}

						r2, err := regexp.Compile(`(?im)<meta.*?charset=['"]?([\w-]+)["']?.*?>`)
						if err != nil {
							return ""
						}
						htmlCharset := r2.FindString(string(body))
						if htmlCharset != "" {
							for _, v := range Charsets {
								if strings.Contains(strings.ToLower(htmlCharset), v) == true {
									return v
								}
							}
						}
						return ""
					}
					encode := GetEncoding()
					//_, encode1, _ := charset.DetermineEncoding(body, "")
					var encode2 string
					detector := chardet.NewTextDetector()
					detectorstr, _ := detector.DetectBest(body)
					if detectorstr != nil {
						encode2 = detectorstr.Charset
					}
					if encode == "gbk" || encode == "gb2312" || strings.Contains(strings.ToLower(encode2), "gb") {
						titleGBK, err := Decodegbk(text)
						if err == nil {
							title = string(titleGBK)
						}
					} else {
						title = string(text)
					}
				} else {
					title = "None"
				}
				title = strings.Trim(title, "\r\n \t")
				title = strings.Replace(title, "\n", "", -1)
				title = strings.Replace(title, "\r", "", -1)
				title = strings.Replace(title, "&nbsp;", " ", -1)
				if len(title) > 100 {
					title = title[:100]
				}
				if title == "" {
					title = "None"
				}
				length := resp.Header.Get("Content-Length")
				if length == "" {
					length = fmt.Sprintf("%v", len(body))
				}
				result := fmt.Sprintf("[*] WebTitle:%-25v code:%-3v len:%-6v title:%v", resp.Request.URL, resp.StatusCode, length, title)
				common.LogSuccess(result)
			}
			CheckData = append(CheckData, WebScan.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})
			redirURL, err1 := resp.Location()
			if err1 == nil {
				return nil, redirURL.String(), CheckData
			}
			if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
				return err, "https", CheckData
			}
			return err, "", CheckData
		}
		return err, "https", CheckData
	}
	return err, "", CheckData
}

func Decodegbk(s []byte) ([]byte, error) { // GBK解码
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
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
		raw, err := ioutil.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

func GetProtocol(host string, Timeout int64) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(Timeout) * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	protocol := "http"
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
