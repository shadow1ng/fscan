package Plugins

import (
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/common"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var CheckData []WebScan.CheckDatas

func WebTitle(info *common.HostInfo) error {
	if info.Ports == "80" {
		info.Url = fmt.Sprintf("http://%s", info.Host)
	} else if info.Ports == "443" {
		info.Url = fmt.Sprintf("https://%s", info.Host)
	} else {
		info.Url = fmt.Sprintf("http://%s:%s", info.Host, info.Ports)
	}

	err, result := geturl(info, true)
	if err != nil {
		return err
	}
	if result == "https" {
		err, _ := geturl(info, true)
		if err != nil {
			return err
		}
	}

	err, _ = geturl(info, false)
	if err != nil {
		return err
	}

	WebScan.InfoCheck(info.Url, CheckData)

	if common.IsWebCan == false {
		WebScan.WebScan(info)
	}

	return err
}

func geturl(info *common.HostInfo, flag bool) (err error, result string) {
	Url := info.Url
	if flag == false {
		Url += "/favicon.ico"
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: false,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(info.WebTimeout) * time.Second,
			KeepAlive: time.Duration(info.WebTimeout+3) * time.Second,
		}).DialContext,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:     time.Duration(info.WebTimeout+3) * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	//u, err := url.Parse("http://127.0.0.1:8080")
	//if err != nil {
	//	return err,result
	//}
	//tr.Proxy = http.ProxyURL(u)

	var client = &http.Client{Timeout: time.Duration(info.WebTimeout) * time.Second, Transport: tr}
	res, err := http.NewRequest("GET", Url, nil)
	if err == nil {
		res.Header.Add("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		res.Header.Add("Accept", "*/*")
		res.Header.Add("Accept-Language", "zh-CN,zh;q=0.9")
		res.Header.Add("Accept-Encoding", "gzip, deflate")
		if flag == true {
			res.Header.Add("Cookie", "rememberMe=1")
		}
		res.Header.Add("Connection", "close")
		resp, err := client.Do(res)
		if err == nil {
			defer resp.Body.Close()
			var title string
			body, _ := ioutil.ReadAll(resp.Body)
			re := regexp.MustCompile("<title>(.*)</title>")
			find := re.FindAllStringSubmatch(string(body), -1)
			if len(find) > 0 {
				title = find[0][1]
				if len(title) > 100 {
					title = title[:100]
				}
			} else {
				title = "None"
			}
			if flag == true {
				result = fmt.Sprintf("WebTitle:%-25v %-3v %v", Url, resp.StatusCode, title)
				common.LogSuccess(result)
			}

			CheckData = append(CheckData, WebScan.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})

			if resp.StatusCode == 400 && info.Url[:5] != "https" {
				info.Url = strings.Replace(info.Url, "http://", "https://", 1)
				return err, "https"
			}
			return err, result
		}
		return err, ""
	}
	return err, ""
}
