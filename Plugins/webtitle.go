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

func WebTitle(info *common.HostInfo) (err error, result string) {
	if info.Ports == "80" {
		info.Url = fmt.Sprintf("http://%s", info.Host)
	} else if info.Ports == "443" {
		info.Url = fmt.Sprintf("https://%s", info.Host)
	} else {
		info.Url = fmt.Sprintf("http://%s:%s", info.Host, info.Ports)
	}

	err, result = geturl(info)
	if info.IsWebCan || err != nil {
		return
	}

	if result == "https" {
		err, result = geturl(info)
		if err == nil {
			WebScan.WebScan(info)
		}
	} else {
		WebScan.WebScan(info)
	}
	return err, result
}

func geturl(info *common.HostInfo) (err error, result string) {
	url := info.Url
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: false,
		DialContext: (&net.Dialer{
			Timeout: time.Duration(info.WebTimeout) * time.Second,
		}).DialContext,
	}
	var client = &http.Client{Timeout: time.Duration(info.WebTimeout) * time.Second, Transport: tr}
	res, err := http.NewRequest("GET", url, nil)
	if err == nil {
		res.Header.Add("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		res.Header.Add("Accept", "*/*")
		res.Header.Add("Accept-Language", "zh-CN,zh;q=0.9")
		res.Header.Add("Accept-Encoding", "gzip, deflate")
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
			result = fmt.Sprintf("WebTitle:%-25v %-3v %v", url, resp.StatusCode, title)
			common.LogSuccess(result)
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
