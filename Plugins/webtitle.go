package Plugins

import (
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/common"
	"io/ioutil"
	"net/http"
	"regexp"
	"sync"
	"time"
)

func WebTitle(info *common.HostInfo, ch chan int, wg *sync.WaitGroup) (err error, result string) {
	info.Url = fmt.Sprintf("http://%s:%s", info.Host, info.Ports)
	err, result = geturl(info)
	if err == nil && info.IsWebCan == false {
		WebScan.WebScan(info)
	}

	info.Url = fmt.Sprintf("https://%s:%s", info.Host, info.Ports)
	err, result = geturl(info)
	if err == nil && info.IsWebCan == false {
		WebScan.WebScan(info)
	}

	wg.Done()
	<-ch
	return err, result
}

func geturl(info *common.HostInfo) (err error, result string) {
	url := info.Url
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
			} else {
				title = "None"
			}
			if len(title) > 50 {
				title = title[:50]
			}
			result = fmt.Sprintf("WebTitle:%v %v %v", url, resp.StatusCode, title)
			common.LogSuccess(result)
			return err, result
		}
		return err, ""
	}
	return err, ""
}
