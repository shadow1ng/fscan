package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"io/ioutil"
	"net/http"
	"strings"
)

func elasticsearchScan(info *common.HostInfo) error {
	_, err := geturl2(info)
	return err
}

func geturl2(info *common.HostInfo) (flag bool, err error) {
	flag = false
	url := fmt.Sprintf("%s:%v/_cat", info.Url, info.Ports)
	res, err := http.NewRequest("GET", url, nil)
	if err == nil {
		res.Header.Add("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		res.Header.Add("Accept", "*/*")
		res.Header.Add("Accept-Language", "zh-CN,zh;q=0.9")
		res.Header.Add("Accept-Encoding", "gzip, deflate")
		res.Header.Add("Connection", "close")
		if common.Pocinfo.Cookie != "" {
			res.Header.Set("Cookie", common.Pocinfo.Cookie)
		}
		resp, err := lib.Client.Do(res)
		if err == nil {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			if strings.Contains(string(body), "/_cat/master") {
				result := fmt.Sprintf("[+] Elastic:%s unauthorized", url)
				common.LogSuccess(result)
				flag = true
			}
		} else {
			errlog := fmt.Sprintf("[-] Elastic:%s %v", url, err)
			common.LogError(errlog)
		}
	}
	return flag, err
}
