package WebScan

import (
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net/http"
	"strings"
	"time"
)


func Shiro(info *common.HostInfo) (err error, result string) {
	url := info.Url
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	var client = &http.Client{Timeout: time.Duration(info.WebTimeout) * time.Second, Transport: tr}
	res, err := http.NewRequest("GET", url, nil)
	if err == nil {
		res.Header.Add("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		res.Header.Add("Accept", "*/*")
		res.Header.Add("Cookie", "rememberMe=1")
		res.Header.Add("Accept-Language", "zh-CN,zh;q=0.9")
		res.Header.Add("Accept-Encoding", "gzip, deflate")
		res.Header.Add("Connection", "close")
		resp, err := client.Do(res)
		if err == nil {
			defer resp.Body.Close()
			for _,a := range resp.Header{
				if len(a) >1{
					for _,b :=range a{
						if strings.Contains(b,"rememberMe"){
							result = fmt.Sprintf("%v is shiro",url)
							 common.LogSuccess(result)
							return err, result
						}
					}
				}
			}
		}
	}
	return err, ""
}