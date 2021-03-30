package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

func WebTitle(info *common.HostInfo) error {
	err := GOWebTitle(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		common.LogError(errlog)
	}
	return err
}

func GOWebTitle(info *common.HostInfo) error {
	var CheckData []WebScan.CheckDatas
	if info.Url == "" {
		if info.Ports == "80" {
			info.Url = fmt.Sprintf("http://%s", info.Host)
		} else if info.Ports == "443" {
			info.Url = fmt.Sprintf("https://%s", info.Host)
		} else {
			info.Url = fmt.Sprintf("http://%s:%s", info.Host, info.Ports)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			info.Url = fmt.Sprintf("http://%s", info.Url)
		}
	}

	err, result, CheckData := geturl(info, true, CheckData)
	if err != nil {
		return err
	}

	if result == "https" {
		err, _, CheckData = geturl(info, true, CheckData)
		if err != nil {
			return err
		}
	}

	err, _, CheckData = geturl(info, false, CheckData)
	if err != nil {
		return err
	}

	WebScan.InfoCheck(info.Url, CheckData)

	if common.IsWebCan == false {
		WebScan.WebScan(info)
	}
	return err
}

func geturl(info *common.HostInfo, flag bool, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	Url := info.Url
	if flag == false {
		Url += "/favicon.ico"
	}
	res, err := http.NewRequest("GET", Url, nil)
	if err == nil {
		res.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		res.Header.Set("Accept", "*/*")
		res.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		res.Header.Set("Accept-Encoding", "gzip, deflate")
		if common.Pocinfo.Cookie != "" {
			res.Header.Set("Cookie", common.Pocinfo.Cookie)
		}
		if flag == true {
			res.Header.Set("Cookie", "rememberMe=1;"+common.Pocinfo.Cookie)
		}
		res.Header.Set("Connection", "close")
		resp, err := lib.Client.Do(res)
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
				result := fmt.Sprintf("[*] WebTitle:%-25v %-3v %v", Url, resp.StatusCode, title)
				common.LogSuccess(result)
			}

			CheckData = append(CheckData, WebScan.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})

			if resp.StatusCode == 400 && info.Url[:5] != "https" {
				info.Url = strings.Replace(info.Url, "http://", "https://", 1)
				return err, "https", CheckData
			}
			return err, "", CheckData
		}
		return err, "", CheckData
	}
	return err, "", CheckData
}
