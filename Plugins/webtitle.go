package Plugins

import (
	"../common"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

func WebTitle(info *common.HostInfo,ch chan int,wg *sync.WaitGroup) (err error, result string) {
	err,result = geturl(info)
    wg.Done()
	<-ch
	return err, result
}


func geturl(info *common.HostInfo) (err error, result string) {
	url := info.Url
	var client = &http.Client{Timeout:time.Duration(info.Timeout)*time.Second }
	res,err:=http.NewRequest("GET",url,nil)
	if err==nil{
		res.Header.Add("User-agent","Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		res.Header.Add("Accept","*/*")
		res.Header.Add("Accept-Language","zh-CN,zh;q=0.9")
		res.Header.Add("Accept-Encoding","gzip, deflate")
		res.Header.Add("Connection","close")
		resp,err:=client.Do(res)
		if err==nil{
			defer resp.Body.Close()
			var title string
			body, _ := ioutil.ReadAll(resp.Body)
			re :=regexp.MustCompile("<title>(.*)</title>")
			find := re.FindAllStringSubmatch(string(body),-1)
			if len(find) > 0{
				title = find[0][1]
			}else {
				title = "None"
			}
			if len(title) > 50{
				title = title[:50]
			}
			if resp.StatusCode == 400 &&  string(url[5]) != "https"{
				info.Url = strings.Replace(url, "http://", "https://", 1)
				return geturl(info)
			}else {
				result = fmt.Sprintf("WebTitle:%v %v %v",url,resp.StatusCode,title)
				common.LogSuccess(result)
			}
			return err, result
		}
	}
	return err, ""

	//fmt.Print("\n")
}
//var client = &http.Client{
//	Transport:&http.Transport{
//		DialContext:(&net.Dialer{
//			Timeout:time.Duration(info.Timeout)*time.Second,
//		}).DialContext,
//	},
//	CheckRedirect:func(req *http.Request, via []*http.Request) error{
//		return http.ErrUseLastResponse
//	},
//}

//if info.Cookie!=""{
//	res.Header.Add("Cookie",info.Cookie)
//}
//if info.Header!=""{
//	var header = make(map[string]string)
//	err:=json.Unmarshal([]byte(info.Header),&header)
//	if err!=nil{
//		Misc.CheckErr(err)
//	}
//	for k,v:=range header{
//		res.Header.Add(k,v)
//	}
//}