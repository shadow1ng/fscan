package Plugins

import (
	"../common"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func elasticsearchScan(info *common.HostInfo,ch chan int,wg *sync.WaitGroup)  {
	geturl2(info)
    wg.Done()
	<-ch
}


func geturl2(info *common.HostInfo) (flag bool,err error) {
	flag = false
	url := fmt.Sprintf("%s:%d/_cat",info.Url,common.PORTList["elastic"])
	var client = &http.Client{
		Transport:&http.Transport{
			DialContext:(&net.Dialer{
				Timeout:time.Duration(info.Timeout)*time.Second,
			}).DialContext,
		},
		CheckRedirect:func(req *http.Request, via []*http.Request) error{
			return http.ErrUseLastResponse
		},
	}
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
			body, _ := ioutil.ReadAll(resp.Body)
			if strings.Contains(string(body),"/_cat/master"){
				result := fmt.Sprintf("Elastic:%s unauthorized",url)
				common.LogSuccess(result)
				flag = true
			}
		}
	}
	return flag,err

	//fmt.Print("\n")
}


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