package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

func Scan(info common.HostInfo) {
	fmt.Println("start infoscan")
	Hosts, _ := common.ParseIP(info.Host, common.HostFile)
	lib.Inithttp(common.Pocinfo)
	var ch = make(chan struct{}, common.Threads)
	var wg = sync.WaitGroup{}
	if len(Hosts) > 0 {
		if common.IsPing == false {
			Hosts = ICMPRun(Hosts, common.Ping)
			fmt.Println("icmp alive hosts len is:", len(Hosts))
		}
		if info.Scantype == "icmp" {
			return
		}
		AlivePorts := PortScan(Hosts, info.Ports, info.Timeout)
		fmt.Println("alive ports len is:", len(AlivePorts))
		if info.Scantype == "portscan" {
			return
		}

		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range common.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		fmt.Println("start vulscan")
		for _, targetIP := range AlivePorts {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			if info.Scantype == "all" {
				switch {
				case info.Ports == "445":
					//AddScan(info.Ports, info, ch, &wg)  //smb
					AddScan("1000001", info, ch, &wg) //ms17010
					AddScan("1000002", info, ch, &wg) //smbghost
				case info.Ports == "9000":
					AddScan(info.Ports, info, ch, &wg) //fcgiscan
					AddScan("1000003", info, ch, &wg)  //http
				case IsContain(severports, info.Ports):
					AddScan(info.Ports, info, ch, &wg) //plugins scan
				default:
					AddScan("1000003", info, ch, &wg) //webtitle
				}
			} else {
				port, _ := common.PORTList[info.Scantype]
				scantype := strconv.Itoa(port)
				AddScan(scantype, info, ch, &wg)
			}
		}
	}
	if common.URL != "" {
		info.Url = common.URL
		AddScan("1000003", info, ch, &wg)
	}
	if len(common.Urls) > 0 {
		for _, url := range common.Urls {
			info.Url = url
			AddScan("1000003", info, ch, &wg)
		}
	}
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	fmt.Println(fmt.Sprintf("已完成 %v/%v", common.End, common.Num))
}

var Mutex = &sync.Mutex{}

func AddScan(scantype string, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()
		ScanFunc(PluginList, scantype, &info)
		wg.Done()
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
		<-ch
	}()
	ch <- struct{}{}
}

func ScanFunc(m map[string]interface{}, name string, infos ...interface{}) (result []reflect.Value, err error) {
	f := reflect.ValueOf(m[name])
	if len(infos) != f.Type().NumIn() {
		err = errors.New("The number of infos is not adapted ")
		fmt.Println(err.Error())
		return result, nil
	}
	in := make([]reflect.Value, len(infos))
	for k, info := range infos {
		in[k] = reflect.ValueOf(info)
	}
	result = f.Call(in)
	return result, nil
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
