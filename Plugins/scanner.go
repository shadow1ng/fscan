package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

func Scan(info common.HostInfo) {
	fmt.Println("scan start")
	Hosts, _ := common.ParseIP(info.Host, info.HostFile)
	if info.Isping == false {
		Hosts = ICMPRun(Hosts, info.IcmpThreads, info.Ping)
		fmt.Println("icmp alive hosts len is:", len(Hosts))
	}
	AlivePorts := TCPportScan(Hosts, info.Ports, info.Timeout)
	if info.Scantype == "portscan" {
		return
	}
	var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
	for _, port := range common.PORTList {
		severports = append(severports, strconv.Itoa(port))
	}
	var ch = make(chan struct{}, info.Threads)
	var wg = sync.WaitGroup{}
	for _, targetIP := range AlivePorts {
		info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
		if info.Scantype == "all" {
			if IsContain(severports, info.Ports) {
				AddScan(info.Ports, info, ch, &wg)
			} else {
				AddScan("1000003", info, ch, &wg) //webtitle
			}
			if info.Ports == "445" { //scan more vul
				AddScan("1000001", info, ch, &wg)
				AddScan("1000002", info, ch, &wg)
			}
		} else {
			port, _ := common.PortlistBack[info.Scantype]
			scantype := strconv.Itoa(port)
			AddScan(scantype, info, ch, &wg)
		}
	}
	wg.Wait()
	common.WaitSave()
}

func AddScan(scantype string, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		err, _ := ScanFunc(PluginList, scantype, &info)
		if info.Debug {
			tmperr := err[0].Interface()
			if tmperr != nil {
				tmperr1 := err[0].Interface().(error)
				errtext := strings.Replace(tmperr1.Error(), "\n", "", -1)
				fmt.Println(info.Host+":"+info.Ports, errtext)
			}
		}
		wg.Done()
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
