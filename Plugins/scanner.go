package Plugins

import (
	"../common"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
)
func scan_func(m map[string]interface{}, name string, infos ...interface{}) (result []reflect.Value, err error) {
	f := reflect.ValueOf(m[name])
	if len(infos) != f.Type().NumIn() {
		err = errors.New("The number of infos is not adapted.")
		if err != nil {
			fmt.Println(err.Error())
		//	//os.Exit(0)
		}
	}
	in := make([]reflect.Value, len(infos))
	for k, info := range infos {
		in[k] = reflect.ValueOf(info)
	}
	result = f.Call(in)
	return result,nil
}
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func Scan(info *common.HostInfo)  {
	Hosts,_ :=  common.ParseIP(info.Host)
	if info.Isping == false{
		Hosts =  ICMPRun(Hosts)
	}
	_,AlivePorts := TCPportScan(Hosts,info.Ports,"icmp",3)   //return AliveHosts,AlivePorts
	var severports  []string         	//severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"}
	for _,port:=range common.PORTList{
		severports = append(severports,strconv.Itoa(port))
	}
	severports1 := []string{"1521"}
	var ch = make(chan int,info.Threads)
	var wg = sync.WaitGroup{}
	var scantype string
	for _,targetIP :=range AlivePorts{
		scan_ip,scan_port := strings.Split(targetIP,":")[0],strings.Split(targetIP,":")[1]
		info.Host = scan_ip
		if info.Scantype == "all"{
			if IsContain(severports,scan_port){
				//scantype = scan_port
				AddScan(scan_port,info,ch,&wg)
			}else {
				if !IsContain(severports1,scan_port){
					info.Url = fmt.Sprintf("http://%s",targetIP)
					wg.Add(1)
					go WebTitle(info,ch,&wg)  					//go scan_func(PluginList,"WebTitle",info,ch,&wg)
					ch <- 1
				}
			}
			if scan_port == "445"{
				AddScan("1000001",info,ch,&wg)
				AddScan("1000002",info,ch,&wg)
			}

		}else {
			port,_:=common.PORTList[info.Scantype]
			scantype = strconv.Itoa(port)
			AddScan(scantype,info,ch,&wg)
			//wg.Add(1)
			//go scan_func(PluginList,scantype,info,ch,&wg)
			//ch <- 1
		}
	}
	wg.Wait()
}

func AddScan(scantype string,info *common.HostInfo,ch chan int,wg *sync.WaitGroup)  {
	wg.Add(1)
	go scan_func(PluginList,scantype,info,ch,wg)
	ch <- 1
}