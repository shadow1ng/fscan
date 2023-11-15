package Plugins

import (
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
	Hosts, err := common.ParseIP(info.Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	lib.Inithttp()
	var ch = make(chan struct{}, common.Threads)
	var wg = sync.WaitGroup{}
	web := strconv.Itoa(common.PORTList["web"])
	ms17010 := strconv.Itoa(common.PORTList["ms17010"])
	if len(Hosts) > 0 || len(common.HostPort) > 0 {
		if common.NoPing == false && len(Hosts) > 1 || common.Scantype == "icmp" {
			Hosts = CheckLive(Hosts, common.Ping)
			fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
		}
		if common.Scantype == "icmp" {
			common.LogWG.Wait()
			return
		}
		var AlivePorts []string
		if common.Scantype == "webonly" || common.Scantype == "webpoc" {
			AlivePorts = NoPortScan(Hosts, common.Ports)
		} else if common.Scantype == "hostname" {
			common.Ports = "139"
			AlivePorts = NoPortScan(Hosts, common.Ports)
		} else if len(Hosts) > 0 {
			AlivePorts = PortScan(Hosts, common.Ports, common.Timeout)
			fmt.Println("[*] alive ports len is:", len(AlivePorts))
			if common.Scantype == "portscan" {
				common.LogWG.Wait()
				return
			}
		}
		if len(common.HostPort) > 0 {
			AlivePorts = append(AlivePorts, common.HostPort...)
			AlivePorts = common.RemoveDuplicate(AlivePorts)
			common.HostPort = nil
			fmt.Println("[*] AlivePorts len is:", len(AlivePorts))
		}
		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range common.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		fmt.Println("start vulscan")
		for _, targetIP := range AlivePorts {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			if common.Scantype == "all" || common.Scantype == "main" {
				switch {
				case info.Ports == "135":
					AddScan(info.Ports, info, &ch, &wg) //findnet
					if common.IsWmi {
						AddScan("1000005", info, &ch, &wg) //wmiexec
					}
				case info.Ports == "445":
					AddScan(ms17010, info, &ch, &wg) //ms17010
					//AddScan(info.Ports, info, ch, &wg)  //smb
					//AddScan("1000002", info, ch, &wg) //smbghost
				case info.Ports == "9000":
					AddScan(web, info, &ch, &wg)        //http
					AddScan(info.Ports, info, &ch, &wg) //fcgiscan
				case IsContain(severports, info.Ports):
					AddScan(info.Ports, info, &ch, &wg) //plugins scan
				default:
					AddScan(web, info, &ch, &wg) //webtitle
				}
			} else {
				scantype := strconv.Itoa(common.PORTList[common.Scantype])
				AddScan(scantype, info, &ch, &wg)
			}
		}
	}
	for _, url := range common.Urls {
		info.Url = url
		AddScan(web, info, &ch, &wg)
	}
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	fmt.Printf("已完成 %v/%v\n", common.End, common.Num)
}

var Mutex = &sync.Mutex{}

func AddScan(scantype string, info common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()
		ScanFunc(&scantype, &info)
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ScanFunc(name *string, info *common.HostInfo) {
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
