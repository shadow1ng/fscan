package Plugins

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
)

func Scan(info common.HostInfo, flags common.Flags) {
	fmt.Println("start infoscan")
	Hosts, err := common.ParseIP(&info.HostPort, info.Host, flags.HostFile, flags.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	lib.Inithttp(flags)
	var ch = make(chan struct{}, flags.Threads)
	var wg = sync.WaitGroup{}
	web := strconv.Itoa(common.PORTList["web"])
	ms17010 := strconv.Itoa(common.PORTList["ms17010"])
	if len(Hosts) > 0 || len(info.HostPort) > 0 {
		if !flags.NoPing && len(Hosts) > 0 {
			Hosts = CheckLive(Hosts, flags.Ping, flags.LiveTop)
			fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
		}
		if flags.Scantype == "icmp" {
			common.LogWG.Wait()
			return
		}

		var AlivePorts []string
		if flags.Scantype == "webonly" || flags.Scantype == "webpoc" {
			AlivePorts = NoPortScan(Hosts, info.Ports, flags)
		} else if flags.Scantype == "hostname" {
			info.Ports = "139"
			AlivePorts = NoPortScan(Hosts, info.Ports, flags)
		} else if len(Hosts) > 0 {
			AlivePorts = PortScan(Hosts, info.Ports, flags)
			fmt.Println("[*] alive ports len is:", len(AlivePorts))
			if flags.Scantype == "portscan" {
				common.LogWG.Wait()
				return
			}
		}
		if len(info.HostPort) > 0 {
			AlivePorts = append(AlivePorts, info.HostPort...)
			AlivePorts = common.RemoveDuplicate(AlivePorts)
			info.HostPort = nil
			fmt.Println("[*] AlivePorts len is:", len(AlivePorts))
		}

		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range common.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		fmt.Println("start vulscan")
		for _, targetIP := range AlivePorts {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			if flags.Scantype == "all" || flags.Scantype == "main" {
				switch {
				case info.Ports == "135":
					AddScan(info.Ports, info, flags, &ch, &wg) //findnet
					if flags.IsWmi {
						AddScan("1000005", info, flags, &ch, &wg) //wmiexec
					}
				case info.Ports == "445":
					AddScan(ms17010, info, flags, &ch, &wg) //ms17010
					//AddScan(info.Ports, info, ch, &wg)  //smb
					//AddScan("1000002", info, ch, &wg) //smbghost
				case info.Ports == "9000":
					AddScan(web, info, flags, &ch, &wg)        //http
					AddScan(info.Ports, info, flags, &ch, &wg) //fcgiscan
				case IsContain(severports, info.Ports):
					AddScan(info.Ports, info, flags, &ch, &wg) //plugins scan
				default:
					AddScan(web, info, flags, &ch, &wg) //webtitle
				}
			} else {
				scantype := strconv.Itoa(common.PORTList[flags.Scantype])
				AddScan(scantype, info, flags, &ch, &wg)
			}
		}
	}

	for _, url := range flags.Urls {
		info.Url = url
		AddScan(web, info, flags, &ch, &wg)
	}

	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)

	fmt.Printf("Finished %d/%d", common.End, common.Num)
}

var Mutex = &sync.Mutex{}

func AddScan(scantype string, info common.HostInfo, flags common.Flags, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()
		ScanFunc(scantype, info, flags)
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ScanFunc(name string, info common.HostInfo, flags common.Flags) {
	f := reflect.ValueOf(PluginList[name])
	in := []reflect.Value{reflect.ValueOf(info), reflect.ValueOf(flags)}
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
