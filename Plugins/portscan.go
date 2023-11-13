package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"sort"
	"strconv"
	"sync"
	"time"
)

type Addr struct {
	ip   string
	port int
}

func PortScan(hostslist []string, ports string, timeout int64) []string {
	var AliveAddress []string
	probePorts := common.ParsePort(ports)
	if len(probePorts) == 0 {
		fmt.Printf("[-] parse port %s error, please check your port format\n", ports)
		return AliveAddress
	}
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	workers := common.Threads
	Addrs := make(chan Addr, len(hostslist)*len(probePorts))
	results := make(chan string, len(hostslist)*len(probePorts))
	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
	return AliveAddress
}

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int64, wg *sync.WaitGroup) {
	host, port := addr.ip, addr.port
	conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	if err == nil {
		defer conn.Close()
		address := host + ":" + strconv.Itoa(port)
		result := fmt.Sprintf("%s open", address)
		common.LogSuccess(result)
		wg.Add(1)
		respondingHosts <- address
	}
}

func NoPortScan(hostslist []string, ports string) (AliveAddress []string) {
	probePorts := common.ParsePort(ports)
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port, _ := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	for _, port := range probePorts {
		for _, host := range hostslist {
			address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, address)
		}
	}
	return
}
