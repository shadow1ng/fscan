package Plugins

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
)

type Addr struct {
	ip   string
	port int
}

func PortScan(hostslist []string, ports string, flags common.Flags) []string {
	var AliveAddress []string
	probePorts := common.ParsePort(ports)
	noPorts := common.ParsePort(flags.NoPorts)
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
	workers := flags.Threads
	Addrs := make(chan Addr, len(hostslist)*len(probePorts))
	results := make(chan string, len(hostslist)*len(probePorts))
	var wg sync.WaitGroup

	// receive result
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			wg.Done()
		}
	}()

	// multithreaded scan
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, common.Socks5{Address: flags.Socks5Proxy}, results, flags.Timeout, &wg)
				wg.Done()
			}
		}()
	}

	// add scan target
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

func PortConnect(addr Addr, socks5Proxy common.Socks5, respondingHosts chan<- string, adjustedTimeout int64, wg *sync.WaitGroup) {
	host, port := addr.ip, addr.port
	conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), socks5Proxy, time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		address := host + ":" + strconv.Itoa(port)
		result := fmt.Sprintf("%s open", address)
		common.LogSuccess(result)
		wg.Add(1)
		respondingHosts <- address
	}
}

func NoPortScan(hostslist []string, ports string, flags common.Flags) (AliveAddress []string) {
	probePorts := common.ParsePort(ports)
	noPorts := common.ParsePort(flags.NoPorts)
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

	for _, port := range probePorts {
		for _, host := range hostslist {
			address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, address)
		}
	}
	return
}
