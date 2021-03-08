package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
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
	workers := common.Threads
	Addrs := make(chan Addr)
	results := make(chan string)
	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			Addrs <- Addr{host, port}
			wg.Add(1)
		}
	}

	wg.Wait()
	close(Addrs)
	close(results)
	return AliveAddress
}

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int64) {
	host, port := addr.ip, addr.port
	con, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", host, port), time.Duration(adjustedTimeout)*time.Second)
	if err == nil {
		con.Close()
		address := host + ":" + strconv.Itoa(port)
		result := fmt.Sprintf("%s open", address)
		common.LogSuccess(result)
		respondingHosts <- address
	}
}
