package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ParsePort(ports string) []int {
	var scanPorts []int
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}
			sort.Strings(ranges)
			port = ranges[0]
			upper = ranges[1]
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	return scanPorts
}

func ProbeHosts(host string, ports <-chan int, respondingHosts chan<- string, done chan<- bool, model string, adjustedTimeout int) {
	Timeout := time.Duration(adjustedTimeout) * time.Second
	for port := range ports {
		start := time.Now()
		con, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", host, port), time.Duration(adjustedTimeout)*time.Second)
		duration := time.Now().Sub(start)
		if err == nil {
			defer con.Close()
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			respondingHosts <- address
		}
		if duration < Timeout {
			difference := Timeout - duration
			Timeout = Timeout - (difference / 2)
		}
	}
	done <- true
}

func ScanAllports(address string, probePorts []int, threads int, timeout time.Duration, model string, adjustedTimeout int) ([]string, error) {
	ports := make(chan int, 20)
	results := make(chan string, 10)
	done := make(chan bool, threads)

	for worker := 0; worker < threads; worker++ {
		go ProbeHosts(address, ports, results, done, model, adjustedTimeout)
	}

	for _, port := range probePorts {
		ports <- port
	}
	close(ports)

	var responses = []string{}
	for {
		select {
		case found := <-results:
			responses = append(responses, found)
		case <-done:
			threads--
			if threads == 0 {
				return responses, nil
			}
		case <-time.After(timeout):
			return responses, nil
		}
	}
}

func TCPportScan(hostslist []string, ports string, model string, timeout int) ([]string, []string) {
	var AliveAddress []string
	var aliveHosts []string
	probePorts := ParsePort(ports)
	lm := 20
	if len(hostslist) > 5 && len(hostslist) <= 50 {
		lm = 40
	} else if len(hostslist) > 50 && len(hostslist) <= 100 {
		lm = 50
	} else if len(hostslist) > 100 && len(hostslist) <= 150 {
		lm = 60
	} else if len(hostslist) > 150 && len(hostslist) <= 200 {
		lm = 70
	} else if len(hostslist) > 200 {
		lm = 75
	}

	thread := 5
	if len(probePorts) > 500 && len(probePorts) <= 4000 {
		thread = len(probePorts) / 100
	} else if len(probePorts) > 4000 && len(probePorts) <= 6000 {
		thread = len(probePorts) / 200
	} else if len(probePorts) > 6000 && len(probePorts) <= 10000 {
		thread = len(probePorts) / 350
	} else if len(probePorts) > 10000 && len(probePorts) < 50000 {
		thread = len(probePorts) / 400
	} else if len(probePorts) >= 50000 && len(probePorts) <= 65535 {
		thread = len(probePorts) / 500
	}

	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan struct{}, lm)
	aliveHost := make(chan string, lm/2)
	go func() {
		for s := range aliveHost {
			fmt.Println(s)
		}
	}()
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer wg.Done()
			if aliveAdd, err := ScanAllports(host, probePorts, thread, 5*time.Second, model, timeout); err == nil && len(aliveAdd) > 0 {
				mutex.Lock()
				aliveHosts = append(aliveHosts, host)
				for _, addr := range aliveAdd {
					AliveAddress = append(AliveAddress, addr)
				}
				mutex.Unlock()
			}
			<-limiter
		}(host)
	}
	wg.Wait()
	close(aliveHost)
	return aliveHosts, AliveAddress
}
