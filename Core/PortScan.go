package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Addr represents the address to be scanned
type Addr struct {
	ip   string // IP address
	port int    // Port number
}

// ScanResult scanning result
type ScanResult struct {
	Address string       // IP address
	Port    int          // Port number
	Service *ServiceInfo // Service information
}

// PortScan executes port scanning
// hostslist: List of hosts to be scanned
// ports: Port range to be scanned
// timeout: Timeout in seconds
// Returns list of active addresses
func PortScan(hostslist []string, ports string, timeout int64) []string {
	var results []ScanResult
	var aliveAddrs []string
	var mu sync.Mutex

	// Parse and validate port list
	probePorts := Common.ParsePort(ports)
	if len(probePorts) == 0 {
		Common.LogError(fmt.Sprintf("Invalid port format: %s", ports))
		return aliveAddrs
	}

	// Exclude specified ports
	probePorts = excludeNoPorts(probePorts)

	// Initialize concurrency control
	workers := Common.ThreadNum
	addrs := make(chan Addr, 100)           // Channel for addresses to be scanned
	scanResults := make(chan ScanResult, 100) // Channel for scan results
	var wg sync.WaitGroup
	var workerWg sync.WaitGroup

	// Start scanning worker goroutines
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for addr := range addrs {
				PortConnect(addr, scanResults, timeout, &wg)
			}
		}()
	}

	// Start result processing goroutine
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range scanResults {
			mu.Lock()
			results = append(results, result)
			aliveAddr := fmt.Sprintf("%s:%d", result.Address, result.Port)
			aliveAddrs = append(aliveAddrs, aliveAddr)
			mu.Unlock()
		}
	}()

	// Distribute scanning tasks
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			addrs <- Addr{host, port}
		}
	}

	// Wait for all tasks to complete
	close(addrs)
	workerWg.Wait()
	wg.Wait()
	close(scanResults)
	resultWg.Wait()

	return aliveAddrs
}

// PortConnect performs connection detection for a single port
// addr: Address to be detected
// results: Results channel
// timeout: Timeout duration
// wg: Wait group
func PortConnect(addr Addr, results chan<- ScanResult, timeout int64, wg *sync.WaitGroup) {
	defer wg.Done()

	var isOpen bool
	var err error
	var conn net.Conn

	// Try to establish TCP connection
	conn, err = Common.WrapperTcpWithTimeout("tcp4",
		fmt.Sprintf("%s:%v", addr.ip, addr.port),
		time.Duration(timeout)*time.Second)
	if err == nil {
		defer conn.Close()
		isOpen = true
	}

	if err != nil || !isOpen {
		return
	}

	// Record open port
	address := fmt.Sprintf("%s:%d", addr.ip, addr.port)
	Common.LogSuccess(fmt.Sprintf("Port open %s", address))

	// Save port scan result
	portResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.PORT,
		Target: addr.ip,
		Status: "open",
		Details: map[string]interface{}{
			"port": addr.port,
		},
	}
	Common.SaveResult(portResult)

	// Construct scan result
	result := ScanResult{
		Address: addr.ip,
		Port:    addr.port,
	}

	// Perform service identification
	if !Common.SkipFingerprint && conn != nil {
		scanner := NewPortInfoScanner(addr.ip, addr.port, conn, time.Duration(timeout)*time.Second)
		if serviceInfo, err := scanner.Identify(); err == nil {
			result.Service = serviceInfo

			// Construct service identification log
			var logMsg strings.Builder
			logMsg.WriteString(fmt.Sprintf("Service identification %s => ", address))

			if serviceInfo.Name != "unknown" {
				logMsg.WriteString(fmt.Sprintf("[%s]", serviceInfo.Name))
			}

			if serviceInfo.Version != "" {
				logMsg.WriteString(fmt.Sprintf(" Version:%s", serviceInfo.Version))
			}

			// Collect service details
			details := map[string]interface{}{
				"port":    addr.port,
				"service": serviceInfo.Name,
			}

			// Add version information
			if serviceInfo.Version != "" {
				details["version"] = serviceInfo.Version
			}

			// Add product information
			if v, ok := serviceInfo.Extras["vendor_product"]; ok && v != "" {
				details["product"] = v
				logMsg.WriteString(fmt.Sprintf(" Product:%s", v))
			}

			// Add operating system information
			if v, ok := serviceInfo.Extras["os"]; ok && v != "" {
				details["os"] = v
				logMsg.WriteString(fmt.Sprintf(" OS:%s", v))
			}

			// Add additional information
			if v, ok := serviceInfo.Extras["info"]; ok && v != "" {
				details["info"] = v
				logMsg.WriteString(fmt.Sprintf(" Info:%s", v))
			}

			// Add Banner information
			if len(serviceInfo.Banner) > 0 && len(serviceInfo.Banner) < 100 {
				details["banner"] = strings.TrimSpace(serviceInfo.Banner)
				logMsg.WriteString(fmt.Sprintf(" Banner:[%s]", strings.TrimSpace(serviceInfo.Banner)))
			}

			// Save service identification result
			serviceResult := &Common.ScanResult{
				Time:    time.Now(),
				Type:    Common.SERVICE,
				Target:  addr.ip,
				Status:  "identified",
				Details: details,
			}
			Common.SaveResult(serviceResult)

			Common.LogSuccess(logMsg.String())
		}
	}

	results <- result
}

// NoPortScan generates a port list (without scanning)
// hostslist: Host list
// ports: Port range
// Returns address list
func NoPortScan(hostslist []string, ports string) []string {
	var AliveAddress []string

	// Parse and exclude ports
	probePorts := excludeNoPorts(Common.ParsePort(ports))

	// Generate address list
	for _, port := range probePorts {
		for _, host := range hostslist {
			address := fmt.Sprintf("%s:%d", host, port)
			AliveAddress = append(AliveAddress, address)
		}
	}

	return AliveAddress
}

// excludeNoPorts excludes specified ports
// ports: Original port list
// Returns filtered port list
func excludeNoPorts(ports []int) []int {
	noPorts := Common.ParsePort(Common.ExcludePorts)
	if len(noPorts) == 0 {
		return ports
	}

	// Use map to filter ports
	temp := make(map[int]struct{})
	for _, port := range ports {
		temp[port] = struct{}{}
	}

	// Remove ports to be excluded
	for _, port := range noPorts {
		delete(temp, port)
	}

	// Convert to ordered slice
	var newPorts []int
	for port := range temp {
		newPorts = append(newPorts, port)
	}
	sort.Ints(newPorts)

	return newPorts
}