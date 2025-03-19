package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// MemcachedScan checks for unauthorized access to Memcached
func MemcachedScan(info *Common.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	timeout := time.Duration(Common.Timeout) * time.Second

	// Establish TCP connection
	client, err := Common.WrapperTcpWithTimeout("tcp", realhost, timeout)
	if err != nil {
		return err
	}
	defer client.Close()

	// Set timeout
	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	// Send stats command
	if _, err := client.Write([]byte("stats\n")); err != nil {
		return err
	}

	// Read response
	rev := make([]byte, 1024)
	n, err := client.Read(rev)
	if err != nil {
		Common.LogError(fmt.Sprintf("Memcached %v:%v %v", info.Host, info.Ports, err))
		return err
	}

	// Check response content
	if strings.Contains(string(rev[:n]), "STAT") {
		// Save result
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":        info.Ports,
				"service":     "memcached",
				"type":        "unauthorized-access",
				"description": "Memcached unauthorized access",
			},
		}
		Common.SaveResult(result)
		Common.LogSuccess(fmt.Sprintf("Memcached %s unauthorized access", realhost))
	}

	return nil
}
