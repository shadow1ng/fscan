package Core

import (
	"bytes"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/net/icmp"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	AliveHosts []string                    // List of alive hosts
	ExistHosts = make(map[string]struct{}) // Record of discovered hosts
	livewg     sync.WaitGroup              // Wait group for live detection
)

// CheckLive checks the live status of hosts
func CheckLive(hostslist []string, Ping bool) []string {
	// Create host channel
	chanHosts := make(chan string, len(hostslist))

	// Handle alive hosts
	go handleAliveHosts(chanHosts, hostslist, Ping)

	// Choose detection method based on Ping parameter
	if Ping {
		// Use ping method
		RunPing(hostslist, chanHosts)
	} else {
		probeWithICMP(hostslist, chanHosts)
	}

	// Wait for all detections to complete
	livewg.Wait()
	close(chanHosts)

	// Print alive statistics
	printAliveStats(hostslist)

	return AliveHosts
}

// IsContain checks if the slice contains the specified element
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func handleAliveHosts(chanHosts chan string, hostslist []string, isPing bool) {
	for ip := range chanHosts {
		if _, ok := ExistHosts[ip]; !ok && IsContain(hostslist, ip) {
			ExistHosts[ip] = struct{}{}
			AliveHosts = append(AliveHosts, ip)

			 // Use Output system to save alive host information
			protocol := "ICMP"
			if isPing {
				protocol = "PING"
			}

			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.HOST,
				Target: ip,
				Status: "alive",
				Details: map[string]interface{}{
					"protocol": protocol,
				},
			}
			Common.SaveResult(result)

			 // Keep original console output
			if !Common.Silent {
				Common.LogSuccess(Common.GetText("target_alive", ip, protocol))
			}
		}
		livewg.Done()
	}
}

// probeWithICMP probes using ICMP method
func probeWithICMP(hostslist []string, chanHosts chan string) {
	// Try to listen on local ICMP
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		RunIcmp1(hostslist, conn, chanHosts)
		return
	}

	Common.LogError(Common.GetText("icmp_listen_failed", err))
	Common.LogInfo(Common.GetText("trying_no_listen_icmp"))

	// Try no-listen ICMP probe
	conn2, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
	if err == nil {
		defer conn2.Close()
		RunIcmp2(hostslist, chanHosts)
		return
	}

	Common.LogError(Common.GetText("icmp_connect_failed", err))
	Common.LogInfo(Common.GetText("insufficient_privileges"))
	Common.LogInfo(Common.GetText("switching_to_ping"))

	// Fallback to ping probe
	RunPing(hostslist, chanHosts)
}

// printAliveStats prints alive statistics
func printAliveStats(hostslist []string) {
	// Output /16 subnet statistics for large-scale scans
	if (len(hostslist) > 1000) {
		arrTop, arrLen := ArrayCountValueTop(AliveHosts, Common.LiveTop, true)
		for i := 0; i < len(arrTop); i++ {
			Common.LogSuccess(Common.GetText("subnet_16_alive", arrTop[i], arrLen[i]))
		}
	}

	// Output /24 subnet statistics
	if (len(hostslist) > 256) {
		arrTop, arrLen := ArrayCountValueTop(AliveHosts, Common.LiveTop, false)
		for i := 0; i < len(arrTop); i++ {
			Common.LogSuccess(Common.GetText("subnet_24_alive", arrTop[i], arrLen[i]))
		}
	}
}

// RunIcmp1 uses ICMP to probe host liveliness (listen mode)
func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	endflag := false

	// Start listening goroutine
	go func() {
		for {
			if endflag {
				return
			}
			// Receive ICMP response
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				livewg.Add(1)
				chanHosts <- sourceIP.String()
			}
		}
	}()

	// Send ICMP requests
	for _, host := range hostslist {
		dst, _ := net.ResolveIPAddr("ip", host)
		IcmpByte := makemsg(host)
		conn.WriteTo(IcmpByte, dst)
	}

	// Wait for responses
	start := time.Now()
	for {
		// Exit if all hosts have responded
		if len(AliveHosts) == len(hostslist) {
			break
		}

		// Set timeout based on number of hosts
		since := time.Since(start)
		wait := time.Second * 6
		if len(hostslist) <= 256 {
			wait = time.Second * 3
		}

		if since > wait {
			break
		}
	}

	endflag = true
	conn.Close()
}

// RunIcmp2 uses ICMP to probe host liveliness (no-listen mode)
func RunIcmp2(hostslist []string, chanHosts chan string) {
	// Control concurrency
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}

	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)

	// Concurrent probing
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			if icmpalive(host) {
				livewg.Add(1)
				chanHosts <- host
			}
		}(host)
	}

	wg.Wait()
	close(limiter)
}

// icmpalive checks if the host is alive using ICMP
func icmpalive(host string) bool {
	startTime := time.Now()

	// Establish ICMP connection
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set timeout
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}

	// Construct and send ICMP request
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	// Receive ICMP response
	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

// RunPing uses system ping command to probe host liveliness concurrently
func RunPing(hostslist []string, chanHosts chan string) {
	var wg sync.WaitGroup
	// Limit concurrency to 50
	limiter := make(chan struct{}, 50)

	// Concurrent probing
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			if ExecCommandPing(host) {
				livewg.Add(1)
				chanHosts <- host
			}
		}(host)
	}

	wg.Wait()
}

// ExecCommandPing executes system ping command to check host liveliness
func ExecCommandPing(ip string) bool {
	// Filter blacklist characters
	forbiddenChars := []string{";", "&", "|", "`", "$", "\\", "'", "%", "\"", "\n"}
	for _, char := range forbiddenChars {
		if strings.Contains(ip, char) {
			return false
		}
	}

	var command *exec.Cmd
	// Choose different ping commands based on OS
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false")
	default: // linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false")
	}

	// Capture command output
	var outinfo bytes.Buffer
	command.Stdout = &outinfo

	// Execute command
	if err := command.Start(); err != nil {
		return false
	}

	if err := command.Wait(); err != nil {
		return false
	}

	// Analyze output result
	output := outinfo.String()
	return strings.Contains(output, "true") && strings.Count(output, ip) > 2
}

// makemsg constructs ICMP echo request message
func makemsg(host string) []byte {
	msg := make([]byte, 40)

	// Get identifier
	id0, id1 := genIdentifier(host)

	// Set ICMP header
	msg[0] = 8                      // Type: Echo Request
	msg[1] = 0                      // Code: 0
	msg[2] = 0                      // Checksum high byte (to be calculated)
	msg[3] = 0                      // Checksum low byte (to be calculated)
	msg[4], msg[5] = id0, id1       // Identifier
	msg[6], msg[7] = genSequence(1) // Sequence Number

	// Calculate checksum
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)  // Set checksum high byte
	msg[3] = byte(check & 255) // Set checksum low byte

	return msg
}

// checkSum calculates ICMP checksum
func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)

	// Accumulate in 16-bit units
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}

	// Handle odd length case
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}

	// Add high 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Take one's complement to get checksum
	return uint16(^sum)
}

// genSequence generates ICMP sequence number
func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)  // High 8 bits
	ret2 := byte(v & 255) // Low 8 bits
	return ret1, ret2
}

// genIdentifier generates identifier based on host address
func genIdentifier(host string) (byte, byte) {
	return host[0], host[1] // Use first two bytes of host address
}

// ArrayCountValueTop counts the number of alive IP segments and returns the top N results
func ArrayCountValueTop(arrInit []string, length int, flag bool) (arrTop []string, arrLen []int) {
	if len(arrInit) == 0 {
		return
	}

	// Count occurrences of each segment
	segmentCounts := make(map[string]int)
	for _, ip := range arrInit {
		segments := strings.Split(ip, ".")
		if len(segments) != 4 {
			continue
		}

		// Determine whether to count B segment or C segment based on flag
		var segment string
		if flag {
			segment = fmt.Sprintf("%s.%s", segments[0], segments[1]) // B segment
		} else {
			segment = fmt.Sprintf("%s.%s.%s", segments[0], segments[1], segments[2]) // C segment
		}

		segmentCounts[segment]++
	}

	// Create a copy for sorting
	sortMap := make(map[string]int)
	for k, v := range segmentCounts {
		sortMap[k] = v
	}

	// Get top N results
	for i := 0; i < length && len(sortMap) > 0; i++ {
		maxSegment := ""
		maxCount := 0

		// Find current maximum value
		for segment, count := range sortMap {
			if count > maxCount {
				maxCount = count
				maxSegment = segment
			}
		}

		// Add to result set
		arrTop = append(arrTop, maxSegment)
		arrLen = append(arrLen, maxCount)

		// Remove processed item from map
		delete(sortMap, maxSegment)
	}

	return
}
