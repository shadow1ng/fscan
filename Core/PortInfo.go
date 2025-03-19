package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"strings"
	"time"
)

// ServiceInfo defines the service identification result information
type ServiceInfo struct {
	Name    string            // Service name, such as http, ssh, etc.
	Banner  string            // Banner information returned by the service
	Version string            // Service version number
	Extras  map[string]string // Other additional information, such as operating system, product name, etc.
}

// Result defines the result of a single detection
type Result struct {
	Service Service           // Identified service information
	Banner  string            // Service banner
	Extras  map[string]string // Additional information
	Send    []byte            // Probe data sent
	Recv    []byte            // Response data received
}

// Service defines the basic information of a service
type Service struct {
	Name   string            // Service name
	Extras map[string]string // Additional service attributes
}

// Info defines the context information for a single port probe
type Info struct {
	Address string    // Target IP address
	Port    int       // Target port
	Conn    net.Conn  // Network connection
	Result  Result    // Detection result
	Found   bool      // Whether the service was successfully identified
}

// PortInfoScanner defines a port service identifier
type PortInfoScanner struct {
	Address string        // Target IP address
	Port    int           // Target port
	Conn    net.Conn      // Network connection
	Timeout time.Duration // Timeout duration
	info    *Info         // Detection context
}

// Predefined basic probes
var (
	null   = new(Probe) // Empty probe, used for basic protocol identification
	common = new(Probe) // Common probe, used for common service identification
)

// NewPortInfoScanner creates a new port service identifier instance
func NewPortInfoScanner(addr string, port int, conn net.Conn, timeout time.Duration) *PortInfoScanner {
	return &PortInfoScanner{
		Address: addr,
		Port:    port, 
		Conn:    conn,
		Timeout: timeout,
		info: &Info{
			Address: addr,
			Port:    port,
			Conn:    conn,
			Result: Result{
				Service: Service{},
			},
		},
	}
}

// Identify performs service identification and returns the result
func (s *PortInfoScanner) Identify() (*ServiceInfo, error) {
	Common.LogDebug(fmt.Sprintf("Starting to identify service %s:%d", s.Address, s.Port))
	s.info.PortInfo()

	// Construct the return result
	serviceInfo := &ServiceInfo{
		Name:    s.info.Result.Service.Name,
		Banner:  s.info.Result.Banner,
		Version: s.info.Result.Service.Extras["version"],
		Extras:  make(map[string]string),
	}

	// Copy additional information
	for k, v := range s.info.Result.Service.Extras {
		serviceInfo.Extras[k] = v
	}

	Common.LogDebug(fmt.Sprintf("Service identification completed %s:%d => %s", s.Address, s.Port, serviceInfo.Name))
	return serviceInfo, nil
}

// PortInfo executes the main logic of port service identification
func (i *Info) PortInfo() {
	// 1. First try to read the initial response from the service
	if response, err := i.Read(); err == nil && len(response) > 0 {
		Common.LogDebug(fmt.Sprintf("Received initial response: %d bytes", len(response)))

		// Check the response using basic probes
		Common.LogDebug("Attempting to check response using basic probes (null/common)")
		if i.tryProbes(response, []*Probe{null, common}) {
			Common.LogDebug("Basic probe matching successful")
			return
		}
		Common.LogDebug("Basic probes did not match")
	} else if err != nil {
		Common.LogDebug(fmt.Sprintf("Failed to read initial response: %v", err))
	}

	// Record used probes to avoid duplication
	usedProbes := make(map[string]struct{})

	// 2. Try to use port-specific probes
	Common.LogDebug(fmt.Sprintf("Attempting to use dedicated probes for port %d", i.Port))
	if i.processPortMapProbes(usedProbes) {
		Common.LogDebug("Port-specific probe matching successful")
		return
	}
	Common.LogDebug("Port-specific probes did not match")

	// 3. Use the default probe list
	Common.LogDebug("Attempting to use default probe list")
	if i.processDefaultProbes(usedProbes) {
		Common.LogDebug("Default probe matching successful")
		return
	}
	Common.LogDebug("Default probes did not match")

	// 4. If all probes fail, mark as unknown service
	if strings.TrimSpace(i.Result.Service.Name) == "" {
		Common.LogDebug("Service not recognized, marking as unknown")
		i.Result.Service.Name = "unknown"
	}
}

// tryProbes attempts to use the specified probe list to check the response
func (i *Info) tryProbes(response []byte, probes []*Probe) bool {
	for _, probe := range probes {
		Common.LogDebug(fmt.Sprintf("Attempting probe: %s", probe.Name))
		i.GetInfo(response, probe)
		if i.Found {
			Common.LogDebug(fmt.Sprintf("Probe %s matched successfully", probe.Name))
			return true
		}
	}
	return false
}

// processPortMapProbes processes dedicated probes in the port mapping
func (i *Info) processPortMapProbes(usedProbes map[string]struct{}) bool {
	// Check if port-specific probes exist
	if len(Common.PortMap[i.Port]) == 0 {
		Common.LogDebug(fmt.Sprintf("Port %d has no dedicated probes", i.Port))
		return false
	}

	// Iterate through port-specific probes
	for _, name := range Common.PortMap[i.Port] {
		Common.LogDebug(fmt.Sprintf("Attempting port-specific probe: %s", name))
		usedProbes[name] = struct{}{} 
		probe := v.ProbesMapKName[name]

		// Decode probe data
		probeData, err := DecodeData(probe.Data)
		if err != nil || len(probeData) == 0 {
			Common.LogDebug(fmt.Sprintf("Failed to decode probe data for %s", name))
			continue
		}

		// Send probe data and get response
		Common.LogDebug(fmt.Sprintf("Sending probe data: %d bytes", len(probeData)))
		if response := i.Connect(probeData); len(response) > 0 {
			Common.LogDebug(fmt.Sprintf("Received response: %d bytes", len(response)))

			// Check response with current probe
			i.GetInfo(response, &probe)
			if i.Found {
				return true
			}

			// Perform additional checks based on probe type
			switch name {
			case "GenericLines":
				if i.tryProbes(response, []*Probe{null}) {
					return true
				}
			case "NULL":
				continue
			default:
				if i.tryProbes(response, []*Probe{common}) {
					return true
				}
			}
		}
	}
	return false
}

// processDefaultProbes processes the default probe list
func (i *Info) processDefaultProbes(usedProbes map[string]struct{}) bool {
	failCount := 0
	const maxFailures = 10 // Maximum failure count

	// Iterate through the default probe list
	for _, name := range Common.DefaultMap {
		// Skip already used probes
		if _, used := usedProbes[name]; used {
			continue
		}

		probe := v.ProbesMapKName[name]
		probeData, err := DecodeData(probe.Data)
		if err != nil || len(probeData) == 0 {
			continue
		}

		// Send probe data and get response
		response := i.Connect(probeData)
		if len(response) == 0 {
			failCount++
			if failCount > maxFailures {
				return false
			}
			continue
		}

		// Check response with current probe
		i.GetInfo(response, &probe)
		if i.Found {
			return true
		}

		// Perform additional checks based on probe type
		switch name {
		case "GenericLines":
			if i.tryProbes(response, []*Probe{null}) {
				return true
			}
		case "NULL":
			continue
		default:
			if i.tryProbes(response, []*Probe{common}) {
				return true
			}
		}

		// Try to use other probes in the port mapping
		if len(Common.PortMap[i.Port]) > 0 {
			for _, mappedName := range Common.PortMap[i.Port] {
				usedProbes[mappedName] = struct{}{}
				mappedProbe := v.ProbesMapKName[mappedName]
				i.GetInfo(response, &mappedProbe)
				if i.Found {
					return true
				}
			}
		}
	}
	return false
}

// GetInfo analyzes response data and extracts service information
func (i *Info) GetInfo(response []byte, probe *Probe) {
	Common.LogDebug(fmt.Sprintf("Starting to analyze response data, length: %d", len(response)))

	// Check response data validity
	if len(response) <= 0 {
		Common.LogDebug("Response data is empty")
		return
	}

	result := &i.Result
	var (
		softMatch Match
		softFound bool
	)

	// Process main matching rules
	Common.LogDebug(fmt.Sprintf("Processing main matching rules for probe %s", probe.Name))
	if matched, match := i.processMatches(response, probe.Matchs); matched {
		Common.LogDebug("Hard match found")
		return
	} else if match != nil {
		Common.LogDebug("Soft match found")
		softFound = true
		softMatch = *match
	}

	// Process fallback matching rules
	if probe.Fallback != "" {
		Common.LogDebug(fmt.Sprintf("Attempting fallback match: %s", probe.Fallback))
		if fbProbe, ok := v.ProbesMapKName[probe.Fallback]; ok {
			if matched, match := i.processMatches(response, fbProbe.Matchs); matched {
				Common.LogDebug("Fallback match successful")
				return
			} else if match != nil {
				Common.LogDebug("Fallback soft match found")
				softFound = true
				softMatch = *match
			}
		}
	}

	// Handle case when no match is found
	if !i.Found {
		Common.LogDebug("No hard match found, handling no match case")
		i.handleNoMatch(response, result, softFound, softMatch)
	}
}

// processMatches processes the set of matching rules
func (i *Info) processMatches(response []byte, matches *[]Match) (bool, *Match) {
	Common.LogDebug(fmt.Sprintf("Starting to process matching rules, total %d rules", len(*matches)))
	var softMatch *Match

	for _, match := range *matches {
		if !match.MatchPattern(response) {
			continue
		}

		if !match.IsSoft {
			Common.LogDebug(fmt.Sprintf("Hard match found: %s", match.Service))
			i.handleHardMatch(response, &match)
			return true, nil
		} else if softMatch == nil {
			Common.LogDebug(fmt.Sprintf("Soft match found: %s", match.Service))
			tmpMatch := match
			softMatch = &tmpMatch
		}
	}

	return false, softMatch
}

// handleHardMatch handles hard match results
func (i *Info) handleHardMatch(response []byte, match *Match) {
	Common.LogDebug(fmt.Sprintf("Processing hard match result: %s", match.Service))
	result := &i.Result
	extras := match.ParseVersionInfo(response)
	extrasMap := extras.ToMap()

	result.Service.Name = match.Service
	result.Extras = extrasMap
	result.Banner = trimBanner(response)
	result.Service.Extras = extrasMap

	// Special handling for microsoft-ds service
	if result.Service.Name == "microsoft-ds" {
		Common.LogDebug("Special handling for microsoft-ds service")
		result.Service.Extras["hostname"] = result.Banner
	}

	i.Found = true
	Common.LogDebug(fmt.Sprintf("Service identification result: %s, Banner: %s", result.Service.Name, result.Banner))
}

// handleNoMatch handles the case when no match is found
func (i *Info) handleNoMatch(response []byte, result *Result, softFound bool, softMatch Match) {
	Common.LogDebug("Handling no match case")
	result.Banner = trimBanner(response)

	if !softFound {
		// Try to identify HTTP service
		if strings.Contains(result.Banner, "HTTP/") ||
			strings.Contains(result.Banner, "html") {
			Common.LogDebug("Identified as HTTP service")
			result.Service.Name = "http"
		} else {
			Common.LogDebug("Unknown service")
			result.Service.Name = "unknown"
		}
	} else {
		Common.LogDebug("Using soft match result")
		extras := softMatch.ParseVersionInfo(response)
		result.Service.Extras = extras.ToMap()
		result.Service.Name = softMatch.Service
		i.Found = true
		Common.LogDebug(fmt.Sprintf("Soft match service: %s", result.Service.Name))
	}
}

// Connect sends data and gets response
func (i *Info) Connect(msg []byte) []byte {
	i.Write(msg)
	reply, _ := i.Read()
	return reply
}

const WrTimeout = 5 // Default read/write timeout (seconds)

// Write writes data to the connection
func (i *Info) Write(msg []byte) error {
	if i.Conn == nil {
		return nil
	}

	// Set write timeout
	i.Conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))

	// Write data
	_, err := i.Conn.Write(msg)
	if err != nil && strings.Contains(err.Error(), "close") {
		i.Conn.Close()
		// Retry when connection is closed
		i.Conn, err = net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", i.Address, i.Port), time.Duration(6)*time.Second)
		if err == nil {
			i.Conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))
			_, err = i.Conn.Write(msg)
		}
	}

	// Record sent data
	if err == nil {
		i.Result.Send = msg
	}

	return err
}

// Read reads response from the connection
func (i *Info) Read() ([]byte, error) {
	if i.Conn == nil {
		return nil, nil
	}

	// Set read timeout
	i.Conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))

	// Read data
	result, err := readFromConn(i.Conn)
	if err != nil && strings.Contains(err.Error(), "close") {
		return result, err
	}

	// Record received data
	if len(result) > 0 {
		i.Result.Recv = result
	}

	return result, err
}

// readFromConn helper function to read data from connection
func readFromConn(conn net.Conn) ([]byte, error) {
	size := 2 * 1024 // Read buffer size
	var result []byte

	for {
		buf := make([]byte, size)
		count, err := conn.Read(buf)

		if count > 0 {
			result = append(result, buf[:count]...)
		}

		if err != nil {
			if len(result) > 0 {
				return result, nil
			}
			if err == io.EOF {
				return result, nil
			}
			return result, err
		}

		if count < size {
			return result, nil
		}
	}
}