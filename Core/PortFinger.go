package Core

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"regexp"
	"strconv"
	"strings"
)

//go:embed nmap-service-probes.txt
var ProbeString string

var v VScan // Changed to VScan type instead of pointer

type VScan struct {
	Exclude        string
	AllProbes      []Probe
	UdpProbes      []Probe
	Probes         []Probe
	ProbesMapKName map[string]Probe
}

type Probe struct {
	Name     string // Probe name
	Data     string // Probe data
	Protocol string // Protocol
	Ports    string // Port range
	SSLPorts string // SSL port range

	TotalWaitMS  int    // Total wait time
	TCPWrappedMS int    // TCP wrapped wait time
	Rarity       int    // Rarity
	Fallback     string // Fallback probe name

	Matchs *[]Match // Match rules list
}

type Match struct {
	IsSoft          bool           // Whether it's a soft match
	Service         string         // Service name
	Pattern         string         // Match pattern
	VersionInfo     string         // Version info format
	FoundItems      []string       // Found items
	PatternCompiled *regexp.Regexp // Compiled regular expression
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

type Extras struct {
	VendorProduct   string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	CPE             string
}

func init() {
	Common.LogDebug("Starting to initialize global variables")

	v = VScan{} // Directly initialize VScan struct
	v.Init()

	// Get and check NULL probe
	if nullProbe, ok := v.ProbesMapKName["NULL"]; ok {
		Common.LogDebug(fmt.Sprintf("Successfully obtained NULL probe, Data length: %d", len(nullProbe.Data)))
		null = &nullProbe
	} else {
		Common.LogDebug("Warning: NULL probe not found")
	}

	// Get and check GenericLines probe
	if commonProbe, ok := v.ProbesMapKName["GenericLines"]; ok {
		Common.LogDebug(fmt.Sprintf("Successfully obtained GenericLines probe, Data length: %d", len(commonProbe.Data)))
		common = &commonProbe
	} else {
		Common.LogDebug("Warning: GenericLines probe not found")
	}

	Common.LogDebug("Global variables initialization complete")
}

// Parse directive syntax, return directive structure
func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	Common.LogDebug("Starting to parse directive syntax, input data: " + data)

	directive = Directive{}
	// Find the position of the first space
	blankIndex := strings.Index(data, " ")
	if blankIndex == -1 {
		Common.LogDebug("Space separator not found")
		return directive
	}

	// Parse each field
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	Common.LogDebug(fmt.Sprintf("Directive parsing result: Name=%s, Flag=%s, Delimiter=%s, Content=%s",
		directiveName, Flag, delimiter, directiveStr))

	return directive
}

// Parse probe information
func (p *Probe) parseProbeInfo(probeStr string) {
	Common.LogDebug("Starting to parse probe information, input string: " + probeStr)

	// Extract protocol and other information
	proto := probeStr[:4]
	other := probeStr[4:]

	// Validate protocol type
	if !(proto == "TCP " || proto == "UDP ") {
		errMsg := "Probe protocol must be TCP or UDP"
		Common.LogDebug("Error: " + errMsg)
		panic(errMsg)
	}

	// Validate other information is not empty
	if len(other) == 0 {
		errMsg := "nmap-service-probes - Invalid probe name"
		Common.LogDebug("Error: " + errMsg)
		panic(errMsg)
	}

	// Parse directive
	directive := p.getDirectiveSyntax(other)

	// Set probe attributes
	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))

	Common.LogDebug(fmt.Sprintf("Probe parsing completed: Name=%s, Data=%s, Protocol=%s",
		p.Name, p.Data, p.Protocol))
}

// Parse probe information from string
func (p *Probe) fromString(data string) error {
	Common.LogDebug("Starting to parse probe string data")
	var err error

	// Preprocess data
	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("Input data is empty")
	}

	probeStr := lines[0]
	p.parseProbeInfo(probeStr)

	// Parse match rules and other configurations
	var matchs []Match
	for _, line := range lines {
		Common.LogDebug("Processing line: " + line)
		switch {
		case strings.HasPrefix(line, "match "):
			match, err := p.getMatch(line)
			if err != nil {
				Common.LogDebug("Failed to parse match: " + err.Error())
				continue
			}
			matchs = append(matchs, match)

		case strings.HasPrefix(line, "softmatch "):
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				Common.LogDebug("Failed to parse softmatch: " + err.Error())
				continue
			}
			matchs = append(matchs, softMatch)

		case strings.HasPrefix(line, "ports "):
			p.parsePorts(line)

		case strings.HasPrefix(line, "sslports "):
			p.parseSSLPorts(line)

		case strings.HasPrefix(line, "totalwaitms "):
			p.parseTotalWaitMS(line)

		case strings.HasPrefix(line, "tcpwrappedms "):
			p.parseTCPWrappedMS(line)

		case strings.HasPrefix(line, "rarity "):
			p.parseRarity(line)

		case strings.HasPrefix(line, "fallback "):
			p.parseFallback(line)
		}
	}
	p.Matchs = &matchs
	Common.LogDebug(fmt.Sprintf("Parsing completed, total of %d match rules", len(matchs)))
	return err
}

// Parse port configuration
func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
	Common.LogDebug("Parsing ports: " + p.Ports)
}

// Parse SSL port configuration
func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
	Common.LogDebug("Parsing SSL ports: " + p.SSLPorts)
}

// Parse total wait time
func (p *Probe) parseTotalWaitMS(data string) {
	waitMS, err := strconv.Atoi(strings.TrimSpace(data[len("totalwaitms")+1:]))
	if err != nil {
		Common.LogDebug("Failed to parse total wait time: " + err.Error())
		return
	}
	p.TotalWaitMS = waitMS
	Common.LogDebug(fmt.Sprintf("Total wait time: %d ms", waitMS))
}

// Parse TCP wrapped wait time
func (p *Probe) parseTCPWrappedMS(data string) {
	wrappedMS, err := strconv.Atoi(strings.TrimSpace(data[len("tcpwrappedms")+1:]))
	if err != nil {
		Common.LogDebug("Failed to parse TCP wrapped wait time: " + err.Error())
		return
	}
	p.TCPWrappedMS = wrappedMS
	Common.LogDebug(fmt.Sprintf("TCP wrapped wait time: %d ms", wrappedMS))
}

// Parse rarity
func (p *Probe) parseRarity(data string) {
	rarity, err := strconv.Atoi(strings.TrimSpace(data[len("rarity")+1:]))
	if err != nil {
		Common.LogDebug("Failed to parse rarity: " + err.Error())
		return
	}
	p.Rarity = rarity
	Common.LogDebug(fmt.Sprintf("Rarity: %d", rarity))
}

// Parse fallback configuration
func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
	Common.LogDebug("Fallback configuration: " + p.Fallback)
}

// Check if it's a hexadecimal code
func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

// Check if it's an octal code
func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

// Check if it's a structured escape character
func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

// Check if it's a regular expression special character
func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

// Check if it's another escape sequence
func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

// Parse probe rules from content
func (v *VScan) parseProbesFromContent(content string) {
	Common.LogDebug("Starting to parse probe rules from file content")
	var probes []Probe
	var lines []string

	// Filter comments and empty lines
	linesTemp := strings.Split(content, "\n")
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}

	// Validate file content
	if len(lines) == 0 {
		errMsg := "Failed to read nmap-service-probes file: Content is empty"
		Common.LogDebug("Error: " + errMsg)
		panic(errMsg)
	}

	// Check Exclude directive
	excludeCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			excludeCount++
		}
		if excludeCount > 1 {
			errMsg := "Only one Exclude directive is allowed in nmap-service-probes file"
			Common.LogDebug("Error: " + errMsg)
			panic(errMsg)
		}
	}

	// Validate first line format
	firstLine := lines[0]
	if !(strings.HasPrefix(firstLine, "Exclude ") || strings.HasPrefix(firstLine, "Probe ")) {
		errMsg := "Parsing error: First line must start with \"Probe \" or \"Exclude \""
		Common.LogDebug("Error: " + errMsg)
		panic(errMsg)
	}

	// Process Exclude directive
	if excludeCount == 1 {
		v.Exclude = firstLine[len("Exclude")+1:]
		lines = lines[1:]
		Common.LogDebug("Parsed Exclude rule: " + v.Exclude)
	}

	// Merge content and split probes
	content = "\n" + strings.Join(lines, "\n")
	probeParts := strings.Split(content, "\nProbe")[1:]

	// Parse each probe
	for _, probePart := range probeParts {
		probe := Probe{}
		if err := probe.fromString(probePart); err != nil {
			Common.LogDebug(fmt.Sprintf("Failed to parse probe: %v", err))
			continue
		}
		probes = append(probes, probe)
	}

	v.AllProbes = probes
	Common.LogDebug(fmt.Sprintf("Successfully parsed %d probe rules", len(probes)))
}

// Convert probes to name mapping
func (v *VScan) parseProbesToMapKName() {
	Common.LogDebug("Starting to build probe name mapping")
	v.ProbesMapKName = map[string]Probe{}
	for _, probe := range v.AllProbes {
		v.ProbesMapKName[probe.Name] = probe
		Common.LogDebug("Added probe mapping: " + probe.Name)
	}
}

// Set probes to be used
func (v *VScan) SetusedProbes() {
	Common.LogDebug("Starting to set probes to be used")

	for _, probe := range v.AllProbes {
		if strings.ToLower(probe.Protocol) == "tcp" {
			if probe.Name == "SSLSessionReq" {
				Common.LogDebug("Skipping SSLSessionReq probe")
				continue
			}

			v.Probes = append(v.Probes, probe)
			Common.LogDebug("Added TCP probe: " + probe.Name)

			// Special handling for TLS session request
			if probe.Name == "TLSSessionReq" {
				sslProbe := v.ProbesMapKName["SSLSessionReq"]
				v.Probes = append(v.Probes, sslProbe)
				Common.LogDebug("Added SSL probe for TLSSessionReq")
			}
		} else {
			v.UdpProbes = append(v.UdpProbes, probe)
			Common.LogDebug("Added UDP probe: " + probe.Name)
		}
	}

	Common.LogDebug(fmt.Sprintf("Probe setting completed, TCP: %d, UDP: %d",
		len(v.Probes), len(v.UdpProbes)))
}

// Parse match directive to get match rule
func (p *Probe) getMatch(data string) (match Match, err error) {
	Common.LogDebug("Starting to parse match directive: " + data)
	match = Match{}

	// Extract match text and parse directive syntax
	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	// Split text to get pattern and version info
	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(textSplited) == 0 {
		return match, fmt.Errorf("Invalid match directive format")
	}

	pattern := textSplited[0]
	versionInfo := strings.Join(textSplited[1:], "")

	// Decode and compile regular expression
	patternUnescaped, decodeErr := DecodePattern(pattern)
	if decodeErr != nil {
		Common.LogDebug("Failed to decode pattern: " + decodeErr.Error())
		return match, decodeErr
	}

	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, compileErr := regexp.Compile(patternUnescapedStr)
	if compileErr != nil {
		Common.LogDebug("Failed to compile regular expression: " + compileErr.Error())
		return match, compileErr
	}

	// Set match object attributes
	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	Common.LogDebug(fmt.Sprintf("Match parsing successful: Service=%s, Pattern=%s",
		match.Service, match.Pattern))
	return match, nil
}

// Parse softmatch directive to get soft match rule
func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	Common.LogDebug("Starting to parse softmatch directive: " + data)
	softMatch = Match{IsSoft: true}

	// Extract softmatch text and parse directive syntax
	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	// Split text to get pattern and version info
	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(textSplited) == 0 {
		return softMatch, fmt.Errorf("Invalid softmatch directive format")
	}

	pattern := textSplited[0]
	versionInfo := strings.Join(textSplited[1:], "")

	// Decode and compile regular expression
	patternUnescaped, decodeErr := DecodePattern(pattern)
	if decodeErr != nil {
		Common.LogDebug("Failed to decode pattern: " + decodeErr.Error())
		return softMatch, decodeErr
	}

	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, compileErr := regexp.Compile(patternUnescapedStr)
	if compileErr != nil {
		Common.LogDebug("Failed to compile regular expression: " + compileErr.Error())
		return softMatch, compileErr
	}

	// Set softMatch object attributes
	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	Common.LogDebug(fmt.Sprintf("Softmatch parsing successful: Service=%s, Pattern=%s",
		softMatch.Service, softMatch.Pattern))
	return softMatch, nil
}

// Decode pattern string, handle escape sequences
func DecodePattern(s string) ([]byte, error) {
	Common.LogDebug("Starting to decode pattern: " + s)
	sByteOrigin := []byte(s)

	// Handle hexadecimal, octal, and structured escape sequences
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte

		// Handle hexadecimal escape
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}

		// Handle structured escape characters
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a bell
				102: []byte{0x0c}, // \f form feed
				116: []byte{0x09}, // \t tab
				110: []byte{0x0a}, // \n newline
				114: []byte{0x0d}, // \r carriage return
				118: []byte{0x0b}, // \v vertical tab
			}
			replace = structCodeMap[int(match[1])]
		}

		// Handle octal escape
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	// Handle other escape sequences
	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		if isOtherEscapeCode(match) {
			return match
		}
		return match
	})

	Common.LogDebug("Pattern decoding completed")
	return sByteDec2, nil
}

// ProbesRarity is a slice of probes for sorting by rarity
type ProbesRarity []Probe

// Len returns slice length, implements sort.Interface
func (ps ProbesRarity) Len() int {
	return len(ps)
}

// Swap exchanges two elements in the slice, implements sort.Interface
func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

// Less comparison function, sorts by rarity in ascending order, implements sort.Interface
func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}

// Target defines target structure
type Target struct {
	IP       string // Target IP address
	Port     int    // Target port
	Protocol string // Protocol type
}

// ContainsPort checks if the specified port is within the probe's port range
func (p *Probe) ContainsPort(testPort int) bool {
	Common.LogDebug(fmt.Sprintf("Checking if port %d is within probe port range: %s", testPort, p.Ports))

	// Check individual ports
	ports := strings.Split(p.Ports, ",")
	for _, port := range ports {
		port = strings.TrimSpace(port)
		cmpPort, err := strconv.Atoi(port)
		if err == nil && testPort == cmpPort {
			Common.LogDebug(fmt.Sprintf("Port %d matches individual port", testPort))
			return true
		}
	}

	// Check port ranges
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			if len(portRange) != 2 {
				Common.LogDebug("Invalid port range format: " + port)
				continue
			}

			start, err1 := strconv.Atoi(strings.TrimSpace(portRange[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(portRange[1]))

			if err1 != nil || err2 != nil {
				Common.LogDebug(fmt.Sprintf("Failed to parse port range: %s", port))
				continue
			}

			if testPort >= start && testPort <= end {
				Common.LogDebug(fmt.Sprintf("Port %d is within range %d-%d", testPort, start, end))
				return true
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("Port %d is not within probe port range", testPort))
	return false
}

// MatchPattern uses regular expression to match response content
func (m *Match) MatchPattern(response []byte) bool {
	// Convert response to string and match
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	if len(foundItems) > 0 {
		m.FoundItems = foundItems
		Common.LogDebug(fmt.Sprintf("Match successful, found %d matching items", len(foundItems)))
		return true
	}
	
	return false
}

// ParseVersionInfo parses version information and returns extra information structure
func (m *Match) ParseVersionInfo(response []byte) Extras {
	Common.LogDebug("Starting to parse version information")
	var extras = Extras{}

	// Replace placeholders in version info
	foundItems := m.FoundItems[1:] // Skip the first complete match item
	versionInfo := m.VersionInfo
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}
	Common.LogDebug("Version info after replacement: " + versionInfo)

	// Define parsing function
	parseField := func(field, pattern string) string {
		patterns := []string{
			pattern + `/([^/]*)/`,   // Slash delimiter
			pattern + `\|([^|]*)\|`, // Pipe delimiter
		}

		for _, p := range patterns {
			if strings.Contains(versionInfo, pattern) {
				regex := regexp.MustCompile(p)
				if matches := regex.FindStringSubmatch(versionInfo); len(matches) > 1 {
					Common.LogDebug(fmt.Sprintf("Parsed %s: %s", field, matches[1]))
					return matches[1]
				}
			}
		}
		return ""
	}

	// Parse each field
	extras.VendorProduct = parseField("vendor product", " p")
	extras.Version = parseField("version", " v")
	extras.Info = parseField("info", " i")
	extras.Hostname = parseField("hostname", " h")
	extras.OperatingSystem = parseField("operating system", " o")
	extras.DeviceType = parseField("device type", " d")

	// Special handling for CPE
	if strings.Contains(versionInfo, " cpe:/") || strings.Contains(versionInfo, " cpe:|") {
		cpePatterns := []string{`cpe:/([^/]*)`, `cpe:\|([^|]*)`}
		for _, pattern := range cpePatterns {
			regex := regexp.MustCompile(pattern)
			if cpeName := regex.FindStringSubmatch(versionInfo); len(cpeName) > 0 {
				if len(cpeName) > 1 {
					extras.CPE = cpeName[1]
				} else {
					extras.CPE = cpeName[0]
				}
				Common.LogDebug("Parsed CPE: " + extras.CPE)
				break
			}
		}
	}

	return extras
}

// ToMap converts Extras to map[string]string
func (e *Extras) ToMap() map[string]string {
	Common.LogDebug("Starting to convert Extras to Map")
	result := make(map[string]string)

	// Define field mapping
	fields := map[string]string{
		"vendor_product": e.VendorProduct,
		"version":        e.Version,
		"info":           e.Info,
		"hostname":       e.Hostname,
		"os":             e.OperatingSystem,
		"device_type":    e.DeviceType,
		"cpe":            e.CPE,
	}

	// Add non-empty fields to result map
	for key, value := range fields {
		if value != "" {
			result[key] = value
			Common.LogDebug(fmt.Sprintf("Added field %s: %s", key, value))
		}
	}

	Common.LogDebug(fmt.Sprintf("Conversion completed, total %d fields", len(result)))
	return result
}

func DecodeData(s string) ([]byte, error) {
	if len(s) == 0 {
		Common.LogDebug("Input data is empty")
		return nil, fmt.Errorf("empty input")
	}

	Common.LogDebug(fmt.Sprintf("Starting to decode data, length: %d, content: %q", len(s), s))
	sByteOrigin := []byte(s)

	// Handle hexadecimal, octal, and structured escape sequences
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) []byte {
		// Handle hexadecimal escape
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, err := strconv.ParseInt(string(hexNum), 16, 32)
			if err != nil {
				return match
			}
			return []byte{uint8(byteNum)}
		}

		// Handle structured escape characters
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a bell
				102: []byte{0x0c}, // \f form feed
				116: []byte{0x09}, // \t tab
				110: []byte{0x0a}, // \n newline
				114: []byte{0x0d}, // \r carriage return
				118: []byte{0x0b}, // \v vertical tab
			}
			if replace, ok := structCodeMap[int(match[1])]; ok {
				return replace
			}
			return match
		}

		// Handle octal escape
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, err := strconv.ParseInt(string(octalNum), 8, 32)
			if err != nil {
				return match
			}
			return []byte{uint8(byteNum)}
		}

		Common.LogDebug(fmt.Sprintf("Unrecognized escape sequence: %s", string(match)))
		return match
	})

	// Handle other escape sequences
	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) []byte {
		if len(match) < 2 {
			return match
		}
		if isOtherEscapeCode(match) {
			return []byte{match[1]}
		}
		return match
	})

	if len(sByteDec2) == 0 {
		Common.LogDebug("Decoded data is empty")
		return nil, fmt.Errorf("decoded data is empty")
	}

	Common.LogDebug(fmt.Sprintf("Decoding completed, result length: %d, content: %x", len(sByteDec2), sByteDec2))
	return sByteDec2, nil
}

// GetAddress gets the target's full address (IP:port)
func (t *Target) GetAddress() string {
	addr := t.IP + ":" + strconv.Itoa(t.Port)
	Common.LogDebug("Getting target address: " + addr)
	return addr
}

// trimBanner processes and cleans banner data
func trimBanner(buf []byte) string {
	Common.LogDebug("Starting to process banner data")
	bufStr := string(buf)

	// Special handling for SMB protocol
	if strings.Contains(bufStr, "SMB") {
		banner := hex.EncodeToString(buf)
		if len(banner) > 0xa+6 && banner[0xa:0xa+6] == "534d42" { // "SMB" in hex
			Common.LogDebug("Detected SMB protocol data")
			plain := banner[0xa2:]
			data, err := hex.DecodeString(plain)
			if err != nil {
				Common.LogDebug("Failed to decode SMB data: " + err.Error())
				return bufStr
			}

			// Parse domain
			var domain string
			var index int
			for i, s := range data {
				if s != 0 {
					domain += string(s)
				} else if i+1 < len(data) && data[i+1] == 0 {
					index = i + 2
					break
				}
			}

			// Parse hostname
			var hostname string
			remainData := data[index:]
			for i, h := range remainData {
				if h != 0 {
					hostname += string(h)
				}
				if i+1 < len(remainData) && remainData[i+1] == 0 {
					break
				}
			}

			smbBanner := fmt.Sprintf("hostname: %s domain: %s", hostname, domain)
			Common.LogDebug("SMB banner: " + smbBanner)
			return smbBanner
		}
	}

	// Process regular data
	var src string
	for _, ch := range bufStr {
		if ch > 32 && ch < 125 {
			src += string(ch)
		} else {
			src += " "
		}
	}

	// Clean up extra whitespace
	re := regexp.MustCompile(`\s{2,}`)
	src = re.ReplaceAllString(src, ".")
	result := strings.TrimSpace(src)
	Common.LogDebug("Processed banner: " + result)
	return result
}

// Init initializes the VScan object
func (v *VScan) Init() {
	Common.LogDebug("Starting to initialize VScan")
	v.parseProbesFromContent(ProbeString)
	v.parseProbesToMapKName()
	v.SetusedProbes()
	Common.LogDebug("VScan initialization completed")
}
