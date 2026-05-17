package parsers

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/i18n"
)

/*
parsers.go - 核心解析函数

保留的核心功能：
- ParseIP()       - IP地址/CIDR/范围解析
- ParsePort()     - 端口解析
- ReadLinesFromFile() - 文件读取
- ParseUserPassFile() - 用户密码对解析
- ParseHashFile()     - 哈希文件解析
*/

// =============================================================================
// IP/主机解析
// =============================================================================

// ParseIP 解析各种格式的IP地址
// 支持单个IP、IP范围、CIDR和文件输入
func ParseIP(host string, filename string, nohosts ...string) ([]string, error) {
	var hosts []string

	// 从文件读取主机列表
	if filename != "" {
		fileHosts, err := ReadLinesFromFile(filename)
		if err != nil {
			return nil, fmt.Errorf(i18n.GetText("parser_read_hosts_failed")+": %w", err)
		}
		for _, h := range fileHosts {
			parsed, err := parseHostString(h)
			if err != nil {
				continue // 跳过无效行
			}
			hosts = append(hosts, parsed...)
		}
	}

	// 解析主机参数
	if host != "" {
		hostList, err := parseHostString(host)
		if err != nil {
			return nil, 		fmt.Errorf(i18n.GetText("parser_parse_host_failed")+": %w", err)
		}
		hosts = append(hosts, hostList...)
	}

	// 处理排除主机
	if len(nohosts) > 0 && nohosts[0] != "" {
		excludeList, err := parseHostString(nohosts[0])
		if err != nil {
			return nil, 		fmt.Errorf(i18n.GetText("parser_parse_exclude_failed")+": %w", err)
		}
		hosts = excludeFromList(hosts, excludeList)
	}

	// 去重和排序
	hosts = removeDuplicateStrings(hosts)
	sort.Strings(hosts)

	if len(hosts) == 0 {
		return nil, fmt.Errorf("%s", i18n.GetText("parser_no_valid_hosts"))
	}

	return hosts, nil
}

// parseHostString 解析主机字符串
func parseHostString(host string) ([]string, error) {
	var hosts []string

	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}

		switch {
		case h == "192":
			cidrHosts, err := parseIPCIDR("192.168.0.0/16", SimpleMaxHosts)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, cidrHosts...)
		case h == "172":
			cidrHosts, err := parseIPCIDR("172.16.0.0/12", SimpleMaxHosts)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, cidrHosts...)
		case h == "10":
			cidrHosts, err := parseIPCIDR("10.0.0.0/8", SimpleMaxHosts)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, cidrHosts...)
		case strings.Contains(h, "/"):
			cidrHosts, err := parseIPCIDR(h, SimpleMaxHosts)
			if err != nil {
				return nil, fmt.Errorf(i18n.Tr("parser_cidr_failed", h)+": %w", err)
			}
			hosts = append(hosts, cidrHosts...)
		case strings.Contains(h, "-") && !strings.Contains(h, ":") && looksLikeIPRange(h):
			rangeHosts, err := parseIPRangeString(h, SimpleMaxHosts)
			if err != nil {
				return nil, fmt.Errorf(i18n.Tr("parser_ip_range_failed", h)+": %w", err)
			}
			hosts = append(hosts, rangeHosts...)
		default:
			hosts = append(hosts, h)
		}
	}

	return hosts, nil
}

// =============================================================================
// 端口解析
// =============================================================================

// ParsePort 解析端口配置字符串为端口号列表
func ParsePort(ports string) []int {
	if ports == "" {
		return nil
	}

	var result []int

	// 展开端口组
	ports = expandPortGroups(ports)

	for _, portStr := range strings.Split(ports, ",") {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		if strings.Contains(portStr, "-") {
			rangePorts := parsePortRange(portStr)
			result = append(result, rangePorts...)
		} else {
			if port, err := strconv.Atoi(portStr); err == nil {
				if port >= MinPort && port <= MaxPort {
					result = append(result, port)
				}
			}
		}
	}

	result = removeDuplicatePorts(result)
	sort.Ints(result)

	return result
}

// parsePortRange 解析端口范围
func parsePortRange(rangeStr string) []int {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil
	}

	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))

	if err1 != nil || err2 != nil || start < MinPort || end > MaxPort || start > end {
		return nil
	}

	ports := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}

	return ports
}

// expandPortGroups 展开端口组
func expandPortGroups(ports string) string {
	portGroups := config.GetPortGroups()
	result := ports
	for group, portList := range portGroups {
		result = strings.ReplaceAll(result, group, portList)
	}
	return result
}

// =============================================================================
// 文件读取
// =============================================================================

// ReadLinesFromFile 从文件读取非空非注释行
func ReadLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

// =============================================================================
// 凭据解析
// =============================================================================

// ParseUserPassFile 解析用户名:密码文件
func ParseUserPassFile(filename string) ([]config.CredentialPair, error) {
	lines, err := ReadLinesFromFile(filename)
	if err != nil {
		return nil, err
	}

	var pairs []config.CredentialPair
	for _, line := range lines {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}

		user := strings.TrimSpace(line[:idx])
		pass := line[idx+1:] // 密码不trim，可能包含空格

		if user == "" {
			continue
		}

		pairs = append(pairs, config.CredentialPair{
			Username: user,
			Password: pass,
		})
	}

	return pairs, nil
}

// ParseHashFile 解析哈希文件
func ParseHashFile(filename string) ([]string, [][]byte, error) {
	lines, err := ReadLinesFromFile(filename)
	if err != nil {
		return nil, nil, err
	}

	var hashValues []string
	var hashBytes [][]byte

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) != 32 { // MD5长度
			continue
		}
		if !CompiledHashRegex.MatchString(line) {
			continue
		}

		hashValues = append(hashValues, line)
		if hashByte, err := hex.DecodeString(line); err == nil {
			hashBytes = append(hashBytes, hashByte)
		}
	}

	return hashValues, hashBytes, nil
}

// =============================================================================
// 内部辅助函数
// =============================================================================

// parseIPCIDR 解析CIDR网段
func parseIPCIDR(cidr string, maxTargets int) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	count := 0
	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		count++
		if maxTargets > 0 && count >= maxTargets {
			break
		}
		incrementIP(ip)
	}

	// 移除网络地址和广播地址
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// looksLikeIPRange 检查字符串是否像IP范围格式
// 如 192.168.1.1-100 或 192.168.1.1-192.168.1.100
// 而不是像 111-555.sss.com 这种域名
func looksLikeIPRange(s string) bool {
	idx := strings.Index(s, "-")
	if idx == -1 {
		return false
	}
	// 检查 - 前面的部分是否是有效IP
	startPart := s[:idx]
	return net.ParseIP(startPart) != nil
}

// parseIPRangeString 解析IP范围字符串
func parseIPRangeString(rangeStr string, maxTargets int) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_ip_range_fmt", rangeStr))
	}

	startIPStr := strings.TrimSpace(parts[0])
	endIPStr := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		return nil, 	fmt.Errorf("%s", i18n.Tr("parser_invalid_start_ip", startIPStr))
	}

	// 处理简写格式 (如: 192.168.1.1-100)
	if len(endIPStr) < 4 || !strings.Contains(endIPStr, ".") {
		return parseIPShortRange(startIPStr, endIPStr, maxTargets)
	}

	// 处理完整格式 (如: 192.168.1.1-192.168.1.100)
	endIP := net.ParseIP(endIPStr)
	if endIP == nil {
		return nil, 	fmt.Errorf("%s", i18n.Tr("parser_invalid_end_ip", endIPStr))
	}

	return parseIPFullRange(startIP, endIP, maxTargets)
}

// parseIPShortRange 解析短格式IP范围
func parseIPShortRange(startIPStr, endSuffix string, maxTargets int) ([]string, error) {
	endNum, err := strconv.Atoi(endSuffix)
	if err != nil || endNum > 255 {
		return nil, 	fmt.Errorf("%s", i18n.Tr("parser_invalid_ip_end_val", endSuffix))
	}

	ipParts := strings.Split(startIPStr, ".")
	if len(ipParts) != 4 {
		return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_ip_fmt", startIPStr))
	}

	prefixIP := strings.Join(ipParts[0:3], ".")
	startNum, err := strconv.Atoi(ipParts[3])
	if err != nil || startNum > endNum {
		return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_ip_range_val", startIPStr, endSuffix))
	}

	var allIP []string
	count := 0
	for i := startNum; i <= endNum; i++ {
		allIP = append(allIP, fmt.Sprintf("%s.%d", prefixIP, i))
		count++
		if maxTargets > 0 && count >= maxTargets {
			break
		}
	}

	return allIP, nil
}

// parseIPFullRange 解析完整格式的IP范围
func parseIPFullRange(startIP, endIP net.IP, maxTargets int) ([]string, error) {
	start4 := startIP.To4()
	end4 := endIP.To4()
	if start4 == nil || end4 == nil {
		return nil, fmt.Errorf("%s", i18n.GetText("parser_ipv4_only"))
	}

	startInt := (int(start4[0]) << 24) | (int(start4[1]) << 16) | (int(start4[2]) << 8) | int(start4[3])
	endInt := (int(end4[0]) << 24) | (int(end4[1]) << 16) | (int(end4[2]) << 8) | int(end4[3])

	if startInt > endInt {
		return nil, fmt.Errorf("%s", i18n.GetText("parser_start_gt_end"))
	}

	var ips []string
	current := make(net.IP, len(start4))
	copy(current, start4)

	count := 0
	for {
		ips = append(ips, current.String())
		count++

		if current.Equal(end4) || (maxTargets > 0 && count >= maxTargets) {
			break
		}
		incrementIP(current)
	}

	return ips, nil
}

// incrementIP 计算下一个IP地址
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// excludeFromList 从列表中排除指定项
func excludeFromList(hosts, excludeList []string) []string {
	if len(excludeList) == 0 {
		return hosts
	}

	excludeMap := make(map[string]struct{}, len(excludeList))
	for _, e := range excludeList {
		excludeMap[e] = struct{}{}
	}

	result := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if _, found := excludeMap[h]; !found {
			result = append(result, h)
		}
	}

	return result
}

// removeDuplicateStrings 去除字符串重复项
func removeDuplicateStrings(slice []string) []string {
	if len(slice) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(slice))
	result := make([]string, 0, len(slice))

	for _, item := range slice {
		if _, found := seen[item]; !found {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// removeDuplicatePorts 去除端口重复项
func removeDuplicatePorts(slice []int) []int {
	if len(slice) == 0 {
		return nil
	}

	seen := make(map[int]struct{}, len(slice))
	result := make([]int, 0, len(slice))

	for _, item := range slice {
		if _, found := seen[item]; !found {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// =============================================================================
