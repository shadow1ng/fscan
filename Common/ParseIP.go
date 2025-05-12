package Common

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// IP解析相关错误
var (
	ErrParseIP = errors.New(GetText("parse_ip_error")) // IP解析失败的统一错误
)

// ParseIP 解析各种格式的IP地址
// 参数:
//   - host: 主机地址（可以是单个IP、IP范围、CIDR或常用网段简写）
//   - filename: 包含主机地址的文件名
//   - nohosts: 需要排除的主机地址列表
//
// 返回:
//   - []string: 解析后的IP地址列表
//   - error: 解析过程中的错误
func ParseIP(host string, filename string, nohosts ...string) (hosts []string, err error) {
	// 处理主机和端口组合的情况 (格式: IP:PORT)
	if filename == "" && strings.Contains(host, ":") {
		hostport := strings.Split(host, ":")
		if len(hostport) == 2 {
			host = hostport[0]
			hosts = parseIPList(host)
			Ports = hostport[1]
			LogBase(GetText("host_port_parsed", Ports))
		}
	} else {
		// 解析主机地址
		hosts = parseIPList(host)

		// 从文件加载额外主机
		if filename != "" {
			fileHosts, err := readIPFile(filename)
			if err != nil {
				LogError(GetText("read_host_file_failed", err))
			} else {
				hosts = append(hosts, fileHosts...)
				LogBase(GetText("extra_hosts_loaded", len(fileHosts)))
			}
		}
	}

	// 处理需要排除的主机
	hosts = excludeHosts(hosts, nohosts)

	// 去重并排序
	hosts = removeDuplicateIPs(hosts)
	LogBase(GetText("final_valid_hosts", len(hosts)))

	// 检查解析结果
	if len(hosts) == 0 && len(HostPort) == 0 && (host != "" || filename != "") {
		return nil, ErrParseIP
	}

	return hosts, nil
}

// parseIPList 解析逗号分隔的IP地址列表
// 参数:
//   - ipList: 逗号分隔的IP地址列表字符串
//
// 返回:
//   - []string: 解析后的IP地址列表
func parseIPList(ipList string) []string {
	var result []string

	// 处理逗号分隔的IP列表
	if strings.Contains(ipList, ",") {
		ips := strings.Split(ipList, ",")
		for _, ip := range ips {
			if parsed := parseSingleIP(ip); len(parsed) > 0 {
				result = append(result, parsed...)
			}
		}
	} else if ipList != "" {
		// 解析单个IP地址或范围
		result = parseSingleIP(ipList)
	}

	return result
}

// parseSingleIP 解析单个IP地址或IP范围
// 支持多种格式:
// - 普通IP: 192.168.1.1
// - 简写网段: 192, 172, 10
// - CIDR: 192.168.0.0/24
// - 范围: 192.168.1.1-192.168.1.100 或 192.168.1.1-100
// - 域名: example.com
// 参数:
//   - ip: IP地址或范围字符串
//
// 返回:
//   - []string: 解析后的IP地址列表
func parseSingleIP(ip string) []string {
	// 检测是否包含字母（可能是域名）
	isAlpha := regexp.MustCompile(`[a-zA-Z]+`).MatchString(ip)

	// 根据不同格式解析IP
	switch {
	case ip == "192":
		// 常用内网段简写
		return parseSingleIP("192.168.0.0/16")
	case ip == "172":
		// 常用内网段简写
		return parseSingleIP("172.16.0.0/12")
	case ip == "10":
		// 常用内网段简写
		return parseSingleIP("10.0.0.0/8")
	case strings.HasSuffix(ip, "/8"):
		// 处理/8网段（使用采样方式）
		return parseSubnet8(ip)
	case strings.Contains(ip, "/"):
		// 处理CIDR格式
		return parseCIDR(ip)
	case isAlpha:
		// 处理域名，直接返回
		return []string{ip}
	case strings.Contains(ip, "-"):
		// 处理IP范围
		return parseIPRange(ip)
	default:
		// 尝试解析为单个IP地址
		if testIP := net.ParseIP(ip); testIP != nil {
			return []string{ip}
		}
		LogError(GetText("invalid_ip_format", ip))
		return nil
	}
}

// parseCIDR 解析CIDR格式的IP地址段
// 例如: 192.168.1.0/24
// 参数:
//   - cidr: CIDR格式的IP地址段
//
// 返回:
//   - []string: 展开后的IP地址列表
func parseCIDR(cidr string) []string {
	// 解析CIDR格式
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		LogError(GetText("cidr_parse_failed", cidr, err))
		return nil
	}

	// 转换为IP范围
	ipRange := calculateIPRange(ipNet)
	hosts := parseIPRange(ipRange)
	LogBase(GetText("parse_cidr_to_range", cidr, ipRange))
	return hosts
}

// calculateIPRange 计算CIDR的起始IP和结束IP
// 例如: 192.168.1.0/24 -> 192.168.1.0-192.168.1.255
// 参数:
//   - cidr: 解析后的IPNet对象
//
// 返回:
//   - string: 格式为"起始IP-结束IP"的范围字符串
func calculateIPRange(cidr *net.IPNet) string {
	// 获取网络起始IP
	start := cidr.IP.String()
	mask := cidr.Mask

	// 计算广播地址(最后一个IP)
	bcst := make(net.IP, len(cidr.IP))
	copy(bcst, cidr.IP)

	// 将网络掩码按位取反，然后与IP地址按位或，得到广播地址
	for i := 0; i < len(mask); i++ {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = cidr.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	end := bcst.String()

	result := fmt.Sprintf("%s-%s", start, end)
	LogBase(GetText("cidr_range", result))
	return result
}

// parseIPRange 解析IP范围格式的地址
// 支持两种格式:
// - 完整格式: 192.168.1.1-192.168.1.100
// - 简写格式: 192.168.1.1-100
// 参数:
//   - ipRange: IP范围字符串
//
// 返回:
//   - []string: 展开后的IP地址列表
func parseIPRange(ipRange string) []string {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		LogError(GetText("ip_range_format_error", ipRange))
		return nil
	}

	startIP := parts[0]
	endIP := parts[1]

	// 验证起始IP
	if net.ParseIP(startIP) == nil {
		LogError(GetText("invalid_ip_format", startIP))
		return nil
	}

	// 处理简写格式 (如: 192.168.1.1-100)
	if len(endIP) < 4 || !strings.Contains(endIP, ".") {
		return parseShortIPRange(startIP, endIP)
	} else {
		// 处理完整格式 (如: 192.168.1.1-192.168.1.100)
		return parseFullIPRange(startIP, endIP)
	}
}

// parseShortIPRange 解析简写格式的IP范围
// 例如: 192.168.1.1-100 表示从192.168.1.1到192.168.1.100
// 参数:
//   - startIP: 起始IP
//   - endSuffix: 结束IP的最后一部分
//
// 返回:
//   - []string: 展开后的IP地址列表
func parseShortIPRange(startIP, endSuffix string) []string {
	var allIP []string

	// 将结束段转换为数字
	endNum, err := strconv.Atoi(endSuffix)
	if err != nil || endNum > 255 {
		LogError(GetText("ip_range_format_error", startIP+"-"+endSuffix))
		return nil
	}

	// 分解起始IP
	ipParts := strings.Split(startIP, ".")
	if len(ipParts) != 4 {
		LogError(GetText("ip_format_error", startIP))
		return nil
	}

	// 获取前缀和起始IP的最后一部分
	prefixIP := strings.Join(ipParts[0:3], ".")
	startNum, err := strconv.Atoi(ipParts[3])
	if err != nil || startNum > endNum {
		LogError(GetText("invalid_ip_range", startNum, endNum))
		return nil
	}

	// 生成IP范围
	for i := startNum; i <= endNum; i++ {
		allIP = append(allIP, fmt.Sprintf("%s.%d", prefixIP, i))
	}

	LogBase(GetText("generate_ip_range", prefixIP, startNum, prefixIP, endNum))
	return allIP
}

// parseFullIPRange 解析完整格式的IP范围
// 例如: 192.168.1.1-192.168.2.100
// 参数:
//   - startIP: 起始IP
//   - endIP: 结束IP
//
// 返回:
//   - []string: 展开后的IP地址列表
func parseFullIPRange(startIP, endIP string) []string {
	var allIP []string

	// 验证结束IP
	if net.ParseIP(endIP) == nil {
		LogError(GetText("invalid_ip_format", endIP))
		return nil
	}

	// 分解起始IP和结束IP
	startParts := strings.Split(startIP, ".")
	endParts := strings.Split(endIP, ".")

	if len(startParts) != 4 || len(endParts) != 4 {
		LogError(GetText("ip_format_error", startIP+"-"+endIP))
		return nil
	}

	// 转换为整数数组
	var start, end [4]int
	for i := 0; i < 4; i++ {
		var err1, err2 error
		start[i], err1 = strconv.Atoi(startParts[i])
		end[i], err2 = strconv.Atoi(endParts[i])

		if err1 != nil || err2 != nil || start[i] > 255 || end[i] > 255 {
			LogError(GetText("ip_format_error", startIP+"-"+endIP))
			return nil
		}
	}

	// 计算IP地址的整数表示
	startInt := (start[0] << 24) | (start[1] << 16) | (start[2] << 8) | start[3]
	endInt := (end[0] << 24) | (end[1] << 16) | (end[2] << 8) | end[3]

	// 检查范围的有效性
	if startInt > endInt {
		LogError(GetText("invalid_ip_range", startIP, endIP))
		return nil
	}

	// 限制IP范围的大小，防止生成过多IP导致内存问题
	if endInt-startInt > 65535 {
		LogError(GetText("ip_range_too_large", startIP, endIP))
		// 可以考虑在这里实现采样或截断策略
	}

	// 生成IP范围
	for ipInt := startInt; ipInt <= endInt; ipInt++ {
		ip := fmt.Sprintf("%d.%d.%d.%d",
			(ipInt>>24)&0xFF,
			(ipInt>>16)&0xFF,
			(ipInt>>8)&0xFF,
			ipInt&0xFF)
		allIP = append(allIP, ip)
	}

	LogBase(GetText("generate_ip_range_full", startIP, endIP, len(allIP)))
	return allIP
}

// parseSubnet8 解析/8网段的IP地址，生成采样IP列表
// 由于/8网段包含1600多万个IP，因此采用采样方式
// 参数:
//   - subnet: CIDR格式的/8网段
//
// 返回:
//   - []string: 采样的IP地址列表
func parseSubnet8(subnet string) []string {
	// 去除CIDR后缀获取基础IP
	baseIP := subnet[:len(subnet)-2]
	if net.ParseIP(baseIP) == nil {
		LogError(GetText("invalid_ip_format", baseIP))
		return nil
	}

	// 获取/8网段的第一段
	firstOctet := strings.Split(baseIP, ".")[0]
	var sampleIPs []string

	LogBase(GetText("parse_subnet", firstOctet))

	// 预分配足够的容量以提高性能
	// 每个二级网段10个IP，共256*256个二级网段
	sampleIPs = make([]string, 0, 10)

	// 对常用网段进行更全面的扫描
	commonSecondOctets := []int{0, 1, 2, 10, 100, 200, 254}

	// 对于每个选定的第二段，采样部分第三段
	for _, secondOctet := range commonSecondOctets {
		for thirdOctet := 0; thirdOctet < 256; thirdOctet += 10 {
			// 添加常见的网关和服务器IP
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.1", firstOctet, secondOctet, thirdOctet))   // 默认网关
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.254", firstOctet, secondOctet, thirdOctet)) // 通常用于路由器/交换机

			// 随机采样不同范围的主机IP
			fourthOctet := randomInt(2, 253)
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, fourthOctet))
		}
	}

	// 对其他二级网段进行稀疏采样
	samplingStep := 32 // 每32个二级网段采样1个
	for secondOctet := 0; secondOctet < 256; secondOctet += samplingStep {
		for thirdOctet := 0; thirdOctet < 256; thirdOctet += samplingStep {
			// 对于采样的网段，取几个代表性IP
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.1", firstOctet, secondOctet, thirdOctet))
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, randomInt(2, 253)))
		}
	}

	LogBase(GetText("sample_ip_generated", len(sampleIPs)))
	return sampleIPs
}

// readIPFile 从文件中按行读取IP地址
// 支持两种格式:
// - 每行一个IP或IP范围
// - IP:PORT 格式指定端口
// 参数:
//   - filename: 包含IP地址的文件路径
//
// 返回:
//   - []string: 解析后的IP地址列表
//   - error: 读取和解析过程中的错误
func readIPFile(filename string) ([]string, error) {
	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		LogError(GetText("open_file_failed", filename, err))
		return nil, err
	}
	defer file.Close()

	var ipList []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// 逐行处理
	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // 跳过空行和注释行
		}

		lineCount++

		// 处理IP:PORT格式
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				// 提取端口部分，处理可能的注释
				portPart := strings.Split(parts[1], " ")[0]
				portPart = strings.Split(portPart, "#")[0]
				port, err := strconv.Atoi(portPart)

				// 验证端口有效性
				if err != nil || port < 1 || port > 65535 {
					LogError(GetText("invalid_port", line))
					continue
				}

				// 解析IP部分并与端口组合
				hosts := parseIPList(parts[0])
				for _, host := range hosts {
					HostPort = append(HostPort, fmt.Sprintf("%s:%s", host, portPart))
				}
				LogBase(GetText("parse_ip_port", line))
			} else {
				LogError(GetText("invalid_ip_port_format", line))
			}
		} else {
			// 处理纯IP格式
			hosts := parseIPList(line)
			ipList = append(ipList, hosts...)
			LogBase(GetText("parse_ip_address", line))
		}
	}

	// 检查扫描过程中的错误
	if err := scanner.Err(); err != nil {
		LogError(GetText("read_file_error", err))
		return ipList, err
	}

	LogBase(GetText("file_parse_complete", len(ipList)))
	return ipList, nil
}

// excludeHosts 从主机列表中排除指定的主机
// 参数:
//   - hosts: 原始主机列表
//   - nohosts: 需要排除的主机列表(可选)
//
// 返回:
//   - []string: 排除后的主机列表
func excludeHosts(hosts []string, nohosts []string) []string {
	// 如果没有需要排除的主机，直接返回原列表
	if len(nohosts) == 0 || nohosts[0] == "" {
		return hosts
	}

	// 解析排除列表
	excludeList := parseIPList(nohosts[0])
	if len(excludeList) == 0 {
		return hosts
	}

	// 使用map存储有效主机，提高查找效率
	hostMap := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		hostMap[host] = struct{}{}
	}

	// 从map中删除需要排除的主机
	for _, host := range excludeList {
		delete(hostMap, host)
	}

	// 重建主机列表
	result := make([]string, 0, len(hostMap))
	for host := range hostMap {
		result = append(result, host)
	}

	// 排序以保持结果的稳定性
	sort.Strings(result)
	LogBase(GetText("hosts_excluded", len(excludeList)))

	return result
}

// removeDuplicateIPs 去除重复的IP地址
// 参数:
//   - ips: 包含可能重复项的IP地址列表
//
// 返回:
//   - []string: 去重后的IP地址列表
func removeDuplicateIPs(ips []string) []string {
	// 使用map去重
	ipMap := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		ipMap[ip] = struct{}{}
	}

	// 创建结果切片并添加唯一的IP
	result := make([]string, 0, len(ipMap))
	for ip := range ipMap {
		result = append(result, ip)
	}

	// 排序以保持结果的稳定性
	sort.Strings(result)
	return result
}

// randomInt 生成指定范围内的随机整数
// 参数:
//   - min: 最小值(包含)
//   - max: 最大值(包含)
//
// 返回:
//   - int: 生成的随机数
func randomInt(min, max int) int {
	if min >= max || min < 0 || max <= 0 {
		return max
	}
	return rand.Intn(max-min+1) + min
}
