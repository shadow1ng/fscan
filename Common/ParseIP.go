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
var ErrParseIP = errors.New(GetText("parse_ip_error")) // IP解析失败的统一错误

// ParseIP 解析各种格式的IP地址并处理排除逻辑
// 参数: host-IP地址表达式, filename-包含IP的文件, nohosts-要排除的IP
// 返回: 解析后的IP列表和可能的错误
func ParseIP(host string, filename string, nohosts string) ([]string, error) {
	var hosts []string

	// 处理主机和端口组合的情况
	if filename == "" && strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		if len(parts) == 2 {
			host = parts[0]
			Ports = parts[1]
			LogInfo(GetText("host_port_parsed", Ports))
		}
	}

	// 解析主机地址
	if host != "" {
		for _, ip := range strings.Split(host, ",") {
			if ip = strings.TrimSpace(ip); ip == "" {
				continue
			}

			// 根据IP表达式的不同格式进行处理
			switch {
			case ip == "192": // 192.168.0.0/16简写
				ips := parseIPRange(expandCIDR("192.168.0.0/16"))
				hosts = append(hosts, ips...)

			case ip == "172": // 172.16.0.0/12简写
				ips := parseIPRange(expandCIDR("172.16.0.0/12"))
				hosts = append(hosts, ips...)

			case ip == "10": // 10.0.0.0/8简写
				hosts = append(hosts, sampleSubnet8("10.0.0.0/8")...)

			case strings.HasSuffix(ip, "/8"): // /8大型网段采样
				hosts = append(hosts, sampleSubnet8(ip)...)

			case strings.Contains(ip, "/"): // CIDR格式
				hosts = append(hosts, parseIPRange(expandCIDR(ip))...)

			case strings.Contains(ip, "-"): // 范围格式
				hosts = append(hosts, parseIPRange(ip)...)

			default: // 单个IP或域名
				if regexp.MustCompile(`[a-zA-Z]`).MatchString(ip) {
					hosts = append(hosts, ip) // 域名直接添加
				} else if net.ParseIP(ip) != nil {
					hosts = append(hosts, ip) // 有效IP直接添加
				} else {
					LogError(GetText("invalid_ip_format", ip))
				}
			}
		}
	}

	// 从文件加载主机地址
	if filename != "" {
		file, err := os.Open(filename)
		if err != nil {
			LogError(GetText("open_file_failed", filename, err))
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue // 跳过空行和注释
				}

				// 处理IP:PORT格式
				if strings.Contains(line, ":") {
					parts := strings.Split(line, ":")
					if len(parts) == 2 {
						// 提取并验证端口
						portPart := strings.Split(strings.Split(parts[1], " ")[0], "#")[0]
						port, err := strconv.Atoi(portPart)
						if err != nil || port < 1 || port > 65535 {
							LogError(GetText("invalid_port", line))
							continue
						}

						// 为每个解析的IP添加端口
						ips, _ := ParseIP(parts[0], "", "") // 修复：正确处理两个返回值，传递空字符串
						for _, ip := range ips {
							HostPort = append(HostPort, fmt.Sprintf("%s:%s", ip, portPart))
						}
					}
				} else {
					// 处理纯IP格式，递归调用ParseIP处理单行
					ips, _ := ParseIP(line, "", "") // 修复：正确处理两个返回值，传递空字符串
					hosts = append(hosts, ips...)
				}
			}

			if err := scanner.Err(); err != nil {
				LogError(GetText("read_file_error", err))
			}
		}
	}

	// 处理排除IP
	if nohosts != "" {
		excludes, _ := ParseIP(nohosts, "", "") // 修复：正确处理两个返回值，传递空字符串
		if len(excludes) > 0 {
			// 使用map存储需排除的IP以加速查找
			excludeMap := make(map[string]struct{})
			for _, ip := range excludes {
				excludeMap[ip] = struct{}{}
			}

			// 过滤IP列表
			var filteredHosts []string
			for _, ip := range hosts {
				if _, excluded := excludeMap[ip]; !excluded {
					filteredHosts = append(filteredHosts, ip)
				}
			}
			hosts = filteredHosts
			LogInfo(GetText("hosts_excluded", len(excludes)))
		}
	}

	// 去重并排序
	if len(hosts) > 0 {
		uniqueMap := make(map[string]struct{})
		var unique []string

		for _, ip := range hosts {
			if _, exists := uniqueMap[ip]; !exists {
				uniqueMap[ip] = struct{}{}
				unique = append(unique, ip)
			}
		}

		sort.Strings(unique)
		hosts = unique
		LogInfo(GetText("final_valid_hosts", len(hosts)))
	}

	// 验证结果
	if len(hosts) == 0 && len(HostPort) == 0 && (host != "" || filename != "") {
		return nil, ErrParseIP
	}

	return hosts, nil
}

// expandCIDR 将CIDR格式转换为IP范围表达式
// 参数: cidr - CIDR格式的IP网段
// 返回: 格式为"起始IP-结束IP"的范围字符串
func expandCIDR(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		LogError(GetText("cidr_parse_failed", cidr, err))
		return ""
	}

	// 计算广播地址
	start := ipNet.IP
	broadcast := make(net.IP, len(start))
	copy(broadcast, start)

	for i := 0; i < len(ipNet.Mask); i++ {
		broadcast[i] = start[i] | ^ipNet.Mask[i]
	}

	return fmt.Sprintf("%s-%s", start.String(), broadcast.String())
}

// parseIPRange 解析IP范围表达式
// 参数: ipRange - IP范围表达式，如192.168.1.1-100或192.168.1.1-192.168.1.100
// 返回: 展开后的IP地址列表
func parseIPRange(ipRange string) []string {
	if ipRange == "" {
		return nil
	}

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

	var ips []string

	// 处理简写格式 (如: 192.168.1.1-100)
	if !strings.Contains(endIP, ".") {
		endNum, err := strconv.Atoi(endIP)
		if err != nil || endNum > 255 {
			LogError(GetText("ip_range_format_error", ipRange))
			return nil
		}

		ipParts := strings.Split(startIP, ".")
		if len(ipParts) != 4 {
			LogError(GetText("ip_format_error", startIP))
			return nil
		}

		prefixIP := strings.Join(ipParts[0:3], ".")
		startNum, _ := strconv.Atoi(ipParts[3])

		if startNum > endNum {
			LogError(GetText("invalid_ip_range", startNum, endNum))
			return nil
		}

		// 生成简写范围的IP列表
		for i := startNum; i <= endNum; i++ {
			ips = append(ips, fmt.Sprintf("%s.%d", prefixIP, i))
		}

		LogInfo(GetText("generate_ip_range", prefixIP, startNum, prefixIP, endNum))
	} else {
		// 处理完整格式 (如: 192.168.1.1-192.168.1.100)
		if net.ParseIP(endIP) == nil {
			LogError(GetText("invalid_ip_format", endIP))
			return nil
		}

		// 转换为整数进行计算
		startInt := ipToInt(startIP)
		endInt := ipToInt(endIP)

		if startInt == 0 || endInt == 0 || startInt > endInt {
			LogError(GetText("invalid_ip_range", startIP, endIP))
			return nil
		}

		// 限制IP范围大小
		if endInt-startInt > 65535 {
			LogError(GetText("ip_range_too_large", startIP, endIP))
			endInt = startInt + 65535 // 截断超大范围
		}

		// 生成完整范围的IP列表
		for i := startInt; i <= endInt; i++ {
			ips = append(ips, intToIP(i))
		}

		LogInfo(GetText("generate_ip_range_full", startIP, endIP, len(ips)))
	}

	return ips
}

// sampleSubnet8 对/8网段采样生成代表性IP列表
// 参数: subnet - /8网段的CIDR表示
// 返回: 采样的IP地址列表
func sampleSubnet8(subnet string) []string {
	// 获取/8网段的第一段
	firstOctet := strings.Split(subnet, ".")[0]
	LogInfo(GetText("parse_subnet", firstOctet))

	// 预分配容量
	sampleIPs := make([]string, 0, 256)

	// 对常用网段进行更全面的扫描
	commonSecondOctets := []int{0, 1, 2, 10, 100, 200, 254}

	// 对常用二级网段采样
	for _, secondOctet := range commonSecondOctets {
		for thirdOctet := 0; thirdOctet < 256; thirdOctet += 10 {
			// 添加常见的网关和服务器IP
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.1", firstOctet, secondOctet, thirdOctet))
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.254", firstOctet, secondOctet, thirdOctet))

			// 随机采样一个主机IP
			fourthOctet := rand.Intn(252) + 2 // 2-253之间的随机数
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, fourthOctet))
		}
	}

	// 对其他二级网段进行稀疏采样
	for secondOctet := 0; secondOctet < 256; secondOctet += 32 {
		for thirdOctet := 0; thirdOctet < 256; thirdOctet += 32 {
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.1", firstOctet, secondOctet, thirdOctet))
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, rand.Intn(252)+2))
		}
	}

	LogInfo(GetText("sample_ip_generated", len(sampleIPs)))
	return sampleIPs
}

// ipToInt 将IP地址转换为32位整数
func ipToInt(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// intToIP 将32位整数转换为IP地址字符串
func intToIP(ipInt uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ipInt>>24)&0xFF,
		(ipInt>>16)&0xFF,
		(ipInt>>8)&0xFF,
		ipInt&0xFF)
}
