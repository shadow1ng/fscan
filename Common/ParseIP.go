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

var ParseIPErr = errors.New(GetText("parse_ip_error"))

// ParseIP 解析IP地址配置
func ParseIP(host string, filename string, nohosts ...string) (hosts []string, err error) {
	// 处理主机和端口组合的情况
	if filename == "" && strings.Contains(host, ":") {
		hostport := strings.Split(host, ":")
		if len(hostport) == 2 {
			host = hostport[0]
			hosts = ParseIPs(host)
			Ports = hostport[1]
			LogInfo(GetText("host_port_parsed", Ports))
		}
	} else {
		// 解析主机地址
		hosts = ParseIPs(host)

		// 从文件加载额外主机
		if filename != "" {
			fileHosts, err := Readipfile(filename)
			if err != nil {
				LogError(GetText("read_host_file_failed", err))
			} else {
				hosts = append(hosts, fileHosts...)
				LogInfo(GetText("extra_hosts_loaded", len(fileHosts)))
			}
		}
	}

	// 处理排除主机
	if len(nohosts) > 0 && nohosts[0] != "" {
		excludeHosts := ParseIPs(nohosts[0])
		if len(excludeHosts) > 0 {
			// 使用map存储有效主机
			temp := make(map[string]struct{})
			for _, host := range hosts {
				temp[host] = struct{}{}
			}

			// 删除需要排除的主机
			for _, host := range excludeHosts {
				delete(temp, host)
			}

			// 重建主机列表
			var newHosts []string
			for host := range temp {
				newHosts = append(newHosts, host)
			}
			hosts = newHosts
			sort.Strings(hosts)
			LogInfo(GetText("hosts_excluded", len(excludeHosts)))
		}
	}

	// 去重处理
	hosts = RemoveDuplicate(hosts)
	LogInfo(GetText("final_valid_hosts", len(hosts)))

	// 检查解析结果
	if len(hosts) == 0 && len(HostPort) == 0 && (host != "" || filename != "") {
		return nil, ParseIPErr
	}

	return hosts, nil
}

func ParseIPs(ip string) (hosts []string) {
	if strings.Contains(ip, ",") {
		IPList := strings.Split(ip, ",")
		var ips []string
		for _, ip := range IPList {
			ips = parseIP(ip)
			hosts = append(hosts, ips...)
		}
	} else {
		hosts = parseIP(ip)
	}
	return hosts
}

func parseIP(ip string) []string {
	reg := regexp.MustCompile(`[a-zA-Z]+`)

	switch {
	case ip == "192":
		return parseIP("192.168.0.0/16")
	case ip == "172":
		return parseIP("172.16.0.0/12")
	case ip == "10":
		return parseIP("10.0.0.0/8")
	case strings.HasSuffix(ip, "/8"):
		return parseIP8(ip)
	case strings.Contains(ip, "/"):
		return parseIP2(ip)
	case reg.MatchString(ip):
		return []string{ip}
	case strings.Contains(ip, "-"):
		return parseIP1(ip)
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			LogError(GetText("invalid_ip_format", ip))
			return nil
		}
		return []string{ip}
	}
}

// parseIP2 解析CIDR格式的IP地址段
func parseIP2(host string) []string {
	_, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		LogError(GetText("cidr_parse_failed", host, err))
		return nil
	}

	ipRange := IPRange(ipNet)
	hosts := parseIP1(ipRange)
	LogInfo(GetText("parse_cidr_to_range", host, ipRange))
	return hosts
}

// parseIP1 解析IP范围格式的地址
func parseIP1(ip string) []string {
	ipRange := strings.Split(ip, "-")
	testIP := net.ParseIP(ipRange[0])
	var allIP []string

	// 处理简写格式 (192.168.111.1-255)
	if len(ipRange[1]) < 4 {
		endNum, err := strconv.Atoi(ipRange[1])
		if testIP == nil || endNum > 255 || err != nil {
			LogError(GetText("ip_range_format_error", ip))
			return nil
		}

		splitIP := strings.Split(ipRange[0], ".")
		startNum, err1 := strconv.Atoi(splitIP[3])
		endNum, err2 := strconv.Atoi(ipRange[1])
		prefixIP := strings.Join(splitIP[0:3], ".")

		if startNum > endNum || err1 != nil || err2 != nil {
			LogError(GetText("invalid_ip_range", startNum, endNum))
			return nil
		}

		for i := startNum; i <= endNum; i++ {
			allIP = append(allIP, prefixIP+"."+strconv.Itoa(i))
		}

		LogInfo(GetText("generate_ip_range", prefixIP, startNum, prefixIP, endNum))
	} else {
		// 处理完整IP范围格式
		splitIP1 := strings.Split(ipRange[0], ".")
		splitIP2 := strings.Split(ipRange[1], ".")

		if len(splitIP1) != 4 || len(splitIP2) != 4 {
			LogError(GetText("ip_format_error", ip))
			return nil
		}

		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(splitIP1[i])
			ip2, err2 := strconv.Atoi(splitIP2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				LogError(GetText("invalid_ip_range", ipRange[0], ipRange[1]))
				return nil
			}
			start[i], end[i] = ip1, ip2
		}

		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]

		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." +
				strconv.Itoa((num>>16)&0xff) + "." +
				strconv.Itoa((num>>8)&0xff) + "." +
				strconv.Itoa((num)&0xff)
			allIP = append(allIP, ip)
		}

		LogInfo(GetText("generate_ip_range", ipRange[0], ipRange[1]))
	}

	return allIP
}

// IPRange 计算CIDR的起始IP和结束IP
func IPRange(c *net.IPNet) string {
	start := c.IP.String()
	mask := c.Mask
	bcst := make(net.IP, len(c.IP))
	copy(bcst, c.IP)

	for i := 0; i < len(mask); i++ {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = c.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	end := bcst.String()

	result := fmt.Sprintf("%s-%s", start, end)
	LogInfo(GetText("cidr_range", result))
	return result
}

// Readipfile 从文件中按行读取IP地址
func Readipfile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		LogError(GetText("open_file_failed", filename, err))
		return nil, err
	}
	defer file.Close()

	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		text := strings.Split(line, ":")
		if len(text) == 2 {
			port := strings.Split(text[1], " ")[0]
			num, err := strconv.Atoi(port)
			if err != nil || num < 1 || num > 65535 {
				LogError(GetText("invalid_port", line))
				continue
			}

			hosts := ParseIPs(text[0])
			for _, host := range hosts {
				HostPort = append(HostPort, fmt.Sprintf("%s:%s", host, port))
			}
			LogInfo(GetText("parse_ip_port", line))
		} else {
			hosts := ParseIPs(line)
			content = append(content, hosts...)
			LogInfo(GetText("parse_ip_address", line))
		}
	}

	if err := scanner.Err(); err != nil {
		LogError(GetText("read_file_error", err))
		return content, err
	}

	LogInfo(GetText("file_parse_complete", len(content)))
	return content, nil
}

// RemoveDuplicate 对字符串切片进行去重
func RemoveDuplicate(old []string) []string {
	temp := make(map[string]struct{})
	var result []string

	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// parseIP8 解析/8网段的IP地址
func parseIP8(ip string) []string {
	// 去除CIDR后缀获取基础IP
	realIP := ip[:len(ip)-2]
	testIP := net.ParseIP(realIP)

	if testIP == nil {
		LogError(GetText("invalid_ip_format", realIP))
		return nil
	}

	// 获取/8网段的第一段
	ipRange := strings.Split(ip, ".")[0]
	var allIP []string

	LogInfo(GetText("parse_subnet", ipRange))

	// 遍历所有可能的第二、三段
	for a := 0; a <= 255; a++ {
		for b := 0; b <= 255; b++ {
			// 添加常用网关IP
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.1", ipRange, a, b)) // 默认网关
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.2", ipRange, a, b)) // 备用网关
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.4", ipRange, a, b)) // 常用服务器
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.5", ipRange, a, b)) // 常用服务器

			// 随机采样不同范围的IP
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", ipRange, a, b, RandInt(6, 55)))    // 低段随机
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", ipRange, a, b, RandInt(56, 100)))  // 中低段随机
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", ipRange, a, b, RandInt(101, 150))) // 中段随机
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", ipRange, a, b, RandInt(151, 200))) // 中高段随机
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.%d", ipRange, a, b, RandInt(201, 253))) // 高段随机
			allIP = append(allIP, fmt.Sprintf("%s.%d.%d.254", ipRange, a, b))                   // 广播地址前
		}
	}

	LogInfo(GetText("sample_ip_generated", len(allIP)))
	return allIP
}

// RandInt 生成指定范围内的随机整数
func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}
