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

var ParseIPErr = errors.New("主机解析错误\n" +
	"支持的格式: \n" +
	"192.168.1.1                   (单个IP)\n" +
	"192.168.1.1/8                 (8位子网)\n" +
	"192.168.1.1/16                (16位子网)\n" +
	"192.168.1.1/24                (24位子网)\n" +
	"192.168.1.1,192.168.1.2       (IP列表)\n" +
	"192.168.1.1-192.168.255.255   (IP范围)\n" +
	"192.168.1.1-255               (最后一位简写范围)")

// ParseIP 解析IP地址配置,支持从主机字符串和文件读取
func ParseIP(host string, filename string, nohosts ...string) (hosts []string, err error) {
	// 处理主机和端口组合的情况 (192.168.0.0/16:80)
	if filename == "" && strings.Contains(host, ":") {
		hostport := strings.Split(host, ":")
		if len(hostport) == 2 {
			host = hostport[0]
			hosts = ParseIPs(host)
			Ports = hostport[1]
			fmt.Printf("[*] 已解析主机端口组合,端口设置为: %s\n", Ports)
		}
	} else {
		// 解析主机地址
		hosts = ParseIPs(host)

		// 从文件加载额外主机
		if filename != "" {
			fileHosts, err := Readipfile(filename)
			if err != nil {
				fmt.Printf("[-] 读取主机文件失败: %v\n", err)
			} else {
				hosts = append(hosts, fileHosts...)
				fmt.Printf("[*] 已从文件加载额外主机: %d 个\n", len(fileHosts))
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
			fmt.Printf("[*] 已排除指定主机: %d 个\n", len(excludeHosts))
		}
	}

	// 去重处理
	hosts = RemoveDuplicate(hosts)
	fmt.Printf("[*] 最终有效主机数量: %d\n", len(hosts))

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

// parseIP 解析不同格式的IP地址,返回解析后的IP列表
func parseIP(ip string) []string {
	reg := regexp.MustCompile(`[a-zA-Z]+`)

	switch {
	// 处理常用内网IP段简写
	case ip == "192":
		return parseIP("192.168.0.0/8")
	case ip == "172":
		return parseIP("172.16.0.0/12")
	case ip == "10":
		return parseIP("10.0.0.0/8")

	// 处理/8网段 - 仅扫描网关和随机IP以避免过多扫描
	case strings.HasSuffix(ip, "/8"):
		return parseIP8(ip)

	// 处理CIDR格式 (/24 /16 /8等)
	case strings.Contains(ip, "/"):
		return parseIP2(ip)

	// 处理域名 - 保留域名格式
	case reg.MatchString(ip):
		return []string{ip}

	// 处理IP范围格式 (192.168.1.1-192.168.1.100)
	case strings.Contains(ip, "-"):
		return parseIP1(ip)

	// 处理单个IP地址
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			fmt.Printf("[-] 无效的IP地址格式: %s\n", ip)
			return nil
		}
		return []string{ip}
	}
}

// parseIP2 解析CIDR格式的IP地址段
func parseIP2(host string) []string {
	// 解析CIDR
	_, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		fmt.Printf("[-] CIDR格式解析失败: %s, %v\n", host, err)
		return nil
	}

	// 转换为IP范围并解析
	ipRange := IPRange(ipNet)
	hosts := parseIP1(ipRange)

	fmt.Printf("[*] 已解析CIDR %s -> IP范围 %s\n", host, ipRange)
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
			fmt.Printf("[-] IP范围格式错误: %s\n", ip)
			return nil
		}

		// 解析IP段
		splitIP := strings.Split(ipRange[0], ".")
		startNum, err1 := strconv.Atoi(splitIP[3])
		endNum, err2 := strconv.Atoi(ipRange[1])
		prefixIP := strings.Join(splitIP[0:3], ".")

		if startNum > endNum || err1 != nil || err2 != nil {
			fmt.Printf("[-] IP范围无效: %d-%d\n", startNum, endNum)
			return nil
		}

		// 生成IP列表
		for i := startNum; i <= endNum; i++ {
			allIP = append(allIP, prefixIP+"."+strconv.Itoa(i))
		}

		fmt.Printf("[*] 已生成IP范围: %s.%d - %s.%d\n", prefixIP, startNum, prefixIP, endNum)
	} else {
		// 处理完整IP范围格式 (192.168.111.1-192.168.112.255)
		splitIP1 := strings.Split(ipRange[0], ".")
		splitIP2 := strings.Split(ipRange[1], ".")

		if len(splitIP1) != 4 || len(splitIP2) != 4 {
			fmt.Printf("[-] IP格式错误: %s\n", ip)
			return nil
		}

		// 解析起始和结束IP
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(splitIP1[i])
			ip2, err2 := strconv.Atoi(splitIP2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				fmt.Printf("[-] IP范围无效: %s-%s\n", ipRange[0], ipRange[1])
				return nil
			}
			start[i], end[i] = ip1, ip2
		}

		// 将IP转换为数值并生成范围内的所有IP
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]

		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." +
				strconv.Itoa((num>>16)&0xff) + "." +
				strconv.Itoa((num>>8)&0xff) + "." +
				strconv.Itoa((num)&0xff)
			allIP = append(allIP, ip)
		}

		fmt.Printf("[*] 已生成IP范围: %s - %s\n", ipRange[0], ipRange[1])
	}

	return allIP
}

// IPRange 计算CIDR的起始IP和结束IP
func IPRange(c *net.IPNet) string {
	// 获取起始IP
	start := c.IP.String()

	// 获取子网掩码
	mask := c.Mask

	// 计算广播地址(结束IP)
	bcst := make(net.IP, len(c.IP))
	copy(bcst, c.IP)

	// 通过位运算计算最大IP地址
	for i := 0; i < len(mask); i++ {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = c.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	end := bcst.String()

	// 返回"起始IP-结束IP"格式的字符串
	result := fmt.Sprintf("%s-%s", start, end)
	fmt.Printf("[*] CIDR范围: %s\n", result)

	return result
}

// Readipfile 从文件中按行读取IP地址
func Readipfile(filename string) ([]string, error) {
	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[-] 打开文件失败 %s: %v\n", filename, err)
		return nil, err
	}
	defer file.Close()

	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// 逐行处理IP
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 解析IP:端口格式
		text := strings.Split(line, ":")
		if len(text) == 2 {
			port := strings.Split(text[1], " ")[0]
			num, err := strconv.Atoi(port)
			if err != nil || num < 1 || num > 65535 {
				fmt.Printf("[-] 忽略无效端口: %s\n", line)
				continue
			}

			// 解析带端口的IP地址
			hosts := ParseIPs(text[0])
			for _, host := range hosts {
				HostPort = append(HostPort, fmt.Sprintf("%s:%s", host, port))
			}
			fmt.Printf("[*] 已解析IP端口组合: %s\n", line)
		} else {
			// 解析纯IP地址
			hosts := ParseIPs(line)
			content = append(content, hosts...)
			fmt.Printf("[*] 已解析IP地址: %s\n", line)
		}
	}

	// 检查扫描过程中是否有错误
	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] 读取文件时出错: %v\n", err)
		return content, err
	}

	fmt.Printf("[*] 从文件加载完成,共解析 %d 个IP地址\n", len(content))
	return content, nil
}

// RemoveDuplicate 对字符串切片进行去重
func RemoveDuplicate(old []string) []string {
	// 使用map存储不重复的元素
	temp := make(map[string]struct{})
	var result []string

	// 遍历并去重
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
		fmt.Printf("[-] 无效的IP地址格式: %s\n", realIP)
		return nil
	}

	// 获取/8网段的第一段
	ipRange := strings.Split(ip, ".")[0]
	var allIP []string

	fmt.Printf("[*] 开始解析 %s.0.0.0/8 网段\n", ipRange)

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

	fmt.Printf("[*] 已生成 %d 个采样IP地址\n", len(allIP))
	return allIP
}

// RandInt 生成指定范围内的随机整数
func RandInt(min, max int) int {
	// 参数验证
	if min >= max || min == 0 || max == 0 {
		return max
	}

	// 生成随机数
	return rand.Intn(max-min) + min
}
