package common

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

var ParseIPErr = errors.New(" host parsing error\n" +
	"format: \n" +
	"192.168.1.1\n" +
	"192.168.1.1/8\n" +
	"192.168.1.1/16\n" +
	"192.168.1.1/24\n" +
	"192.168.1.1,192.168.1.2\n" +
	"192.168.1.1-192.168.255.255\n" +
	"192.168.1.1-255")

func ParseIP(host string, filename string, nohosts ...string) (hosts []string, err error) {
	if filename == "" && strings.Contains(host, ":") {
		//192.168.0.0/16:80
		hostport := strings.Split(host, ":")
		if len(hostport) == 2 {
			host = hostport[0]
			hosts = ParseIPs(host)
			Ports = hostport[1]
		}
	} else {
		hosts = ParseIPs(host)
		if filename != "" {
			var filehost []string
			filehost, _ = Readipfile(filename)
			hosts = append(hosts, filehost...)
		}
	}

	if len(nohosts) > 0 {
		nohost := nohosts[0]
		if nohost != "" {
			nohosts := ParseIPs(nohost)
			if len(nohosts) > 0 {
				temp := map[string]struct{}{}
				for _, host := range hosts {
					temp[host] = struct{}{}
				}

				for _, host := range nohosts {
					delete(temp, host)
				}

				var newDatas []string
				for host := range temp {
					newDatas = append(newDatas, host)
				}
				hosts = newDatas
				sort.Strings(hosts)
			}
		}
	}
	hosts = RemoveDuplicate(hosts)
	if len(hosts) == 0 && len(HostPort) == 0 && host != "" && filename != "" {
		err = ParseIPErr
	}
	return
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
		return parseIP("192.168.0.0/8")
	case ip == "172":
		return parseIP("172.16.0.0/12")
	case ip == "10":
		return parseIP("10.0.0.0/8")
	// 扫描/8时,只扫网关和随机IP,避免扫描过多IP
	case strings.HasSuffix(ip, "/8"):
		return parseIP8(ip)
	//解析 /24 /16 /8 /xxx 等
	case strings.Contains(ip, "/"):
		return parseIP2(ip)
	//可能是域名,用lookup获取ip
	case reg.MatchString(ip):
		//	_, err := net.LookupHost(ip)
		//	if err != nil {
		//		return nil
		//	}
		return []string{ip}
	//192.168.1.1-192.168.1.100
	case strings.Contains(ip, "-"):
		return parseIP1(ip)
	//处理单个ip
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil
		}
		return []string{ip}
	}
}

// 把 192.168.x.x/xx 转换成 192.168.x.x-192.168.x.x
func parseIP2(host string) (hosts []string) {
	_, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		return
	}
	hosts = parseIP1(IPRange(ipNet))
	return
}

// 解析ip段:
//
//	192.168.111.1-255
//	192.168.111.1-192.168.112.255
func parseIP1(ip string) []string {
	IPRange := strings.Split(ip, "-")
	testIP := net.ParseIP(IPRange[0])
	var AllIP []string
	if len(IPRange[1]) < 4 {
		Range, err := strconv.Atoi(IPRange[1])
		if testIP == nil || Range > 255 || err != nil {
			return nil
		}
		SplitIP := strings.Split(IPRange[0], ".")
		ip1, err1 := strconv.Atoi(SplitIP[3])
		ip2, err2 := strconv.Atoi(IPRange[1])
		PrefixIP := strings.Join(SplitIP[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return nil
		}
		for i := ip1; i <= ip2; i++ {
			AllIP = append(AllIP, PrefixIP+"."+strconv.Itoa(i))
		}
	} else {
		SplitIP1 := strings.Split(IPRange[0], ".")
		SplitIP2 := strings.Split(IPRange[1], ".")
		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
			return nil
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(SplitIP1[i])
			ip2, err2 := strconv.Atoi(SplitIP2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return nil
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			AllIP = append(AllIP, ip)
		}
	}
	return AllIP
}

// 获取起始IP、结束IP
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
	return fmt.Sprintf("%s-%s", start, end) //返回用-表示的ip段,192.168.1.0-192.168.255.255
}

// 按行读ip
func Readipfile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Open %s error, %v", filename, err)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			text := strings.Split(line, ":")
			if len(text) == 2 {
				port := strings.Split(text[1], " ")[0]
				num, err := strconv.Atoi(port)
				if err != nil || (num < 1 || num > 65535) {
					continue
				}
				hosts := ParseIPs(text[0])
				for _, host := range hosts {
					HostPort = append(HostPort, fmt.Sprintf("%s:%s", host, port))
				}
			} else {
				host := ParseIPs(line)
				content = append(content, host...)
			}
		}
	}
	return content, nil
}

// 去重
func RemoveDuplicate(old []string) []string {
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func parseIP8(ip string) []string {
	realIP := ip[:len(ip)-2]
	testIP := net.ParseIP(realIP)

	if testIP == nil {
		return nil
	}

	IPrange := strings.Split(ip, ".")[0]
	var AllIP []string
	for a := 0; a <= 255; a++ {
		for b := 0; b <= 255; b++ {
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 1))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 2))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 4))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 5))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(6, 55)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(56, 100)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(101, 150)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(151, 200)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(201, 253)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 254))
		}
	}
	return AllIP
}

func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}
