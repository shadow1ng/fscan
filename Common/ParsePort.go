package Common

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePort 解析端口配置字符串为端口号列表
func ParsePort(ports string) []int {
	if ports == "" {
		return nil
	}

	var scanPorts []int
	slices := strings.Split(ports, ",")

	// 处理每个端口配置
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}

		// 处理预定义端口组
		if PortGroup[port] != "" {
			groupPorts := ParsePort(PortGroup[port])
			scanPorts = append(scanPorts, groupPorts...)
			fmt.Printf("[*] 解析端口组 %s -> %v\n", port, groupPorts)
			continue
		}

		// 处理端口范围
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				fmt.Printf("[!] 无效的端口范围格式: %s\n", port)
				continue
			}

			// 确保起始端口小于结束端口
			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}

		// 生成端口列表
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			if i > 65535 || i < 1 {
				fmt.Printf("[!] 忽略无效端口: %d\n", i)
				continue
			}
			scanPorts = append(scanPorts, i)
		}
	}

	// 去重并排序
	scanPorts = removeDuplicate(scanPorts)
	sort.Ints(scanPorts)

	fmt.Printf("[*] 共解析 %d 个有效端口\n", len(scanPorts))
	return scanPorts
}

// removeDuplicate 对整数切片进行去重
func removeDuplicate(old []int) []int {
	// 使用map存储不重复的元素
	temp := make(map[int]struct{})
	var result []int

	// 遍历并去重
	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
