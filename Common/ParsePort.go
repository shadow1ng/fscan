package Common

import (
	"sort"
	"strconv"
	"strings"
)

// ParsePort 解析端口配置字符串为端口号列表
func ParsePort(ports string) []int {
	// 预定义的端口组
	portGroups := map[string]string{
		"service": ServicePorts,
		"db":      DbPorts,
		"web":     WebPorts,
		"all":     AllPorts,
		"main":    MainPorts,
	}

	// 检查是否匹配预定义组
	if definedPorts, exists := portGroups[ports]; exists {
		ports = definedPorts
	}

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

		// 处理端口范围
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				LogError(GetText("port_range_format_error", port))
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
				LogError(GetText("ignore_invalid_port", i))
				continue
			}
			scanPorts = append(scanPorts, i)
		}
	}

	// 去重并排序
	scanPorts = removeDuplicate(scanPorts)
	sort.Ints(scanPorts)

	LogBase(GetText("valid_port_count", len(scanPorts)))
	return scanPorts
}

// removeDuplicate 对整数切片进行去重
func removeDuplicate(old []int) []int {
	temp := make(map[int]struct{})
	var result []int

	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
