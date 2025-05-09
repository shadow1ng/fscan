package Common

import (
	"sort"
	"strconv"
	"strings"
)

// ParsePort 解析端口配置字符串为端口号列表
// 支持预定义端口组、单个端口和端口范围格式
// 返回已排序且去重的有效端口号切片
func ParsePort(ports string) []int {
	// 检查预定义的端口组
	switch ports {
	case "service":
		ports = ServicePorts
	case "db":
		ports = DbPorts
	case "web":
		ports = WebPorts
	case "all":
		ports = AllPorts
	case "main":
		ports = MainPorts
	}

	// 空配置直接返回nil
	if ports == "" {
		return nil
	}

	// 使用map来自动去重
	portMap := make(map[int]struct{})

	// 处理端口配置
	for _, portConfig := range strings.Split(ports, ",") {
		portConfig = strings.TrimSpace(portConfig)
		if portConfig == "" {
			continue
		}

		// 默认为单端口配置
		start, end := 0, 0

		// 处理端口范围 (如 "80-100")
		if strings.Contains(portConfig, "-") {
			parts := strings.Split(portConfig, "-")
			if len(parts) == 2 {
				// 解析起始和结束端口
				s, errStart := strconv.Atoi(parts[0])
				e, errEnd := strconv.Atoi(parts[1])

				if errStart == nil && errEnd == nil {
					// 确保小端口在前，大端口在后
					if s > e {
						s, e = e, s
					}
					start, end = s, e
				} else {
					LogError(GetText("port_range_format_error", portConfig))
					continue
				}
			} else {
				LogError(GetText("port_range_format_error", portConfig))
				continue
			}
		} else {
			// 单个端口的情况
			p, err := strconv.Atoi(portConfig)
			if err != nil {
				LogError(GetText("port_format_error", portConfig))
				continue
			}
			start, end = p, p
		}

		// 添加端口到映射表，自动去重
		for port := start; port <= end; port++ {
			// 验证端口有效性
			if port < 1 || port > 65535 {
				LogError(GetText("ignore_invalid_port", port))
				continue
			}
			portMap[port] = struct{}{}
		}
	}

	// 将map转换回切片
	result := make([]int, 0, len(portMap))
	for port := range portMap {
		result = append(result, port)
	}

	// 排序端口列表
	sort.Ints(result)

	LogInfo(GetText("valid_port_count", len(result)))
	return result
}
