package common

import (
	"strconv"
	"strings"
)

func ParsePort(ports string) []int {
	var scanPorts []int
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

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
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = removeDuplicate(scanPorts)
	return scanPorts
}

func removeDuplicate(old []int) []int {
	result := make([]int, 0, len(old))
	temp := map[int]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
