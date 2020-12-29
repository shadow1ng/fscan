package common

import (
	"sort"
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
			sort.Strings(ranges)
			port = ranges[0]
			upper = ranges[1]
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	return scanPorts
}