package core

import (
	"sort"
	"sync"
)

// highPriorityPorts 高价值端口优先级表
// 数字越小优先级越高，用户最关心这些服务能快速出结果
var highPriorityPorts = map[int]int{
	80:    1,  // HTTP
	443:   2,  // HTTPS
	22:    3,  // SSH
	3389:  4,  // RDP
	445:   5,  // SMB
	3306:  6,  // MySQL
	1433:  7,  // MSSQL
	6379:  8,  // Redis
	21:    9,  // FTP
	23:    10, // Telnet
	8080:  11, // HTTP-Alt
	8443:  12, // HTTPS-Alt
	5432:  13, // PostgreSQL
	27017: 14, // MongoDB
	1521:  15, // Oracle
	5900:  16, // VNC
	25:    17, // SMTP
	110:   18, // POP3
	143:   19, // IMAP
	53:    20, // DNS
}

// SocketIterator 流式生成 host:port 组合
// 设计原则：O(1) 内存，按需生成
// 使用端口喷洒策略：Port1全IP -> Port2全IP -> ...
// 优势：流量分散，避免单IP限速
type SocketIterator struct {
	hosts   []string
	ports   []int
	hostIdx int
	portIdx int
	total   int64
	mu      sync.Mutex
}

// NewSocketIterator 创建流式迭代器
// 自动对端口进行智能排序：高价值端口优先，让用户更快看到有意义的结果
func NewSocketIterator(hosts []string, ports []int, exclude map[int]struct{}) *SocketIterator {
	validPorts := filterExcludedPorts(ports, exclude)
	sortedPorts := sortPortsByPriority(validPorts)
	return &SocketIterator{
		hosts: hosts,
		ports: sortedPorts,
		total: int64(len(hosts)) * int64(len(sortedPorts)),
	}
}

// sortPortsByPriority 智能排序端口
// 策略：高价值端口优先，其余按数字升序
func sortPortsByPriority(ports []int) []int {
	if len(ports) <= 1 {
		return ports
	}

	result := make([]int, len(ports))
	copy(result, ports)

	sort.Slice(result, func(i, j int) bool {
		pi, pj := result[i], result[j]
		priI, okI := highPriorityPorts[pi]
		priJ, okJ := highPriorityPorts[pj]

		// 都有优先级：按优先级排序
		if okI && okJ {
			return priI < priJ
		}
		// 只有一个有优先级：有优先级的排前面
		if okI {
			return true
		}
		if okJ {
			return false
		}
		// 都没有优先级：按端口号升序
		return pi < pj
	})

	return result
}

// Next 返回下一个 host:port 组合，ok=false 表示迭代结束
// 端口喷洒顺序：先遍历所有IP的同一端口，再换下一个端口
func (it *SocketIterator) Next() (string, int, bool) {
	it.mu.Lock()
	defer it.mu.Unlock()

	// 空输入或迭代结束
	if len(it.hosts) == 0 || it.portIdx >= len(it.ports) {
		return "", 0, false
	}

	host := it.hosts[it.hostIdx]
	port := it.ports[it.portIdx]

	// 端口喷洒：先遍历所有IP，再换端口
	it.hostIdx++
	if it.hostIdx >= len(it.hosts) {
		it.hostIdx = 0
		it.portIdx++
	}

	return host, port, true
}

// Total 返回总任务数（用于进度条）
func (it *SocketIterator) Total() int64 {
	return it.total
}

// filterExcludedPorts 过滤排除的端口
func filterExcludedPorts(ports []int, exclude map[int]struct{}) []int {
	if len(exclude) == 0 {
		return ports
	}
	result := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, excluded := exclude[p]; !excluded {
			result = append(result, p)
		}
	}
	return result
}
