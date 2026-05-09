package output

import (
	"fmt"
	"sync"
)

// ResultBuffer 公共的去重缓冲逻辑，供各Writer复用
type ResultBuffer struct {
	mu sync.Mutex

	// 分类缓冲
	HostResults    []*ScanResult
	PortResults    []*ScanResult
	ServiceResults []*ScanResult
	VulnResults    []*ScanResult

	// 去重map
	seenHosts    map[string]struct{}
	seenPorts    map[string]struct{}
	seenServices map[string]int // 存储索引，用于更新更完整的记录
	seenVulns    map[string]struct{}
}

// NewResultBuffer 创建新的结果缓冲
func NewResultBuffer() *ResultBuffer {
	return &ResultBuffer{
		seenHosts:    make(map[string]struct{}),
		seenPorts:    make(map[string]struct{}),
		seenServices: make(map[string]int),
		seenVulns:    make(map[string]struct{}),
	}
}

// Add 添加结果到缓冲（自动去重）
func (b *ResultBuffer) Add(result *ScanResult) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if result == nil {
		return
	}

	key := b.generateKey(result)

	switch result.Type {
	case TypeHost:
		if _, exists := b.seenHosts[key]; !exists {
			b.seenHosts[key] = struct{}{}
			b.HostResults = append(b.HostResults, result)
		}
	case TypePort:
		if _, exists := b.seenPorts[key]; !exists {
			b.seenPorts[key] = struct{}{}
			b.PortResults = append(b.PortResults, result)
		}
	case TypeService:
		if idx, exists := b.seenServices[key]; !exists {
			b.seenServices[key] = len(b.ServiceResults)
			b.ServiceResults = append(b.ServiceResults, result)
		} else {
			b.mergeDetails(b.ServiceResults[idx], result)
			// 保留信息更完整的记录，同时保留另一条记录补充的字段
			if b.isMoreComplete(result, b.ServiceResults[idx]) {
				b.ServiceResults[idx] = result
			}
		}
	case TypeVuln:
		if _, exists := b.seenVulns[key]; !exists {
			b.seenVulns[key] = struct{}{}
			b.VulnResults = append(b.VulnResults, result)
		}
	}
}

func (b *ResultBuffer) mergeDetails(oldResult, newResult *ScanResult) {
	if oldResult == nil || newResult == nil {
		return
	}
	if oldResult.Details == nil {
		oldResult.Details = make(map[string]interface{})
	}
	if newResult.Details == nil {
		newResult.Details = make(map[string]interface{})
	}
	for k, v := range oldResult.Details {
		if _, exists := newResult.Details[k]; !exists {
			newResult.Details[k] = v
		}
	}
	for k, v := range newResult.Details {
		if _, exists := oldResult.Details[k]; !exists {
			oldResult.Details[k] = v
		}
	}
}

// generateKey 生成结果的唯一键（用于去重）
func (b *ResultBuffer) generateKey(result *ScanResult) string {
	switch result.Type {
	case TypeHost:
		return result.Target
	case TypePort:
		if result.Details != nil {
			if port, ok := result.Details["port"]; ok {
				return fmt.Sprintf("%s:%v", result.Target, port)
			}
		}
		return result.Target
	case TypeService:
		return result.Target
	case TypeVuln:
		return result.Target + "|" + result.Status
	default:
		return result.Target + "|" + result.Status
	}
}

// isMoreComplete 判断新记录是否比旧记录信息更完整
func (b *ResultBuffer) isMoreComplete(newResult, oldResult *ScanResult) bool {
	return b.CalculateCompleteness(newResult) > b.CalculateCompleteness(oldResult)
}

// CalculateCompleteness 计算记录的信息完整度
func (b *ResultBuffer) CalculateCompleteness(result *ScanResult) int {
	score := 0
	if result.Details == nil {
		return score
	}

	// 有 status 码加分
	if status, ok := result.Details["status"]; ok && status != nil && status != 0 {
		score += 2
	}
	// 有 server 加分
	if server, ok := result.Details["server"].(string); ok && server != "" {
		score += 2
	}
	// 有 title 加分
	if title, ok := result.Details["title"].(string); ok && title != "" {
		score += 1
	}
	// 有指纹加分
	if fps := result.Details["fingerprints"]; fps != nil {
		switch v := fps.(type) {
		case []string:
			if len(v) > 0 {
				score += 3
			}
		case []interface{}:
			if len(v) > 0 {
				score += 3
			}
		}
	}
	// 有 banner 加分
	if banner, ok := result.Details["banner"].(string); ok && banner != "" {
		score += 1
	}

	return score
}

// Summary 获取统计摘要
func (b *ResultBuffer) Summary() (hosts, ports, services, vulns int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.HostResults), len(b.PortResults), len(b.ServiceResults), len(b.VulnResults)
}

// Clear 清空缓冲
func (b *ResultBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.HostResults = nil
	b.PortResults = nil
	b.ServiceResults = nil
	b.VulnResults = nil
	b.seenHosts = make(map[string]struct{})
	b.seenPorts = make(map[string]struct{})
	b.seenServices = make(map[string]int)
	b.seenVulns = make(map[string]struct{})
}
