//go:build web

package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
)

// ResultItem 扫描结果项
type ResultItem struct {
	ID      int64       `json:"id"`
	Time    time.Time   `json:"time"`
	Type    string      `json:"type"` // host, port, service, vuln
	Target  string      `json:"target"`
	Status  string      `json:"status"`
	Details interface{} `json:"details,omitempty"`
}

// ResultStore 结果存储
type ResultStore struct {
	mu      sync.RWMutex
	items   []ResultItem
	counter int64
	stats   ScanStats
	// 去重
	seen map[string]bool
	// service 类型按 target 索引，用于更新
	serviceIndex map[string]int
}

// 全局结果存储
var globalResultStore = &ResultStore{
	items:        make([]ResultItem, 0),
	seen:         make(map[string]bool),
	serviceIndex: make(map[string]int),
}

// Add 添加结果，返回格式化后的结果项（去重，重复则返回nil）
func (s *ResultStore) Add(result interface{}) *ResultItem {
	s.mu.Lock()
	defer s.mu.Unlock()

	item := ResultItem{
		Time:    time.Now(),
		Details: result,
	}

	// 根据结果类型分类
	if m, ok := result.(map[string]interface{}); ok {
		if t, ok := m["type"].(string); ok {
			item.Type = strings.ToLower(t) // 统一转小写
		}
		if target, ok := m["target"].(string); ok {
			item.Target = target
		}
		if status, ok := m["status"].(string); ok {
			item.Status = status
		}
		// 从details提取更多信息
		if details, ok := m["details"].(map[string]interface{}); ok {
			item.Details = details
			// 组合 target:port
			if port, ok := details["port"]; ok {
				if item.Target != "" && !strings.Contains(item.Target, ":") {
					item.Target = fmt.Sprintf("%s:%v", item.Target, port)
				}
			}
			// 构建更有意义的status
			item.Status = buildStatusFromDetails(item.Type, item.Status, details)
		}
	}

	// 生成去重键
	key := fmt.Sprintf("%s|%s|%s", item.Type, item.Target, item.Status)
	if s.seen[key] {
		return nil // 完全重复，不添加
	}

	// service/port 类型特殊处理：同一 target 只保留最详细的
	if item.Type == "service" || item.Type == "port" {
		indexKey := item.Type + "|" + item.Target
		if idx, exists := s.serviceIndex[indexKey]; exists {
			oldStatus := s.items[idx].Status
			// 如果旧的是基础状态，新的更详细，则更新
			if (oldStatus == "identified" || oldStatus == "open" || oldStatus == "") &&
				item.Status != "identified" && item.Status != "open" && item.Status != "" {
				s.items[idx].Status = item.Status
				s.items[idx].Details = item.Details
				s.items[idx].Time = item.Time
				s.seen[key] = true
				return &s.items[idx]
			}
			// 否则跳过（保留已有信息）
			return nil
		}
		// 新记录，记录索引
		s.serviceIndex[indexKey] = len(s.items)
	}

	s.seen[key] = true

	// 统计
	switch item.Type {
	case "host":
		s.stats.HostsScanned++
	case "port":
		s.stats.PortsScanned++
	case "service":
		s.stats.ServicesFound++
	case "vuln":
		s.stats.VulnsFound++
	}

	s.counter++
	item.ID = s.counter
	s.items = append(s.items, item)
	return &item
}

// List 获取所有结果
func (s *ResultStore) List() []ResultItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ResultItem{}, s.items...)
}

// Stats 获取统计信息
func (s *ResultStore) Stats() ScanStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// Clear 清空结果
func (s *ResultStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = make([]ResultItem, 0)
	s.counter = 0
	s.stats = ScanStats{}
	s.seen = make(map[string]bool)
	s.serviceIndex = make(map[string]int)
}

// ResultHandler 结果处理器
type ResultHandler struct {
	store *ResultStore
}

// NewResultHandler 创建结果处理器
func NewResultHandler() *ResultHandler {
	return &ResultHandler{
		store: globalResultStore,
	}
}

// List 获取结果列表
func (h *ResultHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 支持类型过滤
	typeFilter := r.URL.Query().Get("type")
	items := h.store.List()

	if typeFilter != "" {
		filtered := make([]ResultItem, 0)
		for _, item := range items {
			if item.Type == typeFilter {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"total": len(items),
		"stats": h.store.Stats(),
	})
}

// ExportOutput 导出输出结构（与CLI格式一致）
type ExportOutput struct {
	ScanTime time.Time     `json:"scan_time"`
	Summary  ExportSummary `json:"summary"`
	Hosts    []ResultItem  `json:"hosts,omitempty"`
	Ports    []ResultItem  `json:"ports,omitempty"`
	Services []ResultItem  `json:"services,omitempty"`
	Vulns    []ResultItem  `json:"vulns,omitempty"`
}

// ExportSummary 导出摘要
type ExportSummary struct {
	TotalHosts    int `json:"total_hosts"`
	TotalPorts    int `json:"total_ports"`
	TotalServices int `json:"total_services"`
	TotalVulns    int `json:"total_vulns"`
}

// Export 导出结果（与CLI格式一致）
func (h *ResultHandler) Export(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	items := h.store.List()

	// 按类型分类
	var hosts, ports, services, vulns []ResultItem
	for _, item := range items {
		switch item.Type {
		case "host":
			hosts = append(hosts, item)
		case "port":
			ports = append(ports, item)
		case "service":
			services = append(services, item)
		case "vuln":
			vulns = append(vulns, item)
		}
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=fscan_results.json")

		output := ExportOutput{
			ScanTime: time.Now(),
			Summary: ExportSummary{
				TotalHosts:    len(hosts),
				TotalPorts:    len(ports),
				TotalServices: len(services),
				TotalVulns:    len(vulns),
			},
			Hosts:    hosts,
			Ports:    ports,
			Services: services,
			Vulns:    vulns,
		}
		json.NewEncoder(w).Encode(output)

	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=fscan_results.csv")
		writer := csv.NewWriter(w)

		// Hosts section
		if len(hosts) > 0 {
			writer.Write([]string{"# Hosts"})
			writer.Write([]string{"Target"})
			for _, item := range hosts {
				writer.Write([]string{item.Target})
			}
			writer.Write([]string{})
		}

		// Ports section
		if len(ports) > 0 {
			writer.Write([]string{"# Ports"})
			writer.Write([]string{"Target", "Port", "Status"})
			for _, item := range ports {
				port := extractPort(item.Target)
				target := extractHost(item.Target)
				writer.Write([]string{target, port, "open"})
			}
			writer.Write([]string{})
		}

		// Services section
		if len(services) > 0 {
			writer.Write([]string{"# Services"})
			writer.Write([]string{"Target", "Service", "Version", "Banner"})
			for _, item := range services {
				service, version, banner := extractServiceInfo(item.Details)
				writer.Write([]string{item.Target, service, version, banner})
			}
			writer.Write([]string{})
		}

		// Vulns section
		if len(vulns) > 0 {
			writer.Write([]string{"# Vulns"})
			writer.Write([]string{"Target", "Type", "Details"})
			for _, item := range vulns {
				vulnType := extractVulnType(item.Details)
				writer.Write([]string{item.Target, vulnType, item.Status})
			}
			writer.Write([]string{})
		}

		writer.Flush()

	default:
		http.Error(w, "Unsupported format", http.StatusBadRequest)
	}
}

// extractPort 从 "ip:port" 中提取端口
func extractPort(target string) string {
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		return target[idx+1:]
	}
	return ""
}

// extractHost 从 "ip:port" 中提取主机
func extractHost(target string) string {
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		return target[:idx]
	}
	return target
}

// extractServiceInfo 从 details 中提取服务信息
func extractServiceInfo(details interface{}) (service, version, banner string) {
	if m, ok := details.(map[string]interface{}); ok {
		if s, ok := m["service"].(string); ok {
			service = s
		}
		if s, ok := m["name"].(string); ok && service == "" {
			service = s
		}
		if v, ok := m["version"].(string); ok {
			version = v
		}
		if b, ok := m["banner"].(string); ok {
			banner = escapeControlChars(b)
			if len(banner) > 100 {
				banner = banner[:100] + "..."
			}
		}
	}
	return
}

// extractVulnType 从 details 中提取漏洞类型
func extractVulnType(details interface{}) string {
	if m, ok := details.(map[string]interface{}); ok {
		if t, ok := m["type"].(string); ok {
			return t
		}
	}
	return ""
}

// escapeControlChars 转义控制字符
func escapeControlChars(s string) string {
	replacer := strings.NewReplacer(
		"\r\n", "\\r\\n",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
	)
	return replacer.Replace(s)
}

// Clear 清空结果
func (h *ResultHandler) Clear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.store.Clear()
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "cleared",
	})
}

// buildStatusFromDetails 从details构建可读的status
func buildStatusFromDetails(resultType, originalStatus string, details map[string]interface{}) string {
	var parts []string

	switch resultType {
	case "port":
		return "open"

	case "service":
		// 服务名
		if name, ok := details["name"].(string); ok && name != "" {
			parts = append(parts, name)
		}
		// 版本
		if version, ok := details["version"].(string); ok && version != "" {
			parts = append(parts, version)
		}
		// 产品
		if product, ok := details["product"].(string); ok && product != "" {
			parts = append(parts, product)
		}
		// 系统
		if os, ok := details["os"].(string); ok && os != "" {
			parts = append(parts, os)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " | ")
		}

	case "vuln":
		// 统一漏洞显示格式
		return normalizeVulnStatus(originalStatus, details)

	case "host":
		return "alive"
	}

	return originalStatus
}

// normalizeVulnStatus 统一漏洞状态显示
func normalizeVulnStatus(status string, details map[string]interface{}) string {
	// 英文转中文映射
	vulnTranslations := map[string]string{
		"weak_credential": i18n.GetText("web_result_weak_credential"),
		"unauthorized":    i18n.GetText("unauthorized_access"),
		"unauth":          i18n.GetText("unauthorized_access"),
		"anonymous":       i18n.GetText("web_result_anonymous_access"),
		"CVE":             i18n.GetText("web_result_vulnerability"),
	}

	// 处理 "weak_credential: user:pass" 格式
	if strings.HasPrefix(status, "weak_credential:") {
		cred := strings.TrimPrefix(status, "weak_credential:")
		cred = strings.TrimSpace(cred)
		return i18n.Tr("web_result_weak_credential_detail", cred)
	}

	// 处理其他已知格式
	for eng, chn := range vulnTranslations {
		if strings.Contains(strings.ToLower(status), strings.ToLower(eng)) {
			// 如果已经是中文格式，直接返回
			if strings.Contains(status, chn) {
				return status
			}
			// 替换英文部分
			return strings.Replace(status, eng, chn, 1)
		}
	}

	return status
}
