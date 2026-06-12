//go:build web

package api

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
	_ "modernc.org/sqlite"
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

// ResultStore SQLite 结果存储
type ResultStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// 全局结果存储
var globalResultStore *ResultStore

func init() {
	store, err := NewResultStore()
	if err != nil {
		panic(fmt.Sprintf("failed to init result store: %v", err))
	}
	globalResultStore = store
}

// dbPath 返回数据库文件路径
func dbPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".fscan")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "results.db")
}

// NewResultStore 创建 SQLite 存储
func NewResultStore() (*ResultStore, error) {
	db, err := sql.Open("sqlite", dbPath())
	if err != nil {
		return nil, err
	}

	// WAL 模式，提升并发读写
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS results (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			time    TEXT    NOT NULL,
			type    TEXT    NOT NULL,
			target  TEXT    NOT NULL,
			status  TEXT    NOT NULL DEFAULT '',
			details TEXT    NOT NULL DEFAULT '{}',
			UNIQUE(type, target, status)
		)
	`); err != nil {
		db.Close()
		return nil, err
	}

	return &ResultStore{db: db}, nil
}

// Add 添加结果（去重，重复返回 nil）
func (s *ResultStore) Add(result interface{}) *ResultItem {
	s.mu.Lock()
	defer s.mu.Unlock()

	item := ResultItem{
		Time:    time.Now(),
		Details: result,
	}

	// 解析结果字段
	if m, ok := result.(map[string]interface{}); ok {
		if t, ok := m["type"].(string); ok {
			item.Type = strings.ToLower(t)
		}
		if target, ok := m["target"].(string); ok {
			item.Target = target
		}
		if status, ok := m["status"].(string); ok {
			item.Status = status
		}
		if details, ok := m["details"].(map[string]interface{}); ok {
			item.Details = details
			if port, ok := details["port"]; ok {
				if item.Target != "" && !strings.Contains(item.Target, ":") {
					item.Target = fmt.Sprintf("%s:%v", item.Target, port)
				}
			}
			item.Status = buildStatusFromDetails(item.Type, item.Status, details)
		}
	}

	detailsJSON, _ := json.Marshal(item.Details)

	// service/port 类型：同一 target 只保留最详细的
	if item.Type == "service" || item.Type == "port" {
		var existID int64
		var existStatus string
		err := s.db.QueryRow(
			"SELECT id, status FROM results WHERE type = ? AND target = ? LIMIT 1",
			item.Type, item.Target,
		).Scan(&existID, &existStatus)

		if err == nil {
			// 已有记录，判断是否需要更新
			if (existStatus == "identified" || existStatus == "open" || existStatus == "") &&
				item.Status != "identified" && item.Status != "open" && item.Status != "" {
				s.db.Exec(
					"UPDATE results SET status = ?, details = ?, time = ? WHERE id = ?",
					item.Status, string(detailsJSON), item.Time.Format(time.RFC3339), existID,
				)
				item.ID = existID
				return &item
			}
			return nil
		}
	}

	// 插入（UNIQUE 约束自动去重）
	res, err := s.db.Exec(
		"INSERT OR IGNORE INTO results (time, type, target, status, details) VALUES (?, ?, ?, ?, ?)",
		item.Time.Format(time.RFC3339), item.Type, item.Target, item.Status, string(detailsJSON),
	)
	if err != nil {
		return nil
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		return nil // 重复
	}

	item.ID, _ = res.LastInsertId()
	return &item
}

// List 获取所有结果
func (s *ResultStore) List() []ResultItem {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, time, type, target, status, details FROM results ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	return scanRows(rows)
}

// Stats 获取统计信息
func (s *ResultStore) Stats() ScanStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stats ScanStats
	rows, err := s.db.Query("SELECT type, COUNT(*) FROM results GROUP BY type")
	if err != nil {
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var t string
		var count int
		if rows.Scan(&t, &count) == nil {
			switch t {
			case "host":
				stats.HostsScanned = count
			case "port":
				stats.PortsScanned = count
			case "service":
				stats.ServicesFound = count
			case "vuln":
				stats.VulnsFound = count
			}
		}
	}
	return stats
}

// Clear 清空结果
func (s *ResultStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM results")
}

// scanRows 解析查询结果
func scanRows(rows *sql.Rows) []ResultItem {
	var items []ResultItem
	for rows.Next() {
		var item ResultItem
		var timeStr, detailsStr string
		if err := rows.Scan(&item.ID, &timeStr, &item.Type, &item.Target, &item.Status, &detailsStr); err != nil {
			continue
		}
		item.Time, _ = time.Parse(time.RFC3339, timeStr)
		var details interface{}
		if json.Unmarshal([]byte(detailsStr), &details) == nil {
			item.Details = details
		}
		items = append(items, item)
	}
	return items
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

// ExportOutput 导出输出结构
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

// Export 导出结果
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

		if len(hosts) > 0 {
			writer.Write([]string{"# Hosts"})
			writer.Write([]string{"Target"})
			for _, item := range hosts {
				writer.Write([]string{item.Target})
			}
			writer.Write([]string{})
		}

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

		if len(services) > 0 {
			writer.Write([]string{"# Services"})
			writer.Write([]string{"Target", "Service", "Version", "Banner"})
			for _, item := range services {
				service, version, banner := extractServiceInfo(item.Details)
				writer.Write([]string{item.Target, service, version, banner})
			}
			writer.Write([]string{})
		}

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
	_, port, ok := splitTargetHostPort(target)
	if !ok {
		return ""
	}
	return port
}

// extractHost 从 "ip:port" 中提取主机
func extractHost(target string) string {
	host, _, ok := splitTargetHostPort(target)
	if !ok {
		return target
	}
	return host
}

func splitTargetHostPort(target string) (string, string, bool) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if strings.Count(target, ":") != 1 {
			return "", "", false
		}
		parts := strings.SplitN(target, ":", 2)
		host, port = parts[0], parts[1]
	}
	if host == "" || port == "" {
		return "", "", false
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", "", false
	}
	return host, port, true
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
		if name, ok := details["name"].(string); ok && name != "" {
			parts = append(parts, name)
		}
		if version, ok := details["version"].(string); ok && version != "" {
			parts = append(parts, version)
		}
		if product, ok := details["product"].(string); ok && product != "" {
			parts = append(parts, product)
		}
		if os, ok := details["os"].(string); ok && os != "" {
			parts = append(parts, os)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " | ")
		}

	case "vuln":
		return normalizeVulnStatus(originalStatus, details)

	case "host":
		return "alive"
	}

	return originalStatus
}

// normalizeVulnStatus 统一漏洞状态显示
func normalizeVulnStatus(status string, details map[string]interface{}) string {
	vulnTranslations := map[string]string{
		"weak_credential": i18n.GetText("web_result_weak_credential"),
		"unauthorized":    i18n.GetText("unauthorized_access"),
		"unauth":          i18n.GetText("unauthorized_access"),
		"anonymous":       i18n.GetText("web_result_anonymous_access"),
		"CVE":             i18n.GetText("web_result_vulnerability"),
	}

	if strings.HasPrefix(status, "weak_credential:") {
		cred := strings.TrimPrefix(status, "weak_credential:")
		cred = strings.TrimSpace(cred)
		return i18n.Tr("web_result_weak_credential_detail", cred)
	}

	for eng, chn := range vulnTranslations {
		if strings.Contains(strings.ToLower(status), strings.ToLower(eng)) {
			if strings.Contains(status, chn) {
				return status
			}
			return strings.Replace(status, eng, chn, 1)
		}
	}

	return status
}
