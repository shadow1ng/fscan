package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// escapeControlChars 转义控制字符
func escapeControlChars(s string) string {
	s = strings.ToValidUTF8(s, "?")

	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, "\\x%02x", r)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// =============================================================================
// TXTWriter - 文本格式写入器
// =============================================================================

// TXTWriter 文本格式写入器（分类缓冲，按类型聚合输出）
type TXTWriter struct {
	file         *os.File
	bufWriter    *bufio.Writer
	mu           sync.Mutex
	closed       bool
	buffer       *ResultBuffer // 内存分类缓冲
	realtimeFile *os.File      // 实时备份文件
	realtimePath string        // 实时备份文件路径
}

// NewTXTWriter 创建文本写入器
func NewTXTWriter(filePath string) (*TXTWriter, error) {
	file, err := os.OpenFile(filePath, DefaultFileFlags, DefaultFilePermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to create TXT file: %w", err)
	}

	// 创建实时备份文件（防崩溃丢数据）
	realtimePath := filePath + ".realtime.tmp"
	realtimeFile, err := os.OpenFile(realtimePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create realtime backup file: %w", err)
	}

	return &TXTWriter{
		file:         file,
		bufWriter:    bufio.NewWriter(file),
		buffer:       NewResultBuffer(),
		realtimeFile: realtimeFile,
		realtimePath: realtimePath,
	}, nil
}

// WriteHeader 写入头部
func (w *TXTWriter) WriteHeader() error {
	return nil
}

// Write 收集扫描结果到分类缓冲，同时实时备份
func (w *TXTWriter) Write(result *ScanResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("writer is closed")
	}
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	// 1. 加入内存分类缓冲（用于最终有序输出）
	w.buffer.Add(result)

	// 2. 实时写入备份文件（防崩溃丢数据）
	if w.realtimeFile != nil {
		line := w.formatLine(result)
		if _, err := w.realtimeFile.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write realtime backup: %w", err)
		}
		if err := w.realtimeFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync realtime backup: %w", err)
		}
	}

	return nil
}

// getSeparator 获取分隔线文本
func (w *TXTWriter) getSeparator(newType ResultType) string {
	switch newType {
	case TypeHost:
		return "# ===== 存活主机 ====="
	case TypePort:
		return "# ===== 开放端口 ====="
	case TypeService:
		return "# ===== 服务信息 ====="
	case TypeVuln:
		return "# ===== 漏洞信息 ====="
	default:
		return "# ===================="
	}
}

// formatLine 根据结果类型格式化输出行
func (w *TXTWriter) formatLine(result *ScanResult) string {
	switch result.Type {
	case TypeHost:
		return result.Target
	case TypePort:
		port := w.getDetail(result, "port")
		if port != nil {
			return fmt.Sprintf("%s:%v", result.Target, port)
		}
		return result.Target
	case TypeService:
		return w.formatServiceLine(result)
	case TypeVuln:
		return w.formatVulnLine(result)
	default:
		return result.Target
	}
}

// formatServiceLine 格式化服务识别结果
func (w *TXTWriter) formatServiceLine(result *ScanResult) string {
	service := w.getDetailStr(result, "service")
	banner := w.getDetailStr(result, "banner")

	// 判断是否为Web服务
	isWebFlag := false
	if v, ok := w.getDetail(result, "is_web").(bool); ok && v {
		isWebFlag = true
	}
	if !isWebFlag {
		if w.getDetail(result, "status") != nil || w.getDetailStr(result, "server") != "" {
			isWebFlag = true
		}
	}

	if isWebFlag || service == "http" || service == "https" {
		return w.formatWebServiceLine(result)
	}

	// 非Web服务：ip:port service banner
	target := result.Target
	if !strings.Contains(target, ":") {
		if port := w.getDetail(result, "port"); port != nil {
			target = fmt.Sprintf("%s:%v", target, port)
		}
	}

	var parts []string
	parts = append(parts, target)
	if service != "" {
		parts = append(parts, service)
	}
	if banner != "" {
		if len(banner) > 100 {
			banner = banner[:100] + "..."
		}
		banner = escapeControlChars(banner)
		parts = append(parts, banner)
	}
	return strings.Join(parts, " ")
}

// formatWebServiceLine 格式化Web服务结果
func (w *TXTWriter) formatWebServiceLine(result *ScanResult) string {
	target := result.Target
	if !strings.Contains(target, ":") {
		if port := w.getDetail(result, "port"); port != nil {
			target = fmt.Sprintf("%s:%v", target, port)
		}
	}

	url := fmt.Sprintf("%s://%s", w.webProtocol(result, target), target)
	title := w.getDetailStr(result, "title")
	status := w.getDetail(result, "status")
	server := w.getDetailStr(result, "server")
	fingerprints := w.getFingerprints(result)

	var parts []string
	parts = append(parts, url)
	if title != "" {
		parts = append(parts, fmt.Sprintf("[%s]", title))
	}
	if status != nil && status != 0 {
		parts = append(parts, fmt.Sprintf("%v", status))
	}
	if server != "" {
		parts = append(parts, server)
	}
	if len(fingerprints) > 0 {
		parts = append(parts, fingerprints)
	}
	return strings.Join(parts, " ")
}

// getFingerprints 获取指纹信息并格式化
func (w *TXTWriter) getFingerprints(result *ScanResult) string {
	fp := w.getDetail(result, "fingerprints")
	if fp == nil {
		return ""
	}

	switch v := fp.(type) {
	case []string:
		if len(v) > 0 {
			return "[" + strings.Join(v, ",") + "]"
		}
	case []interface{}:
		if len(v) > 0 {
			var fps []string
			for _, f := range v {
				fps = append(fps, fmt.Sprintf("%v", f))
			}
			return "[" + strings.Join(fps, ",") + "]"
		}
	}
	return ""
}

// formatVulnLine 格式化漏洞发现结果
func (w *TXTWriter) formatVulnLine(result *ScanResult) string {
	vulnType := w.getDetailStr(result, "type")

	if vulnType == "weak_credential" {
		username := w.getDetailStr(result, "username")
		password := w.getDetailStr(result, "password")
		service := w.getDetailStr(result, "service")

		if service != "" {
			return fmt.Sprintf("%s %s %s/%s", result.Target, service, username, password)
		}
		return fmt.Sprintf("%s %s/%s", result.Target, username, password)
	}

	vuln := w.getDetailStr(result, "vulnerability")
	if vuln != "" {
		return fmt.Sprintf("%s %s", result.Target, vuln)
	}
	return fmt.Sprintf("%s %s", result.Target, result.Status)
}

// getDetail 获取详情字段值
func (w *TXTWriter) getDetail(result *ScanResult, key string) interface{} {
	if result.Details == nil {
		return nil
	}
	return result.Details[key]
}

// getDetailStr 获取详情字段字符串值
func (w *TXTWriter) getDetailStr(result *ScanResult, key string) string {
	val := w.getDetail(result, key)
	if val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", val)
}

// Flush 刷新写入器
func (w *TXTWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	if err := w.bufWriter.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}

// Close 关闭写入器（清理资源，删除临时备份）
func (w *TXTWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	// 按顺序写入所有分类结果
	w.writeSection(TypeHost, w.buffer.HostResults)
	w.writeSection(TypePort, w.buffer.PortResults)
	w.writeSection(TypeService, w.buffer.ServiceResults)
	w.writeSection(TypeVuln, w.buffer.VulnResults)

	// 单独输出 Web 服务列表（便于复制测试）
	w.writeWebServices()

	w.closed = true

	// 关闭并删除实时备份文件（正常结束，不再需要）
	if w.realtimeFile != nil {
		w.realtimeFile.Close()
		os.Remove(w.realtimePath)
	}

	if err := w.bufWriter.Flush(); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	return w.file.Close()
}

// writeSection 写入一个分类的所有结果
func (w *TXTWriter) writeSection(resultType ResultType, results []*ScanResult) {
	if len(results) == 0 {
		return
	}

	separator := w.getSeparator(resultType)
	_, _ = w.bufWriter.WriteString(separator + "\n")

	for _, result := range results {
		line := w.formatLine(result)
		if line != "" {
			_, _ = w.bufWriter.WriteString(line + "\n")
		}
	}
	_, _ = w.bufWriter.WriteString("\n")
}

// writeWebServices 单独输出 Web 服务 URL 列表
func (w *TXTWriter) writeWebServices() {
	var urls []string

	for _, result := range w.buffer.ServiceResults {
		if !w.isWebService(result) {
			continue
		}

		target := result.Target
		if !strings.Contains(target, ":") {
			if port := w.getDetail(result, "port"); port != nil {
				target = fmt.Sprintf("%s:%v", target, port)
			}
		}

		urls = append(urls, fmt.Sprintf("%s://%s", w.webProtocol(result, target), target))
	}

	if len(urls) == 0 {
		return
	}

	_, _ = w.bufWriter.WriteString("# ===== Web服务 =====\n")
	for _, url := range urls {
		_, _ = w.bufWriter.WriteString(url + "\n")
	}
	_, _ = w.bufWriter.WriteString("\n")
}

// isWebService 判断是否为 Web 服务
func (w *TXTWriter) isWebService(result *ScanResult) bool {
	if v, ok := w.getDetail(result, "is_web").(bool); ok && v {
		return true
	}
	if w.getDetail(result, "status") != nil {
		return true
	}
	if w.getDetailStr(result, "server") != "" {
		return true
	}
	service := w.getDetailStr(result, "service")
	return service == "http" || service == "https"
}

func (w *TXTWriter) webProtocol(result *ScanResult, target string) string {
	protocol := strings.ToLower(w.getDetailStr(result, "protocol"))
	if protocol == "http" || protocol == "https" {
		return protocol
	}

	service := strings.ToLower(w.getDetailStr(result, "service"))
	if service == "https" || strings.Contains(target, ":443") {
		return "https"
	}
	return "http"
}

// GetFormat 获取格式类型
func (w *TXTWriter) GetFormat() Format {
	return FormatTXT
}

// =============================================================================
// JSONWriter - JSON格式写入器
// =============================================================================

// JSONWriter JSON格式写入器（分类去重，输出完整JSON）
// 双写机制：内存分类缓冲 + 实时NDJSON备份
type JSONWriter struct {
	file         *os.File
	mu           sync.Mutex
	closed       bool
	buffer       *ResultBuffer
	realtimeFile *os.File // 实时备份文件（NDJSON格式）
	realtimePath string   // 实时备份文件路径
}

// JSONOutput JSON输出结构
type JSONOutput struct {
	ScanTime time.Time     `json:"scan_time"`
	Summary  JSONSummary   `json:"summary"`
	Hosts    []*ScanResult `json:"hosts,omitempty"`
	Ports    []*ScanResult `json:"ports,omitempty"`
	Services []*ScanResult `json:"services,omitempty"`
	Vulns    []*ScanResult `json:"vulns,omitempty"`
}

// JSONSummary 扫描摘要
type JSONSummary struct {
	TotalHosts    int `json:"total_hosts"`
	TotalPorts    int `json:"total_ports"`
	TotalServices int `json:"total_services"`
	TotalVulns    int `json:"total_vulns"`
}

// NewJSONWriter 创建JSON写入器
func NewJSONWriter(filePath string) (*JSONWriter, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON file: %w", err)
	}

	// 创建实时备份文件（NDJSON格式，每行一个JSON对象）
	realtimePath := filePath + ".realtime.tmp"
	realtimeFile, err := os.OpenFile(realtimePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create realtime backup file: %w", err)
	}

	return &JSONWriter{
		file:         file,
		buffer:       NewResultBuffer(),
		realtimeFile: realtimeFile,
		realtimePath: realtimePath,
	}, nil
}

// WriteHeader 写入头部
func (w *JSONWriter) WriteHeader() error {
	return nil
}

// Write 收集扫描结果，同时实时写入备份文件
func (w *JSONWriter) Write(result *ScanResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("writer is closed")
	}
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	// 1. 加入内存分类缓冲（用于最终有序输出）
	w.buffer.Add(result)

	// 2. 实时写入备份文件（NDJSON格式，防崩溃丢失）
	if w.realtimeFile != nil {
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		if _, err := w.realtimeFile.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("failed to write realtime backup: %w", err)
		}
		if err := w.realtimeFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync realtime backup: %w", err)
		}
	}

	return nil
}

// Flush 刷新写入器
func (w *JSONWriter) Flush() error {
	return nil
}

// Close 关闭写入器（写入完整JSON，删除临时备份）
func (w *JSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	hosts, ports, services, vulns := w.buffer.Summary()
	output := JSONOutput{
		ScanTime: time.Now(),
		Summary: JSONSummary{
			TotalHosts:    hosts,
			TotalPorts:    ports,
			TotalServices: services,
			TotalVulns:    vulns,
		},
		Hosts:    w.buffer.HostResults,
		Ports:    w.buffer.PortResults,
		Services: w.buffer.ServiceResults,
		Vulns:    w.buffer.VulnResults,
	}

	data, err := json.MarshalIndent(output, JSONIndentPrefix, JSONIndentString)
	if err != nil {
		return err
	}

	w.closed = true

	// 关闭并删除实时备份文件（正常结束，不再需要）
	if w.realtimeFile != nil {
		w.realtimeFile.Close()
		os.Remove(w.realtimePath)
	}

	if _, err := w.file.Write(data); err != nil {
		return err
	}
	return w.file.Close()
}

// GetFormat 获取格式类型
func (w *JSONWriter) GetFormat() Format {
	return FormatJSON
}

// =============================================================================
// CSVWriter - CSV格式写入器
// =============================================================================

// CSVWriter CSV格式写入器（分类去重）
// 双写机制：内存分类缓冲 + 实时NDJSON备份
type CSVWriter struct {
	file         *os.File
	bufWriter    *bufio.Writer
	csvWriter    *csv.Writer
	mu           sync.Mutex
	closed       bool
	buffer       *ResultBuffer
	realtimeFile *os.File // 实时备份文件（NDJSON格式）
	realtimePath string   // 实时备份文件路径
}

// NewCSVWriter 创建CSV写入器
func NewCSVWriter(filePath string) (*CSVWriter, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSV file: %w", err)
	}

	// 创建实时备份文件（NDJSON格式）
	realtimePath := filePath + ".realtime.tmp"
	realtimeFile, err := os.OpenFile(realtimePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create realtime backup file: %w", err)
	}

	bufWriter := bufio.NewWriter(file)
	csvWriter := csv.NewWriter(bufWriter)

	return &CSVWriter{
		file:         file,
		bufWriter:    bufWriter,
		csvWriter:    csvWriter,
		buffer:       NewResultBuffer(),
		realtimeFile: realtimeFile,
		realtimePath: realtimePath,
	}, nil
}

// WriteHeader 写入CSV头部
func (w *CSVWriter) WriteHeader() error {
	return nil // 延迟到Close时写入
}

// Write 收集扫描结果，同时实时写入备份文件
func (w *CSVWriter) Write(result *ScanResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("writer is closed")
	}
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	// 1. 加入内存分类缓冲（用于最终有序输出）
	w.buffer.Add(result)

	// 2. 实时写入备份文件（NDJSON格式，防崩溃丢失）
	if w.realtimeFile != nil {
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		if _, err := w.realtimeFile.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("failed to write realtime backup: %w", err)
		}
		if err := w.realtimeFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync realtime backup: %w", err)
		}
	}

	return nil
}

// Flush 刷新写入器
func (w *CSVWriter) Flush() error {
	return nil
}

// Close 关闭写入器（按类型分组写入，删除临时备份）
func (w *CSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	// 写入各分类
	w.writeSection("# Hosts", []string{"Target"}, w.buffer.HostResults, w.formatHostRecord)
	w.writeSection("# Ports", []string{"Target", "Port", "Status"}, w.buffer.PortResults, w.formatPortRecord)
	w.writeSection("# Services", []string{"Target", "Service", "Version", "Title", "Status", "Server", "Fingerprints", "Banner"}, w.buffer.ServiceResults, w.formatServiceRecord)
	w.writeSection("# Vulns", []string{"Target", "Type", "Details"}, w.buffer.VulnResults, w.formatVulnRecord)

	w.closed = true

	// 关闭并删除实时备份文件（正常结束，不再需要）
	if w.realtimeFile != nil {
		w.realtimeFile.Close()
		os.Remove(w.realtimePath)
	}

	w.csvWriter.Flush()
	if err := w.csvWriter.Error(); err != nil {
		return err
	}
	if err := w.bufWriter.Flush(); err != nil {
		return err
	}
	return w.file.Close()
}

func (w *CSVWriter) writeSection(title string, headers []string, results []*ScanResult, formatter func(*ScanResult) []string) {
	if len(results) == 0 {
		return
	}

	_ = w.csvWriter.Write([]string{title})
	_ = w.csvWriter.Write(headers)

	for _, result := range results {
		_ = w.csvWriter.Write(formatter(result))
	}
	_ = w.csvWriter.Write([]string{})
}

func (w *CSVWriter) formatHostRecord(result *ScanResult) []string {
	return []string{result.Target}
}

func (w *CSVWriter) formatPortRecord(result *ScanResult) []string {
	port := ""
	if result.Details != nil {
		if p, ok := result.Details["port"]; ok {
			port = fmt.Sprintf("%v", p)
		}
	}
	return []string{result.Target, port, "open"}
}

func (w *CSVWriter) formatServiceRecord(result *ScanResult) []string {
	service, version, title, status, server, fingerprints, banner := "", "", "", "", "", "", ""
	if result.Details != nil {
		if s, ok := result.Details["service"].(string); ok {
			service = s
		}
		if s, ok := result.Details["name"].(string); ok && service == "" {
			service = s
		}
		if s, ok := result.Details["plugin"].(string); ok && service == "" {
			service = s
		}
		if v, ok := result.Details["version"].(string); ok {
			version = v
		}
		if t, ok := result.Details["title"].(string); ok {
			title = escapeControlChars(t)
		}
		if s, ok := result.Details["status"]; ok && s != nil && s != 0 {
			status = fmt.Sprintf("%v", s)
		}
		if s, ok := result.Details["server"].(string); ok {
			server = escapeControlChars(s)
		}
		fingerprints = formatFingerprints(result.Details["fingerprints"])
		if b, ok := result.Details["banner"].(string); ok {
			banner = escapeControlChars(b)
			if len(banner) > 100 {
				banner = banner[:100] + "..."
			}
		}
	}
	target := result.Target
	if !strings.Contains(target, ":") {
		if p, ok := result.Details["port"]; ok {
			target = fmt.Sprintf("%s:%v", target, p)
		}
	}
	return []string{target, service, version, title, status, server, fingerprints, banner}
}

func formatFingerprints(value interface{}) string {
	switch v := value.(type) {
	case []string:
		return strings.Join(v, ",")
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func (w *CSVWriter) formatVulnRecord(result *ScanResult) []string {
	vulnType := ""
	if result.Details != nil {
		if t, ok := result.Details["type"].(string); ok {
			vulnType = t
		}
	}
	return []string{result.Target, vulnType, result.Status}
}

// GetFormat 获取格式类型
func (w *CSVWriter) GetFormat() Format {
	return FormatCSV
}
