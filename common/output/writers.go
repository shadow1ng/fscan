package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"scanner/common/i18n"
)

const (
	realtimeSyncBatchSize = 128
	realtimeSyncInterval  = time.Second
)

func maybeSyncRealtime(file *os.File, pending *int, lastSync *time.Time, force bool) error {
	if file == nil || pending == nil || lastSync == nil || *pending == 0 {
		return nil
	}
	if !force && *pending < realtimeSyncBatchSize && time.Since(*lastSync) < realtimeSyncInterval {
		return nil
	}
	if err := file.Sync(); err != nil {
		return err
	}
	*pending = 0
	*lastSync = time.Now()
	return nil
}

func syncStreamingArtifacts(store *diskResultStore, realtimeFile *os.File, pending *int, lastSync *time.Time) error {
	if store != nil {
		if err := store.Sync(); err != nil {
			return err
		}
	}
	return maybeSyncRealtime(realtimeFile, pending, lastSync, true)
}

func closeStreamingArtifacts(store *diskResultStore, realtimeFile *os.File, realtimePath string, pending *int, lastSync *time.Time, finalOK bool) error {
	var firstErr error
	if store != nil {
		if err := store.Close(); err != nil {
			firstErr = err
		}
	}
	if realtimeFile != nil {
		if err := maybeSyncRealtime(realtimeFile, pending, lastSync, true); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := realtimeFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if finalOK && firstErr == nil {
		if store != nil {
			if err := store.Remove(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := os.Remove(realtimePath); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func sanitizeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func sanitizeCSVRecord(record []string) []string {
	for i := range record {
		record[i] = sanitizeCSVCell(record[i])
	}
	return record
}

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

func truncateString(s string, maxRunes int) string {
	if maxRunes < 0 {
		return s
	}
	for i := range s {
		if maxRunes == 0 {
			return s[:i] + "..."
		}
		maxRunes--
	}
	return s
}

func targetWithPort(target string, port interface{}) string {
	if port == nil {
		return target
	}
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	portText := fmt.Sprint(port)
	if strings.TrimSpace(portText) == "" {
		return target
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = strings.TrimPrefix(strings.TrimSuffix(target, "]"), "[")
	}
	if strings.Count(target, ":") == 1 {
		return target
	}
	return net.JoinHostPort(target, portText)
}

// =============================================================================
// TXTWriter - 文本格式写入器
// =============================================================================

// TXTWriter 文本格式写入器（磁盘分类存储，按类型聚合输出）
type TXTWriter struct {
	file         *os.File
	bufWriter    *bufio.Writer
	mu           sync.Mutex
	closed       bool
	store        *diskResultStore
	realtimeFile *os.File // 实时备份文件
	realtimePath string   // 实时备份文件路径
	pendingSync  int
	lastSync     time.Time
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
	store, err := newDiskResultStore(filePath)
	if err != nil {
		_ = realtimeFile.Close()
		_ = os.Remove(realtimePath)
		_ = file.Close()
		return nil, err
	}

	return &TXTWriter{
		file:         file,
		bufWriter:    bufio.NewWriter(file),
		store:        store,
		realtimeFile: realtimeFile,
		realtimePath: realtimePath,
		lastSync:     time.Now(),
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

	// 1. 写入磁盘分类存储（保持去重和最终分组输出）
	if err := w.store.Add(result); err != nil {
		return err
	}

	// 2. 实时写入备份文件（防崩溃丢数据）
	if w.realtimeFile != nil {
		line := w.formatLine(result)
		if _, err := w.realtimeFile.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write realtime backup: %w", err)
		}
		w.pendingSync++
		if err := maybeSyncRealtime(w.realtimeFile, &w.pendingSync, &w.lastSync, false); err != nil {
			return fmt.Errorf("failed to sync realtime backup: %w", err)
		}
	}

	return nil
}

// getSeparator 获取分隔线文本
func (w *TXTWriter) getSeparator(newType ResultType) string {
	switch newType {
	case TypeHost:
		return i18n.GetText("output_section_hosts")
	case TypePort:
		return i18n.GetText("output_section_ports")
	case TypeService:
		return i18n.GetText("output_section_services")
	case TypeVuln:
		return i18n.GetText("output_section_vulns")
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
			return targetWithPort(result.Target, port)
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
	target := targetWithPort(result.Target, w.getDetail(result, "port"))

	var parts []string
	parts = append(parts, target)
	if service != "" {
		parts = append(parts, service)
	}
	if banner != "" {
		banner = escapeControlChars(banner)
		banner = truncateString(banner, 100)
		parts = append(parts, banner)
	}
	return strings.Join(parts, " ")
}

// formatWebServiceLine 格式化Web服务结果
func (w *TXTWriter) formatWebServiceLine(result *ScanResult) string {
	target := targetWithPort(result.Target, w.getDetail(result, "port"))

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
	if vuln == "" {
		vuln = w.getDetailStr(result, "vulnerability_name")
	}
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
	if err := syncStreamingArtifacts(w.store, w.realtimeFile, &w.pendingSync, &w.lastSync); err != nil {
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

	var firstErr error
	for _, resultType := range storedResultTypes {
		if err := w.writeSection(resultType); err != nil {
			firstErr = err
			break
		}
	}
	if firstErr == nil {
		firstErr = w.writeWebServices()
	}
	w.closed = true

	if err := w.bufWriter.Flush(); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}
	if err := w.file.Sync(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	finalOK := firstErr == nil
	if err := closeStreamingArtifacts(w.store, w.realtimeFile, w.realtimePath, &w.pendingSync, &w.lastSync, finalOK); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// writeSection 写入一个分类的所有结果
func (w *TXTWriter) writeSection(resultType ResultType) error {
	wroteHeader := false
	err := w.store.ForEach(resultType, func(result *ScanResult) error {
		if !wroteHeader {
			if _, err := w.bufWriter.WriteString(w.getSeparator(resultType) + "\n"); err != nil {
				return err
			}
			wroteHeader = true
		}
		line := w.formatLine(result)
		if line != "" {
			if _, err := w.bufWriter.WriteString(line + "\n"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if wroteHeader {
		_, err = w.bufWriter.WriteString("\n")
	}
	return err
}

// writeWebServices 单独输出 Web 服务 URL 列表
func (w *TXTWriter) writeWebServices() error {
	wroteHeader := false
	err := w.store.ForEach(TypeService, func(result *ScanResult) error {
		if !w.isWebService(result) {
			return nil
		}
		if !wroteHeader {
			if _, err := w.bufWriter.WriteString(i18n.GetText("output_section_web_services") + "\n"); err != nil {
				return err
			}
			wroteHeader = true
		}
		target := targetWithPort(result.Target, w.getDetail(result, "port"))
		_, err := fmt.Fprintf(w.bufWriter, "%s://%s\n", w.webProtocol(result, target), target)
		return err
	})
	if err != nil {
		return err
	}
	if wroteHeader {
		_, err = w.bufWriter.WriteString("\n")
	}
	return err
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

// JSONWriter JSON格式写入器（磁盘分类去重，流式生成完整JSON）
// 双写机制：磁盘事务存储 + 实时NDJSON备份
type JSONWriter struct {
	file         *os.File
	mu           sync.Mutex
	closed       bool
	store        *diskResultStore
	realtimeFile *os.File // 实时备份文件（NDJSON格式）
	realtimePath string   // 实时备份文件路径
	pendingSync  int
	lastSync     time.Time
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
	store, err := newDiskResultStore(filePath)
	if err != nil {
		_ = realtimeFile.Close()
		_ = os.Remove(realtimePath)
		_ = file.Close()
		return nil, err
	}

	return &JSONWriter{
		file:         file,
		store:        store,
		realtimeFile: realtimeFile,
		realtimePath: realtimePath,
		lastSync:     time.Now(),
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

	// 1. 写入磁盘分类存储（用于最终有序输出）
	if err := w.store.Add(result); err != nil {
		return err
	}

	// 2. 实时写入备份文件（NDJSON格式，防崩溃丢失）
	if w.realtimeFile != nil {
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		if _, err := w.realtimeFile.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("failed to write realtime backup: %w", err)
		}
		w.pendingSync++
		if err := maybeSyncRealtime(w.realtimeFile, &w.pendingSync, &w.lastSync, false); err != nil {
			return fmt.Errorf("failed to sync realtime backup: %w", err)
		}
	}

	return nil
}

// Flush 刷新写入器
func (w *JSONWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	return syncStreamingArtifacts(w.store, w.realtimeFile, &w.pendingSync, &w.lastSync)
}

// Close 关闭写入器（写入完整JSON，删除临时备份）
func (w *JSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	w.closed = true

	var firstErr error
	if err := w.writeJSONOutput(); err != nil {
		firstErr = err
	}
	if err := w.file.Sync(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	finalOK := firstErr == nil
	if err := closeStreamingArtifacts(w.store, w.realtimeFile, w.realtimePath, &w.pendingSync, &w.lastSync, finalOK); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (w *JSONWriter) writeJSONOutput() error {
	hosts, ports, services, vulns, err := w.store.Summary()
	if err != nil {
		return err
	}
	scanTime, err := json.Marshal(time.Now())
	if err != nil {
		return err
	}
	summary, err := json.Marshal(JSONSummary{
		TotalHosts:    hosts,
		TotalPorts:    ports,
		TotalServices: services,
		TotalVulns:    vulns,
	})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w.file, "{\n  \"scan_time\": %s,\n  \"summary\": %s", scanTime, summary); err != nil {
		return err
	}

	sections := []struct {
		name       string
		resultType ResultType
		count      int
	}{
		{name: "hosts", resultType: TypeHost, count: hosts},
		{name: "ports", resultType: TypePort, count: ports},
		{name: "services", resultType: TypeService, count: services},
		{name: "vulns", resultType: TypeVuln, count: vulns},
	}
	for _, section := range sections {
		if section.count == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w.file, ",\n  %q: [", section.name); err != nil {
			return err
		}
		first := true
		if err := w.store.ForEach(section.resultType, func(result *ScanResult) error {
			data, err := json.Marshal(result)
			if err != nil {
				return err
			}
			separator := ",\n"
			if first {
				separator = "\n"
				first = false
			}
			if _, err := w.file.WriteString(separator + "    "); err != nil {
				return err
			}
			_, err = w.file.Write(data)
			return err
		}); err != nil {
			return err
		}
		if _, err := w.file.WriteString("\n  ]"); err != nil {
			return err
		}
	}
	_, err = w.file.WriteString("\n}")
	return err
}

// GetFormat 获取格式类型
func (w *JSONWriter) GetFormat() Format {
	return FormatJSON
}

// =============================================================================
// CSVWriter - CSV格式写入器
// =============================================================================

// CSVWriter CSV格式写入器（磁盘分类去重）
// 双写机制：磁盘事务存储 + 实时NDJSON备份
type CSVWriter struct {
	file         *os.File
	bufWriter    *bufio.Writer
	csvWriter    *csv.Writer
	mu           sync.Mutex
	closed       bool
	store        *diskResultStore
	realtimeFile *os.File // 实时备份文件（NDJSON格式）
	realtimePath string   // 实时备份文件路径
	pendingSync  int
	lastSync     time.Time
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
	store, err := newDiskResultStore(filePath)
	if err != nil {
		_ = realtimeFile.Close()
		_ = os.Remove(realtimePath)
		_ = file.Close()
		return nil, err
	}

	bufWriter := bufio.NewWriter(file)
	csvWriter := csv.NewWriter(bufWriter)

	return &CSVWriter{
		file:         file,
		bufWriter:    bufWriter,
		csvWriter:    csvWriter,
		store:        store,
		realtimeFile: realtimeFile,
		realtimePath: realtimePath,
		lastSync:     time.Now(),
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

	// 1. 写入磁盘分类存储（用于最终有序输出）
	if err := w.store.Add(result); err != nil {
		return err
	}

	// 2. 实时写入备份文件（NDJSON格式，防崩溃丢失）
	if w.realtimeFile != nil {
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		if _, err := w.realtimeFile.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("failed to write realtime backup: %w", err)
		}
		w.pendingSync++
		if err := maybeSyncRealtime(w.realtimeFile, &w.pendingSync, &w.lastSync, false); err != nil {
			return fmt.Errorf("failed to sync realtime backup: %w", err)
		}
	}

	return nil
}

// Flush 刷新写入器
func (w *CSVWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	return syncStreamingArtifacts(w.store, w.realtimeFile, &w.pendingSync, &w.lastSync)
}

// Close 关闭写入器（按类型分组写入，删除临时备份）
func (w *CSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	w.closed = true

	var firstErr error
	sections := []struct {
		title      string
		headers    []string
		resultType ResultType
		formatter  func(*ScanResult) []string
	}{
		{title: "# Hosts", headers: []string{"Target"}, resultType: TypeHost, formatter: w.formatHostRecord},
		{title: "# Ports", headers: []string{"Target", "Port", "Status"}, resultType: TypePort, formatter: w.formatPortRecord},
		{title: "# Services", headers: []string{"Target", "Service", "Version", "Title", "Status", "Server", "Fingerprints", "Banner"}, resultType: TypeService, formatter: w.formatServiceRecord},
		{title: "# Vulns", headers: []string{"Target", "Type", "Details"}, resultType: TypeVuln, formatter: w.formatVulnRecord},
	}
	for _, section := range sections {
		if err := w.writeSection(section.title, section.headers, section.resultType, section.formatter); err != nil {
			firstErr = err
			break
		}
	}
	w.csvWriter.Flush()
	if err := w.csvWriter.Error(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.bufWriter.Flush(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.file.Sync(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	finalOK := firstErr == nil
	if err := closeStreamingArtifacts(w.store, w.realtimeFile, w.realtimePath, &w.pendingSync, &w.lastSync, finalOK); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (w *CSVWriter) writeSection(title string, headers []string, resultType ResultType, formatter func(*ScanResult) []string) error {
	wroteHeader := false
	err := w.store.ForEach(resultType, func(result *ScanResult) error {
		if !wroteHeader {
			if err := w.csvWriter.Write([]string{title}); err != nil {
				return err
			}
			if err := w.csvWriter.Write(headers); err != nil {
				return err
			}
			wroteHeader = true
		}
		return w.csvWriter.Write(sanitizeCSVRecord(formatter(result)))
	})
	if err != nil {
		return err
	}
	if wroteHeader {
		return w.csvWriter.Write([]string{})
	}
	return nil
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
			banner = truncateString(banner, 100)
		}
	}
	target := result.Target
	if result.Details != nil {
		target = targetWithPort(target, result.Details["port"])
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
	vulnName := result.Status
	if result.Details != nil {
		if t, ok := result.Details["type"].(string); ok {
			vulnType = t
		}
		if v, ok := result.Details["vulnerability"].(string); ok && v != "" {
			vulnName = v
		} else if v, ok := result.Details["vulnerability_name"].(string); ok && v != "" {
			vulnName = v
		}
	}
	return []string{result.Target, vulnType, vulnName}
}

// GetFormat 获取格式类型
func (w *CSVWriter) GetFormat() Format {
	return FormatCSV
}
