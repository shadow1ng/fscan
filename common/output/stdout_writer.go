package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

type StdoutNDJSONWriter struct {
	mu     sync.Mutex
	writer *bufio.Writer
}

func NewStdoutNDJSONWriter() *StdoutNDJSONWriter {
	return &StdoutNDJSONWriter{
		writer: bufio.NewWriter(os.Stdout),
	}
}

// ndjsonRecord NDJSON 输出的扁平化结构
type ndjsonRecord struct {
	Type    ResultType `json:"type"`
	Target  string     `json:"target"`
	Status  string     `json:"status"`
	Host    string     `json:"host,omitempty"`
	Port    int        `json:"port,omitempty"`
	Service string     `json:"service,omitempty"`
	// 通用可选字段
	Protocol string `json:"protocol,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Title    string `json:"title,omitempty"`
	URL      string `json:"url,omitempty"`
	// 漏洞/弱口令
	Vulnerability string `json:"vulnerability,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	// 其他
	Plugin  string `json:"plugin,omitempty"`
	Version string `json:"version,omitempty"`
	OS      string `json:"os,omitempty"`
}

func (w *StdoutNDJSONWriter) WriteResult(result *ScanResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	rec := w.flatten(result)
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	return w.writer.Flush()
}

func (w *StdoutNDJSONWriter) flatten(r *ScanResult) *ndjsonRecord {
	rec := &ndjsonRecord{
		Type:   r.Type,
		Target: r.Target,
		Status: r.Status,
	}

	// 从 target 拆分 host:port
	if host, port, ok := splitHostPort(r.Target); ok {
		rec.Host = host
		rec.Port = port
	} else {
		rec.Host = r.Target
	}

	d := r.Details
	if d == nil {
		return rec
	}

	// 从 details 提升一级字段（覆盖拆分结果）
	if v, ok := d["port"]; ok {
		if p, ok := toInt(v); ok {
			rec.Port = p
		}
	}

	rec.Service = strVal(d, "service")
	rec.Protocol = strVal(d, "protocol")
	rec.Banner = strVal(d, "banner")
	rec.Title = strVal(d, "title")
	rec.URL = strVal(d, "url")
	rec.Vulnerability = strVal(d, "vulnerability")
	rec.Username = strVal(d, "username")
	rec.Password = strVal(d, "password")
	rec.Plugin = strVal(d, "plugin")
	rec.Version = strVal(d, "version")
	rec.OS = strVal(d, "os")

	return rec
}

func (w *StdoutNDJSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Flush()
}

func strVal(d map[string]interface{}, key string) string {
	v, ok := d[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

func splitHostPort(target string) (string, int, bool) {
	idx := strings.LastIndex(target, ":")
	if idx < 0 {
		return "", 0, false
	}
	host := target[:idx]
	var port int
	if _, err := fmt.Sscanf(target[idx+1:], "%d", &port); err != nil {
		return "", 0, false
	}
	return host, port, true
}
