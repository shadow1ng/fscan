package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort int
		wantOK   bool
	}{
		{name: "ipv4", target: "192.168.1.1:80", wantHost: "192.168.1.1", wantPort: 80, wantOK: true},
		{name: "hostname", target: "example.com:443", wantHost: "example.com", wantPort: 443, wantOK: true},
		{name: "bracketed ipv6", target: "[2001:db8::1]:8443", wantHost: "2001:db8::1", wantPort: 8443, wantOK: true},
		{name: "bare ipv6 without port", target: "2001:db8::1", wantOK: false},
		{name: "invalid port", target: "example.com:abc", wantOK: false},
		{name: "port out of range", target: "example.com:65536", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, ok := splitHostPort(tt.target)
			if ok != tt.wantOK {
				t.Fatalf("splitHostPort(%q) ok = %v, want %v", tt.target, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("splitHostPort(%q) = (%q, %d), want (%q, %d)", tt.target, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestNewStdoutNDJSONWriter(t *testing.T) {
	writer := NewStdoutNDJSONWriter()
	if writer == nil || writer.writer == nil {
		t.Fatalf("NewStdoutNDJSONWriter = %#v, want initialized writer", writer)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
}

func TestStdoutNDJSONWriterWriteResult(t *testing.T) {
	var buf bytes.Buffer
	writer := &StdoutNDJSONWriter{writer: bufio.NewWriter(&buf)}

	result := &ScanResult{
		Type:   TypeService,
		Target: "[2001:db8::1]:8443",
		Status: "OPEN",
		Details: map[string]interface{}{
			"port":          float64(9443),
			"service":       "https",
			"protocol":      "tcp",
			"banner":        123,
			"title":         "admin",
			"url":           "https://[2001:db8::1]:8443",
			"vulnerability": "weak credential",
			"username":      "admin",
			"password":      "secret",
			"plugin":        "webtitle",
			"version":       "1.2.3",
			"os":            "linux",
		},
	}

	if err := writer.WriteResult(result); err != nil {
		t.Fatalf("WriteResult error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	var rec ndjsonRecord
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("invalid ndjson output %q: %v", buf.String(), err)
	}
	if rec.Host != "2001:db8::1" || rec.Port != 9443 {
		t.Fatalf("host/port = %q/%d", rec.Host, rec.Port)
	}
	if rec.Service != "https" || rec.Protocol != "tcp" || rec.Banner != "123" || rec.Title != "admin" {
		t.Fatalf("flattened fields missing: %#v", rec)
	}
	if rec.URL != "https://[2001:db8::1]:8443" || rec.Vulnerability != "weak credential" {
		t.Fatalf("url/vuln fields missing: %#v", rec)
	}
	if rec.Username != "admin" || rec.Password != "secret" || rec.Plugin != "webtitle" || rec.Version != "1.2.3" || rec.OS != "linux" {
		t.Fatalf("credential/plugin fields missing: %#v", rec)
	}
}

func TestStdoutNDJSONFlattenFallbacks(t *testing.T) {
	writer := &StdoutNDJSONWriter{writer: bufio.NewWriter(&bytes.Buffer{})}

	rec := writer.flatten(&ScanResult{
		Type:   TypeHost,
		Target: "2001:db8::1",
		Status: "ALIVE",
		Details: map[string]interface{}{
			"port": int64(22),
		},
	})
	if rec.Host != "2001:db8::1" || rec.Port != 22 {
		t.Fatalf("flatten fallback = %#v", rec)
	}

	if got, ok := toInt("22"); ok || got != 0 {
		t.Fatalf("toInt string = %d/%v, want 0/false", got, ok)
	}
	if got := strVal(map[string]interface{}{}, "missing"); got != "" {
		t.Fatalf("missing strVal = %q, want empty", got)
	}
}
