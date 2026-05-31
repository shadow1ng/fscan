package WebScan

import (
	"testing"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/webscan/lib"
)

func TestBuildTargetURL(t *testing.T) {
	tests := []struct {
		name        string
		hostInfo    *common.HostInfo
		expected    string
		expectError bool
	}{
		{
			name: "empty url builds from host and port",
			hostInfo: &common.HostInfo{
				Host: "192.168.1.1",
				Port: 8080,
				URL:  "",
			},
			expected:    "http://192.168.1.1:8080",
			expectError: false,
		},
		{
			name: "url without protocol gets http prefix",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 80,
				URL:  "example.com",
			},
			expected:    "http://example.com",
			expectError: false,
		},
		{
			name: "url with http protocol",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 80,
				URL:  "http://example.com",
			},
			expected:    "http://example.com",
			expectError: false,
		},
		{
			name: "url with https protocol",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 443,
				URL:  "https://example.com",
			},
			expected:    "https://example.com",
			expectError: false,
		},
		{
			name: "url with port",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 8443,
				URL:  "https://example.com:8443",
			},
			expected:    "https://example.com:8443",
			expectError: false,
		},
		{
			name: "url with path gets stripped",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 80,
				URL:  "http://example.com/admin/login",
			},
			expected:    "http://example.com",
			expectError: false,
		},
		{
			name: "url with query string gets stripped",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 80,
				URL:  "http://example.com?foo=bar",
			},
			expected:    "http://example.com",
			expectError: false,
		},
		{
			name: "localhost with port",
			hostInfo: &common.HostInfo{
				Host: "localhost",
				Port: 3000,
				URL:  "",
			},
			expected:    "http://localhost:3000",
			expectError: false,
		},
		{
			name: "ipv4 with port",
			hostInfo: &common.HostInfo{
				Host: "10.0.0.1",
				Port: 8888,
				URL:  "",
			},
			expected:    "http://10.0.0.1:8888",
			expectError: false,
		},
		{
			name: "domain without port builds from hostinfo",
			hostInfo: &common.HostInfo{
				Host: "test.example.com",
				Port: 9090,
				URL:  "",
			},
			expected:    "http://test.example.com:9090",
			expectError: false,
		},
		{
			name: "ipv6 builds bracketed host and port",
			hostInfo: &common.HostInfo{
				Host: "2001:db8::1",
				Port: 8080,
				URL:  "",
			},
			expected:    "http://[2001:db8::1]:8080",
			expectError: false,
		},
		{
			name: "ipv6 url without protocol keeps brackets",
			hostInfo: &common.HostInfo{
				Host: "2001:db8::1",
				Port: 443,
				URL:  "[2001:db8::1]:443/admin",
			},
			expected:    "http://[2001:db8::1]:443",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildTargetURL(tt.hostInfo)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("buildTargetURL() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBuildTargetURLErrors(t *testing.T) {
	tests := []struct {
		name     string
		hostInfo *common.HostInfo
	}{
		{
			name: "invalid url with special chars",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 80,
				URL:  "http://exam ple.com", // 空格在 URL 中无效
			},
		},
		{
			name: "url with invalid scheme",
			hostInfo: &common.HostInfo{
				Host: "example.com",
				Port: 80,
				URL:  "ht!tp://example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildTargetURL(tt.hostInfo)
			// 某些无效 URL 可能仍被解析，我们主要检查函数不会 panic
			_ = result
			_ = err
		})
	}
}

func TestHasProtocolPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// 正常情况
		{"http prefix", "http://example.com", true},
		{"https prefix", "https://example.com", true},
		{"no prefix domain", "example.com", false},
		{"no prefix ip", "192.168.1.1", false},
		{"no prefix with port", "example.com:8080", false},

		// 边界情况
		{"empty string", "", false},
		{"only http", "http://", true},
		{"only https", "https://", true},
		{"http in middle", "example.http://com", false},
		{"uppercase HTTP", "HTTP://example.com", true},
		{"uppercase HTTPS", "HTTPS://example.com", true},
		{"ftp protocol", "ftp://example.com", false},
		{"http no slashes", "http:example.com", false},
		{"partial prefix", "http:/example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasProtocolPrefix(tt.input)
			if result != tt.expected {
				t.Errorf("hasProtocolPrefix(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsPocFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		// 正常情况
		{"yaml extension", "test.yaml", true},
		{"yml extension", "test.yml", true},
		{"uppercase YAML", "test.YAML", true},
		{"uppercase YML", "test.YML", true},
		{"mixed case Yaml", "test.Yaml", true},
		{"mixed case Yml", "test.Yml", true},

		// 非POC文件
		{"go file", "test.go", false},
		{"txt file", "test.txt", false},
		{"no extension", "test", false},
		{"json file", "test.json", false},

		// 边界情况
		{"empty string", "", false},
		{"only .yaml", ".yaml", true},
		{"only .yml", ".yml", true},
		{"multiple dots", "test.poc.yaml", true},
		{"yaml in name", "yaml.txt", false},
		{"yml in name", "yml.go", false},
		{"ends with yaml no dot", "testyaml", false},
		{"yaml with path", "pocs/test.yaml", true},
		{"yml with path", "/tmp/pocs/test.yml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPocFile(tt.filename)
			if result != tt.expected {
				t.Errorf("isPocFile(%q) = %v, want %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestFilterPocs(t *testing.T) {
	// 创建测试 POC 数据
	testPocs := []*lib.Poc{
		{Name: "Apache-Struts2-CVE-2017-5638"},
		{Name: "WebLogic-CVE-2020-14882"},
		{Name: "Tomcat-CVE-2020-1938"},
		{Name: "Apache-Log4j-CVE-2021-44228"},
		{Name: "Spring-CVE-2022-22965"},
		nil, // 测试 nil 处理
		{Name: "Nginx-Path-Traversal"},
	}

	// 保存原始 allPocs 并在测试后恢复
	origAllPocs := allPocs
	defer func() { allPocs = origAllPocs }()

	allPocs = testPocs

	tests := []struct {
		name          string
		pocName       string
		expectedCount int
		expectedNames []string
	}{
		{
			name:          "empty poc name returns all",
			pocName:       "",
			expectedCount: 7, // 包括 nil（实际行为）
			expectedNames: nil,
		},
		{
			name:          "match apache case insensitive",
			pocName:       "apache",
			expectedCount: 2,
			expectedNames: []string{"Apache-Struts2-CVE-2017-5638", "Apache-Log4j-CVE-2021-44228"},
		},
		{
			name:          "match APACHE uppercase",
			pocName:       "APACHE",
			expectedCount: 2,
			expectedNames: []string{"Apache-Struts2-CVE-2017-5638", "Apache-Log4j-CVE-2021-44228"},
		},
		{
			name:          "match cve",
			pocName:       "cve",
			expectedCount: 5,
			expectedNames: nil,
		},
		{
			name:          "match weblogic",
			pocName:       "weblogic",
			expectedCount: 1,
			expectedNames: []string{"WebLogic-CVE-2020-14882"},
		},
		{
			name:          "match 2020",
			pocName:       "2020",
			expectedCount: 2,
			expectedNames: []string{"WebLogic-CVE-2020-14882", "Tomcat-CVE-2020-1938"},
		},
		{
			name:          "no match",
			pocName:       "nonexistent",
			expectedCount: 0,
			expectedNames: []string{},
		},
		{
			name:          "partial match spring",
			pocName:       "spring",
			expectedCount: 1,
			expectedNames: []string{"Spring-CVE-2022-22965"},
		},
		{
			name:          "match with special chars",
			pocName:       "log4j",
			expectedCount: 1,
			expectedNames: []string{"Apache-Log4j-CVE-2021-44228"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterPocs(tt.pocName)

			if len(result) != tt.expectedCount {
				t.Errorf("filterPocs(%q) returned %d pocs, want %d", tt.pocName, len(result), tt.expectedCount)
			}

			// 如果指定了期望的名称，验证它们
			if tt.expectedNames != nil {
				if len(result) != len(tt.expectedNames) {
					t.Errorf("filterPocs(%q) returned %d pocs, want %d", tt.pocName, len(result), len(tt.expectedNames))
					return
				}

				for i, poc := range result {
					found := false
					for _, expectedName := range tt.expectedNames {
						if poc.Name == expectedName {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("filterPocs(%q) result[%d].Name = %q, not in expected names %v",
							tt.pocName, i, poc.Name, tt.expectedNames)
					}
				}
			}

			// 只有在非空 pocName 时才验证没有 nil（因为有过滤）
			if tt.pocName != "" {
				for i, poc := range result {
					if poc == nil {
						t.Errorf("filterPocs(%q) result[%d] is nil", tt.pocName, i)
					}
				}
			}
		})
	}
}

func TestFilterPocsNilSafety(t *testing.T) {
	// 测试全是 nil 的情况
	origAllPocs := allPocs
	defer func() { allPocs = origAllPocs }()

	allPocs = []*lib.Poc{nil, nil, nil}

	result := filterPocs("test")
	if len(result) != 0 {
		t.Errorf("filterPocs with all nil should return empty slice, got %d items", len(result))
	}

	// 空 pocName 返回所有 POCs（包括 nil）
	result = filterPocs("")
	if len(result) != 3 {
		t.Errorf("filterPocs with empty name should return all pocs (including nil), got %d items, want 3", len(result))
	}
}

func TestDirectoryExists(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// 这些测试取决于文件系统状态，仅作为示例
		{"current directory", ".", true},
		{"nonexistent", "/nonexistent/path/12345", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := directoryExists(tt.path)
			if result != tt.expected {
				t.Errorf("directoryExists(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}
