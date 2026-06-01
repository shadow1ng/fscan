package lib

import (
	"strings"
	"testing"
)

// TestDetectPocFormat 测试POC格式检测
func TestDetectPocFormat(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected PocFormat
	}{
		{
			name: "fscan格式 - 有name和rules",
			yaml: `
name: test-poc
rules:
  - method: GET
    path: /test
`,
			expected: FormatFscan,
		},
		{
			name: "fscan格式 - 有name和groups",
			yaml: `
name: test-poc
groups:
  group1:
    - method: GET
      path: /test
`,
			expected: FormatFscan,
		},
		{
			name: "Nuclei格式 - 有id和info",
			yaml: `
id: test-nuclei
info:
  name: Test Template
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
`,
			expected: FormatNuclei,
		},
		{
			name: "未知格式",
			yaml: `
unknown: field
data: test
`,
			expected: FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format := DetectPocFormat([]byte(tt.yaml))
			if format != tt.expected {
				t.Errorf("DetectPocFormat() = %v, want %v", format, tt.expected)
			}
		})
	}
}

// TestFscanPocAdapter 测试fscan格式适配器
func TestFscanPocAdapter(t *testing.T) {
	yaml := `
name: poc-yaml-test-fscan
set:
  rand: randomInt(10000, 99999)
rules:
  - method: GET
    path: /api/test
    expression: |
      response.status == 200
detail:
  author: test
  links:
    - https://example.com
`

	adapter, err := loadFscanPoc([]byte(yaml))
	if err != nil {
		t.Fatalf("loadFscanPoc() error = %v", err)
	}

	if adapter.GetFormat() != FormatFscan {
		t.Errorf("GetFormat() = %v, want %v", adapter.GetFormat(), FormatFscan)
	}

	if adapter.GetName() != "poc-yaml-test-fscan" {
		t.Errorf("GetName() = %v, want %v", adapter.GetName(), "poc-yaml-test-fscan")
	}

	poc, err := adapter.ToFscanPoc()
	if err != nil {
		t.Fatalf("ToFscanPoc() error = %v", err)
	}

	if poc.Name != "poc-yaml-test-fscan" {
		t.Errorf("Poc.Name = %v, want %v", poc.Name, "poc-yaml-test-fscan")
	}

	if len(poc.Rules) != 1 {
		t.Errorf("len(Poc.Rules) = %v, want %v", len(poc.Rules), 1)
	}

	if poc.Detail.Author != "test" {
		t.Errorf("Poc.Detail.Author = %v, want %v", poc.Detail.Author, "test")
	}
}

// TestNucleiPocAdapter 测试Nuclei格式适配器
func TestNucleiPocAdapter(t *testing.T) {
	yaml := `
id: test-nuclei-template
info:
  name: Test Nuclei Template
  author: pdteam
  severity: high
  description: Test template for nuclei adapter
  reference:
    - https://example.com/vuln
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/api"
    matchers:
      - type: word
        words:
          - "admin panel"
          - "dashboard"
      - type: status
        status:
          - 200
`

	adapter, err := loadNucleiPoc([]byte(yaml))
	if err != nil {
		t.Fatalf("loadNucleiPoc() error = %v", err)
	}

	if adapter.GetFormat() != FormatNuclei {
		t.Errorf("GetFormat() = %v, want %v", adapter.GetFormat(), FormatNuclei)
	}

	if adapter.GetName() != "Test Nuclei Template" {
		t.Errorf("GetName() = %v, want %v", adapter.GetName(), "Test Nuclei Template")
	}

	poc, err := adapter.ToFscanPoc()
	if err != nil {
		t.Fatalf("ToFscanPoc() error = %v", err)
	}

	if poc.Name != "Test Nuclei Template" {
		t.Errorf("Poc.Name = %v, want %v", poc.Name, "Test Nuclei Template")
	}

	// Nuclei的两个path应该转换为2个rule
	if len(poc.Rules) != 2 {
		t.Errorf("len(Poc.Rules) = %v, want %v", len(poc.Rules), 2)
	}

	if poc.Detail.Author != "pdteam" {
		t.Errorf("Poc.Detail.Author = %v, want %v", poc.Detail.Author, "pdteam")
	}

	// 验证expression包含word匹配
	if poc.Rules[0].Expression == "" {
		t.Error("Rule.Expression should not be empty")
	}
}

// TestConvertNucleiMatchers 测试Nuclei matcher转换
func TestConvertNucleiMatchers(t *testing.T) {
	tests := []struct {
		name              string
		matchers          []struct {
			Type      string   `yaml:"type"`
			Words     []string `yaml:"words"`
			Status    []int    `yaml:"status"`
			Regex     []string `yaml:"regex"`
			Condition string   `yaml:"condition"`
			Part      string   `yaml:"part"`
		}
		matchersCondition string
		wantContains      string
	}{
		{
			name: "单个word matcher",
			matchers: []struct {
				Type      string   `yaml:"type"`
				Words     []string `yaml:"words"`
				Status    []int    `yaml:"status"`
				Regex     []string `yaml:"regex"`
				Condition string   `yaml:"condition"`
				Part      string   `yaml:"part"`
			}{
				{
					Type:  "word",
					Words: []string{"admin"},
				},
			},
			matchersCondition: "",
			wantContains:      "response.body.bcontains",
		},
		{
			name: "单个status matcher",
			matchers: []struct {
				Type      string   `yaml:"type"`
				Words     []string `yaml:"words"`
				Status    []int    `yaml:"status"`
				Regex     []string `yaml:"regex"`
				Condition string   `yaml:"condition"`
				Part      string   `yaml:"part"`
			}{
				{
					Type:   "status",
					Status: []int{200},
				},
			},
			matchersCondition: "",
			wantContains:      "response.status == 200",
		},
		{
			name: "多个matcher - AND条件",
			matchers: []struct {
				Type      string   `yaml:"type"`
				Words     []string `yaml:"words"`
				Status    []int    `yaml:"status"`
				Regex     []string `yaml:"regex"`
				Condition string   `yaml:"condition"`
				Part      string   `yaml:"part"`
			}{
				{
					Type:  "word",
					Words: []string{"admin"},
				},
				{
					Type:   "status",
					Status: []int{200},
				},
			},
			matchersCondition: "",
			wantContains:      "&&",
		},
		{
			name: "多个matcher - OR条件",
			matchers: []struct {
				Type      string   `yaml:"type"`
				Words     []string `yaml:"words"`
				Status    []int    `yaml:"status"`
				Regex     []string `yaml:"regex"`
				Condition string   `yaml:"condition"`
				Part      string   `yaml:"part"`
			}{
				{
					Type:  "word",
					Words: []string{"admin"},
				},
				{
					Type:   "status",
					Status: []int{200},
				},
			},
			matchersCondition: "or",
			wantContains:      "||",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertNucleiMatchers(tt.matchers, tt.matchersCondition)
			if result == "" {
				t.Error("convertNucleiMatchers() returned empty string")
			}
			// 简单验证是否包含预期内容
			if tt.wantContains != "" {
				found := false
				for _, word := range []string{tt.wantContains} {
					if contains(result, word) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("convertNucleiMatchers() = %v, want to contain %v", result, tt.wantContains)
				}
			}
		})
	}
}

// contains 检查字符串是否包含子串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && hasSubstring(s, substr))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestLoadUniversalPoc 测试通用加载器
func TestLoadUniversalPoc(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		yaml     string
		wantType PocFormat
		wantErr  bool
	}{
		{
			name:     "加载fscan格式",
			filename: "test-fscan.yml",
			yaml: `
name: test-fscan
rules:
  - method: GET
    path: /test
`,
			wantType: FormatFscan,
			wantErr:  false,
		},
		{
			name:     "加载nuclei格式",
			filename: "test-nuclei.yaml",
			yaml: `
id: test-nuclei
info:
  name: Test
http:
  - method: GET
    path:
      - "{{BaseURL}}"
`,
			wantType: FormatNuclei,
			wantErr:  false,
		},
		{
			name:     "未知格式报错",
			filename: "test-unknown.yml",
			yaml: `
unknown: format
`,
			wantType: FormatUnknown,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			poc, err := LoadUniversalPoc(tt.filename, []byte(tt.yaml))
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadUniversalPoc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if poc.GetFormat() != tt.wantType {
					t.Errorf("LoadUniversalPoc() format = %v, want %v", poc.GetFormat(), tt.wantType)
				}

				// 验证转换为fscan格式
				fscanPoc, err := poc.ToFscanPoc()
				if err != nil {
					t.Errorf("ToFscanPoc() error = %v", err)
				}
				if fscanPoc == nil {
					t.Error("ToFscanPoc() returned nil")
				}
			}
		})
	}
}

// TestXrayOutputToSearch 测试 xray output 字段到 Search 的转换
func TestXrayOutputToSearch(t *testing.T) {
	// 多步POC: r0 提取 cookie，r1 使用 {{cookie}}
	yamlData := `
name: poc-yaml-test-cookie-extract
transport: http
rules:
  r0:
    request:
      method: POST
      path: /login
      headers:
        Content-Type: text/xml
      body: userID=admin
      follow_redirects: false
    expression: response.status == 200
    output:
      search: "Set-Cookie:(?P<cookie>.*)"
  r1:
    request:
      method: GET
      path: /admin/dashboard
      headers:
        Cookie: "{{cookie}}"
    expression: response.status == 200
detail:
  author: test
`

	adapter, err := loadXrayPoc([]byte(yamlData))
	if err != nil {
		t.Fatalf("loadXrayPoc() error = %v", err)
	}

	poc, err := adapter.ToFscanPoc()
	if err != nil {
		t.Fatalf("ToFscanPoc() error = %v", err)
	}

	if len(poc.Rules) != 2 {
		t.Fatalf("len(Poc.Rules) = %d, want 2", len(poc.Rules))
	}

	// r0 应该有 Search 字段（从 output.search 转换）
	if poc.Rules[0].Search == "" {
		t.Error("Rules[0].Search should not be empty — output.search was not converted")
	}
	if !strings.Contains(poc.Rules[0].Search, "cookie") {
		t.Errorf("Rules[0].Search = %q, should contain 'cookie'", poc.Rules[0].Search)
	}

	// r1 不应该有 Search（没有 output 字段）
	if poc.Rules[1].Search != "" {
		t.Errorf("Rules[1].Search = %q, should be empty", poc.Rules[1].Search)
	}

	// r1 的 Headers 应保留 {{cookie}} 占位符
	if poc.Rules[1].Headers["Cookie"] != `{{cookie}}` {
		t.Errorf("Rules[1].Headers[Cookie] = %q, want %q", poc.Rules[1].Headers["Cookie"], `{{cookie}}`)
	}
}

// TestXrayNoOutput 测试 xray 没有 output 字段时 Search 为空（回归）
func TestXrayNoOutput(t *testing.T) {
	yamlData := `
name: poc-yaml-test-simple
transport: http
rules:
  r0:
    request:
      method: GET
      path: /api/test
    expression: response.status == 200
detail:
  author: test
`

	adapter, err := loadXrayPoc([]byte(yamlData))
	if err != nil {
		t.Fatalf("loadXrayPoc() error = %v", err)
	}

	poc, err := adapter.ToFscanPoc()
	if err != nil {
		t.Fatalf("ToFscanPoc() error = %v", err)
	}

	if len(poc.Rules) != 1 {
		t.Fatalf("len(Poc.Rules) = %d, want 1", len(poc.Rules))
	}

	if poc.Rules[0].Search != "" {
		t.Errorf("Rules[0].Search = %q, should be empty when no output field", poc.Rules[0].Search)
	}
}

// TestAfrogOutputToSearch 测试 afrog output 字段到 Search 的转换
func TestAfrogOutputToSearch(t *testing.T) {
	yamlData := `
id: test-afrog-cookie
info:
  name: 测试Cookie提取
  author: test
  severity: high
rules:
  r0:
    request:
      method: POST
      path: /login
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: username=admin&password=123456
    expression: response.status == 200 && response.body.bcontains(b"success")
    output:
      search: "Set-Cookie:(?P<sessid>.*)"
  r1:
    request:
      method: GET
      path: /panel
      headers:
        Cookie: "{{sessid}}"
    expression: response.status == 200 && response.body.bcontains(b"admin")
`

	adapter, err := loadAfrogPoc([]byte(yamlData))
	if err != nil {
		t.Fatalf("loadAfrogPoc() error = %v", err)
	}

	poc, err := adapter.ToFscanPoc()
	if err != nil {
		t.Fatalf("ToFscanPoc() error = %v", err)
	}

	if len(poc.Rules) != 2 {
		t.Fatalf("len(Poc.Rules) = %d, want 2", len(poc.Rules))
	}

	if poc.Rules[0].Search == "" {
		t.Error("Rules[0].Search should not be empty — output.search was not converted")
	}

	// r1 的占位符应对应捕获组名 sessid
	if poc.Rules[1].Headers["Cookie"] != `{{sessid}}` {
		t.Errorf("Rules[1].Headers[Cookie] = %q, want %q", poc.Rules[1].Headers["Cookie"], `{{sessid}}`)
	}
}
