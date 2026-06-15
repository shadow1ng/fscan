package portfinger

import (
	"strings"
	"testing"
)

/*
version_parser_test.go - Banner清理与版本解析测试

测试目标：TrimBanner 函数
价值：Banner清理是服务识别的预处理步骤，错误会导致：
  - 误识别服务类型
  - 正则匹配失败
  - 日志输出混乱（控制字符污染）

"Banner清理看起来简单，但涉及ASCII控制字符、Unicode、空格压缩。
这是真实的网络数据处理，必须测试边界情况。"
*/

// =============================================================================
// TrimBanner - Banner清理测试
// =============================================================================

// TestTrimBanner_BasicCases 测试基本的清理功能
func TestTrimBanner_BasicCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "普通字符串-无需清理",
			input:    "SSH-2.0-OpenSSH_8.0",
			expected: "SSH-2.0-OpenSSH_8.0",
		},
		{
			name:     "前后有空格",
			input:    "  SSH-2.0-OpenSSH_8.0  ",
			expected: "SSH-2.0-OpenSSH_8.0",
		},
		{
			name:     "多个连续空格",
			input:    "SSH   2.0   OpenSSH",
			expected: "SSH 2.0 OpenSSH",
		},
		{
			name:     "空字符串",
			input:    "",
			expected: "",
		},
		{
			name:     "只有空格",
			input:    "     ",
			expected: "",
		},
		{
			name:     "只有制表符",
			input:    "\t\t\t",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimBanner(tt.input)
			if result != tt.expected {
				t.Errorf("TrimBanner(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestTrimBanner_ControlCharacters 测试控制字符处理
func TestTrimBanner_ControlCharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "NULL字符-移除",
			input:    "SSH\x00-2.0",
			expected: "SSH -2.0",
		},
		{
			name:     "BEL响铃-移除",
			input:    "SSH\x07-2.0",
			expected: "SSH -2.0",
		},
		{
			name:     "退格符-移除",
			input:    "SSH\x08-2.0",
			expected: "SSH -2.0",
		},
		{
			name:     "ESC转义符-移除控制字符部分",
			input:    "SSH\x1b[31m-2.0",
			expected: "SSH [31m-2.0", // ESC被移除，但[31m是可打印字符
		},
		{
			name:     "DEL删除符-移除",
			input:    "SSH\x7f-2.0",
			expected: "SSH -2.0",
		},
		{
			name:     "多个控制字符",
			input:    "\x01\x02SSH\x03\x04-2.0\x05\x06",
			expected: "SSH -2.0",
		},
		{
			name:     "只有控制字符",
			input:    "\x00\x01\x02\x03\x04\x05",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimBanner(tt.input)
			if result != tt.expected {
				t.Errorf("TrimBanner(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestTrimBanner_PreservedCharacters 测试保留的特殊字符
func TestTrimBanner_PreservedCharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "保留换行符",
			input:    "SSH-2.0\nOpenSSH_8.0",
			expected: "SSH-2.0 OpenSSH_8.0", // 连续空白被压缩
		},
		{
			name:     "保留制表符",
			input:    "SSH-2.0\tOpenSSH_8.0",
			expected: "SSH-2.0 OpenSSH_8.0", // 制表符被压缩为空格
		},
		{
			name:     "混合换行符和制表符",
			input:    "SSH\n\t2.0\n\tOpenSSH",
			expected: "SSH 2.0 OpenSSH",
		},
		{
			name:     "多个连续换行符",
			input:    "SSH\n\n\n2.0",
			expected: "SSH 2.0",
		},
		{
			name:     "Windows换行符CRLF",
			input:    "SSH-2.0\r\nOpenSSH_8.0",
			expected: "SSH-2.0 OpenSSH_8.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimBanner(tt.input)
			if result != tt.expected {
				t.Errorf("TrimBanner(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestTrimBanner_SpaceCompression 测试空格压缩
func TestTrimBanner_SpaceCompression(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "两个空格",
			input:    "SSH  2.0",
			expected: "SSH 2.0",
		},
		{
			name:     "多个空格",
			input:    "SSH     2.0     OpenSSH",
			expected: "SSH 2.0 OpenSSH",
		},
		{
			name:     "混合空白字符",
			input:    "SSH \t \n 2.0",
			expected: "SSH 2.0",
		},
		{
			name:     "开头多个空格",
			input:    "     SSH-2.0",
			expected: "SSH-2.0",
		},
		{
			name:     "结尾多个空格",
			input:    "SSH-2.0     ",
			expected: "SSH-2.0",
		},
		{
			name:     "前后和中间都有多余空格",
			input:    "   SSH   2.0   OpenSSH   ",
			expected: "SSH 2.0 OpenSSH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimBanner(tt.input)
			if result != tt.expected {
				t.Errorf("TrimBanner(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestTrimBanner_ProductionScenarios 测试生产环境真实场景
func TestTrimBanner_ProductionScenarios(t *testing.T) {
	t.Run("SSH服务Banner", func(t *testing.T) {
		// 真实的SSH banner，可能包含控制字符
		input := "\x00\x00SSH-2.0-OpenSSH_8.0 Ubuntu\x00\x00"
		expected := "SSH-2.0-OpenSSH_8.0 Ubuntu"
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("SSH banner清理失败: got %q, want %q", result, expected)
		}
	})

	t.Run("HTTP服务Banner", func(t *testing.T) {
		// HTTP响应可能包含多余空白
		input := "  HTTP/1.1 200 OK\r\nServer: nginx/1.18.0  "
		expected := "HTTP/1.1 200 OK Server: nginx/1.18.0"
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("HTTP banner清理失败: got %q, want %q", result, expected)
		}
	})

	t.Run("FTP服务Banner", func(t *testing.T) {
		// FTP欢迎消息，可能包含换行符
		input := "220\tProFTPD Server\n(Welcome)\n"
		expected := "220 ProFTPD Server (Welcome)"
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("FTP banner清理失败: got %q, want %q", result, expected)
		}
	})

	t.Run("MySQL服务Banner", func(t *testing.T) {
		// MySQL握手包可能包含二进制数据
		input := "\x00\x00\x005.7.30-log\x00"
		expected := "5.7.30-log"
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("MySQL banner清理失败: got %q, want %q", result, expected)
		}
	})

	t.Run("Telnet服务Banner", func(t *testing.T) {
		// Telnet可能包含ANSI转义序列
		// 注意：当前实现只移除控制字符，ANSI序列的参数部分（可打印字符）会保留
		input := "\x1b[2J\x1b[HWelcome to Linux\x1b[0m"
		expected := "[2J [HWelcome to Linux [0m" // ESC被移除，参数保留
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("Telnet banner清理失败: got %q, want %q", result, expected)
		}
	})
}

// TestTrimBanner_EdgeCases 测试边界情况
func TestTrimBanner_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "单个字符",
			input:    "S",
			expected: "S",
		},
		{
			name:     "单个空格",
			input:    " ",
			expected: "",
		},
		{
			name:     "单个控制字符",
			input:    "\x00",
			expected: "",
		},
		{
			name:     "所有可打印ASCII字符",
			input:    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
			expected: "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
		},
		{
			name:     "混合可打印和不可打印字符",
			input:    "A\x00B\x01C\x1fD E",
			expected: "A B C D E",
		},
		{
			name:     "长Banner-1000字符",
			input:    strings.Repeat("SSH-2.0 ", 125), // 1000字符
			expected: strings.TrimSpace(strings.Repeat("SSH-2.0 ", 125)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimBanner(tt.input)
			if result != tt.expected {
				t.Errorf("TrimBanner(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestTrimBanner_ASCIIRanges 测试ASCII范围边界
func TestTrimBanner_ASCIIRanges(t *testing.T) {
	t.Run("ASCII-31-控制字符边界", func(t *testing.T) {
		// ASCII 0-31 是控制字符（除了\n和\t）
		input := string([]byte{31, 32, 33}) // US控制符, 空格, !
		expected := "!"                     // 31被移除，32变空格被trim，33保留
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("ASCII 31边界测试失败: got %q, want %q", result, expected)
		}
	})

	t.Run("ASCII-32-空格-最小可打印字符", func(t *testing.T) {
		input := string([]byte{32}) // 空格
		expected := ""              // trim掉
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("ASCII 32测试失败: got %q, want %q", result, expected)
		}
	})

	t.Run("ASCII-126-波浪号-最大可打印字符", func(t *testing.T) {
		input := string([]byte{126}) // ~
		expected := "~"
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("ASCII 126测试失败: got %q, want %q", result, expected)
		}
	})

	t.Run("ASCII-127-DEL-控制字符", func(t *testing.T) {
		input := string([]byte{127}) // DEL
		expected := ""               // 被移除
		result := TrimBanner(input)
		if result != expected {
			t.Errorf("ASCII 127测试失败: got %q, want %q", result, expected)
		}
	})
}

// TestTrimBanner_SpecialCases 测试特殊场景
func TestTrimBanner_SpecialCases(t *testing.T) {
	t.Run("换行符保留-但被压缩", func(t *testing.T) {
		input := "Line1\nLine2"
		result := TrimBanner(input)
		// 换行符应该被保留，但被压缩为空格
		if !strings.Contains(result, "Line1") || !strings.Contains(result, "Line2") {
			t.Errorf("换行符处理错误: got %q", result)
		}
	})

	t.Run("制表符保留-但被压缩", func(t *testing.T) {
		input := "Col1\tCol2"
		result := TrimBanner(input)
		// 制表符应该被保留，但被压缩为空格
		if !strings.Contains(result, "Col1") || !strings.Contains(result, "Col2") {
			t.Errorf("制表符处理错误: got %q", result)
		}
	})

	t.Run("连续控制字符-被替换为单个空格", func(t *testing.T) {
		input := "SSH\x00\x01\x02-2.0"
		result := TrimBanner(input)
		// 多个控制字符应该被压缩
		expected := "SSH -2.0"
		if result != expected {
			t.Errorf("控制字符压缩错误: got %q, want %q", result, expected)
		}
	})

	t.Run("空字符串不panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("空字符串导致panic: %v", r)
			}
		}()
		result := TrimBanner("")
		if result != "" {
			t.Errorf("空字符串处理错误: got %q", result)
		}
	})
}

// TestTrimBanner_PerformanceBaseline 性能基准测试
func TestTrimBanner_PerformanceBaseline(t *testing.T) {
	// 测试大字符串不会超时
	largeInput := strings.Repeat("SSH-2.0-OpenSSH_8.0 ", 10000) // ~200KB
	result := TrimBanner(largeInput)
	if len(result) == 0 {
		t.Error("大字符串处理失败")
	}
}

// =============================================================================
// ToMap - 结构体转Map测试
// =============================================================================

// TestExtras_ToMap_BasicCases 测试基本的ToMap功能
func TestExtras_ToMap_BasicCases(t *testing.T) {
	tests := []struct {
		name     string
		extras   Extras
		expected map[string]string
	}{
		{
			name: "所有字段都有值",
			extras: Extras{
				VendorProduct:   "Apache httpd",
				Version:         "2.4.41",
				Info:            "Ubuntu",
				Hostname:        "web-server",
				OperatingSystem: "Linux",
				DeviceType:      "general purpose",
				CPE:             "cpe:/a:apache:http_server:2.4.41",
			},
			expected: map[string]string{
				"vendor_product": "Apache httpd",
				"version":        "2.4.41",
				"info":           "Ubuntu",
				"hostname":       "web-server",
				"os":             "Linux",
				"device_type":    "general purpose",
				"cpe":            "cpe:/a:apache:http_server:2.4.41",
			},
		},
		{
			name:     "所有字段都为空",
			extras:   Extras{},
			expected: map[string]string{},
		},
		{
			name: "只有部分字段有值",
			extras: Extras{
				VendorProduct: "OpenSSH",
				Version:       "8.0",
			},
			expected: map[string]string{
				"vendor_product": "OpenSSH",
				"version":        "8.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.extras.ToMap()

			// 验证长度
			if len(result) != len(tt.expected) {
				t.Errorf("ToMap() 返回map长度 = %d, want %d",
					len(result), len(tt.expected))
			}

			// 验证每个字段
			for key, expectedValue := range tt.expected {
				if actualValue, ok := result[key]; !ok {
					t.Errorf("ToMap() 缺少字段 %q", key)
				} else if actualValue != expectedValue {
					t.Errorf("ToMap()[%q] = %q, want %q",
						key, actualValue, expectedValue)
				}
			}

			// 验证没有多余字段
			for key := range result {
				if _, ok := tt.expected[key]; !ok {
					t.Errorf("ToMap() 包含意外字段 %q = %q",
						key, result[key])
				}
			}
		})
	}
}

// TestExtras_ToMap_EmptyStringFiltering 测试空字符串过滤
func TestExtras_ToMap_EmptyStringFiltering(t *testing.T) {
	t.Run("空字符串不应出现在map中", func(t *testing.T) {
		extras := Extras{
			VendorProduct:   "Apache",
			Version:         "", // 空
			Info:            "Ubuntu",
			Hostname:        "", // 空
			OperatingSystem: "",
			DeviceType:      "",
			CPE:             "",
		}

		result := extras.ToMap()

		// 应该只有两个非空字段
		if len(result) != 2 {
			t.Errorf("ToMap() 应该过滤空字符串, got length %d, want 2", len(result))
		}

		// 验证空字段不存在
		emptyFields := []string{"version", "hostname", "os", "device_type", "cpe"}
		for _, field := range emptyFields {
			if _, exists := result[field]; exists {
				t.Errorf("ToMap() 不应包含空字段 %q", field)
			}
		}
	})
}

// =============================================================================
// ParseVersionInfo 测试
// =============================================================================

func TestParseVersionInfo(t *testing.T) {
	tests := []struct {
		name        string
		versionInfo string
		foundItems  []string
		wantVP      string // VendorProduct
		wantVer     string // Version
		wantCPE     string
	}{
		{
			name:        "只有product-斜线分隔符",
			versionInfo: " p/Apache/",
			wantVP:      "Apache",
		},
		{
			name:        "product和version-斜线分隔符",
			versionInfo: " p/nginx/ v/1.18.0/",
			wantVP:      "nginx",
			wantVer:     "1.18.0",
		},
		{
			name:        "pipe分隔符",
			versionInfo: " p|OpenSSH| v|8.2p1|",
			wantVP:      "OpenSSH",
			wantVer:     "8.2p1",
		},
		{
			name:        "含$1占位符替换后解析",
			versionInfo: " p/OpenSSH/ v/$1/",
			foundItems:  []string{"8.2p1"},
			wantVP:      "OpenSSH",
			wantVer:     "8.2p1",
		},
		{
			name:        "CPE解析",
			versionInfo: " cpe:/a:apache:httpd:2.4.41",
			wantCPE:     "a:apache:httpd:2.4.41",
		},
		{
			name:        "空VersionInfo返回全空Extras",
			versionInfo: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Match{
				VersionInfo: tt.versionInfo,
				FoundItems:  tt.foundItems,
			}
			got := m.ParseVersionInfo(nil)

			if got.VendorProduct != tt.wantVP {
				t.Errorf("VendorProduct = %q, want %q", got.VendorProduct, tt.wantVP)
			}
			if got.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVer)
			}
			if got.CPE != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", got.CPE, tt.wantCPE)
			}
		})
	}
}
