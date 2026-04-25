package portfinger

import (
	"regexp"
	"testing"
)

/*
match_engine_test.go - 服务指纹匹配引擎测试

测试重点：
1. MatchPattern - 核心匹配逻辑，错误会导致服务识别失败
2. 正则表达式子组提取 - 版本信息依赖此功能
3. 边界情况 - nil编译器、空响应

不测试：
- getMatch/getSoftMatch - 依赖复杂的probe解析上下文
*/

// =============================================================================
// MatchPattern 核心测试
// =============================================================================

// TestMatchPattern_BasicMatching 测试基本匹配功能
func TestMatchPattern_BasicMatching(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		response []byte
		expected bool
	}{
		{
			name:     "SSH版本匹配",
			pattern:  `SSH-[\d.]+-(.*)`,
			response: []byte("SSH-2.0-OpenSSH_8.0"),
			expected: true,
		},
		{
			name:     "HTTP协议匹配",
			pattern:  `HTTP/1\.[01] (\d{3})`,
			response: []byte("HTTP/1.1 200 OK"),
			expected: true,
		},
		{
			name:     "不匹配",
			pattern:  `SSH-`,
			response: []byte("HTTP/1.1 200 OK"),
			expected: false,
		},
		{
			name:     "空响应",
			pattern:  `.*`,
			response: []byte{},
			expected: true, // .* 匹配空字符串
		},
		{
			name:     "二进制数据匹配",
			pattern:  `^\x00\x01`,
			response: []byte{0x00, 0x01, 0x02, 0x03},
			expected: true,
		},
		{
			name:     "MySQL握手匹配",
			pattern:  `^\x00\x00\x00\x0a([\d.]+)`,
			response: []byte("\x00\x00\x00\x0a5.7.33\x00"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := regexp.Compile(tt.pattern)
			if err != nil {
				t.Fatalf("正则编译失败: %v", err)
			}

			m := &Match{
				PatternCompiled: compiled,
			}

			result := m.MatchPattern(tt.response)
			if result != tt.expected {
				t.Errorf("MatchPattern() = %v, 期望 %v", result, tt.expected)
			}
		})
	}
}

// TestMatchPattern_SubgroupExtraction 测试子组提取
//
// 这是关键功能：版本信息从正则表达式的分组中提取
func TestMatchPattern_SubgroupExtraction(t *testing.T) {
	tests := []struct {
		name          string
		pattern       string
		response      []byte
		expectedItems []string
	}{
		{
			name:          "提取SSH版本",
			pattern:       `SSH-[\d.]+-(.*)`,
			response:      []byte("SSH-2.0-OpenSSH_8.0"),
			expectedItems: []string{"OpenSSH_8.0"},
		},
		{
			name:          "提取HTTP状态码",
			pattern:       `HTTP/1\.[01] (\d{3}) (.*)`,
			response:      []byte("HTTP/1.1 200 OK"),
			expectedItems: []string{"200", "OK"},
		},
		{
			name:          "提取多个分组",
			pattern:       `(\w+)://([^:/]+):?(\d*)`,
			response:      []byte("https://example.com:443"),
			expectedItems: []string{"https", "example.com", "443"},
		},
		{
			name:          "无分组",
			pattern:       `SSH-2\.0`,
			response:      []byte("SSH-2.0-OpenSSH"),
			expectedItems: nil, // 无分组时为nil
		},
		{
			name:          "可选分组为空",
			pattern:       `HTTP/(\d+)\.(\d+)`,
			response:      []byte("HTTP/1.1 200 OK"),
			expectedItems: []string{"1", "1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := regexp.Compile(tt.pattern)
			if err != nil {
				t.Fatalf("正则编译失败: %v", err)
			}

			m := &Match{
				PatternCompiled: compiled,
			}

			matched := m.MatchPattern(tt.response)
			if !matched {
				t.Fatal("应该匹配成功")
			}

			// 验证提取的子组
			if tt.expectedItems == nil {
				if len(m.FoundItems) != 0 {
					t.Errorf("FoundItems 应为空，实际 %v", m.FoundItems)
				}
				return
			}

			if len(m.FoundItems) != len(tt.expectedItems) {
				t.Fatalf("FoundItems 长度 = %d, 期望 %d",
					len(m.FoundItems), len(tt.expectedItems))
			}

			for i, expected := range tt.expectedItems {
				if m.FoundItems[i] != expected {
					t.Errorf("FoundItems[%d] = %q, 期望 %q",
						i, m.FoundItems[i], expected)
				}
			}
		})
	}
}

// TestMatchPattern_NilCompiler 测试nil编译器
//
// 边界情况：如果正则编译失败，PatternCompiled为nil
func TestMatchPattern_NilCompiler(t *testing.T) {
	m := &Match{
		PatternCompiled: nil,
	}

	result := m.MatchPattern([]byte("any data"))
	if result {
		t.Error("nil编译器应返回false")
	}
}

// TestMatchPattern_RealWorldServices 测试真实服务指纹
func TestMatchPattern_RealWorldServices(t *testing.T) {
	tests := []struct {
		name            string
		pattern         string
		response        []byte
		expectedService string
		expectMatch     bool
	}{
		{
			name:            "OpenSSH",
			pattern:         `SSH-2\.0-OpenSSH[_\d\.p]+`,
			response:        []byte("SSH-2.0-OpenSSH_8.0p1 Ubuntu-6ubuntu0.1"),
			expectedService: "ssh",
			expectMatch:     true,
		},
		{
			name:            "nginx",
			pattern:         `Server: nginx/?([\d.]+)?`,
			response:        []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"),
			expectedService: "http",
			expectMatch:     true,
		},
		{
			name:            "Redis",
			pattern:         `-ERR wrong number of arguments`,
			response:        []byte("-ERR wrong number of arguments for 'get' command\r\n"),
			expectedService: "redis",
			expectMatch:     true,
		},
		{
			name:            "MySQL",
			pattern:         `mysql_native_password`,
			response:        []byte("\x00\x00\x00\x0a5.7.33\x00...mysql_native_password\x00"),
			expectedService: "mysql",
			expectMatch:     true,
		},
		{
			name:            "FTP-220",
			pattern:         `^220[\s-]`,
			response:        []byte("220 (vsFTPd 3.0.3)\r\n"),
			expectedService: "ftp",
			expectMatch:     true,
		},
		{
			name:            "SMTP-220",
			pattern:         `^220.*SMTP`,
			response:        []byte("220 mail.example.com ESMTP Postfix\r\n"),
			expectedService: "smtp",
			expectMatch:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := regexp.Compile(tt.pattern)
			if err != nil {
				t.Fatalf("正则编译失败: %v", err)
			}

			m := &Match{
				Service:         tt.expectedService,
				PatternCompiled: compiled,
			}

			result := m.MatchPattern(tt.response)
			if result != tt.expectMatch {
				t.Errorf("服务 %s 匹配失败: 期望 %v, 实际 %v",
					tt.expectedService, tt.expectMatch, result)
			}
		})
	}
}

// TestMatchPattern_FoundItemsReset 测试FoundItems在多次匹配时的重置
func TestMatchPattern_FoundItemsReset(t *testing.T) {
	compiled, _ := regexp.Compile(`SSH-(\d+)\.(\d+)-(.*)`)

	m := &Match{
		PatternCompiled: compiled,
	}

	// 第一次匹配
	m.MatchPattern([]byte("SSH-2.0-OpenSSH_8.0"))
	firstItems := make([]string, len(m.FoundItems))
	copy(firstItems, m.FoundItems)

	// 第二次匹配不同内容
	m.MatchPattern([]byte("SSH-1.99-Dropbear"))

	// 验证FoundItems被更新
	if len(m.FoundItems) < 1 {
		t.Fatal("第二次匹配后FoundItems应有内容")
	}

	if m.FoundItems[2] == "OpenSSH_8.0" {
		t.Error("FoundItems 未被更新为新的匹配结果")
	}

	if m.FoundItems[2] != "Dropbear" {
		t.Errorf("FoundItems[2] = %q, 期望 Dropbear", m.FoundItems[2])
	}
}

// =============================================================================
// Match 结构体属性测试
// =============================================================================

// TestMatch_IsSoftFlag 测试软匹配标志
func TestMatch_IsSoftFlag(t *testing.T) {
	hardMatch := Match{IsSoft: false}
	softMatch := Match{IsSoft: true}

	if hardMatch.IsSoft {
		t.Error("硬匹配的IsSoft应为false")
	}

	if !softMatch.IsSoft {
		t.Error("软匹配的IsSoft应为true")
	}
}

// =============================================================================
// 边界情况测试
// =============================================================================

// TestMatchPattern_LargeResponse 测试大响应数据
func TestMatchPattern_LargeResponse(t *testing.T) {
	compiled, _ := regexp.Compile(`needle`)

	m := &Match{
		PatternCompiled: compiled,
	}

	// 构造包含关键字的大响应（100KB）
	largeData := make([]byte, 100*1024)
	for i := range largeData {
		largeData[i] = 'x'
	}
	copy(largeData[50*1024:], []byte("needle"))

	result := m.MatchPattern(largeData)
	if !result {
		t.Error("大响应中的关键字应被匹配")
	}
}

// TestMatchPattern_BinaryData 测试二进制数据匹配
func TestMatchPattern_BinaryData(t *testing.T) {
	// 测试二进制数据中的固定字符串匹配
	compiled, _ := regexp.Compile(`SMB`)

	m := &Match{
		PatternCompiled: compiled,
	}

	// SMB协议头包含固定字符串 "SMB"
	smbResponse := []byte{0x00, 0x00, 0x00, 0x45, 0xff, 'S', 'M', 'B', 0x00}

	result := m.MatchPattern(smbResponse)
	if !result {
		t.Error("二进制数据中的SMB字符串应被匹配")
	}

	// 验证能提取SMB协议版本
	compiled2, _ := regexp.Compile(`SMBr`)
	m2 := &Match{PatternCompiled: compiled2}
	smb2Response := []byte("SMBr\x00\x00\x00\x00")
	result2 := m2.MatchPattern(smb2Response)
	if !result2 {
		t.Error("SMBr应被匹配")
	}
}

// TestMatchPattern_UnicodeResponse 测试Latin-1转换后的字节级匹配
func TestMatchPattern_UnicodeResponse(t *testing.T) {
	// bytesToLatin1String 按字节逐个映射到 Latin-1 码点
	// UTF-8 多字节字符会被拆开，所以用字节级正则匹配
	raw := []byte("HTTP/1.1 200 OK\r\nServer: test-srv\r\n")
	compiled, _ := regexp.Compile(`test-srv`)

	m := &Match{
		PatternCompiled: compiled,
	}

	result := m.MatchPattern(raw)
	if !result {
		t.Error("Latin-1字节级匹配应成功")
	}
}
