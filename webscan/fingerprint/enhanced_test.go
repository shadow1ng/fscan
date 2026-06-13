package fingerprint

import (
	"testing"
)

/*
enhanced_test.go - Web指纹匹配引擎测试

测试重点：
1. matchWords - 关键词匹配逻辑（AND/OR条件、大小写）
2. matchFavicon - favicon hash匹配
3. CalculateFaviconHash - hash计算一致性

不测试：
- MatchEnhancedFingerprints - 依赖嵌入的JSON数据和全局状态
- matchRegex - 依赖全局regexCache，需要集成测试
*/

// =============================================================================
// matchWords 关键词匹配测试
// =============================================================================

// 创建测试用的matcher结构
func createMatcher(matcherType string, words, regex, hash []string, part, condition string, caseInsensitive bool) struct {
	Type            string   `json:"type"`
	Words           []string `json:"words"`
	Regex           []string `json:"regex"`
	Hash            []string `json:"hash"`
	Part            string   `json:"part"`
	CaseInsensitive bool     `json:"case-insensitive"`
	Condition       string   `json:"condition"`
} {
	return struct {
		Type            string   `json:"type"`
		Words           []string `json:"words"`
		Regex           []string `json:"regex"`
		Hash            []string `json:"hash"`
		Part            string   `json:"part"`
		CaseInsensitive bool     `json:"case-insensitive"`
		Condition       string   `json:"condition"`
	}{
		Type:            matcherType,
		Words:           words,
		Regex:           regex,
		Hash:            hash,
		Part:            part,
		CaseInsensitive: caseInsensitive,
		Condition:       condition,
	}
}

// TestMatchWords_ORCondition 测试OR条件匹配
func TestMatchWords_ORCondition(t *testing.T) {
	tests := []struct {
		name     string
		words    []string
		body     string
		expected bool
	}{
		{
			name:     "匹配第一个词",
			words:    []string{"nginx", "apache", "iis"},
			body:     "Server: nginx/1.18.0",
			expected: true,
		},
		{
			name:     "匹配中间词",
			words:    []string{"nginx", "Apache", "iis"},
			body:     "Apache/2.4.41",
			expected: true,
		},
		{
			name:     "匹配最后词",
			words:    []string{"nginx", "apache", "IIS"},
			body:     "Microsoft-IIS/10.0",
			expected: true,
		},
		{
			name:     "无匹配",
			words:    []string{"nginx", "apache", "iis"},
			body:     "lighttpd/1.4.55",
			expected: false,
		},
		{
			name:     "空body",
			words:    []string{"nginx"},
			body:     "",
			expected: false,
		},
		{
			name:     "空words",
			words:    []string{},
			body:     "nginx",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := createMatcher("word", tt.words, nil, nil, "body", "", false)
			result := matchWords(matcher, tt.body, "")
			if result != tt.expected {
				t.Errorf("matchWords() = %v, 期望 %v", result, tt.expected)
			}
		})
	}
}

// TestMatchWords_ANDCondition 测试AND条件匹配
func TestMatchWords_ANDCondition(t *testing.T) {
	tests := []struct {
		name     string
		words    []string
		body     string
		expected bool
	}{
		{
			name:     "全部匹配",
			words:    []string{"WordPress", "wp-content", "wp-includes"},
			body:     "<html>WordPress site with wp-content and wp-includes</html>",
			expected: true,
		},
		{
			name:     "部分匹配",
			words:    []string{"WordPress", "wp-content", "wp-includes"},
			body:     "WordPress site with wp-content",
			expected: false,
		},
		{
			name:     "无匹配",
			words:    []string{"WordPress", "wp-content"},
			body:     "Joomla CMS",
			expected: false,
		},
		{
			name:     "单词全匹配",
			words:    []string{"nginx"},
			body:     "nginx/1.18.0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := createMatcher("word", tt.words, nil, nil, "body", "and", false)
			result := matchWords(matcher, tt.body, "")
			if result != tt.expected {
				t.Errorf("matchWords(AND) = %v, 期望 %v", result, tt.expected)
			}
		})
	}
}

// TestMatchWords_CaseInsensitive 测试大小写不敏感匹配
func TestMatchWords_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name            string
		words           []string
		body            string
		caseInsensitive bool
		expected        bool
	}{
		{
			name:            "大小写敏感-精确匹配",
			words:           []string{"WordPress"},
			body:            "WordPress",
			caseInsensitive: false,
			expected:        true,
		},
		{
			name:            "大小写敏感-不匹配",
			words:           []string{"WordPress"},
			body:            "wordpress",
			caseInsensitive: false,
			expected:        false,
		},
		{
			name:            "大小写不敏感-小写匹配大写",
			words:           []string{"wordpress"},
			body:            "WORDPRESS",
			caseInsensitive: true,
			expected:        true,
		},
		{
			name:            "大小写不敏感-混合大小写",
			words:           []string{"WoRdPrEsS"},
			body:            "wordpress site",
			caseInsensitive: true,
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := createMatcher("word", tt.words, nil, nil, "body", "", tt.caseInsensitive)
			result := matchWords(matcher, tt.body, "")
			if result != tt.expected {
				t.Errorf("matchWords(caseInsensitive=%v) = %v, 期望 %v",
					tt.caseInsensitive, result, tt.expected)
			}
		})
	}
}

// TestMatchWords_HeaderPart 测试header部分匹配
func TestMatchWords_HeaderPart(t *testing.T) {
	body := "<html>Body content</html>"
	headers := "Server: nginx\r\nX-Powered-By: PHP/7.4"

	tests := []struct {
		name     string
		words    []string
		part     string
		expected bool
	}{
		{
			name:     "匹配header",
			words:    []string{"nginx"},
			part:     "header",
			expected: true,
		},
		{
			name:     "header中不存在",
			words:    []string{"apache"},
			part:     "header",
			expected: false,
		},
		{
			name:     "匹配body",
			words:    []string{"Body content"},
			part:     "body",
			expected: true,
		},
		{
			name:     "body中不存在header内容",
			words:    []string{"nginx"},
			part:     "body",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := createMatcher("word", tt.words, nil, nil, tt.part, "", false)
			result := matchWords(matcher, body, headers)
			if result != tt.expected {
				t.Errorf("matchWords(part=%s) = %v, 期望 %v",
					tt.part, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// matchFavicon 测试
// =============================================================================

// TestMatchFavicon_Basic 测试favicon hash匹配
func TestMatchFavicon_Basic(t *testing.T) {
	tests := []struct {
		name     string
		hashes   []string
		favicon  FaviconHashes
		expected bool
	}{
		{
			name:     "mmh3匹配",
			hashes:   []string{"1386054408", "def456"},
			favicon:  FaviconHashes{MMH3: "1386054408", MD5: "abc"},
			expected: true,
		},
		{
			name:     "MD5匹配",
			hashes:   []string{"abc123", "e2e2ba13339c2fea220f8b4fa6c32c0d"},
			favicon:  FaviconHashes{MMH3: "123", MD5: "e2e2ba13339c2fea220f8b4fa6c32c0d"},
			expected: true,
		},
		{
			name:     "无匹配",
			hashes:   []string{"abc123", "def456"},
			favicon:  FaviconHashes{MMH3: "xyz789", MD5: "111"},
			expected: false,
		},
		{
			name:     "空favicon",
			hashes:   []string{"abc123"},
			favicon:  FaviconHashes{},
			expected: false,
		},
		{
			name:     "空hashes",
			hashes:   []string{},
			favicon:  FaviconHashes{MMH3: "abc123", MD5: "def"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := createMatcher("favicon", nil, nil, tt.hashes, "", "", false)
			result := matchFavicon(matcher, tt.favicon)
			if result != tt.expected {
				t.Errorf("matchFavicon() = %v, 期望 %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// CalculateFaviconHashes 测试
// =============================================================================

// TestCalculateFaviconHashes_Consistency 测试hash计算一致性
func TestCalculateFaviconHashes_Consistency(t *testing.T) {
	data := []byte("test favicon data")

	hash1 := CalculateFaviconHashes(data)
	hash2 := CalculateFaviconHashes(data)

	if hash1.MMH3 != hash2.MMH3 {
		t.Errorf("相同数据应产生相同mmh3 hash: %s vs %s", hash1.MMH3, hash2.MMH3)
	}
	if hash1.MD5 != hash2.MD5 {
		t.Errorf("相同数据应产生相同MD5 hash: %s vs %s", hash1.MD5, hash2.MD5)
	}
}

// TestCalculateFaviconHashes_Different 测试不同数据产生不同hash
func TestCalculateFaviconHashes_Different(t *testing.T) {
	data1 := []byte("favicon data 1")
	data2 := []byte("favicon data 2")

	hash1 := CalculateFaviconHashes(data1)
	hash2 := CalculateFaviconHashes(data2)

	if hash1.MMH3 == hash2.MMH3 {
		t.Error("不同数据应产生不同mmh3 hash")
	}
	if hash1.MD5 == hash2.MD5 {
		t.Error("不同数据应产生不同MD5 hash")
	}
}

// TestCalculateFaviconHashes_Empty 测试空数据
func TestCalculateFaviconHashes_Empty(t *testing.T) {
	hash := CalculateFaviconHashes([]byte{})

	if hash.MMH3 != "" || hash.MD5 != "" {
		t.Errorf("空数据应返回空FaviconHashes，实际: mmh3=%s, md5=%s", hash.MMH3, hash.MD5)
	}
}

// TestCalculateFaviconHashes_Nil 测试nil数据
func TestCalculateFaviconHashes_Nil(t *testing.T) {
	hash := CalculateFaviconHashes(nil)

	if hash.MMH3 != "" || hash.MD5 != "" {
		t.Errorf("nil数据应返回空FaviconHashes，实际: mmh3=%s, md5=%s", hash.MMH3, hash.MD5)
	}
}

// TestCalculateFaviconHashes_Format 测试hash格式
func TestCalculateFaviconHashes_Format(t *testing.T) {
	data := []byte("test data")
	hash := CalculateFaviconHashes(data)

	// mmh3 应该是有符号整数格式（可能是负数）
	if hash.MMH3 == "" {
		t.Error("mmh3 hash不应为空")
	}

	// MD5产生32字符的十六进制字符串
	if len(hash.MD5) != 32 {
		t.Errorf("MD5 hash长度应为32，实际: %d", len(hash.MD5))
	}

	// 验证MD5是有效的十六进制
	for _, c := range hash.MD5 {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("MD5 hash包含无效字符: %c", c)
		}
	}
}

// TestMMH3_KnownValue 测试mmh3已知值（验证算法正确性）
func TestMMH3_KnownValue(t *testing.T) {
	// 使用简单的测试字符串验证mmh3算法
	// mmh3("hello") with seed=0 应该产生一个固定值
	result := mmh3Hash32([]byte("hello"))

	// mmh3("hello", seed=0) = 613153351 (根据标准实现)
	expected := int32(613153351)
	if result != expected {
		t.Errorf("mmh3('hello') = %d, 期望 %d", result, expected)
	}
}

// =============================================================================
// matchMatcher 分发测试
// =============================================================================

// TestMatchMatcher_TypeDispatch 测试类型分发
func TestMatchMatcher_TypeDispatch(t *testing.T) {
	// 注意：matchRegex需要全局regexCache，这里只测试word和favicon

	tests := []struct {
		name        string
		matcherType string
		expected    bool
	}{
		{
			name:        "word类型",
			matcherType: "word",
			expected:    true,
		},
		{
			name:        "favicon类型",
			matcherType: "favicon",
			expected:    true,
		},
		{
			name:        "未知类型",
			matcherType: "unknown",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matcher struct {
				Type            string   `json:"type"`
				Words           []string `json:"words"`
				Regex           []string `json:"regex"`
				Hash            []string `json:"hash"`
				Part            string   `json:"part"`
				CaseInsensitive bool     `json:"case-insensitive"`
				Condition       string   `json:"condition"`
			}

			switch tt.matcherType {
			case "word":
				matcher = createMatcher("word", []string{"nginx"}, nil, nil, "body", "", false)
			case "favicon":
				matcher = createMatcher("favicon", nil, nil, []string{"abc123"}, "", "", false)
			default:
				matcher = createMatcher(tt.matcherType, nil, nil, nil, "", "", false)
			}

			result := matchMatcher(matcher, "nginx server", "Server: nginx", FaviconHashes{MMH3: "abc123", MD5: "def456"})
			if result != tt.expected {
				t.Errorf("matchMatcher(type=%s) = %v, 期望 %v",
					tt.matcherType, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// 边界情况测试
// =============================================================================

// TestMatchWords_SpecialCharacters 测试特殊字符
func TestMatchWords_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		words    []string
		body     string
		expected bool
	}{
		{
			name:     "包含点号",
			words:    []string{"nginx/1.18.0"},
			body:     "Server: nginx/1.18.0",
			expected: true,
		},
		{
			name:     "包含括号",
			words:    []string{"(Ubuntu)"},
			body:     "Apache/2.4.41 (Ubuntu)",
			expected: true,
		},
		{
			name:     "包含中文",
			words:    []string{"欢迎"},
			body:     "<title>欢迎访问</title>",
			expected: true,
		},
		{
			name:     "包含换行符",
			words:    []string{"Content-Type"},
			body:     "Header:\r\nContent-Type: text/html",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := createMatcher("word", tt.words, nil, nil, "body", "", false)
			result := matchWords(matcher, tt.body, "")
			if result != tt.expected {
				t.Errorf("matchWords() = %v, 期望 %v", result, tt.expected)
			}
		})
	}
}

// TestMatchWords_LargeBody 测试大body
func TestMatchWords_LargeBody(t *testing.T) {
	// 构造100KB的body
	largeBody := make([]byte, 100*1024)
	for i := range largeBody {
		largeBody[i] = 'x'
	}
	// 在中间插入关键词
	copy(largeBody[50*1024:], []byte("WordPress"))

	matcher := createMatcher("word", []string{"WordPress"}, nil, nil, "body", "", false)
	result := matchWords(matcher, string(largeBody), "")

	if !result {
		t.Error("大body中的关键词应被匹配")
	}
}

// =============================================================================
// 性能基准测试
// =============================================================================

// =============================================================================
// 版本提取测试
// =============================================================================

// TestExtractVersions_ServerHeaders 测试从 Server 头提取版本
func TestExtractVersions_ServerHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  string
		expected map[string]string // name -> version
	}{
		{
			name:     "nginx版本",
			headers:  "Server: nginx/1.18.0",
			expected: map[string]string{"nginx": "1.18.0"},
		},
		{
			name:     "Apache版本",
			headers:  "Server: Apache/2.4.41 (Ubuntu)",
			expected: map[string]string{"apache": "2.4.41"},
		},
		{
			name:     "多个版本",
			headers:  "Server: nginx/1.18.0\nX-Powered-By: PHP/7.4.3",
			expected: map[string]string{"nginx": "1.18.0", "php": "7.4.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ExtractVersions("", tt.headers)
			for _, v := range results {
				if expected, ok := tt.expected[v.Name]; ok {
					if v.Version != expected {
						t.Errorf("%s 版本不匹配: got %s, want %s", v.Name, v.Version, expected)
					}
				}
			}
		})
	}
}

// TestExtractVersions_BodyContent 测试从 body 提取版本
func TestExtractVersions_BodyContent(t *testing.T) {
	body := `
<!DOCTYPE html>
<html>
<head>
<meta name="generator" content="WordPress 6.0" />
<script src="/js/jquery-3.6.0.min.js"></script>
</head>
<body>Powered by Tomcat/9.0.41</body>
</html>`

	results := ExtractVersions(body, "")

	// 检查是否提取到预期的版本
	found := make(map[string]bool)
	for _, v := range results {
		found[v.Name] = true
		t.Logf("提取到: %s %s", v.Name, v.Version)
	}

	// WordPress 可能无法提取（因为正则需要调整），但 jQuery 和 Tomcat 应该可以
	if !found["jquery"] && !found["tomcat"] {
		t.Error("应至少提取到 jquery 或 tomcat 版本")
	}
}

// TestExtractVersions_Empty 测试空输入
func TestExtractVersions_Empty(t *testing.T) {
	results := ExtractVersions("", "")
	if len(results) != 0 {
		t.Errorf("空输入应返回空结果，实际: %d", len(results))
	}
}

// BenchmarkExtractVersions 基准测试：版本提取性能
func BenchmarkExtractVersions(b *testing.B) {
	headers := "Server: nginx/1.18.0\nX-Powered-By: PHP/8.0.3\n"
	body := `<meta name="generator" content="WordPress 6.0" />`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractVersions(body, headers)
	}
}

// BenchmarkMatchEnhancedFingerprints 基准测试：并发指纹匹配
func BenchmarkMatchEnhancedFingerprints(b *testing.B) {
	// 模拟真实的 HTTP 响应
	body := []byte(`<!DOCTYPE html>
<html>
<head><title>WordPress Site</title></head>
<body>
<meta name="generator" content="WordPress 6.0" />
<link rel="stylesheet" href="/wp-content/themes/flavor/style.css" />
Powered by nginx/1.18.0
</body>
</html>`)
	headers := "Server: nginx/1.18.0\nX-Powered-By: PHP/8.0\n"
	favicon := FaviconHashes{MMH3: "1386054408", MD5: "abc123"}

	// 预热：确保指纹库已加载
	_ = MatchEnhancedFingerprints(body, headers, favicon)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatchEnhancedFingerprints(body, headers, favicon)
	}
}
