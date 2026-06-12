package lib

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/cel-go/common/types"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// =============================================================================
// eval_encoding.go 测试 - 编码解码函数
// =============================================================================

func TestBase64Encoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"简单字符串", "hello", "aGVsbG8="},
		{"特殊字符", "test@123", "dGVzdEAxMjM="},
		{"中文", "测试", "5rWL6K+V"},
		{"空字符串", "", ""},
	}

	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `base64("` + tt.input + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if string(str) != tt.expected {
				t.Errorf("base64() = %q, want %q", str, tt.expected)
			}
		})
	}
}

func TestBase64Decoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"简单字符串", "aGVsbG8=", "hello"},
		{"特殊字符", "dGVzdEAxMjM=", "test@123"},
		{"空字符串", "", ""},
	}

	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `base64Decode("` + tt.input + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if string(str) != tt.expected {
				t.Errorf("base64Decode() = %q, want %q", str, tt.expected)
			}
		})
	}
}

func TestURLEncoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"普通字符串", "hello world", "hello+world"},
		{"特殊字符", "test@example.com", "test%40example.com"},
		{"路径", "/api/v1/users", "%2Fapi%2Fv1%2Fusers"},
		{"空字符串", "", ""},
	}

	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `urlencode("` + tt.input + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if string(str) != tt.expected {
				t.Errorf("urlencode() = %q, want %q", str, tt.expected)
			}
		})
	}
}

func TestURLDecoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"空格编码", "hello+world", "hello world"},
		{"特殊字符", "test%40example.com", "test@example.com"},
		{"路径", "%2Fapi%2Fv1%2Fusers", "/api/v1/users"},
		{"空字符串", "", ""},
	}

	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `urldecode("` + tt.input + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if string(str) != tt.expected {
				t.Errorf("urldecode() = %q, want %q", str, tt.expected)
			}
		})
	}
}

// =============================================================================
// eval_crypto.go 测试 - 加密函数
// =============================================================================

func TestMD5Function(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"简单字符串", "hello", "5d41402abc4b2a76b9719d911017c592"},
		{"数字", "123456", "e10adc3949ba59abbe56e057f20f883e"},
		{"空字符串", "", "d41d8cd98f00b204e9800998ecf8427e"},
		{"特殊字符", "admin@123", "e6e061838856bf47e1de730719fb2609"},
	}

	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `md5("` + tt.input + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if string(str) != tt.expected {
				t.Errorf("md5() = %q, want %q", str, tt.expected)
			}
		})
	}
}

// =============================================================================
// eval_random.go 测试 - 随机函数
// =============================================================================

func TestRandomInt(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name string
		expr string
		min  int64
		max  int64
	}{
		{"范围1-10", "randomInt(1, 10)", 1, 10},
		{"范围100-200", "randomInt(100, 200)", 100, 200},
		{"范围0-1", "randomInt(0, 1)", 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 10; i++ { // 运行10次确保随机性
				result, err := Evaluate(env, tt.expr, map[string]interface{}{})
				if err != nil {
					t.Fatalf("表达式评估失败: %v", err)
				}

				num, ok := result.(types.Int)
				if !ok {
					t.Fatalf("返回值类型错误，期望 Int，实际 %T", result)
				}

				if int64(num) < tt.min || int64(num) >= tt.max {
					t.Errorf("randomInt() = %d, 超出范围 [%d, %d)", num, tt.min, tt.max)
				}
			}
		})
	}
}

func TestRandomIntRejectsOverflowingRange(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	if _, err := Evaluate(env, "randomInt(-9223372036854775808, 9223372036854775807)", map[string]interface{}{}); err == nil {
		t.Fatal("Evaluate() error = nil, want randomInt range error")
	}
	if _, err := randomIntSpan(-9223372036854775807-1, 9223372036854775807); err == nil {
		t.Fatal("randomIntSpan() error = nil, want range too large")
	}
}

func TestRandomLowercase(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name   string
		length int
	}{
		{"长度5", 5},
		{"长度10", 10},
		{"长度1", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := fmt.Sprintf("randomLowercase(%d)", tt.length)
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if len(str) != tt.length {
				t.Errorf("randomLowercase() 长度 = %d, want %d", len(str), tt.length)
			}

			// 验证所有字符都是小写字母
			for _, c := range str {
				if c < 'a' || c > 'z' {
					t.Errorf("randomLowercase() 包含非小写字母字符: %c", c)
					break
				}
			}
		})
	}
}

func TestRandomUppercase(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name   string
		length int
	}{
		{"长度5", 5},
		{"长度8", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := fmt.Sprintf("randomUppercase(%d)", tt.length)
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if len(str) != tt.length {
				t.Errorf("randomUppercase() 长度 = %d, want %d", len(str), tt.length)
			}

			// 验证所有字符都是大写字母
			for _, c := range str {
				if c < 'A' || c > 'Z' {
					t.Errorf("randomUppercase() 包含非大写字母字符: %c", c)
					break
				}
			}
		})
	}
}

func TestRandomString(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name   string
		length int
	}{
		{"长度10", 10},
		{"长度20", 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := fmt.Sprintf("randomString(%d)", tt.length)
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if len(str) != tt.length {
				t.Errorf("randomString() 长度 = %d, want %d", len(str), tt.length)
			}

			// 验证所有字符都是字母或数字
			for _, c := range str {
				if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
					t.Errorf("randomString() 包含非字母数字字符: %c", c)
					break
				}
			}
		})
	}
}

func TestRandomStringLengthValidation(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	for _, expr := range []string{
		"randomLowercase(-1)",
		fmt.Sprintf("randomUppercase(%d)", maxRandomStringLength+1),
		fmt.Sprintf("randomString(%d)", maxRandomStringLength+1),
	} {
		t.Run(expr, func(t *testing.T) {
			if _, err := Evaluate(env, expr, map[string]interface{}{}); err == nil {
				t.Fatal("Evaluate() error = nil, want invalid random string length")
			}
		})
	}
}

// =============================================================================
// eval_string.go 测试 - 字符串函数
// =============================================================================

func TestIContains(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name     string
		str      string
		substr   string
		expected bool
	}{
		{"大小写不敏感匹配", "Hello World", "WORLD", true},
		{"小写匹配", "hello world", "world", true},
		{"不匹配", "hello", "bye", false},
		{"空子串", "hello", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `"` + tt.str + `".icontains("` + tt.substr + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			b, ok := result.(types.Bool)
			if !ok {
				t.Fatalf("返回值类型错误，期望 Bool，实际 %T", result)
			}

			if bool(b) != tt.expected {
				t.Errorf("icontains() = %v, want %v", b, tt.expected)
			}
		})
	}
}

func TestSubstr(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name     string
		str      string
		start    int
		length   int
		expected string
	}{
		{"正常提取", "hello world", 0, 5, "hello"},
		{"中间提取", "hello world", 6, 5, "world"},
		{"提取一个字符", "test", 1, 1, "e"},
		{"中文字符", "你好世界", 0, 2, "你好"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := fmt.Sprintf(`substr("%s", %d, %d)`, tt.str, tt.start, tt.length)
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			str, ok := result.(types.String)
			if !ok {
				t.Fatalf("返回值类型错误，期望 String，实际 %T", result)
			}

			if string(str) != tt.expected {
				t.Errorf("substr() = %q, want %q", str, tt.expected)
			}
		})
	}

	t.Run("长度溢出不panic", func(t *testing.T) {
		if _, err := Evaluate(env, `substr("hello", 1, 9223372036854775807)`, map[string]interface{}{}); err == nil {
			t.Fatal("Evaluate() error = nil, want invalid substr bounds")
		}
	})
}

func TestIStartsWith(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name     string
		str      string
		prefix   string
		expected bool
	}{
		{"大小写不敏感匹配", "Hello World", "HELLO", true},
		{"小写匹配", "hello world", "hello", true},
		{"不匹配", "hello", "world", false},
		{"空前缀", "hello", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `"` + tt.str + `".istartsWith("` + tt.prefix + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			b, ok := result.(types.Bool)
			if !ok {
				t.Fatalf("返回值类型错误，期望 Bool，实际 %T", result)
			}

			if bool(b) != tt.expected {
				t.Errorf("istartsWith() = %v, want %v", b, tt.expected)
			}
		})
	}
}

// =============================================================================
// 核心函数测试 - Evaluate
// =============================================================================

func TestEvaluate(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		params   map[string]interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "空表达式返回true",
			expr:     "",
			params:   map[string]interface{}{},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "简单布尔表达式",
			expr:     "true && false",
			params:   map[string]interface{}{},
			expected: false,
			wantErr:  false,
		},
		{
			name:     "数学计算",
			expr:     "1 + 2 * 3",
			params:   map[string]interface{}{},
			expected: int64(7),
			wantErr:  false,
		},
		{
			name:     "字符串拼接",
			expr:     `"hello" + " " + "world"`,
			params:   map[string]interface{}{},
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "无效表达式",
			expr:     "invalid syntax +++",
			params:   map[string]interface{}{},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Evaluate(env, tt.expr, tt.params)

			if (err != nil) != tt.wantErr {
				t.Errorf("Evaluate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// 类型转换和比较
			switch expected := tt.expected.(type) {
			case bool:
				if b, ok := result.(types.Bool); ok {
					if bool(b) != expected {
						t.Errorf("Evaluate() = %v, want %v", b, expected)
					}
				} else {
					t.Errorf("Evaluate() 返回类型错误，期望 Bool，实际 %T", result)
				}
			case int64:
				if i, ok := result.(types.Int); ok {
					if int64(i) != expected {
						t.Errorf("Evaluate() = %v, want %v", i, expected)
					}
				} else {
					t.Errorf("Evaluate() 返回类型错误，期望 Int，实际 %T", result)
				}
			case string:
				if s, ok := result.(types.String); ok {
					if string(s) != expected {
						t.Errorf("Evaluate() = %v, want %v", s, expected)
					}
				} else {
					t.Errorf("Evaluate() 返回类型错误，期望 String，实际 %T", result)
				}
			}
		})
	}
}

// =============================================================================
// 辅助函数测试
// =============================================================================

func TestURLTypeToString(t *testing.T) {
	tests := []struct {
		name     string
		url      *UrlType
		expected string
	}{
		{
			name: "完整URL",
			url: &UrlType{
				Scheme:   "https",
				Host:     "example.com:443",
				Path:     "/api/v1/users",
				Query:    "page=1&size=10",
				Fragment: "section1",
			},
			expected: "https://example.com:443/api/v1/users?page=1&size=10#section1",
		},
		{
			name: "无端口号",
			url: &UrlType{
				Scheme: "http",
				Host:   "example.com",
				Path:   "/test",
			},
			expected: "http://example.com/test",
		},
		{
			name: "IPv6 host",
			url: &UrlType{
				Scheme: "http",
				Host:   "2001:db8::1",
				Path:   "/test",
			},
			expected: "http://[2001:db8::1]/test",
		},
		{
			name: "仅路径",
			url: &UrlType{
				Path: "/api/test",
			},
			expected: "/api/test",
		},
		{
			name: "带查询参数无路径",
			url: &UrlType{
				Scheme: "https",
				Host:   "example.com",
				Query:  "q=test",
			},
			expected: "https://example.com?q=test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := URLTypeToString(tt.url)
			if result != tt.expected {
				t.Errorf("URLTypeToString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestRandomStrHelpers(t *testing.T) {
	t.Run("randomLowercase生成小写字母", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			result := randomLowercase(10)
			if len(result) != 10 {
				t.Errorf("randomLowercase(10) 长度 = %d, want 10", len(result))
			}
			for _, c := range result {
				if c < 'a' || c > 'z' {
					t.Errorf("randomLowercase() 包含非小写字母: %c", c)
					break
				}
			}
		}
	})

	t.Run("randomUppercase生成大写字母", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			result := randomUppercase(10)
			if len(result) != 10 {
				t.Errorf("randomUppercase(10) 长度 = %d, want 10", len(result))
			}
			for _, c := range result {
				if c < 'A' || c > 'Z' {
					t.Errorf("randomUppercase() 包含非大写字母: %c", c)
					break
				}
			}
		}
	})

	t.Run("randomString生成字母数字", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			result := randomString(15)
			if len(result) != 15 {
				t.Errorf("randomString(15) 长度 = %d, want 15", len(result))
			}
			for _, c := range result {
				if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
					t.Errorf("randomString() 包含非字母数字字符: %c", c)
					break
				}
			}
		}
	})
}

func TestCompileAndProgramOptions(t *testing.T) {
	customLib := NewEnvOption()

	t.Run("CompileOptions返回非空", func(t *testing.T) {
		opts := customLib.CompileOptions()
		if len(opts) == 0 {
			t.Error("CompileOptions() 返回空切片")
		}
	})

	t.Run("ProgramOptions返回空切片", func(t *testing.T) {
		// ProgramOptions() 返回空切片是预期行为
		// 函数实现通过 GetBaseProgramOptions() 在 Evaluate() 时注入
		// 这避免了多次创建环境时重复注册函数导致的冲突
		opts := customLib.ProgramOptions()
		if len(opts) != 0 {
			t.Error("ProgramOptions() 应返回空切片以避免重复注册函数")
		}
	})

	t.Run("GetBaseProgramOptions返回非空", func(t *testing.T) {
		// 函数实现通过 GetBaseProgramOptions() 提供
		opts := GetBaseProgramOptions()
		if len(opts) == 0 {
			t.Error("GetBaseProgramOptions() 返回空切片")
		}
	})
}

func TestUpdateCompileOptions(t *testing.T) {
	customLib := NewEnvOption()

	tests := []struct {
		name     string
		args     StrMap
		checkVar string
	}{
		{
			name: "添加randomInt变量",
			args: StrMap{
				{Key: "myrand", Value: "randomInt(1, 100)"},
			},
			checkVar: "myrand",
		},
		{
			name: "添加字符串变量",
			args: StrMap{
				{Key: "mystr", Value: "somevalue"},
			},
			checkVar: "mystr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialLen := len(customLib.envOptions)
			customLib.UpdateCompileOptions(tt.args)

			if len(customLib.envOptions) <= initialLen {
				t.Error("UpdateCompileOptions() 未添加新的环境选项")
			}
		})
	}
}

func TestBcontainsBytes(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name     string
		haystack string
		needle   string
		expected bool
	}{
		{"包含", "hello world", "world", true},
		{"不包含", "hello", "world", false},
		{"空needle", "hello", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := `b"` + tt.haystack + `".bcontains(b"` + tt.needle + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			b, ok := result.(types.Bool)
			if !ok {
				t.Fatalf("返回值类型错误，期望 Bool，实际 %T", result)
			}

			if bool(b) != tt.expected {
				t.Errorf("bcontains() = %v, want %v", b, tt.expected)
			}
		})
	}
}

func TestBmatches(t *testing.T) {
	customLib := NewEnvOption()
	env, err := NewEnv(&customLib)
	if err != nil {
		t.Fatalf("创建 CEL 环境失败: %v", err)
	}

	tests := []struct {
		name     string
		pattern  string
		text     string
		expected bool
	}{
		{"匹配数字", `\d+`, "abc123", true},
		{"匹配邮箱", `\w+@\w+\.\w+`, "test@example.com", true},
		{"不匹配", `\d+`, "abcdef", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 需要转义反斜杠
			pattern := strings.ReplaceAll(tt.pattern, `\`, `\\`)
			expr := `"` + pattern + `".bmatches(b"` + tt.text + `")`
			result, err := Evaluate(env, expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("表达式评估失败: %v", err)
			}

			b, ok := result.(types.Bool)
			if !ok {
				t.Fatalf("返回值类型错误，期望 Bool，实际 %T", result)
			}

			if bool(b) != tt.expected {
				t.Errorf("bmatches() = %v, want %v", b, tt.expected)
			}
		})
	}
}

// =============================================================================
// HTTP 解析函数测试
// =============================================================================

func TestParseURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *UrlType
	}{
		{
			name:  "完整URL",
			input: "https://example.com:443/api/v1/users?page=1&size=10#section1",
			expected: &UrlType{
				Scheme:   "https",
				Domain:   "example.com",
				Host:     "example.com:443",
				Port:     "443",
				Path:     "/api/v1/users",
				Query:    "page=1&size=10",
				Fragment: "section1",
			},
		},
		{
			name:  "HTTP URL",
			input: "http://example.com/test",
			expected: &UrlType{
				Scheme: "http",
				Domain: "example.com",
				Host:   "example.com",
				Port:   "",
				Path:   "/test",
				Query:  "",
			},
		},
		{
			name:  "仅域名",
			input: "https://example.com",
			expected: &UrlType{
				Scheme: "https",
				Domain: "example.com",
				Host:   "example.com",
				Port:   "",
				Path:   "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.input)
			if err != nil {
				t.Fatalf("URL 解析失败: %v", err)
			}

			result := ParseURL(u)

			if result.Scheme != tt.expected.Scheme {
				t.Errorf("Scheme = %q, want %q", result.Scheme, tt.expected.Scheme)
			}
			if result.Domain != tt.expected.Domain {
				t.Errorf("Domain = %q, want %q", result.Domain, tt.expected.Domain)
			}
			if result.Host != tt.expected.Host {
				t.Errorf("Host = %q, want %q", result.Host, tt.expected.Host)
			}
			if result.Port != tt.expected.Port {
				t.Errorf("Port = %q, want %q", result.Port, tt.expected.Port)
			}
			if result.Path != tt.expected.Path {
				t.Errorf("Path = %q, want %q", result.Path, tt.expected.Path)
			}
			if result.Query != tt.expected.Query {
				t.Errorf("Query = %q, want %q", result.Query, tt.expected.Query)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		url         string
		headers     map[string]string
		body        string
		wantMethod  string
		wantPath    string
		wantHeaders int
	}{
		{
			name:   "GET请求",
			method: "GET",
			url:    "http://example.com/api/test",
			headers: map[string]string{
				"User-Agent": "test-agent",
				"Accept":     "application/json",
			},
			body:        "",
			wantMethod:  "GET",
			wantPath:    "/api/test",
			wantHeaders: 2,
		},
		{
			name:   "POST请求带Body",
			method: "POST",
			url:    "http://example.com/api/login",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:        `{"username":"admin","password":"123456"}`,
			wantMethod:  "POST",
			wantPath:    "/api/login",
			wantHeaders: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.url)
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}

			httpReq, err := http.NewRequest(tt.method, u.String(), bodyReader)
			if err != nil {
				t.Fatalf("创建 HTTP 请求失败: %v", err)
			}

			for k, v := range tt.headers {
				httpReq.Header.Set(k, v)
			}

			req, err := ParseRequest(httpReq)
			if err != nil {
				t.Fatalf("ParseRequest() error = %v", err)
			}

			if req.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", req.Method, tt.wantMethod)
			}

			if req.URL.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", req.URL.Path, tt.wantPath)
			}

			if len(req.Headers) < tt.wantHeaders {
				t.Errorf("Headers count = %d, want at least %d", len(req.Headers), tt.wantHeaders)
			}

			if tt.body != "" && string(req.Body) != tt.body {
				t.Errorf("Body = %q, want %q", req.Body, tt.body)
			}
		})
	}
}

func TestGetRespBody(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		compress    bool
		wantContent string
		wantErr     bool
	}{
		{
			name:        "普通响应体",
			body:        "Hello, World!",
			compress:    false,
			wantContent: "Hello, World!",
			wantErr:     false,
		},
		{
			name:        "空响应体",
			body:        "",
			compress:    false,
			wantContent: "",
			wantErr:     false,
		},
		{
			name:        "JSON响应",
			body:        `{"status":"success","data":{"id":1}}`,
			compress:    false,
			wantContent: `{"status":"success","data":{"id":1}}`,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建模拟响应
			resp := &http.Response{
				Header: make(http.Header),
			}

			var bodyReader io.ReadCloser
			if tt.compress {
				resp.Header.Set("Content-Encoding", "gzip")
				// 这里需要 gzip 压缩，暂时跳过
				t.Skip("gzip 测试需要额外实现")
			} else {
				bodyReader = io.NopCloser(strings.NewReader(tt.body))
			}
			resp.Body = bodyReader

			result, err := getRespBody(resp)

			if (err != nil) != tt.wantErr {
				t.Errorf("getRespBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(result) != tt.wantContent {
				t.Errorf("getRespBody() = %q, want %q", result, tt.wantContent)
			}
		})
	}
}

func TestGetRespBodyLimitsPlainBody(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader(strings.Repeat("a", maxPOCResponseBodyBytes+1024))),
	}

	body, err := getRespBody(resp)
	if err != nil {
		t.Fatalf("getRespBody error = %v", err)
	}
	if len(body) != maxPOCResponseBodyBytes {
		t.Fatalf("body len = %d, want %d", len(body), maxPOCResponseBodyBytes)
	}
}

func TestGetRespBodyLimitsGzipBody(t *testing.T) {
	var compressed strings.Builder
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write([]byte(strings.Repeat("a", maxPOCResponseBodyBytes+1024))); err != nil {
		t.Fatalf("gzip write error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip close error = %v", err)
	}

	resp := &http.Response{
		Header: http.Header{"Content-Encoding": []string{"gzip"}},
		Body:   io.NopCloser(strings.NewReader(compressed.String())),
	}

	body, err := getRespBody(resp)
	if err != nil {
		t.Fatalf("getRespBody error = %v", err)
	}
	if len(body) != maxPOCResponseBodyBytes {
		t.Fatalf("body len = %d, want %d", len(body), maxPOCResponseBodyBytes)
	}
}

func TestDoRequestBuffersUnknownLengthBody(t *testing.T) {
	previous := ClientNoRedirect
	defer func() { ClientNoRedirect = previous }()

	var gotContentLength string
	var gotBody string
	ClientNoRedirect = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotContentLength = req.Header.Get("Content-Length")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		gotBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})}

	req, err := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(strings.NewReader("abc")))
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}
	req.ContentLength = -1

	if _, err := DoRequest(req, false, nil); err != nil {
		t.Fatalf("DoRequest error = %v", err)
	}
	if gotContentLength != "3" {
		t.Fatalf("Content-Length = %q, want 3", gotContentLength)
	}
	if gotBody != "abc" {
		t.Fatalf("body = %q, want abc", gotBody)
	}
}

func TestDoRequestUsesFallbackClientWhenGlobalClientNil(t *testing.T) {
	previous := ClientNoRedirect
	ClientNoRedirect = nil
	defer func() { ClientNoRedirect = previous }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}

	resp, err := DoRequest(req, false, nil)
	if err != nil {
		t.Fatalf("DoRequest error = %v", err)
	}
	if string(resp.Body) != "ok" {
		t.Fatalf("body = %q, want ok", resp.Body)
	}
}

func TestDoRequestSkipsNilGMTLSFallback(t *testing.T) {
	previousNR, previousGM := ClientNoRedirect, ClientNoRedirectGM
	defer func() {
		ClientNoRedirect = previousNR
		ClientNoRedirectGM = previousGM
	}()

	ClientNoRedirect = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("standard tls failed")
	})}
	ClientNoRedirectGM = nil

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}

	if _, err := DoRequest(req, false, nil); err == nil {
		t.Fatal("DoRequest expected standard TLS error")
	}
}

func TestDoRequestReplaysBodyForGMTLSFallback(t *testing.T) {
	previousNR, previousGM := ClientNoRedirect, ClientNoRedirectGM
	defer func() {
		ClientNoRedirect = previousNR
		ClientNoRedirectGM = previousGM
	}()

	ClientNoRedirect = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_, _ = io.ReadAll(req.Body)
		return nil, errors.New("standard tls failed")
	})}

	var gotBody string
	ClientNoRedirectGM = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		gotBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})}

	req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}

	if _, err := DoRequest(req, false, nil); err != nil {
		t.Fatalf("DoRequest error = %v", err)
	}
	if gotBody != "payload" {
		t.Fatalf("fallback body = %q, want payload", gotBody)
	}
}

func TestRandomStr(t *testing.T) {
	tests := []struct {
		name       string
		charset    string
		length     int
		checkRange func(c rune) bool
	}{
		{
			name:    "数字字符集",
			charset: "0123456789",
			length:  10,
			checkRange: func(c rune) bool {
				return c >= '0' && c <= '9'
			},
		},
		{
			name:    "小写字母字符集",
			charset: "abcdefghijklmnopqrstuvwxyz",
			length:  15,
			checkRange: func(c rune) bool {
				return c >= 'a' && c <= 'z'
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 5; i++ { // 运行多次确保稳定性
				result := RandomStr(randSource, tt.charset, tt.length)

				if len(result) != tt.length {
					t.Errorf("RandomStr() 长度 = %d, want %d", len(result), tt.length)
				}

				for _, c := range result {
					if !tt.checkRange(c) {
						t.Errorf("RandomStr() 包含无效字符: %c", c)
						break
					}
				}
			}
		})
	}
}

func TestRandomStrRejectsNegativeLength(t *testing.T) {
	if got := RandomStr(randSource, "abc", -1); got != "" {
		t.Fatalf("RandomStr negative length = %q, want empty", got)
	}
}
