package lib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/output"
)

// =============================================================================
// 重构后函数的单元测试
// =============================================================================

// TestGetRuleHash 测试规则哈希计算
func TestGetRuleHash(t *testing.T) {
	tests := []struct {
		name      string
		rule1     *Rules
		rule2     *Rules
		wantSame  bool
		wantEmpty bool
	}{
		{
			name: "相同规则产生相同哈希",
			rule1: &Rules{
				Method:  "GET",
				Path:    "/api/test",
				Headers: map[string]string{"User-Agent": "test"},
				Body:    "",
			},
			rule2: &Rules{
				Method:  "GET",
				Path:    "/api/test",
				Headers: map[string]string{"User-Agent": "test"},
				Body:    "",
			},
			wantSame: true,
		},
		{
			name: "不同Method产生不同哈希",
			rule1: &Rules{
				Method:  "GET",
				Path:    "/api/test",
				Headers: map[string]string{},
				Body:    "",
			},
			rule2: &Rules{
				Method:  "POST",
				Path:    "/api/test",
				Headers: map[string]string{},
				Body:    "",
			},
			wantSame: false,
		},
		{
			name: "不同Path产生不同哈希",
			rule1: &Rules{
				Method:  "GET",
				Path:    "/api/test1",
				Headers: map[string]string{},
				Body:    "",
			},
			rule2: &Rules{
				Method:  "GET",
				Path:    "/api/test2",
				Headers: map[string]string{},
				Body:    "",
			},
			wantSame: false,
		},
		{
			name: "空规则产生非空哈希",
			rule1: &Rules{
				Method:  "",
				Path:    "",
				Headers: map[string]string{},
				Body:    "",
			},
			rule2:     nil,
			wantSame:  false,
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := getRuleHash(tt.rule1)

			// 验证哈希非空（MD5应该是32个十六进制字符）
			if !tt.wantEmpty && len(hash1) != 32 {
				t.Errorf("getRuleHash() 返回的哈希长度不正确，期望32，实际%d", len(hash1))
			}

			// 验证哈希是否相同
			if tt.rule2 != nil {
				hash2 := getRuleHash(tt.rule2)
				areSame := hash1 == hash2
				if areSame != tt.wantSame {
					t.Errorf("getRuleHash() 哈希相同性不符合预期\n规则1哈希: %s\n规则2哈希: %s\n期望相同: %v\n实际相同: %v",
						hash1, hash2, tt.wantSame, areSame)
				}
			}
		})
	}
}

func TestCheckMultiPocSavesSimpleRulesPoc(t *testing.T) {
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case paths <- r.URL.Path:
		default:
		}
		_, _ = w.Write([]byte("kei-poc-hit"))
	}))
	defer server.Close()

	cfg := common.NewConfig()
	cfg.Output.Silent = true
	cfg.Network.WebTimeout = 5 * time.Second
	cfg.Network.MaxRedirects = 3
	cfg.POC.Num = 1
	if err := Inithttp(cfg); err != nil {
		t.Fatalf("Inithttp: %v", err)
	}

	var results []*output.ScanResult
	session := common.NewScanSession(cfg, common.NewState(), &common.FlagVars{})
	session.ResultSink = func(result *output.ScanResult) error {
		results = append(results, result)
		return nil
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	poc := &Poc{
		Name: "poc-yaml-kei-repro",
		Rules: []Rules{{
			Method:     http.MethodGet,
			Path:       "/kei-poc",
			Expression: `response.status == 200 && response.body.bcontains(b"kei-poc-hit")`,
		}},
	}
	CheckMultiPoc(req, []*Poc{poc}, 1, &POCContext{Session: session})

	select {
	case got := <-paths:
		if got != "/kei-poc" {
			t.Fatalf("request path = %q, want /kei-poc", got)
		}
	default:
		t.Fatal("POC request was not sent")
	}
	if len(results) != 1 {
		t.Fatalf("saved results = %d, want 1", len(results))
	}
	if results[0].Type != output.TypeVuln || results[0].Target != server.URL {
		t.Fatalf("saved result = %#v", results[0])
	}
	if got := results[0].Details["vulnerability_name"]; got != "poc-yaml-kei-repro" {
		t.Fatalf("vulnerability_name = %v, want poc-yaml-kei-repro", got)
	}
}

// TestDoSearchSetCookieOptimization 测试 Set-Cookie 提取和清理
func TestDoSearchSetCookieOptimization(t *testing.T) {
	responseHeaders := "HTTP/1.1 200 OK\r\n"
	cases := []struct {
		name           string
		regex          string
		body           string
		wantContain    string // 期望结果包含的内容
		wantNotContain string // 期望结果不包含的内容
	}{
		{
			name:           "捕获组名为cookie时清理属性",
			regex:          `Set-Cookie:(?P<cookie>.*)`,
			body:           responseHeaders + "Set-Cookie: sessionid=abc123; Path=/; HttpOnly\r\n\r\n<html></html>",
			wantContain:    "sessionid=abc123",
			wantNotContain: "Path",
		},
		{
			name:           "捕获组名为sessid时也清理属性",
			regex:          `Set-Cookie:(?P<sessid>.*)`,
			body:           responseHeaders + "Set-Cookie: JSESSIONID=xyz789; Path=/app; Secure; HttpOnly\r\n\r\n{}",
			wantContain:    "JSESSIONID=xyz789",
			wantNotContain: "Secure",
		},
		{
			name:           "捕获组名为token时也清理属性",
			regex:          `Set-Cookie:(?P<token>.*)`,
			body:           responseHeaders + "Set-Cookie: csrf_token=tok123; Max-Age=3600; SameSite=Strict\r\n\r\nOK",
			wantContain:    "csrf_token=tok123",
			wantNotContain: "Max-Age",
		},
		{
			name:        "非Set-Cookie的正则不触发清理",
			regex:       `X-Custom:(?P<value>.*)`,
			body:        responseHeaders + "X-Custom: some-value; extra=stuff\r\n\r\ndone",
			wantContain: "some-value; extra=stuff",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := doSearch(c.regex, c.body)
			if result == nil {
				t.Fatal("doSearch() returned nil")
			}
			for _, v := range result {
				if c.wantContain != "" && !strings.Contains(v, c.wantContain) {
					t.Errorf("result should contain %q, got %q", c.wantContain, v)
				}
				if c.wantNotContain != "" && strings.Contains(v, c.wantNotContain) {
					t.Errorf("result should NOT contain %q, got %q", c.wantNotContain, v)
				}
			}
		})
	}
}

// TestOptimizeCookies 测试 Cookie 清理函数
func TestOptimizeCookies(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "标准Set-Cookie带多个属性",
			raw:  "sessionid=abc123; Path=/; HttpOnly; Secure",
			want: "sessionid=abc123",
		},
		{
			name: "多个cookie键值对",
			raw:  "token=xyz; user=admin; Path=/app; Expires=Wed, 21 Oct 2025 07:28:00 GMT",
			want: "token=xyz; user=admin",
		},
		{
			name: "无属性的干净cookie",
			raw:  "sid=simple",
			want: "sid=simple",
		},
		{
			name: "分号后无空格",
			raw:  "token=xyz;user=admin;Path=/app;HttpOnly",
			want: "token=xyz; user=admin",
		},
		{
			name: "键名周围空格",
			raw:  " token =xyz; user =admin; Path =/",
			want: "token=xyz; user=admin",
		},
		{
			name: "空字符串",
			raw:  "",
			want: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := optimizeCookies(c.raw)
			if got != c.want {
				t.Errorf("optimizeCookies(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

// TestApplyParametersToRule 测试参数替换逻辑
func TestApplyParametersToRule(t *testing.T) {
	tests := []struct {
		name            string
		rule            Rules
		sets            ListMap
		payloads        map[string]interface{}
		variableMap     map[string]interface{}
		payloadExpr     string
		wantReplacement bool
		wantPath        string
		wantHeader      string
		wantBody        string
	}{
		{
			name: "替换Path中的参数",
			rule: Rules{
				Method:  "GET",
				Path:    "/api/{{key}}/test",
				Headers: map[string]string{},
				Body:    "",
			},
			sets: ListMap{
				{Key: "key", Value: []string{"value1"}},
			},
			payloads: map[string]interface{}{
				"key": "myvalue",
			},
			variableMap:     map[string]interface{}{},
			payloadExpr:     "",
			wantReplacement: true,
			wantPath:        "/api/myvalue/test",
		},
		{
			name: "替换Header中的参数",
			rule: Rules{
				Method:  "GET",
				Path:    "/test",
				Headers: map[string]string{"X-Custom": "{{token}}"},
				Body:    "",
			},
			sets: ListMap{
				{Key: "token", Value: []string{"abc123"}},
			},
			payloads: map[string]interface{}{
				"token": "secret123",
			},
			variableMap:     map[string]interface{}{},
			payloadExpr:     "",
			wantReplacement: true,
			wantHeader:      "secret123",
		},
		{
			name: "替换Body中的参数",
			rule: Rules{
				Method:  "POST",
				Path:    "/api/login",
				Headers: map[string]string{},
				Body:    `{"username":"{{user}}","password":"{{pass}}"}`,
			},
			sets: ListMap{
				{Key: "user", Value: []string{"admin"}},
				{Key: "pass", Value: []string{"123456"}},
			},
			payloads: map[string]interface{}{
				"user": "testuser",
				"pass": "testpass",
			},
			variableMap:     map[string]interface{}{},
			payloadExpr:     "",
			wantReplacement: true,
			wantBody:        `{"username":"testuser","password":"testpass"}`,
		},
		{
			name: "无匹配参数时不替换",
			rule: Rules{
				Method:  "GET",
				Path:    "/static/page",
				Headers: map[string]string{},
				Body:    "",
			},
			sets: ListMap{
				{Key: "key", Value: []string{"value"}},
			},
			payloads: map[string]interface{}{
				"key": "test",
			},
			variableMap:     map[string]interface{}{},
			payloadExpr:     "",
			wantReplacement: false,
			wantPath:        "/static/page",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 克隆规则避免修改原始数据
			currentRule := Rules{
				Method:  tt.rule.Method,
				Path:    tt.rule.Path,
				Headers: make(map[string]string),
				Body:    tt.rule.Body,
			}
			for k, v := range tt.rule.Headers {
				currentRule.Headers[k] = v
			}

			hasReplacement, replacedParams := applyParametersToRule(
				&currentRule,
				tt.sets,
				tt.payloads,
				tt.variableMap,
				tt.payloadExpr,
			)

			// 验证是否发生替换
			if hasReplacement != tt.wantReplacement {
				t.Errorf("applyParametersToRule() hasReplacement = %v, want %v", hasReplacement, tt.wantReplacement)
			}

			// 验证替换后的值
			if tt.wantPath != "" && currentRule.Path != tt.wantPath {
				t.Errorf("applyParametersToRule() Path = %q, want %q", currentRule.Path, tt.wantPath)
			}

			if tt.wantHeader != "" {
				found := false
				for _, v := range currentRule.Headers {
					if v == tt.wantHeader {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("applyParametersToRule() Header 未找到期望值 %q", tt.wantHeader)
				}
			}

			if tt.wantBody != "" && currentRule.Body != tt.wantBody {
				t.Errorf("applyParametersToRule() Body = %q, want %q", currentRule.Body, tt.wantBody)
			}

			// 验证替换参数列表
			if hasReplacement && len(replacedParams) == 0 {
				t.Error("applyParametersToRule() 有替换但replacedParams为空")
			}
		})
	}
}

func TestPocExecutorPureHelpers(t *testing.T) {
	t.Run("isFuzz detects placeholders", func(t *testing.T) {
		sets := ListMap{{Key: "token", Value: []string{"a", "b"}}}
		if !isFuzz(Rules{Headers: map[string]string{"X-Token": "{{token}}"}}, sets) {
			t.Fatal("header placeholder should require fuzzing")
		}
		if !isFuzz(Rules{Path: "/api/{{token}}"}, sets) {
			t.Fatal("path placeholder should require fuzzing")
		}
		if !isFuzz(Rules{Body: "token={{token}}"}, sets) {
			t.Fatal("body placeholder should require fuzzing")
		}
		if isFuzz(Rules{Path: "/api/static"}, sets) {
			t.Fatal("static rule should not require fuzzing")
		}
	})

	t.Run("Combo and MakeData", func(t *testing.T) {
		if got := Combo(nil); got != nil {
			t.Fatalf("Combo(nil) = %#v, want nil", got)
		}
		one := Combo(ListMap{{Key: "user", Value: []string{"admin", "root"}}})
		if len(one) != 2 || one[0][0] != "admin" || one[1][0] != "root" {
			t.Fatalf("single Combo = %#v", one)
		}
		combos := Combo(ListMap{
			{Key: "user", Value: []string{"admin", "root"}},
			{Key: "pass", Value: []string{"123", "456"}},
		})
		want := [][]string{{"admin", "123"}, {"root", "123"}, {"admin", "456"}, {"root", "456"}}
		if !stringMatrixEqual(combos, want) {
			t.Fatalf("Combo = %#v, want %#v", combos, want)
		}
		made := MakeData([][]string{{"b"}, {"c"}}, []string{"a"})
		if !stringMatrixEqual(made, [][]string{{"a", "b"}, {"a", "c"}}) {
			t.Fatalf("MakeData = %#v", made)
		}
		if got := shiroKeyMode([]string{"only-key"}); got != "" {
			t.Fatalf("shiroKeyMode(short combo) = %q, want empty", got)
		}
		if got := shiroKeyMode([]string{"key", "cbc"}); got != "cbc" {
			t.Fatalf("shiroKeyMode() = %q, want cbc", got)
		}
	})

	t.Run("cloneRules deep-copies headers", func(t *testing.T) {
		original := Rules{
			Method:          "POST",
			Path:            "/login",
			Body:            "a=b",
			Search:          "token",
			FollowRedirects: true,
			Expression:      "true",
			Headers:         map[string]string{"X-Test": "one"},
			Continue:        true,
		}
		cloned := cloneRules(original)
		cloned.Headers["X-Test"] = "two"
		if original.Headers["X-Test"] != "one" {
			t.Fatalf("cloneRules should deep copy headers, original = %#v", original.Headers)
		}
		if cloned.Method != original.Method || cloned.Path != original.Path || !cloned.FollowRedirects || !cloned.Continue {
			t.Fatalf("cloneRules lost fields: %#v", cloned)
		}
		if cloneMap(nil) != nil {
			t.Fatal("cloneMap(nil) should return nil")
		}
	})

	t.Run("doSearch and GetHeader", func(t *testing.T) {
		header := GetHeader(map[string]string{"Set-Cookie": "sid=abc; Path=/; HttpOnly", "Server": "nginx"})
		if !strings.Contains(header, "Set-Cookie: sid=abc; Path=/; HttpOnly") || !strings.HasSuffix(header, "\r\n") {
			t.Fatalf("GetHeader output = %q", header)
		}
		result := doSearch(`Set-Cookie:\s*(?P<cookie>[^\n]+)`, header)
		if result["cookie"] != "sid=abc" {
			t.Fatalf("cookie search = %#v", result)
		}
		result = doSearch(`token=(\w+)&id=(?P<id>\d+)`, "token=abc&id=42")
		if result[""] != "" || result["id"] != "42" || len(result) != 1 {
			t.Fatalf("unnamed groups should be skipped, got %#v", result)
		}
		if got := doSearch(`(?P<bad>`, "body"); got != nil {
			t.Fatalf("invalid regex result = %#v, want nil", got)
		}
		if got := doSearch(`nomatch(?P<value>\d+)`, "body"); got != nil {
			t.Fatalf("no match result = %#v, want nil", got)
		}
	})
}

// =============================================================================
// isPlainLiteral 测试
// =============================================================================

func TestIsPlainLiteral_EmptyString(t *testing.T) {
	if isPlainLiteral("", nil) {
		t.Error("空字符串不是字面量")
	}
}

func TestIsPlainLiteral_PlainWord(t *testing.T) {
	if !isPlainLiteral("database", nil) {
		t.Error("纯单词 'database' 应视为字面量")
	}
}

func TestIsPlainLiteral_WithParens(t *testing.T) {
	if isPlainLiteral("func()", nil) {
		t.Error("含括号的表达式不是字面量")
	}
}

func TestIsPlainLiteral_WithOperator(t *testing.T) {
	for _, expr := range []string{"a+b", "a*b", "a==b", "a!=b", "a<b", "a>b", "a&&b", "a||b"} {
		if isPlainLiteral(expr, nil) {
			t.Errorf("含运算符的表达式 %q 不是字面量", expr)
		}
	}
}

func TestIsPlainLiteral_WithQuotes(t *testing.T) {
	if isPlainLiteral(`"hello"`, nil) {
		t.Error("含引号的表达式不是字面量")
	}
	if isPlainLiteral("'hello'", nil) {
		t.Error("含单引号的表达式不是字面量")
	}
}

func TestIsPlainLiteral_VariableRef(t *testing.T) {
	// 如果 expr 是已声明变量的名字，应走 CEL 求值
	varMap := map[string]interface{}{"token": "abc123"}
	if isPlainLiteral("token", varMap) {
		t.Error("已声明变量不应被视为字面量")
	}
}

func TestIsPlainLiteral_UndeclaredVariable(t *testing.T) {
	varMap := map[string]interface{}{"token": "abc123"}
	// 未声明的变量名且无特殊字符 -> 字面量
	if !isPlainLiteral("sql", varMap) {
		t.Error("未声明的纯单词 'sql' 应视为字面量")
	}
}

func TestIsPlainLiteral_WithBracket(t *testing.T) {
	if isPlainLiteral("arr[0]", nil) {
		t.Error("含方括号的表达式不是字面量")
	}
}

func TestIsPlainLiteral_PathLike(t *testing.T) {
	// 路径中可能含 /，但 / 不在排除字符中，视为字面量
	if !isPlainLiteral("admin", nil) {
		t.Error("纯字母字符串应为字面量")
	}
}

func stringMatrixEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

// =============================================================================
// buildVulnDetails 测试
// =============================================================================

func TestBuildVulnDetails(t *testing.T) {
	tests := []struct {
		name          string
		pocDef        *Poc
		vulName       string
		params        StrMap
		wantKeys      []string
		wantNoKeys    []string
		wantVulnType  string
		wantVulnName  string
		wantParamVal  string
		wantParamKey  string
	}{
		{
			name:         "最小Poc只有Name",
			pocDef:       &Poc{Name: "poc-yaml-test"},
			vulName:      "poc-yaml-test",
			params:       nil,
			wantKeys:     []string{"vulnerability_type", "vulnerability_name"},
			wantNoKeys:   []string{"author", "references", "description", "parameters"},
			wantVulnType: "poc-yaml-test",
			wantVulnName: "poc-yaml-test",
		},
		{
			name: "完整Poc含Author+Links+Description",
			pocDef: &Poc{
				Name: "poc-yaml-full",
				Detail: Detail{
					Author:      "kei",
					Links:       []string{"https://example.com"},
					Description: "test vuln",
				},
			},
			vulName:      "Full Vuln",
			params:       nil,
			wantKeys:     []string{"vulnerability_type", "vulnerability_name", "author", "references", "description"},
			wantNoKeys:   []string{"parameters"},
			wantVulnType: "poc-yaml-full",
			wantVulnName: "Full Vuln",
		},
		{
			name:   "有params则details含parameters字段",
			pocDef: &Poc{Name: "poc-yaml-params"},
			vulName: "Params Vuln",
			params: StrMap{
				{Key: "user", Value: "admin"},
				{Key: "pass", Value: "123456"},
			},
			wantKeys:    []string{"vulnerability_type", "vulnerability_name", "parameters"},
			wantNoKeys:  []string{"author"},
			wantParamKey: "user",
			wantParamVal: "admin",
		},
		{
			name:       "空params不含parameters字段",
			pocDef:     &Poc{Name: "poc-yaml-empty-params"},
			vulName:    "Empty Params",
			params:     StrMap{},
			wantKeys:   []string{"vulnerability_type", "vulnerability_name"},
			wantNoKeys: []string{"parameters"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details := buildVulnDetails(tt.pocDef, tt.vulName, tt.params)

			for _, k := range tt.wantKeys {
				if _, ok := details[k]; !ok {
					t.Errorf("details 缺少字段 %q", k)
				}
			}
			for _, k := range tt.wantNoKeys {
				if _, ok := details[k]; ok {
					t.Errorf("details 不应含字段 %q", k)
				}
			}
			if tt.wantVulnType != "" {
				if got, _ := details["vulnerability_type"].(string); got != tt.wantVulnType {
					t.Errorf("vulnerability_type = %q, want %q", got, tt.wantVulnType)
				}
			}
			if tt.wantVulnName != "" {
				if got, _ := details["vulnerability_name"].(string); got != tt.wantVulnName {
					t.Errorf("vulnerability_name = %q, want %q", got, tt.wantVulnName)
				}
			}
			if tt.wantParamKey != "" {
				pm, ok := details["parameters"].(map[string]string)
				if !ok {
					t.Fatalf("parameters 类型错误，实际 %T", details["parameters"])
				}
				if got := pm[tt.wantParamKey]; got != tt.wantParamVal {
					t.Errorf("parameters[%q] = %q, want %q", tt.wantParamKey, got, tt.wantParamVal)
				}
			}
		})
	}
}

// =============================================================================
// buildVulnLogMsg 测试
// =============================================================================

func TestBuildVulnLogMsg(t *testing.T) {
	tests := []struct {
		name      string
		targetURL string
		pocDef    *Poc
		vulName   string
		params    StrMap
	}{
		{
			name:      "backup-file名称走特殊模板",
			targetURL: "http://example.com",
			pocDef:    &Poc{Name: "poc-yaml-backup-file"},
			vulName:   "poc-yaml-backup-file",
			params:    nil,
		},
		{
			name:      "sql-file名称走特殊模板",
			targetURL: "http://example.com",
			pocDef:    &Poc{Name: "poc-yaml-sql-file"},
			vulName:   "poc-yaml-sql-file",
			params:    nil,
		},
		{
			name:      "有params走params模板",
			targetURL: "http://example.com",
			pocDef:    &Poc{Name: "poc-yaml-rce"},
			vulName:   "RCE",
			params:    StrMap{{Key: "cmd", Value: "id"}},
		},
		{
			name:      "无params走detail_header模板",
			targetURL: "http://example.com",
			pocDef: &Poc{
				Name: "poc-yaml-sqli",
				Detail: Detail{
					Author:      "kei",
					Links:       []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001"},
					Description: "SQL injection",
				},
			},
			vulName: "SQLi",
			params:  nil,
		},
		{
			name:      "无params无detail只走header",
			targetURL: "http://example.com",
			pocDef:    &Poc{Name: "poc-yaml-generic"},
			vulName:   "Generic",
			params:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildVulnLogMsg(tt.targetURL, tt.pocDef, tt.vulName, tt.params)
			if msg == "" {
				t.Errorf("buildVulnLogMsg() 返回空字符串")
			}
		})
	}
}

// =============================================================================
// collectVarDeclarations 测试
// =============================================================================

func TestCollectVarDeclarations(t *testing.T) {
	t.Run("空 POC 返回空切片", func(t *testing.T) {
		p := &Poc{}
		decls := collectVarDeclarations(p)
		if len(decls) != 0 {
			t.Fatalf("len = %d, want 0", len(decls))
		}
	})

	t.Run("仅 Set 字段", func(t *testing.T) {
		p := &Poc{
			Set: StrMap{
				{Key: "token", Value: "randomLowercase(8)"},
				{Key: "port", Value: "randomInt(1000, 9000)"},
			},
		}
		decls := collectVarDeclarations(p)
		if len(decls) != 2 {
			t.Fatalf("len = %d, want 2", len(decls))
		}
		if decls[0].Name != "token" {
			t.Errorf("decls[0].Name = %q, want token", decls[0].Name)
		}
		if decls[1].Name != "port" {
			t.Errorf("decls[1].Name = %q, want port", decls[1].Name)
		}
	})

	t.Run("仅 Sets 字段", func(t *testing.T) {
		p := &Poc{
			Sets: ListMap{
				{Key: "user", Value: []string{"admin", "root"}},
			},
		}
		decls := collectVarDeclarations(p)
		if len(decls) != 1 {
			t.Fatalf("len = %d, want 1", len(decls))
		}
		if decls[0].Name != "user" {
			t.Errorf("decls[0].Name = %q, want user", decls[0].Name)
		}
	})

	t.Run("Sets 空值列表不 panic", func(t *testing.T) {
		p := &Poc{
			Sets: ListMap{
				{Key: "empty", Value: []string{}},
			},
		}
		decls := collectVarDeclarations(p)
		if len(decls) != 1 {
			t.Fatalf("len = %d, want 1", len(decls))
		}
		if decls[0].Name != "empty" {
			t.Errorf("decls[0].Name = %q, want empty", decls[0].Name)
		}
	})

	t.Run("Set 和 Sets 合并", func(t *testing.T) {
		p := &Poc{
			Set: StrMap{
				{Key: "a", Value: "x"},
			},
			Sets: ListMap{
				{Key: "b", Value: []string{"y"}},
			},
		}
		decls := collectVarDeclarations(p)
		if len(decls) != 2 {
			t.Fatalf("len = %d, want 2", len(decls))
		}
	})

	t.Run("newReverse 前缀推断 Object 类型", func(t *testing.T) {
		p := &Poc{
			Set: StrMap{
				{Key: "rev", Value: "newReverse()"},
			},
		}
		decls := collectVarDeclarations(p)
		if len(decls) != 1 {
			t.Fatalf("len = %d, want 1", len(decls))
		}
		tp := decls[0].GetIdent().GetType()
		if tp == nil || tp.GetMessageType() == "" {
			t.Errorf("期望 Object 类型，实际 %v", tp)
		}
	})
}
