package fingerprint

import (
	"testing"
)

// =============================================================================
// calcPriority 测试
// =============================================================================

func TestCalcPriority_FaviconHighest(t *testing.T) {
	fp := &EnhancedFingerprint{}
	p := calcPriority(fp, "favicon")
	if p != 100 {
		t.Errorf("favicon 优先级应为 100，实际 %d", p)
	}
}

func TestCalcPriority_RegexMedium(t *testing.T) {
	fp := &EnhancedFingerprint{}
	p := calcPriority(fp, "regex")
	if p != 50 {
		t.Errorf("regex 优先级应为 50，实际 %d", p)
	}
}

func TestCalcPriority_WordLow(t *testing.T) {
	fp := &EnhancedFingerprint{}
	p := calcPriority(fp, "word")
	if p != 30 {
		t.Errorf("word 优先级应为 30，实际 %d", p)
	}
}

func TestCalcPriority_UnknownTypeZero(t *testing.T) {
	fp := &EnhancedFingerprint{}
	p := calcPriority(fp, "unknown")
	if p != 0 {
		t.Errorf("未知类型优先级应为 0，实际 %d", p)
	}
}

func TestCalcPriority_VerifiedBonus(t *testing.T) {
	fp := &EnhancedFingerprint{}
	fp.Info.Metadata = map[string]interface{}{
		"verified": true,
	}
	p := calcPriority(fp, "word")
	// word(30) + verified(20) = 50
	if p != 50 {
		t.Errorf("word+verified 优先级应为 50，实际 %d", p)
	}
}

func TestCalcPriority_VerifiedFavicon(t *testing.T) {
	fp := &EnhancedFingerprint{}
	fp.Info.Metadata = map[string]interface{}{
		"verified": true,
	}
	p := calcPriority(fp, "favicon")
	// favicon(100) + verified(20) = 120
	if p != 120 {
		t.Errorf("favicon+verified 优先级应为 120，实际 %d", p)
	}
}

func TestCalcPriority_VerifiedFalse(t *testing.T) {
	fp := &EnhancedFingerprint{}
	fp.Info.Metadata = map[string]interface{}{
		"verified": false,
	}
	p := calcPriority(fp, "regex")
	// verified=false 不加分
	if p != 50 {
		t.Errorf("verified=false 时优先级应为 50，实际 %d", p)
	}
}

func TestCalcPriority_NilMetadata(t *testing.T) {
	fp := &EnhancedFingerprint{}
	// Metadata 为 nil，不加分
	p := calcPriority(fp, "favicon")
	if p != 100 {
		t.Errorf("nil metadata 时 favicon 优先级应为 100，实际 %d", p)
	}
}

// =============================================================================
// matchRegex 测试 - 需要初始化 enhancedDB
// =============================================================================

func initEnhancedDBForTest(t *testing.T) {
	t.Helper()
	if enhancedDB == nil {
		if err := LoadEnhancedFingerprints(); err != nil {
			t.Fatalf("LoadEnhancedFingerprints 失败: %v", err)
		}
	}
}

func TestMatchRegex_BodyMatch(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{`nginx/[\d.]+`}, nil, "body", "", false)
	result := matchRegex(matcher, "Server: nginx/1.18.0 running", "")
	if !result {
		t.Error("body 中应匹配 nginx 版本正则")
	}
}

func TestMatchRegex_HeaderMatch(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{`X-Powered-By: PHP/[\d.]+`}, nil, "header", "", false)
	result := matchRegex(matcher, "", "X-Powered-By: PHP/7.4.3")
	if !result {
		t.Error("header 中应匹配 PHP 版本正则")
	}
}

func TestMatchRegex_NoMatch(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{`apache/[\d.]+`}, nil, "body", "", false)
	result := matchRegex(matcher, "nginx server running", "")
	if result {
		t.Error("不应匹配 apache 正则")
	}
}

func TestMatchRegex_ANDConditionAllMatch(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{`nginx`, `1\.18`}, nil, "body", "and", false)
	result := matchRegex(matcher, "nginx/1.18.0 server", "")
	if !result {
		t.Error("AND 条件下两个正则都匹配应返回 true")
	}
}

func TestMatchRegex_ANDConditionPartialMatch(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{`nginx`, `apache`}, nil, "body", "and", false)
	result := matchRegex(matcher, "nginx server", "")
	if result {
		t.Error("AND 条件下只有一个匹配应返回 false")
	}
}

func TestMatchRegex_ORConditionOneMatch(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{`nginx`, `apache`}, nil, "body", "or", false)
	result := matchRegex(matcher, "apache httpd", "")
	if !result {
		t.Error("OR 条件下至少一个匹配应返回 true")
	}
}

func TestMatchRegex_CaseInsensitive(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{`NGINX`}, nil, "body", "", true)
	result := matchRegex(matcher, "nginx/1.18.0", "")
	if !result {
		t.Error("大小写不敏感模式下应匹配")
	}
}

func TestMatchRegex_InvalidPattern(t *testing.T) {
	initEnhancedDBForTest(t)

	// 无效正则不应崩溃
	matcher := createMatcher("regex", nil, []string{`[invalid regex(`}, nil, "body", "", false)
	result := matchRegex(matcher, "test content", "")
	if result {
		t.Error("无效正则不应产生匹配")
	}
}

func TestMatchRegex_EmptyPatterns(t *testing.T) {
	initEnhancedDBForTest(t)

	matcher := createMatcher("regex", nil, []string{}, nil, "body", "and", false)
	result := matchRegex(matcher, "nginx", "")
	// AND 条件且无 pattern：isAnd && len(Regex) > 0 为 false
	if result {
		t.Error("AND 条件下空 patterns 应返回 false")
	}
}
