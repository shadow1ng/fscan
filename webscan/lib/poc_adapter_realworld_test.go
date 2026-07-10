package lib

import (
	"os"
	"testing"
)

// TestXrayRealPoc 测试真实的 xray POC
func TestXrayRealPoc(t *testing.T) {
	// 读取 xray 的实际 POC 文件
	xrayPocPath := "C:\\Users\\29037\\GolandProjects\\xray\\pocs\\74cms-sqli-1.yml"
	data, err := os.ReadFile(xrayPocPath)
	if err != nil {
		t.Skipf("跳过测试：无法读取 xray POC 文件: %v", err)
		return
	}

	t.Run("格式检测", func(t *testing.T) {
		format := DetectPocFormat(data)
		if format != FormatXray {
			t.Errorf("DetectPocFormat() = %v, want %v", format, FormatXray)
		}
	})

	t.Run("加载POC", func(t *testing.T) {
		poc, err := LoadUniversalPoc("74cms-sqli-1.yml", data)
		if err != nil {
			t.Fatalf("LoadUniversalPoc() error = %v", err)
		}

		if poc.GetFormat() != FormatXray {
			t.Errorf("GetFormat() = %v, want %v", poc.GetFormat(), FormatXray)
		}

		if poc.GetName() != "poc-yaml-74cms-sqli-1" {
			t.Errorf("GetName() = %v, want %v", poc.GetName(), "poc-yaml-74cms-sqli-1")
		}
	})

	t.Run("转换为fscan格式", func(t *testing.T) {
		poc, _ := LoadUniversalPoc("74cms-sqli-1.yml", data)
		fscanPoc, err := poc.ToNativePoc()
		if err != nil {
			t.Fatalf("ToNativePoc() error = %v", err)
		}

		if fscanPoc.Name != "poc-yaml-74cms-sqli-1" {
			t.Errorf("Poc.Name = %v, want %v", fscanPoc.Name, "poc-yaml-74cms-sqli-1")
		}

		// xray 的 r0 规则应该转为 1 个 fscan rule
		if len(fscanPoc.Rules) != 1 {
			t.Errorf("len(Poc.Rules) = %v, want %v", len(fscanPoc.Rules), 1)
		}

		// 检查 rule 内容
		rule := fscanPoc.Rules[0]
		if rule.Method != "POST" {
			t.Errorf("Rule.Method = %v, want %v", rule.Method, "POST")
		}

		if rule.Expression == "" {
			t.Error("Rule.Expression should not be empty")
		}

		// 验证 detail
		if fscanPoc.Detail.Author != "betta(https://github.com/betta-cyber)" {
			t.Errorf("Poc.Detail.Author = %v", fscanPoc.Detail.Author)
		}
	})
}

// TestAfrogRealPoc 测试真实的 afrog POC
func TestAfrogRealPoc(t *testing.T) {
	// 读取 afrog 的实际 POC 文件
	afrogPocPath := "C:\\Users\\29037\\GolandProjects\\afrog\\pocs\\afrog-pocs\\CNVD\\2020\\CNVD-2020-62422.yaml"
	data, err := os.ReadFile(afrogPocPath)
	if err != nil {
		t.Skipf("跳过测试：无法读取 afrog POC 文件: %v", err)
		return
	}

	t.Run("格式检测", func(t *testing.T) {
		format := DetectPocFormat(data)
		if format != FormatAfrog {
			t.Errorf("DetectPocFormat() = %v, want %v", format, FormatAfrog)
		}
	})

	t.Run("加载POC", func(t *testing.T) {
		poc, err := LoadUniversalPoc("CNVD-2020-62422.yaml", data)
		if err != nil {
			t.Fatalf("LoadUniversalPoc() error = %v", err)
		}

		if poc.GetFormat() != FormatAfrog {
			t.Errorf("GetFormat() = %v, want %v", poc.GetFormat(), FormatAfrog)
		}

		if poc.GetName() != "致远oa系统存在任意文件读取漏洞" {
			t.Errorf("GetName() = %v, want %v", poc.GetName(), "致远oa系统存在任意文件读取漏洞")
		}
	})

	t.Run("转换为fscan格式", func(t *testing.T) {
		poc, _ := LoadUniversalPoc("CNVD-2020-62422.yaml", data)
		fscanPoc, err := poc.ToNativePoc()
		if err != nil {
			t.Fatalf("ToNativePoc() error = %v", err)
		}

		if fscanPoc.Name != "致远oa系统存在任意文件读取漏洞" {
			t.Errorf("Poc.Name = %v", fscanPoc.Name)
		}

		// afrog 的 r0 规则应该转为 1 个 fscan rule
		if len(fscanPoc.Rules) != 1 {
			t.Errorf("len(Poc.Rules) = %v, want %v", len(fscanPoc.Rules), 1)
		}

		// 检查 rule 内容
		rule := fscanPoc.Rules[0]
		if rule.Method != "GET" {
			t.Errorf("Rule.Method = %v, want %v", rule.Method, "GET")
		}

		if rule.Path == "" {
			t.Error("Rule.Path should not be empty")
		}

		if rule.Expression == "" {
			t.Error("Rule.Expression should not be empty")
		}

		// 验证 detail
		if fscanPoc.Detail.Author != "Aquilao" {
			t.Errorf("Poc.Detail.Author = %v, want %v", fscanPoc.Detail.Author, "Aquilao")
		}
	})
}

// TestAfrogMultiRulePoc 测试 afrog 多规则 POC
func TestAfrogMultiRulePoc(t *testing.T) {
	// 读取有多个规则的 afrog POC
	afrogPocPath := "C:\\Users\\29037\\GolandProjects\\afrog\\pocs\\afrog-pocs\\CNVD\\2017\\CNVD-2017-03561.yaml"
	data, err := os.ReadFile(afrogPocPath)
	if err != nil {
		t.Skipf("跳过测试：无法读取 afrog POC 文件: %v", err)
		return
	}

	t.Run("格式检测", func(t *testing.T) {
		format := DetectPocFormat(data)
		if format != FormatAfrog {
			t.Errorf("DetectPocFormat() = %v, want %v", format, FormatAfrog)
		}
	})

	t.Run("转换多规则POC", func(t *testing.T) {
		poc, err := LoadUniversalPoc("CNVD-2017-03561.yaml", data)
		if err != nil {
			t.Fatalf("LoadUniversalPoc() error = %v", err)
		}

		fscanPoc, err := poc.ToNativePoc()
		if err != nil {
			t.Fatalf("ToNativePoc() error = %v", err)
		}

		// 这个 POC 有 r0 和 r1 两个规则
		if len(fscanPoc.Rules) != 2 {
			t.Errorf("len(Poc.Rules) = %v, want %v", len(fscanPoc.Rules), 2)
		}

		// 验证第一个规则
		if fscanPoc.Rules[0].Path != "/login.do?message={{n1}}*{{n2}}" {
			t.Errorf("Rules[0].Path = %v", fscanPoc.Rules[0].Path)
		}

		// 验证第二个规则
		if fscanPoc.Rules[1].Path != "/login/login.do?message={{n1}}*{{n2}}" {
			t.Errorf("Rules[1].Path = %v", fscanPoc.Rules[1].Path)
		}
	})
}

// TestXrayMultiRulePoc 测试 xray 多规则 POC
func TestXrayMultiRulePoc(t *testing.T) {
	// 读取有多个规则的 xray POC
	xrayPocPath := "C:\\Users\\29037\\GolandProjects\\xray\\pocs\\activemq-cve-2016-3088.yml"
	data, err := os.ReadFile(xrayPocPath)
	if err != nil {
		t.Skipf("跳过测试：无法读取 xray POC 文件: %v", err)
		return
	}

	t.Run("格式检测", func(t *testing.T) {
		format := DetectPocFormat(data)
		if format != FormatXray {
			t.Errorf("DetectPocFormat() = %v, want %v", format, FormatXray)
		}
	})

	t.Run("转换多规则POC", func(t *testing.T) {
		poc, err := LoadUniversalPoc("activemq-cve-2016-3088.yml", data)
		if err != nil {
			t.Fatalf("LoadUniversalPoc() error = %v", err)
		}

		fscanPoc, err := poc.ToNativePoc()
		if err != nil {
			t.Fatalf("ToNativePoc() error = %v", err)
		}

		// 这个 POC 有 r0, r1, r2, r3 四个规则
		if len(fscanPoc.Rules) != 4 {
			t.Errorf("len(Poc.Rules) = %v, want %v", len(fscanPoc.Rules), 4)
		}

		// 验证每个规则的 method
		expectedMethods := []string{"PUT", "GET", "MOVE", "GET"}
		for i, expected := range expectedMethods {
			if fscanPoc.Rules[i].Method != expected {
				t.Errorf("Rules[%d].Method = %v, want %v", i, fscanPoc.Rules[i].Method, expected)
			}
		}

		// 验证所有规则都有 expression
		for i, rule := range fscanPoc.Rules {
			if rule.Expression == "" {
				t.Errorf("Rules[%d].Expression should not be empty", i)
			}
		}
	})
}

// TestFormatDetectionComparison 对比四种格式的检测
func TestFormatDetectionComparison(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected PocFormat
	}{
		{
			name:     "fscan格式",
			path:     "C:\\Users\\29037\\GolandProjects\\fscan\\webscan\\pocs\\74cms-sqli-1.yml",
			expected: FormatNative,
		},
		{
			name:     "xray格式",
			path:     "C:\\Users\\29037\\GolandProjects\\xray\\pocs\\74cms-sqli-1.yml",
			expected: FormatXray,
		},
		{
			name:     "afrog格式",
			path:     "C:\\Users\\29037\\GolandProjects\\afrog\\pocs\\afrog-pocs\\CNVD\\2020\\CNVD-2020-62422.yaml",
			expected: FormatAfrog,
		},
		{
			name:     "Nuclei格式",
			path:     "C:\\Users\\29037\\GolandProjects\\fscan\\webscan\\pocs\\test-nuclei-example.yaml",
			expected: FormatNuclei,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Skipf("跳过：无法读取文件 %s: %v", tt.path, err)
				return
			}

			format := DetectPocFormat(data)
			if format != tt.expected {
				t.Errorf("DetectPocFormat() = %v, want %v", format, tt.expected)
			}
		})
	}
}
