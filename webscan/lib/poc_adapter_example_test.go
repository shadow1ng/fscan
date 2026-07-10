package lib

import (
	"fmt"
	"testing"
)

// TestPocAdapterExample 演示多格式POC加载
func TestPocAdapterExample(t *testing.T) {
	fmt.Println("\n========== 多格式 POC 适配器演示 ==========")

	// 示例1: fscan原生格式
	fscanYaml := `
name: poc-yaml-test-fscan
set:
  rand: randomInt(10000, 99999)
rules:
  - method: GET
    path: /api/check?id={{rand}}
    expression: |
      response.status == 200 && response.body.bcontains(b"success")
detail:
  author: fscan-dev
  description: fscan原生格式示例
`

	fmt.Println("1. 加载 fscan 原生格式 POC:")
	fmt.Println("   YAML内容:", fscanYaml[:100], "...")

	poc1, err := LoadUniversalPoc("test-fscan.yml", []byte(fscanYaml))
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	fmt.Printf("   ✓ 格式: %s\n", poc1.GetFormat())
	fmt.Printf("   ✓ 名称: %s\n", poc1.GetName())

	fscanPoc1, _ := poc1.ToNativePoc()
	fmt.Printf("   ✓ 规则数: %d\n", len(fscanPoc1.Rules))
	fmt.Println()

	// 示例2: Nuclei格式
	nucleiYaml := `
id: test-nuclei-sqli
info:
  name: SQL Injection Detection
  author: pdteam
  severity: high
  description: Detects SQL injection vulnerabilities
  reference:
    - https://owasp.org/www-community/attacks/SQL_Injection
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/user?id=1'"
      - "{{BaseURL}}/search?q=test'"
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
        condition: or
      - type: status
        status:
          - 500
`

	fmt.Println("2. 加载 Nuclei 格式 POC:")
	fmt.Println("   YAML内容:", nucleiYaml[:100], "...")

	poc2, err := LoadUniversalPoc("test-nuclei.yaml", []byte(nucleiYaml))
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	fmt.Printf("   ✓ 格式: %s\n", poc2.GetFormat())
	fmt.Printf("   ✓ 名称: %s\n", poc2.GetName())

	fscanPoc2, _ := poc2.ToNativePoc()
	fmt.Printf("   ✓ 规则数: %d (Nuclei的2个path转为2个rule)\n", len(fscanPoc2.Rules))
	fmt.Printf("   ✓ 第一条规则表达式: %s\n", fscanPoc2.Rules[0].Expression[:80]+"...")
	fmt.Println()

	// 示例3: 格式检测
	fmt.Println("3. 自动格式检测:")

	testCases := []struct {
		name   string
		yaml   string
		format PocFormat
	}{
		{
			"fscan格式",
			`name: test
rules:
  - method: GET`,
			FormatNative,
		},
		{
			"Nuclei格式",
			`id: test
info:
  name: test`,
			FormatNuclei,
		},
		{
			"未知格式",
			`unknown: field`,
			FormatUnknown,
		},
	}

	for _, tc := range testCases {
		detected := DetectPocFormat([]byte(tc.yaml))
		status := "✓"
		if detected != tc.format {
			status = "✗"
		}
		fmt.Printf("   %s %s: 检测为 %s\n", status, tc.name, detected)
	}

	fmt.Println("\n========== 演示结束 ==========")
}

// TestPocAdapterFeatures 展示适配器特性
func TestPocAdapterFeatures(t *testing.T) {
	fmt.Println("\n========== POC 适配器特性展示 ==========")

	nucleiYaml := `
id: features-demo
info:
  name: Feature Demo
  author: test
  severity: medium
http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    headers:
      Content-Type: application/json
    body: '{"user":"admin","pass":"test"}'
    matchers:
      - type: word
        words:
          - "success"
          - "authenticated"
        condition: and
      - type: status
        status:
          - 200
          - 302
    matchers-condition: and
`

	fmt.Println("特性1: Nuclei matcher 转换")
	poc, _ := LoadUniversalPoc("demo.yaml", []byte(nucleiYaml))
	fscanPoc, _ := poc.ToNativePoc()

	fmt.Printf("   原始: Nuclei format with 2 matchers\n")
	fmt.Printf("   转换: fscan expression\n")
	fmt.Printf("   结果: %s\n", fscanPoc.Rules[0].Expression)
	fmt.Println()

	fmt.Println("特性2: 多 path 处理")
	multiPathYaml := `
id: multi-path-demo
info:
  name: Multi Path Demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/dashboard"
      - "{{BaseURL}}/config"
    matchers:
      - type: status
        status:
          - 200
`

	poc2, _ := LoadUniversalPoc("multi.yaml", []byte(multiPathYaml))
	fscanPoc2, _ := poc2.ToNativePoc()

	fmt.Printf("   原始: 3个 path\n")
	fmt.Printf("   转换: %d 个 rule\n", len(fscanPoc2.Rules))
	for i, rule := range fscanPoc2.Rules {
		fmt.Printf("      Rule %d: %s\n", i+1, rule.Path)
	}

	fmt.Println("\n========== 特性展示结束 ==========")
}
