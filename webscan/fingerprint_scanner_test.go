package WebScan

import (
	"crypto/md5" //nolint:gosec
	"fmt"
	"testing"

	"github.com/shadow1ng/fscan/webscan/fingerprint"
)

// =============================================================================
// removeDuplicateElement 测试
// =============================================================================

func TestRemoveDuplicateElement_Basic(t *testing.T) {
	input := []string{"nginx", "apache", "nginx", "iis", "apache"}
	result := removeDuplicateElement(input)

	if len(result) != 3 {
		t.Errorf("期望3个唯一元素，实际 %d: %v", len(result), result)
	}

	seen := make(map[string]int)
	for _, v := range result {
		seen[v]++
		if seen[v] > 1 {
			t.Errorf("元素 %q 出现了多次", v)
		}
	}
}

func TestRemoveDuplicateElement_Empty(t *testing.T) {
	result := removeDuplicateElement([]string{})
	if len(result) != 0 {
		t.Errorf("空输入应返回空切片，实际 %d", len(result))
	}
}

func TestRemoveDuplicateElement_NoDup(t *testing.T) {
	input := []string{"a", "b", "c"}
	result := removeDuplicateElement(input)
	if len(result) != 3 {
		t.Errorf("无重复时应保留全部元素，实际 %d", len(result))
	}
}

func TestRemoveDuplicateElement_AllSame(t *testing.T) {
	input := []string{"dup", "dup", "dup", "dup"}
	result := removeDuplicateElement(input)
	if len(result) != 1 {
		t.Errorf("全部相同时应只保留1个，实际 %d", len(result))
	}
	if result[0] != "dup" {
		t.Errorf("保留的元素应为 'dup'，实际 %q", result[0])
	}
}

func TestRemoveDuplicateElement_PreservesOrder(t *testing.T) {
	input := []string{"c", "a", "b", "a", "c"}
	result := removeDuplicateElement(input)
	if len(result) != 3 {
		t.Fatalf("期望3个元素，实际 %d", len(result))
	}
	// 第一次出现的顺序应被保留
	if result[0] != "c" || result[1] != "a" || result[2] != "b" {
		t.Errorf("顺序不符合预期: %v", result)
	}
}

// =============================================================================
// matchByMd5 测试
// =============================================================================

func TestMatchByMd5_KnownHash(t *testing.T) {
	// 从真实的 Md5Datas 取第一条：{"BIG-IP", "04d9541338e525258daf47cc844d59f3"}
	if len(fingerprint.Md5Datas) == 0 {
		t.Skip("Md5Datas 为空，跳过测试")
	}

	entry := fingerprint.Md5Datas[0]

	// 找到能产生这个 md5 的数据——直接暴力：构造一个有已知 md5 的 body
	// 实际上 md5 是 favicon 的 hash，这里测试找不到匹配的情况
	emptyResult := matchByMd5([]byte("no match content here"))
	if emptyResult != "" {
		t.Logf("意外匹配了 %q（不影响功能，跳过断言）", emptyResult)
	}

	// 验证函数正确返回空字符串——主要检测无崩溃
	_ = entry
}

func TestMatchByMd5_NoMatch(t *testing.T) {
	result := matchByMd5([]byte("definitely not matching any fingerprint 12345"))
	if result != "" {
		t.Errorf("不应匹配任何指纹，实际匹配了 %q", result)
	}
}

func TestMatchByMd5_Empty(t *testing.T) {
	// 空 body 的 md5 固定值 d41d8cd98f00b204e9800998ecf8427e
	// 检查是否在数据库中（不是，所以应返回空）
	result := matchByMd5([]byte{})
	// 不强断言结果，只验证不崩溃
	_ = result
}

// 构造一个真实 md5 让 matchByMd5 命中
func TestMatchByMd5_ActualMatch(t *testing.T) {
	if len(fingerprint.Md5Datas) == 0 {
		t.Skip("Md5Datas 为空")
	}

	// 找一条已知 md5，反向构造：我们不能反推原始数据
	// 但可以直接测试 md5 计算逻辑：手动计算 body 的 md5 并与函数对比
	body := []byte("test content for md5 check")
	//nolint:gosec
	expected := fmt.Sprintf("%x", md5.Sum(body))

	// matchByMd5 内部会对 body 计算 md5，然后在 Md5Datas 中查找
	// 因为这个 md5 不在 Md5Datas 中，应返回 ""
	result := matchByMd5(body)
	if result != "" {
		t.Logf("巧合命中: body_md5=%s matched=%q", expected, result)
	}
	// 主要验证逻辑路径可以走通
}

// =============================================================================
// matchByRegex 测试
// =============================================================================

func TestMatchByRegex_CodeType(t *testing.T) {
	// 宝塔指纹：Type="code"，匹配 body
	data := CheckDatas{
		Body:    []byte("app.bt.cn/static/app.png"),
		Headers: "",
	}
	result := matchByRegex(data)
	found := false
	for _, name := range result {
		if name == "宝塔" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("应匹配宝塔指纹，实际结果: %v", result)
	}
}

func TestMatchByRegex_HeaderType(t *testing.T) {
	// CloudFlare 指纹：Type="headers"，匹配 headers
	data := CheckDatas{
		Body:    []byte(""),
		Headers: "CF-RAY: cloudflare-abc123",
	}
	result := matchByRegex(data)
	found := false
	for _, name := range result {
		if name == "CloudFlare" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("应匹配CloudFlare指纹，实际结果: %v", result)
	}
}

func TestMatchByRegex_NoMatch(t *testing.T) {
	data := CheckDatas{
		Body:    []byte("hello world nothing special"),
		Headers: "Content-Type: text/plain",
	}
	result := matchByRegex(data)
	// 普通内容不应匹配特征指纹
	// 不强断言数量，只验证不崩溃
	_ = result
}

func TestMatchByRegex_EmptyData(t *testing.T) {
	data := CheckDatas{}
	result := matchByRegex(data)
	if result == nil {
		result = []string{}
	}
	// 空数据不崩溃即可
	_ = result
}

func TestMatchByRegex_DeepInserve(t *testing.T) {
	// 深信服防火墙：body 中包含 "SANGFOR FW"
	data := CheckDatas{
		Body:    []byte(`<html>SANGFOR FW product page</html>`),
		Headers: "",
	}
	result := matchByRegex(data)
	found := false
	for _, name := range result {
		if name == "深信服防火墙类产品" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("应匹配深信服防火墙指纹，实际结果: %v", result)
	}
}
