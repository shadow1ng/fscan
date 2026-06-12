package parsers

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

/*
parse_test.go - 简化解析器测试

测试目标：ParseIP和ParsePort两个核心解析函数
价值：解析错误会导致：
  - 错误的扫描目标（用户扫描了错误的主机）
  - 错误的端口范围（遗漏关键服务）
  - 性能问题（重复目标导致浪费）

"解析器是扫描器的入口。解析错误=整个扫描就是错的。
端口范围解析bug会让用户遗漏漏洞。这是真实问题。"
*/

// =============================================================================
// ParsePort - 端口解析测试
// =============================================================================

// TestParsePort_Empty 测试空字符串
//
// 验证：空输入返回nil而不是空切片
//
// empty slice表示'有数据但是空的'。这个区别很重要。"
func TestParsePort_Empty(t *testing.T) {
	result := ParsePort("")

	if result != nil {
		t.Errorf("ParsePort(\"\") = %v, want nil", result)
	}

	t.Logf("✓ 空字符串正确返回nil")
}

// TestParsePort_SinglePort 测试单个端口
func TestParsePort_SinglePort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{"HTTP", "80", []int{80}},
		{"HTTPS", "443", []int{443}},
		{"SSH", "22", []int{22}},
		{"MinPort", "1", []int{1}},
		{"MaxPort", "65535", []int{65535}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) → %v", tt.input, result)
		})
	}
}

// TestParsePort_MultiplePorts 测试多个端口
func TestParsePort_MultiplePorts(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			"Web端口",
			"80,443,8080",
			[]int{80, 443, 8080},
		},
		{
			"数据库端口",
			"3306,5432,27017",
			[]int{3306, 5432, 27017},
		},
		{
			"带空格",
			" 80 , 443 , 8080 ",
			[]int{80, 443, 8080},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) → %v", tt.input, result)
		})
	}
}

// TestParsePort_PortRange 测试端口范围
//
// 验证：范围解析正确，包含起始和结束端口
//
// 1-5应该是[1,2,3,4,5]还是[1,2,3,4]？搞错了就是bug。"
func TestParsePort_PortRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			"小范围",
			"1-5",
			[]int{1, 2, 3, 4, 5},
		},
		{
			"HTTP备用端口",
			"8000-8003",
			[]int{8000, 8001, 8002, 8003},
		},
		{
			"单端口范围",
			"80-80",
			[]int{80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) → %v", tt.input, result)
		})
	}
}

// TestParsePort_MixedFormat 测试混合格式
func TestParsePort_MixedFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			"端口+范围",
			"80,100-102,443",
			[]int{80, 100, 101, 102, 443},
		},
		{
			"多个范围",
			"1-3,10-12",
			[]int{1, 2, 3, 10, 11, 12},
		},
		{
			"复杂混合",
			"22,80-82,443,8000-8001",
			[]int{22, 80, 81, 82, 443, 8000, 8001},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) → %v", tt.input, result)
		})
	}
}

// TestParsePort_InvalidRange 测试无效范围
//
// 验证：无效范围被正确过滤
func TestParsePort_InvalidRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			"反向范围",
			"100-50",
			nil,
		},
		{
			"超出上限起始",
			"65536-65540",
			nil,
		},
		{
			"低于下限",
			"0-5",
			nil,
		},
		{
			"无效格式",
			"80-90-100",
			nil,
		},
		{
			"非数字",
			"abc-xyz",
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) 正确拒绝无效范围", tt.input)
		})
	}
}

// TestParsePort_OutOfRange 测试超出范围的端口
func TestParsePort_OutOfRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			"端口0",
			"0",
			nil,
		},
		{
			"端口65536",
			"65536",
			nil,
		},
		{
			"混合有效和无效",
			"0,80,443,65536",
			[]int{80, 443},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) 正确过滤无效端口", tt.input)
		})
	}
}

// TestParsePort_Deduplicate 测试去重
//
// 验证：重复端口被去重，结果已排序
func TestParsePort_Deduplicate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			"简单重复",
			"80,80,80",
			[]int{80},
		},
		{
			"多个重复",
			"80,443,80,22,443",
			[]int{22, 80, 443},
		},
		{
			"范围重复",
			"1-3,2-4",
			[]int{1, 2, 3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			// 验证已排序
			if !sort.IntsAreSorted(result) {
				t.Errorf("ParsePort(%q) 结果未排序: %v", tt.input, result)
			}

			t.Logf("✓ ParsePort(%q) 正确去重并排序 → %v", tt.input, result)
		})
	}
}

// TestParsePort_Sorted 测试排序
func TestParsePort_Sorted(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"乱序端口", "8080,22,443,80"},
		{"乱序范围", "1000-1002,80-82"},
		{"混合乱序", "443,100-102,22,80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !sort.IntsAreSorted(result) {
				t.Errorf("ParsePort(%q) 结果未排序: %v", tt.input, result)
			}

			t.Logf("✓ ParsePort(%q) 结果已排序: %v", tt.input, result)
		})
	}
}

// TestParsePort_PortGroups 测试端口组展开
//
// 验证：预定义端口组被正确展开
func TestParsePort_PortGroups(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		shouldContain  []int
		shouldNotBeNil bool
	}{
		{
			"web组",
			"web",
			[]int{80, 443, 8080, 8443},
			true,
		},
		{
			"all组",
			"all",
			[]int{1, 100, 1000, 10000, 65535},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if tt.shouldNotBeNil && result == nil {
				t.Errorf("ParsePort(%q) = nil, want non-nil", tt.input)
				return
			}

			// 验证包含特定端口
			resultMap := make(map[int]bool)
			for _, port := range result {
				resultMap[port] = true
			}

			for _, port := range tt.shouldContain {
				if !resultMap[port] {
					t.Errorf("ParsePort(%q) 应该包含端口 %d，但不包含", tt.input, port)
				}
			}

			t.Logf("✓ ParsePort(%q) 正确展开端口组（%d个端口）", tt.input, len(result))
		})
	}
}

func TestParsePortGroupsRequireWholeToken(t *testing.T) {
	if got := ParsePort("web8080"); len(got) != 0 {
		t.Fatalf("ParsePort(web8080) = %v, want empty invalid token", got)
	}
	if got := ParsePort("web,8080"); len(got) == 0 || got[len(got)-1] != 28018 {
		t.Fatalf("ParsePort(web,8080) = %v, want expanded web group", got)
	}
}

// TestParsePort_WhitespaceHandling 测试空格处理
func TestParsePort_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			"端口前后空格",
			" 80 , 443 ",
			[]int{80, 443},
		},
		{
			"范围中的空格",
			" 1 - 3 ",
			[]int{1, 2, 3},
		},
		{
			"混合空格",
			"  80  ,  100 - 102  ,  443  ",
			[]int{80, 100, 101, 102, 443},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) 正确处理空格", tt.input)
		})
	}
}

// =============================================================================
// ParseIP - IP解析测试
// =============================================================================

// TestParseIP_SingleIP 测试单个IP
func TestParseIP_SingleIP(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected []string
	}{
		{
			"IPv4",
			"192.168.1.1",
			[]string{"192.168.1.1"},
		},
		{
			"域名",
			"example.com",
			[]string{"example.com"},
		},
		{
			"带横杠的域名",
			"111-555.sss.com",
			[]string{"111-555.sss.com"},
		},
		{
			"多段横杠域名",
			"my-test-server.example.com",
			[]string{"my-test-server.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIP(tt.host, "", "")

			if err != nil {
				t.Fatalf("ParseIP(%q) error = %v", tt.host, err)
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIP(%q) = %v, want %v", tt.host, result, tt.expected)
			}

			t.Logf("✓ ParseIP(%q) → %v", tt.host, result)
		})
	}
}

// TestParseIP_MultipleIPs 测试多个IP
func TestParseIP_MultipleIPs(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected []string
	}{
		{
			"两个IP",
			"192.168.1.1,192.168.1.2",
			[]string{"192.168.1.1", "192.168.1.2"},
		},
		{
			"三个IP带空格",
			" 192.168.1.1 , 192.168.1.2 , 192.168.1.3 ",
			[]string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIP(tt.host, "", "")

			if err != nil {
				t.Fatalf("ParseIP(%q) error = %v", tt.host, err)
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIP(%q) = %v, want %v", tt.host, result, tt.expected)
			}

			t.Logf("✓ ParseIP(%q) → %d个IP", tt.host, len(result))
		})
	}
}

// TestParseIP_CIDR 测试CIDR格式
//
// 验证：CIDR被正确展开为IP列表
func TestParseIP_CIDR(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		expectCount int
	}{
		{
			"/30网络",
			"192.168.1.0/30",
			2, // .1, .2 (排除网络地址和广播地址)
		},
		{
			"/29网络",
			"10.0.0.0/29",
			6, // .1-.6
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIP(tt.cidr, "", "")

			if err != nil {
				t.Fatalf("ParseIP(%q) error = %v", tt.cidr, err)
			}

			if len(result) != tt.expectCount {
				t.Errorf("ParseIP(%q) 返回%d个IP，期望%d个",
					tt.cidr, len(result), tt.expectCount)
			}

			// 验证已排序
			if !sort.StringsAreSorted(result) {
				t.Errorf("ParseIP(%q) 结果未排序", tt.cidr)
			}

			t.Logf("✓ ParseIP(%q) → %d个IP", tt.cidr, len(result))
		})
	}
}

// TestParseIP_IPRange 测试IP范围
func TestParseIP_IPRange(t *testing.T) {
	tests := []struct {
		name        string
		rangeStr    string
		expectCount int
	}{
		{
			"小范围",
			"192.168.1.1-3",
			3,
		},
		{
			"单IP范围",
			"192.168.1.1-1",
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIP(tt.rangeStr, "", "")

			if err != nil {
				t.Fatalf("ParseIP(%q) error = %v", tt.rangeStr, err)
			}

			if len(result) != tt.expectCount {
				t.Errorf("ParseIP(%q) 返回%d个IP，期望%d个",
					tt.rangeStr, len(result), tt.expectCount)
			}

			t.Logf("✓ ParseIP(%q) → %d个IP", tt.rangeStr, len(result))
		})
	}
}

func TestParseIP_IPRangeNoLimit(t *testing.T) {
	result, err := parseIPRangeString("192.168.1.1-5")
	if err != nil {
		t.Fatalf("parseIPRangeString error = %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("parseIPRangeString = %v, want %v", result, expected)
	}
}

// TestParseIP_FromFile 测试从文件读取
//
// 验证：文件中的IP列表被正确读取
func TestParseIP_FromFile(t *testing.T) {
	// 创建临时文件
	tmpDir := t.TempDir()
	hostFile := filepath.Join(tmpDir, "hosts.txt")

	content := `# 这是注释
192.168.1.1
192.168.1.2

# 空行会被忽略
192.168.1.3
`

	if err := os.WriteFile(hostFile, []byte(content), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	result, err := ParseIP("", hostFile, "")

	if err != nil {
		t.Fatalf("ParseIP(file=%q) error = %v", hostFile, err)
	}

	expected := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("ParseIP(file) = %v, want %v", result, expected)
	}

	t.Logf("✓ 从文件读取%d个IP（正确过滤注释和空行）", len(result))
}

// TestParseIP_FileNotFound 测试文件不存在
func TestParseIP_FileNotFound(t *testing.T) {
	_, err := ParseIP("", "nonexistent_file_12345.txt", "")

	if err == nil {
		t.Error("ParseIP(不存在的文件) 应该返回错误")
	}

	t.Logf("✓ 文件不存在时正确返回错误: %v", err)
}

// TestParseIP_Exclude 测试排除主机
//
// 验证：排除列表中的主机被正确过滤
func TestParseIP_Exclude(t *testing.T) {
	tests := []struct {
		name     string
		hosts    string
		exclude  string
		expected []string
	}{
		{
			"排除单个",
			"192.168.1.1,192.168.1.2,192.168.1.3",
			"192.168.1.2",
			[]string{"192.168.1.1", "192.168.1.3"},
		},
		{
			"排除多个",
			"192.168.1.1,192.168.1.2,192.168.1.3",
			"192.168.1.1,192.168.1.3",
			[]string{"192.168.1.2"},
		},
		{
			"排除不存在的",
			"192.168.1.1,192.168.1.2",
			"192.168.1.100",
			[]string{"192.168.1.1", "192.168.1.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIP(tt.hosts, "", tt.exclude)

			if err != nil {
				t.Fatalf("ParseIP error = %v", err)
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIP(hosts=%q, exclude=%q) = %v, want %v",
					tt.hosts, tt.exclude, result, tt.expected)
			}

			t.Logf("✓ 正确排除指定主机: %d → %d",
				len(tt.expected)+len(result)-len(tt.expected), len(result))
		})
	}
}

func TestParseIPMultipleExcludeSources(t *testing.T) {
	result, err := ParseIP("192.168.1.1-192.168.1.4", "", "192.168.1.2", "192.168.1.4")
	if err != nil {
		t.Fatalf("ParseIP error = %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.3"}
	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("ParseIP with multiple excludes = %v, want %v", result, expected)
	}
}

// TestParseIP_Deduplicate 测试去重
func TestParseIP_Deduplicate(t *testing.T) {
	result, err := ParseIP("192.168.1.1,192.168.1.1,192.168.1.2,192.168.1.2", "", "")

	if err != nil {
		t.Fatalf("ParseIP error = %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("ParseIP(重复IP) = %v, want %v", result, expected)
	}

	t.Logf("✓ 正确去重: 4个输入 → %d个输出", len(result))
}

// TestParseIP_Sorted 测试排序
func TestParseIP_Sorted(t *testing.T) {
	result, err := ParseIP("192.168.1.3,192.168.1.1,192.168.1.2", "", "")

	if err != nil {
		t.Fatalf("ParseIP error = %v", err)
	}

	if !sort.StringsAreSorted(result) {
		t.Errorf("ParseIP 结果未排序: %v", result)
	}

	t.Logf("✓ 结果已排序: %v", result)
}

// TestParseIP_NoHosts 测试无有效主机
func TestParseIP_NoHosts(t *testing.T) {
	_, err := ParseIP("", "", "")

	if err == nil {
		t.Error("ParseIP(空输入) 应该返回错误")
	}

	if err.Error() != "没有找到有效的主机" {
		t.Errorf("错误信息不匹配: %v", err)
	}

	t.Logf("✓ 无有效主机时正确返回错误")
}

// TestParseIP_MixedSources 测试混合来源
func TestParseIP_MixedSources(t *testing.T) {
	// 创建临时文件
	tmpDir := t.TempDir()
	hostFile := filepath.Join(tmpDir, "hosts.txt")

	if err := os.WriteFile(hostFile, []byte("192.168.1.1\n192.168.1.2\n"), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	// 命令行 + 文件
	result, err := ParseIP("192.168.1.3,192.168.1.4", hostFile, "")

	if err != nil {
		t.Fatalf("ParseIP error = %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("ParseIP(混合来源) = %v, want %v", result, expected)
	}

	t.Logf("✓ 正确合并多个来源: %d个IP", len(result))
}

// =============================================================================
// 辅助函数测试
// =============================================================================

// TestParsePortRange 测试端口范围解析
func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{"正常范围", "1-5", []int{1, 2, 3, 4, 5}},
		{"单端口", "80-80", []int{80}},
		{"反向范围", "5-1", nil},
		{"超出范围", "65535-65540", nil},
		{"格式错误", "1-2-3", nil},
		{"非数字", "a-b", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePortRange(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parsePortRange(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestExcludeHosts 测试排除主机
func TestExcludeHosts(t *testing.T) {
	hosts := []string{"host1", "host2", "host3", "host4"}
	exclude := newHostMatcher()
	exclude.exact["host2"] = struct{}{}
	exclude.exact["host4"] = struct{}{}

	result := excludeFromList(hosts, exclude)
	expected := []string{"host1", "host3"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("excludeFromList = %v, want %v", result, expected)
	}

	t.Logf("✓ excludeFromList: %d → %d", len(hosts), len(result))
}

// TestExcludeHosts_EmptyExclude 测试空排除列表
func TestExcludeHosts_EmptyExclude(t *testing.T) {
	hosts := []string{"host1", "host2"}
	result := excludeFromList(hosts, nil)

	if !reflect.DeepEqual(result, hosts) {
		t.Errorf("excludeFromList(空排除列表) 应该返回原列表")
	}
}

// TestRemoveDuplicates 测试去重
func TestRemoveDuplicates(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	result := removeDuplicateStrings(input)

	// 验证无重复
	seen := make(map[string]bool)
	for _, item := range result {
		if seen[item] {
			t.Errorf("removeDuplicateStrings 结果包含重复项: %s", item)
		}
		seen[item] = true
	}

	// 验证长度
	if len(result) != 4 {
		t.Errorf("removeDuplicateStrings 返回%d项，期望4项", len(result))
	}

	t.Logf("✓ removeDuplicateStrings: %d → %d", len(input), len(result))
}

// TestRemoveDuplicatePorts 测试端口去重
func TestRemoveDuplicatePorts(t *testing.T) {
	input := []int{80, 443, 80, 22, 443, 8080}
	result := removeDuplicatePorts(input)

	// 验证无重复
	seen := make(map[int]bool)
	for _, port := range result {
		if seen[port] {
			t.Errorf("removeDuplicatePorts 结果包含重复项: %d", port)
		}
		seen[port] = true
	}

	// 验证长度
	if len(result) != 4 {
		t.Errorf("removeDuplicatePorts 返回%d项，期望4项", len(result))
	}

	t.Logf("✓ removeDuplicatePorts: %d → %d", len(input), len(result))
}

// =============================================================================
// 边缘情况测试 - IP解析
// =============================================================================

// TestParseIP_InternalNetworkShortcuts 测试内网简写
func TestParseIP_InternalNetworkShortcuts(t *testing.T) {
	tests := []struct {
		name        string
		shortcut    string
		expectMin   int // 最少应该有多少IP
		sampleCheck string
	}{
		{
			"192简写",
			"192",
			100, // 192.168.0.0/16 应该很多
			"192.168.",
		},
		{
			"172简写",
			"172",
			100, // 172.16.0.0/12 应该很多
			"172.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIP(tt.shortcut, "", "")

			if err != nil {
				t.Fatalf("ParseIP(%q) error = %v", tt.shortcut, err)
			}

			if len(result) < tt.expectMin {
				t.Errorf("ParseIP(%q) 返回%d个IP，期望至少%d个",
					tt.shortcut, len(result), tt.expectMin)
			}

			// 检查样本
			hasMatch := false
			for _, ip := range result[:min(10, len(result))] {
				if len(ip) >= len(tt.sampleCheck) && ip[:len(tt.sampleCheck)] == tt.sampleCheck {
					hasMatch = true
					break
				}
			}
			if !hasMatch {
				t.Errorf("ParseIP(%q) 结果不包含预期前缀 %q", tt.shortcut, tt.sampleCheck)
			}

			t.Logf("✓ ParseIP(%q) → %d个IP（内网简写展开正确）", tt.shortcut, len(result))
		})
	}
}

// TestParseIP_FullIPRange 测试完整IP范围格式
func TestParseIP_FullIPRange(t *testing.T) {
	tests := []struct {
		name        string
		rangeStr    string
		expectCount int
		expectFirst string
		expectLast  string
	}{
		{
			"完整范围小",
			"192.168.1.1-192.168.1.5",
			5,
			"192.168.1.1",
			"192.168.1.5",
		},
		{
			"跨子网范围",
			"192.168.1.254-192.168.2.2",
			5, // .254, .255, .0, .1, .2
			"192.168.1.254",
			"192.168.2.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIP(tt.rangeStr, "", "")

			if err != nil {
				t.Fatalf("ParseIP(%q) error = %v", tt.rangeStr, err)
			}

			if len(result) != tt.expectCount {
				t.Errorf("ParseIP(%q) 返回%d个IP，期望%d个",
					tt.rangeStr, len(result), tt.expectCount)
			}

			if len(result) > 0 && result[0] != tt.expectFirst {
				t.Errorf("ParseIP(%q) 第一个IP = %q，期望 %q",
					tt.rangeStr, result[0], tt.expectFirst)
			}

			if len(result) > 0 && result[len(result)-1] != tt.expectLast {
				t.Errorf("ParseIP(%q) 最后一个IP = %q，期望 %q",
					tt.rangeStr, result[len(result)-1], tt.expectLast)
			}

			t.Logf("✓ ParseIP(%q) → %v", tt.rangeStr, result)
		})
	}
}

func TestParseIP_FullIPRangeComplete(t *testing.T) {
	result, err := parseIPRangeString("192.168.1.1-192.168.1.5")
	if err != nil {
		t.Fatalf("parseIPRangeString error = %v", err)
	}

	expected := []string{
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
		"192.168.1.4",
		"192.168.1.5",
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("parseIPRangeString no limit = %v, want %v", result, expected)
	}
}

// TestParseIP_InvalidCIDR 测试无效CIDR
func TestParseIP_InvalidCIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		expectErr bool
	}{
		{"无效掩码/33", "192.168.1.0/33", true},
		{"有效掩码/32", "192.168.1.1/32", false},
		{"格式错误", "192.168.1.0/abc", true},
		{"缺少掩码", "192.168.1.0/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIP(tt.cidr, "", "")

			if tt.expectErr && err == nil {
				t.Errorf("ParseIP(%q) 应该返回错误", tt.cidr)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("ParseIP(%q) 不应该返回错误: %v", tt.cidr, err)
			}

			t.Logf("✓ ParseIP(%q) 错误处理正确", tt.cidr)
		})
	}
}

// TestParseIP_InvalidIPRange 测试无效IP范围
func TestParseIP_InvalidIPRange(t *testing.T) {
	tests := []struct {
		name      string
		rangeStr  string
		expectErr bool
	}{
		{"起始大于结束", "192.168.1.100-50", true},
		{"结束值超255", "192.168.1.1-256", true},
		// 注意: "999.999.999.999-192.168.1.100" 不会报错，
		// 因为 looksLikeIPRange 检测到无效IP后会把它当作普通主机名处理
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIP(tt.rangeStr, "", "")

			if tt.expectErr && err == nil {
				t.Errorf("ParseIP(%q) 应该返回错误", tt.rangeStr)
				return
			}
			if !tt.expectErr && err != nil {
				t.Errorf("ParseIP(%q) 不应返回错误: %v", tt.rangeStr, err)
				return
			}

			t.Logf("✓ ParseIP(%q) 错误处理正确", tt.rangeStr)
		})
	}
}

// =============================================================================
// 边缘情况测试 - 文件读取
// =============================================================================

// TestReadLinesFromFile_WindowsLineEndings 测试Windows行尾
func TestReadLinesFromFile_WindowsLineEndings(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crlf.txt")

	// Windows风格行尾: CRLF
	content := "line1\r\nline2\r\nline3\r\n"
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	result, err := ReadLinesFromFile(testFile)
	if err != nil {
		t.Fatalf("ReadLinesFromFile error = %v", err)
	}

	// 应该有3行，且不包含\r
	if len(result) != 3 {
		t.Errorf("ReadLinesFromFile 返回%d行，期望3行", len(result))
	}

	for i, line := range result {
		if len(line) > 0 && line[len(line)-1] == '\r' {
			t.Errorf("第%d行包含\\r: %q", i+1, line)
		}
	}

	t.Logf("✓ Windows行尾处理正确: %v", result)
}

// TestReadLinesFromFile_OnlyComments 测试只有注释的文件
func TestReadLinesFromFile_OnlyComments(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "comments.txt")

	content := `# comment 1
# comment 2
# comment 3
`
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	result, err := ReadLinesFromFile(testFile)
	if err != nil {
		t.Fatalf("ReadLinesFromFile error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("只有注释的文件应该返回空列表，实际返回: %v", result)
	}

	t.Logf("✓ 只有注释的文件正确返回空列表")
}

// TestReadLinesFromFile_EmptyFile 测试空文件
func TestReadLinesFromFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	if err := os.WriteFile(testFile, []byte(""), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	result, err := ReadLinesFromFile(testFile)
	if err != nil {
		t.Fatalf("ReadLinesFromFile error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("空文件应该返回空列表，实际返回: %v", result)
	}

	t.Logf("✓ 空文件正确返回空列表")
}

// TestReadLinesFromFile_MixedContent 测试混合内容
func TestReadLinesFromFile_MixedContent(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "mixed.txt")

	content := `# Header comment
192.168.1.1
  # indented comment
192.168.1.2

   192.168.1.3
# trailing comment
`
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	result, err := ReadLinesFromFile(testFile)
	if err != nil {
		t.Fatalf("ReadLinesFromFile error = %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("ReadLinesFromFile = %v, want %v", result, expected)
	}

	t.Logf("✓ 混合内容处理正确: %v", result)
}

// =============================================================================
// 边缘情况测试 - 凭据解析
// =============================================================================

// TestParseUserPassFile 测试用户密码文件解析
func TestParseUserPassFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "userpass.txt")

	content := `admin:password123
root:toor
# comment line
user:pass:with:colons
:emptyuser
nopassword
test:
`
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	result, err := ParseUserPassFile(testFile)
	if err != nil {
		t.Fatalf("ParseUserPassFile error = %v", err)
	}

	// 验证解析结果
	tests := []struct {
		username string
		password string
	}{
		{"admin", "password123"},
		{"root", "toor"},
		{"user", "pass:with:colons"}, // 密码可以包含冒号
		{"test", ""},                 // 空密码
	}

	if len(result) != len(tests) {
		t.Errorf("ParseUserPassFile 返回%d对，期望%d对", len(result), len(tests))
	}

	for i, tt := range tests {
		if i >= len(result) {
			break
		}
		if result[i].Username != tt.username || result[i].Password != tt.password {
			t.Errorf("第%d对: got (%q, %q), want (%q, %q)",
				i, result[i].Username, result[i].Password, tt.username, tt.password)
		}
	}

	t.Logf("✓ 用户密码文件解析正确: %d对", len(result))
}

// TestParseHashFile 测试哈希文件解析
func TestParseHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "hashes.txt")

	content := `# MD5 hashes
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6
# invalid hash (too short)
5d41402abc4b2a76
# invalid hash (non-hex)
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
# valid hash
d41d8cd98f00b204e9800998ecf8427e
`
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	hashValues, hashBytes, err := ParseHashFile(testFile)
	if err != nil {
		t.Fatalf("ParseHashFile error = %v", err)
	}

	// 应该只有3个有效hash
	if len(hashValues) != 3 {
		t.Errorf("ParseHashFile 返回%d个hash，期望3个", len(hashValues))
	}

	if len(hashBytes) != 3 {
		t.Errorf("ParseHashFile hashBytes 返回%d个，期望3个", len(hashBytes))
	}

	// 验证hash bytes长度
	for i, hb := range hashBytes {
		if len(hb) != 16 { // MD5 = 16 bytes
			t.Errorf("hashBytes[%d] 长度=%d，期望16", i, len(hb))
		}
	}

	t.Logf("✓ 哈希文件解析正确: %d个有效hash", len(hashValues))
}

// =============================================================================
// 边缘情况测试 - 端口解析
// =============================================================================

// TestParsePort_LargeRange 测试大范围端口
func TestParsePort_LargeRange(t *testing.T) {
	result := ParsePort("1-1000")

	if len(result) != 1000 {
		t.Errorf("ParsePort(1-1000) 返回%d个端口，期望1000个", len(result))
	}

	// 验证第一个和最后一个
	if result[0] != 1 || result[len(result)-1] != 1000 {
		t.Errorf("ParsePort(1-1000) 范围不正确: first=%d, last=%d",
			result[0], result[len(result)-1])
	}

	t.Logf("✓ 大范围端口解析正确: %d个", len(result))
}

// TestParsePort_EmptyElements 测试空元素
func TestParsePort_EmptyElements(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{"连续逗号", "80,,443", []int{80, 443}},
		{"开头逗号", ",80,443", []int{80, 443}},
		{"结尾逗号", "80,443,", []int{80, 443}},
		{"多个空", "80,,,443,,,", []int{80, 443}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParsePort(%q) = %v, want %v", tt.input, result, tt.expected)
			}

			t.Logf("✓ ParsePort(%q) 正确处理空元素", tt.input)
		})
	}
}

// =============================================================================
// 辅助函数
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
