package core

import (
	"testing"
)

// =============================================================================
// 插件列表解析测试
// =============================================================================

/*
插件列表解析 - parsePluginList 函数测试

测试价值：用户输入解析是扫描器的入口，解析错误会导致用户指定的插件无法执行

"字符串解析看起来简单，但边界情况会咬你一口。空格、空字符串、
逗号分隔符——这些是真实的bug来源。必须测试。"
*/

// TestParsePluginList_BasicCases 测试基本的插件列表解析
func TestParsePluginList_BasicCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "单个插件",
			input:    "ssh",
			expected: []string{"ssh"},
		},
		{
			name:     "两个插件-逗号分隔",
			input:    "ssh,redis",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "多个插件-逗号分隔",
			input:    "ssh,redis,mysql,mssql",
			expected: []string{"ssh", "redis", "mysql", "mssql"},
		},
		{
			name:     "空字符串",
			input:    "",
			expected: []string{},
		},
		{
			name:     "单个逗号",
			input:    ",",
			expected: []string{},
		},
		{
			name:     "多个逗号",
			input:    ",,,",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePluginList(tt.input)
			if !slicesEqual(result, tt.expected) {
				t.Errorf("parsePluginList(%q) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestParsePluginList_Whitespace 测试空格处理
func TestParsePluginList_Whitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "插件名前后有空格",
			input:    " ssh ",
			expected: []string{"ssh"},
		},
		{
			name:     "逗号前后有空格",
			input:    "ssh , redis",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "多个空格",
			input:    "  ssh  ,  redis  ",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "Tab字符",
			input:    "ssh\t,\tredis",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "混合空白字符",
			input:    " \tssh\t , \tredis \t",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "只有空格",
			input:    "   ",
			expected: []string{},
		},
		{
			name:     "空格和逗号混合",
			input:    " , , , ",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePluginList(tt.input)
			if !slicesEqual(result, tt.expected) {
				t.Errorf("parsePluginList(%q) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestParsePluginList_EdgeCases 测试边界情况
func TestParsePluginList_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "连续逗号",
			input:    "ssh,,redis",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "开头有逗号",
			input:    ",ssh,redis",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "结尾有逗号",
			input:    "ssh,redis,",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "开头结尾都有逗号",
			input:    ",ssh,redis,",
			expected: []string{"ssh", "redis"},
		},
		{
			name:     "空元素混合",
			input:    "ssh, ,redis, , ,mysql",
			expected: []string{"ssh", "redis", "mysql"},
		},
		{
			name:     "单字符插件名",
			input:    "a,b,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "长插件名",
			input:    "verylongpluginname1,verylongpluginname2",
			expected: []string{"verylongpluginname1", "verylongpluginname2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePluginList(tt.input)
			if !slicesEqual(result, tt.expected) {
				t.Errorf("parsePluginList(%q) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestParsePluginList_ProductionScenarios 测试生产环境真实场景
func TestParsePluginList_ProductionScenarios(t *testing.T) {
	t.Run("用户复制粘贴带空格", func(t *testing.T) {
		// 用户从文档复制 "ssh, redis, mysql" 粘贴到命令行
		input := "ssh, redis, mysql"
		expected := []string{"ssh", "redis", "mysql"}
		result := parsePluginList(input)
		if !slicesEqual(result, expected) {
			t.Errorf("应该正确处理用户复制粘贴的空格")
		}
	})

	t.Run("用户手误多打逗号", func(t *testing.T) {
		// 用户打错了："ssh,,redis"
		input := "ssh,,redis"
		expected := []string{"ssh", "redis"}
		result := parsePluginList(input)
		if !slicesEqual(result, expected) {
			t.Errorf("应该容错处理连续逗号")
		}
	})

	t.Run("常见的all模式", func(t *testing.T) {
		// 虽然 "all" 在上层处理，但解析器也要能处理
		input := "all"
		expected := []string{"all"}
		result := parsePluginList(input)
		if !slicesEqual(result, expected) {
			t.Errorf("应该正确解析 'all' 关键字")
		}
	})

	t.Run("混合大小写插件名", func(t *testing.T) {
		// Go插件名通常小写，但用户可能输入大写
		input := "SSH,Redis,MySQL"
		expected := []string{"SSH", "Redis", "MySQL"}
		result := parsePluginList(input)
		// 注意：当前实现不做大小写转换，保留原始输入
		if !slicesEqual(result, expected) {
			t.Errorf("应该保留原始大小写（交给上层验证）")
		}
	})
}

// TestParsePluginList_ReturnValue 测试返回值特性
func TestParsePluginList_ReturnValue(t *testing.T) {
	t.Run("返回空切片而非nil", func(t *testing.T) {
		result := parsePluginList("")
		if result == nil {
			t.Error("空输入应该返回空切片，而不是nil")
		}
		if len(result) != 0 {
			t.Errorf("空输入应该返回长度为0的切片，got length %d", len(result))
		}
	})

	t.Run("返回新切片-不共享内存", func(t *testing.T) {
		input := "ssh,redis"
		result1 := parsePluginList(input)
		result2 := parsePluginList(input)

		// 修改result1不应该影响result2
		if len(result1) > 0 {
			result1[0] = "modified"
			if result2[0] == "modified" {
				t.Error("每次调用应该返回新的切片，不共享内存")
			}
		}
	})
}

// slicesEqual 比较两个字符串切片是否相等
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOrderWebPlugins(t *testing.T) {
	plugins := []string{"ssh", "webpoc", "redis", "webtitle", "mysql"}

	orderWebPlugins(plugins)

	expected := []string{"webtitle", "ssh", "redis", "mysql", "webpoc"}
	if !slicesEqual(plugins, expected) {
		t.Fatalf("orderWebPlugins = %#v, want %#v", plugins, expected)
	}
}

// TestNewBaseScanStrategy 测试构造函数
func TestNewBaseScanStrategy(t *testing.T) {
	tests := []struct {
		name         string
		strategyName string
		filterType   PluginFilterType
	}{
		{
			name:         "FilterNone",
			strategyName: "无过滤",
			filterType:   FilterNone,
		},
		{
			name:         "FilterLocal",
			strategyName: "本地扫描",
			filterType:   FilterLocal,
		},
		{
			name:         "FilterService",
			strategyName: "服务扫描",
			filterType:   FilterService,
		},
		{
			name:         "FilterWeb",
			strategyName: "Web扫描",
			filterType:   FilterWeb,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := NewBaseScanStrategy(tt.strategyName, tt.filterType)

			if strategy == nil {
				t.Fatal("NewBaseScanStrategy 返回 nil")
			}

			if strategy.strategyName != tt.strategyName {
				t.Errorf("strategyName: 期望 %q, 实际 %q", tt.strategyName, strategy.strategyName)
			}

			if strategy.filterType != tt.filterType {
				t.Errorf("filterType: 期望 %d, 实际 %d", tt.filterType, strategy.filterType)
			}
		})
	}
}

// TestPluginFilterTypeConstants 测试过滤器类型常量
func TestPluginFilterTypeConstants(t *testing.T) {
	// 验证常量值的唯一性和连续性
	filterTypes := []PluginFilterType{
		FilterNone,
		FilterLocal,
		FilterService,
		FilterWeb,
	}

	// 检查值是否唯一
	seen := make(map[PluginFilterType]bool)
	for _, ft := range filterTypes {
		if seen[ft] {
			t.Errorf("PluginFilterType 值重复: %d", ft)
		}
		seen[ft] = true
	}

	// 验证预期值
	expectedValues := map[PluginFilterType]int{
		FilterNone:    0,
		FilterLocal:   1,
		FilterService: 2,
		FilterWeb:     3,
	}

	for ft, expectedVal := range expectedValues {
		if int(ft) != expectedVal {
			t.Errorf("PluginFilterType %d: 期望值 %d, 实际值 %d", ft, expectedVal, int(ft))
		}
	}
}

// TestBaseScanStrategy_ValidateConfiguration 测试配置验证
func TestBaseScanStrategy_ValidateConfiguration(t *testing.T) {
	strategy := NewBaseScanStrategy("测试", FilterNone)

	err := strategy.ValidateConfiguration()
	if err != nil {
		t.Errorf("ValidateConfiguration 应返回 nil, 实际: %v", err)
	}
}
