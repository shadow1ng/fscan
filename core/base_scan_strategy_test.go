package core

import (
	"testing"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
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

func TestBaseScanStrategyPluginSelectionAndApplicability(t *testing.T) {
	registerTestPlugins(t)
	plugins.RegisterWithOptions("core_test_local", func() plugins.Plugin { return nil }, nil, []string{plugins.PluginTypeLocal}, false)
	plugins.RegisterWithOptions("core_test_udp", func() plugins.Plugin { return nil }, []int{161}, []string{plugins.PluginTypeUDP}, true)
	clearServiceCache()

	cfg := common.NewConfig()
	cfg.Mode = "ssh, missing_plugin, webtitle"
	strategy := NewBaseScanStrategy("service", FilterService)
	got, custom := strategy.GetPlugins(cfg)
	if !custom {
		t.Fatal("explicit mode should be marked as custom")
	}
	if !slicesEqual(got, []string{"ssh", "webtitle"}) {
		t.Fatalf("custom plugins = %#v, want ssh/webtitle", got)
	}

	cfg.Mode = "all"
	servicePlugins, custom := strategy.GetPlugins(cfg)
	if custom {
		t.Fatal("all mode should not be custom")
	}
	if !containsString(servicePlugins, "ssh") || containsString(servicePlugins, "core_test_local") || containsString(servicePlugins, "core_test_udp") {
		t.Fatalf("service filtered plugins = %#v", servicePlugins)
	}

	if !strategy.pluginExists("ssh") || strategy.pluginExists("missing_plugin") {
		t.Fatal("pluginExists returned wrong result")
	}
	if !strategy.isPluginApplicableToPort("ssh", 22) || strategy.isPluginApplicableToPort("ssh", 23) {
		t.Fatal("port applicability for ssh is wrong")
	}
	CacheServiceInfo("10.0.0.9", 22222, &ServiceInfo{Name: "ssh"})
	if !strategy.isPluginApplicableToPortWithHost("ssh", "10.0.0.9", 22222) {
		t.Fatal("service cache should allow ssh on a non-standard port")
	}
	if !strategy.IsPluginApplicableByName("ssh", "10.0.0.9", 1, true, cfg) {
		t.Fatal("custom mode should respect explicitly selected plugin")
	}
	if strategy.IsPluginApplicableByName("missing_plugin", "10.0.0.9", 22, true, cfg) {
		t.Fatal("missing plugin should never be applicable")
	}
}

func TestBaseScanStrategyFilterTypes(t *testing.T) {
	plugins.RegisterWithOptions("core_test_local_filter", func() plugins.Plugin { return nil }, nil, []string{plugins.PluginTypeLocal}, false)
	plugins.RegisterWithOptions("core_test_web_filter", func() plugins.Plugin { return nil }, nil, []string{plugins.PluginTypeWeb}, true)
	plugins.RegisterWithOptions("core_test_udp_filter", func() plugins.Plugin { return nil }, []int{53}, []string{plugins.PluginTypeUDP}, true)

	cfg := common.NewConfig()
	localStrategy := NewBaseScanStrategy("local", FilterLocal)
	if localStrategy.isPluginPassesFilterType("core_test_local_filter", false, cfg) {
		t.Fatal("local plugin should require explicit -local selection")
	}
	cfg.LocalPlugin = "core_test_local_filter"
	if !localStrategy.isPluginPassesFilterType("core_test_local_filter", false, cfg) {
		t.Fatal("explicit local plugin should pass local filter")
	}

	serviceStrategy := NewBaseScanStrategy("service", FilterService)
	if !serviceStrategy.isPluginPassesFilterType("ssh", false, cfg) {
		t.Fatal("service plugin should pass service filter")
	}
	if serviceStrategy.isPluginPassesFilterType("core_test_local_filter", false, cfg) ||
		serviceStrategy.isPluginPassesFilterType("core_test_udp_filter", false, cfg) {
		t.Fatal("service filter should reject local and UDP plugins")
	}

	webStrategy := NewBaseScanStrategy("web", FilterWeb)
	if !webStrategy.isPluginPassesFilterType("core_test_web_filter", false, cfg) ||
		webStrategy.isPluginPassesFilterType("ssh", false, cfg) {
		t.Fatal("web filter should only allow web plugins")
	}
	if webPluginOrder("webtitle") != 0 || webPluginOrder("webpoc") != 2 || webPluginOrder("other") != 1 {
		t.Fatal("web plugin order changed")
	}
}

func TestFormatPluginList(t *testing.T) {
	if got := formatPluginList([]string{"a", "b", "c"}); got != "a, b, c" {
		t.Fatalf("short plugin list = %q", got)
	}
	if got := formatPluginList([]string{"a", "b", "c", "d", "e", "f"}); got == "" || got == "a, b, c, d, e, f" {
		t.Fatalf("long plugin list should be summarized, got %q", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

// =============================================================================
// IsPluginApplicableByName 补充覆盖
// =============================================================================

// TestIsPluginApplicableByName_FullModeWebPlugin 测试 -full 模式下 web 插件对任意端口生效
func TestIsPluginApplicableByName_FullModeWebPlugin(t *testing.T) {
	registerTestPlugins(t)
	clearServiceCache()

	cfg := common.NewConfig()
	cfg.POC.Full = true

	strategy := NewBaseScanStrategy("service", FilterService)

	// webtitle 是 web 插件；-full 模式下不检查 IsMarkedWebService，直接走 passesFilterType
	// FilterService 不允许 local/udp，但允许 web 插件
	got := strategy.IsPluginApplicableByName("webtitle", "10.0.0.1", 12345, false, cfg)
	if !got {
		t.Error("full 模式下 web 插件应对任意端口返回 true")
	}
}

// TestIsPluginApplicableByName_FullModeNonWebPlugin 确认 -full 不影响非 web 插件的端口匹配
func TestIsPluginApplicableByName_FullModeNonWebPlugin(t *testing.T) {
	registerTestPlugins(t)
	clearServiceCache()

	cfg := common.NewConfig()
	cfg.POC.Full = true

	strategy := NewBaseScanStrategy("service", FilterService)

	// ssh 不是 web 插件，-full 无特殊逻辑，走普通端口匹配
	// ssh 默认端口 22；用 99999 端口应该不匹配
	got := strategy.IsPluginApplicableByName("ssh", "10.0.0.1", 99999, false, cfg)
	if got {
		t.Error("-full 模式对非 web 插件不应绕过端口匹配")
	}
}

// =============================================================================
// isPluginApplicableToPort 补充覆盖
// =============================================================================

// TestIsPluginApplicableToPort_WebPlugin web 插件忽略端口直接返回 true
func TestIsPluginApplicableToPort_WebPlugin(t *testing.T) {
	registerTestPlugins(t)
	strategy := NewBaseScanStrategy("service", FilterService)

	// webtitle 是 web 插件，任何端口都应返回 true
	if !strategy.isPluginApplicableToPort("webtitle", 8080) {
		t.Error("web 插件在任意端口应返回 true")
	}
	if !strategy.isPluginApplicableToPort("webtitle", 0) {
		t.Error("web 插件在端口 0 也应返回 true")
	}
}

// TestIsPluginApplicableToPort_NonWebPlugin 非 web 插件走端口匹配逻辑
func TestIsPluginApplicableToPort_NonWebPlugin(t *testing.T) {
	registerTestPlugins(t)
	clearServiceCache()
	strategy := NewBaseScanStrategy("service", FilterService)

	// ssh 端口 22 匹配
	if !strategy.isPluginApplicableToPort("ssh", 22) {
		t.Error("ssh 应匹配端口 22")
	}
	// ssh 端口 9999 不匹配（无服务缓存）
	if strategy.isPluginApplicableToPort("ssh", 9999) {
		t.Error("ssh 不应匹配端口 9999")
	}
}

// =============================================================================
// isPluginPassesFilterType 补充覆盖
// =============================================================================

// TestIsPluginPassesFilterType_CustomMode isCustomMode=true 应直接跳过过滤返回 true（非 UDP）
func TestIsPluginPassesFilterType_CustomMode(t *testing.T) {
	registerTestPlugins(t)
	cfg := common.NewConfig()

	// FilterLocal 策略下 custom mode 也应通过
	localStrategy := NewBaseScanStrategy("local", FilterLocal)
	if !localStrategy.isPluginPassesFilterType("ssh", true, cfg) {
		t.Error("custom mode 下非 UDP 插件应直接返回 true")
	}

	// FilterService 策略下 custom mode 也应通过
	serviceStrategy := NewBaseScanStrategy("service", FilterService)
	if !serviceStrategy.isPluginPassesFilterType("ssh", true, cfg) {
		t.Error("custom mode 下 service 策略应直接返回 true")
	}
}

// TestIsPluginPassesFilterType_FilterNoneNonLocal FilterNone + 普通 TCP 插件 → true
func TestIsPluginPassesFilterType_FilterNoneNonLocal(t *testing.T) {
	registerTestPlugins(t)
	cfg := common.NewConfig()

	noneStrategy := NewBaseScanStrategy("none", FilterNone)

	// ssh 不是 local 插件，FilterNone 应直接返回 true
	if !noneStrategy.isPluginPassesFilterType("ssh", false, cfg) {
		t.Error("FilterNone + 非 local 插件应返回 true")
	}
	if !noneStrategy.isPluginPassesFilterType("redis", false, cfg) {
		t.Error("FilterNone + 非 local 插件 redis 应返回 true")
	}
}

// TestIsPluginPassesFilterType_FilterNoneLocalPlugin FilterNone + local 插件：需要 -local 显式指定
func TestIsPluginPassesFilterType_FilterNoneLocalPlugin(t *testing.T) {
	plugins.RegisterWithOptions("core_test_local_none", func() plugins.Plugin { return nil }, nil, []string{plugins.PluginTypeLocal}, false)
	cfg := common.NewConfig()

	noneStrategy := NewBaseScanStrategy("none", FilterNone)

	// 未指定 LocalPlugin，应返回 false
	if noneStrategy.isPluginPassesFilterType("core_test_local_none", false, cfg) {
		t.Error("FilterNone + local 插件未显式指定时应返回 false")
	}

	// 指定后应返回 true
	cfg.LocalPlugin = "core_test_local_none"
	if !noneStrategy.isPluginPassesFilterType("core_test_local_none", false, cfg) {
		t.Error("FilterNone + local 插件显式指定后应返回 true")
	}
}
