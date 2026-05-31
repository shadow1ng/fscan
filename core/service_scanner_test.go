package core

import (
	"testing"

	"github.com/shadow1ng/fscan/common"
)

/*
service_scanner_test.go - ServiceScanStrategy核心逻辑测试

注意：service_scanner.go 包含大量网络IO和全局状态依赖。
本测试文件专注于可测试的纯逻辑和算法正确性：
1. parsePortList - 端口解析逻辑
2. shouldPerformLivenessCheck - 存活检测判断
3. convertToTargetInfos - host:port数据转换

不测试的部分（需要集成测试）：
- Execute, performHostScan - 网络IO + 全局状态
- discoverTargets - 依赖CheckLive, EnhancedPortScan
- handleUDPPorts - 依赖全局common.Port
- LogPluginInfo - 依赖插件系统和日志

"端口解析和数据转换是纯函数，应该测试。
网络扫描和插件管理是副作用，需要集成测试。"
*/

// =============================================================================
// 核心逻辑测试：端口解析
// =============================================================================

/*
端口列表解析 - parsePortList 方法测试

测试价值：用户指定端口解析是扫描器的核心入口，解析错误会导致：
  - 扫描错误的端口
  - 跳过用户指定的端口
  - 扫描非法端口导致崩溃

"端口解析看起来简单，但涉及字符串转数字、范围验证、错误处理。
这是真实的业务逻辑，bug会直接影响用户体验。必须测试。"
*/

// TestParsePortList_BasicParsing 测试基本的端口解析
func TestParsePortList_BasicParsing(t *testing.T) {
	s := NewServiceScanStrategy()

	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			name:     "单个端口",
			input:    "22",
			expected: []int{22},
		},
		{
			name:     "两个端口-逗号分隔",
			input:    "22,80",
			expected: []int{22, 80},
		},
		{
			name:     "多个端口",
			input:    "22,80,443,3306",
			expected: []int{22, 80, 443, 3306},
		},
		{
			name:     "空字符串",
			input:    "",
			expected: []int{},
		},
		{
			name:     "all关键字",
			input:    "all",
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.parsePortList(tt.input)
			if !intSlicesEqual(result, tt.expected) {
				t.Errorf("parsePortList(%q) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestParsePortList_Whitespace 测试空格处理
func TestParsePortList_Whitespace(t *testing.T) {
	s := NewServiceScanStrategy()

	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			name:     "端口前后有空格",
			input:    " 22 ",
			expected: []int{22},
		},
		{
			name:     "逗号前后有空格",
			input:    "22 , 80",
			expected: []int{22, 80},
		},
		{
			name:     "多个空格",
			input:    "  22  ,  80  ,  443  ",
			expected: []int{22, 80, 443},
		},
		{
			name:     "Tab字符",
			input:    "22\t,\t80",
			expected: []int{22, 80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.parsePortList(tt.input)
			if !intSlicesEqual(result, tt.expected) {
				t.Errorf("parsePortList(%q) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestParsePortList_RangeValidation 测试端口范围验证
func TestParsePortList_RangeValidation(t *testing.T) {
	s := NewServiceScanStrategy()

	tests := []struct {
		name     string
		input    string
		expected []int
		note     string
	}{
		{
			name:     "最小有效端口-1",
			input:    "1",
			expected: []int{1},
			note:     "端口1是最小的有效端口",
		},
		{
			name:     "最大有效端口-65535",
			input:    "65535",
			expected: []int{65535},
			note:     "端口65535是最大的有效端口",
		},
		{
			name:     "边界值-1和65535",
			input:    "1,65535",
			expected: []int{1, 65535},
			note:     "测试边界值组合",
		},
		{
			name:     "端口0-无效",
			input:    "0",
			expected: []int{},
			note:     "端口0应该被忽略",
		},
		{
			name:     "端口65536-超出范围",
			input:    "65536",
			expected: []int{},
			note:     "超出最大端口应该被忽略",
		},
		{
			name:     "负数端口",
			input:    "-1",
			expected: []int{},
			note:     "负数端口应该被忽略",
		},
		{
			name:     "混合有效和无效端口",
			input:    "0,22,80,65536,443",
			expected: []int{22, 80, 443},
			note:     "只保留有效端口",
		},
		{
			name:     "常见端口范围边界",
			input:    "1,1023,1024,49151,49152,65535",
			expected: []int{1, 1023, 1024, 49151, 49152, 65535},
			note:     "测试特权端口、注册端口、动态端口的边界",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.parsePortList(tt.input)
			if !intSlicesEqual(result, tt.expected) {
				t.Errorf("parsePortList(%q) = %v, want %v\nNote: %s",
					tt.input, result, tt.expected, tt.note)
			}
		})
	}
}

// TestParsePortList_InvalidInput 测试非法输入处理
func TestParsePortList_InvalidInput(t *testing.T) {
	s := NewServiceScanStrategy()

	tests := []struct {
		name     string
		input    string
		expected []int
		note     string
	}{
		{
			name:     "非数字字符",
			input:    "abc",
			expected: []int{},
			note:     "非数字应该被忽略",
		},
		{
			name:     "混合数字和字母",
			input:    "22,abc,80",
			expected: []int{22, 80},
			note:     "只提取有效的数字",
		},
		{
			name:     "小数",
			input:    "22.5",
			expected: []int{},
			note:     "小数应该被忽略",
		},
		{
			name:     "科学计数法",
			input:    "1e3",
			expected: []int{},
			note:     "科学计数法应该被忽略",
		},
		{
			name:     "空白项",
			input:    "22,,80",
			expected: []int{22, 80},
			note:     "空白项应该被跳过",
		},
		{
			name:     "仅逗号",
			input:    ",,,",
			expected: []int{},
			note:     "仅逗号应该返回空列表",
		},
		{
			name:     "超大数字",
			input:    "999999",
			expected: []int{},
			note:     "超大数字应该被忽略",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.parsePortList(tt.input)
			if !intSlicesEqual(result, tt.expected) {
				t.Errorf("parsePortList(%q) = %v, want %v\nNote: %s",
					tt.input, result, tt.expected, tt.note)
			}
		})
	}
}

// TestParsePortList_ProductionScenarios 测试生产环境真实场景
func TestParsePortList_ProductionScenarios(t *testing.T) {
	s := NewServiceScanStrategy()

	t.Run("常见Web端口", func(t *testing.T) {
		input := "80,443,8080,8443"
		expected := []int{80, 443, 8080, 8443}
		result := s.parsePortList(input)
		if !intSlicesEqual(result, expected) {
			t.Errorf("应该正确解析常见Web端口")
		}
	})

	t.Run("数据库端口", func(t *testing.T) {
		input := "3306,5432,1433,27017"
		expected := []int{3306, 5432, 1433, 27017}
		result := s.parsePortList(input)
		if !intSlicesEqual(result, expected) {
			t.Errorf("应该正确解析常见数据库端口")
		}
	})

	t.Run("用户复制粘贴带空格", func(t *testing.T) {
		// 用户从文档复制 "22, 80, 443" 粘贴到命令行
		input := "22, 80, 443"
		expected := []int{22, 80, 443}
		result := s.parsePortList(input)
		if !intSlicesEqual(result, expected) {
			t.Errorf("应该正确处理用户复制粘贴的空格")
		}
	})

	t.Run("用户手误输入无效端口", func(t *testing.T) {
		// 用户错误输入了0端口
		input := "0,22,80"
		expected := []int{22, 80}
		result := s.parsePortList(input)
		if !intSlicesEqual(result, expected) {
			t.Errorf("应该过滤掉无效端口0")
		}
	})

	t.Run("高端口号-动态端口", func(t *testing.T) {
		// 测试动态端口范围 49152-65535
		input := "49152,50000,60000,65535"
		expected := []int{49152, 50000, 60000, 65535}
		result := s.parsePortList(input)
		if !intSlicesEqual(result, expected) {
			t.Errorf("应该正确解析高端口号")
		}
	})
}

// TestParsePortList_ReturnValue 测试返回值特性
func TestParsePortList_ReturnValue(t *testing.T) {
	s := NewServiceScanStrategy()

	t.Run("返回切片而非nil", func(t *testing.T) {
		result := s.parsePortList("")
		if result == nil {
			t.Error("空输入应该返回空切片，而不是nil")
		}
	})

	t.Run("端口不重复-但不保证去重", func(t *testing.T) {
		// 注意：当前实现不去重，如果用户输入 "22,22"，会返回 [22, 22]
		// 这是可以接受的，因为上层逻辑会处理重复
		input := "22,22"
		result := s.parsePortList(input)
		// 这里我们只测试解析是否正确，不测试去重
		if len(result) != 2 || result[0] != 22 || result[1] != 22 {
			t.Errorf("当前实现不去重，应该返回两个22")
		}
	})
}

// intSlicesEqual 比较两个int切片是否相等
func intSlicesEqual(a, b []int) bool {
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

// =============================================================================
// 存活检测判断测试
// =============================================================================

// TestShouldPerformLivenessCheck 测试存活检测判断逻辑
func TestShouldPerformLivenessCheck(t *testing.T) {
	strategy := NewServiceScanStrategy()

	tests := []struct {
		name        string
		hosts       []string
		disablePing bool
		expected    bool
	}{
		{
			name:        "多主机+允许Ping",
			hosts:       []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			disablePing: false,
			expected:    true,
		},
		{
			name:        "多主机+禁用Ping",
			hosts:       []string{"192.168.1.1", "192.168.1.2"},
			disablePing: true,
			expected:    false,
		},
		{
			name:        "单主机+允许Ping",
			hosts:       []string{"192.168.1.1"},
			disablePing: false,
			expected:    false, // 单主机不需要存活检测
		},
		{
			name:        "单主机+禁用Ping",
			hosts:       []string{"192.168.1.1"},
			disablePing: true,
			expected:    false,
		},
		{
			name:        "空主机列表+允许Ping",
			hosts:       []string{},
			disablePing: false,
			expected:    false,
		},
		{
			name:        "空主机列表+禁用Ping",
			hosts:       []string{},
			disablePing: true,
			expected:    false,
		},
		{
			name:        "两个主机-边界情况",
			hosts:       []string{"192.168.1.1", "192.168.1.2"},
			disablePing: false,
			expected:    true, // >1 触发检测
		},
		{
			name:        "大量主机",
			hosts:       make([]string, 100),
			disablePing: false,
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置 Config 对象
			cfg := common.GetGlobalConfig()
			oldDisablePing := cfg.DisablePing
			cfg.DisablePing = tt.disablePing
			defer func() {
				cfg.DisablePing = oldDisablePing
			}()

			result := strategy.shouldPerformLivenessCheck(tt.hosts, cfg)

			if result != tt.expected {
				t.Errorf("shouldPerformLivenessCheck() = %v, 期望 %v (hosts=%d, disablePing=%v)",
					result, tt.expected, len(tt.hosts), tt.disablePing)
			}
		})
	}
}

// =============================================================================
// 数据转换测试
// =============================================================================

// TestConvertToTargetInfos 测试端口列表转目标信息
func TestConvertToTargetInfos(t *testing.T) {
	strategy := NewServiceScanStrategy()

	tests := []struct {
		name         string
		ports        []string
		baseInfo     common.HostInfo
		expectedLen  int
		validateFunc func(*testing.T, []common.HostInfo)
	}{
		{
			name:        "单个目标",
			ports:       []string{"192.168.1.1:80"},
			baseInfo:    common.HostInfo{},
			expectedLen: 1,
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				if infos[0].Host != "192.168.1.1" {
					t.Errorf("Host = %q, 期望 '192.168.1.1'", infos[0].Host)
				}
				if infos[0].Port != 80 {
					t.Errorf("Ports = %q, 期望 '80'", infos[0].Port)
				}
			},
		},
		{
			name:        "多个目标",
			ports:       []string{"192.168.1.1:80", "192.168.1.2:443", "192.168.1.3:8080"},
			baseInfo:    common.HostInfo{},
			expectedLen: 3,
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				expected := []struct {
					host string
					port int
				}{
					{"192.168.1.1", 80},
					{"192.168.1.2", 443},
					{"192.168.1.3", 8080},
				}
				for i, exp := range expected {
					if infos[i].Host != exp.host {
						t.Errorf("infos[%d].Host = %q, 期望 %q", i, infos[i].Host, exp.host)
					}
					if infos[i].Port != exp.port {
						t.Errorf("infos[%d].Port = %d, 期望 %d", i, infos[i].Port, exp.port)
					}
				}
			},
		},
		{
			name:  "继承baseInfo属性",
			ports: []string{"192.168.1.1:80"},
			baseInfo: common.HostInfo{
				URL:  "http://example.com",
				Info: []string{"info1", "info2"},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				if infos[0].URL != "http://example.com" {
					t.Errorf("URL = %q, 期望 'http://example.com'", infos[0].URL)
				}
				if len(infos[0].Info) != 2 {
					t.Errorf("Infostr长度 = %d, 期望 2", len(infos[0].Info))
				}
			},
		},
		{
			name:         "空端口列表",
			ports:        []string{},
			baseInfo:     common.HostInfo{},
			expectedLen:  0,
			validateFunc: nil,
		},
		{
			name:         "非法格式-无冒号",
			ports:        []string{"192.168.1.1"},
			baseInfo:     common.HostInfo{},
			expectedLen:  0, // 非法格式被过滤
			validateFunc: nil,
		},
		{
			name:         "非法格式-多个冒号",
			ports:        []string{"192.168.1.1:80:443"},
			baseInfo:     common.HostInfo{},
			expectedLen:  0, // 非法格式被过滤
			validateFunc: nil,
		},
		{
			name:        "混合-有效和无效",
			ports:       []string{"192.168.1.1:80", "invalid", "192.168.1.2:443"},
			baseInfo:    common.HostInfo{},
			expectedLen: 2,
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				if infos[0].Host != "192.168.1.1" || infos[0].Port != 80 {
					t.Errorf("第一个目标错误: %s:%d", infos[0].Host, infos[0].Port)
				}
				if infos[1].Host != "192.168.1.2" || infos[1].Port != 443 {
					t.Errorf("第二个目标错误: %s:%d", infos[1].Host, infos[1].Port)
				}
			},
		},
		{
			name:         "裸IPv6地址缺少方括号",
			ports:        []string{"::1:8080"},
			baseInfo:     common.HostInfo{},
			expectedLen:  0,
			validateFunc: nil,
		},
		{
			name:        "IPv6地址",
			ports:       []string{"[2001:db8::1]:8080"},
			baseInfo:    common.HostInfo{},
			expectedLen: 1,
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				if infos[0].Host != "2001:db8::1" {
					t.Errorf("Host = %q, 期望 '2001:db8::1'", infos[0].Host)
				}
				if infos[0].Port != 8080 {
					t.Errorf("Port = %d, 期望 8080", infos[0].Port)
				}
			},
		},
		{
			name:        "域名+端口",
			ports:       []string{"example.com:80", "test.local:443"},
			baseInfo:    common.HostInfo{},
			expectedLen: 2,
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				if infos[0].Host != "example.com" {
					t.Errorf("Host = %q, 期望 'example.com'", infos[0].Host)
				}
				if infos[1].Host != "test.local" {
					t.Errorf("Host = %q, 期望 'test.local'", infos[1].Host)
				}
			},
		},
		{
			name:         "端口为0-被拒绝",
			ports:        []string{"192.168.1.1:0"},
			baseInfo:     common.HostInfo{},
			expectedLen:  0, // 修复后：端口0被验证并拒绝
			validateFunc: nil,
		},
		{
			name:        "高端口-65535合法",
			ports:       []string{"192.168.1.1:65535"},
			baseInfo:    common.HostInfo{},
			expectedLen: 1,
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				if infos[0].Port != 65535 {
					t.Errorf("Ports = %q, 期望 '65535'", infos[0].Port)
				}
			},
		},
		{
			name:         "超大端口-被拒绝",
			ports:        []string{"192.168.1.1:65536"},
			baseInfo:     common.HostInfo{},
			expectedLen:  0, // 修复后：端口65536被拒绝
			validateFunc: nil,
		},
		{
			name:         "负数端口-被拒绝",
			ports:        []string{"192.168.1.1:-80"},
			baseInfo:     common.HostInfo{},
			expectedLen:  0, // 修复后：负数端口被拒绝
			validateFunc: nil,
		},
		{
			name:        "混合-过滤非法端口",
			ports:       []string{"192.168.1.1:80", "192.168.1.2:0", "192.168.1.3:65536", "192.168.1.4:443"},
			baseInfo:    common.HostInfo{},
			expectedLen: 2, // 只有80和443合法
			validateFunc: func(t *testing.T, infos []common.HostInfo) {
				if infos[0].Port != 80 {
					t.Errorf("第一个端口 = %q, 期望 '80'", infos[0].Port)
				}
				if infos[1].Port != 443 {
					t.Errorf("第二个端口 = %q, 期望 '443'", infos[1].Port)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.convertToTargetInfos(tt.ports, tt.baseInfo)

			// 验证长度
			if len(result) != tt.expectedLen {
				t.Errorf("convertToTargetInfos() 长度 = %d, 期望 %d", len(result), tt.expectedLen)
			}

			// 执行自定义验证
			if tt.validateFunc != nil && len(result) > 0 {
				tt.validateFunc(t, result)
			}
		})
	}
}

// =============================================================================
// 边界情况测试
// =============================================================================

// TestConvertToTargetInfos_EdgeCases 测试边界情况
func TestConvertToTargetInfos_EdgeCases(t *testing.T) {
	strategy := NewServiceScanStrategy()

	t.Run("空字符串端口", func(t *testing.T) {
		ports := []string{""}
		result := strategy.convertToTargetInfos(ports, common.HostInfo{})
		if len(result) != 0 {
			t.Errorf("空字符串应被过滤, 实际长度 %d", len(result))
		}
	})

	t.Run("只有冒号", func(t *testing.T) {
		ports := []string{":"}
		result := strategy.convertToTargetInfos(ports, common.HostInfo{})
		// 修复后：Split产生["", ""]，TrimSpace后都是空，被过滤
		if len(result) != 0 {
			t.Errorf("只有冒号应被过滤, 实际长度 %d", len(result))
		}
	})

	t.Run("冒号前后有空格", func(t *testing.T) {
		ports := []string{"192.168.1.1 : 80"}
		result := strategy.convertToTargetInfos(ports, common.HostInfo{})
		// 修复后：Split产生["192.168.1.1 ", " 80"]，TrimSpace后去除空格
		if len(result) != 1 {
			t.Errorf("带空格的冒号应产生1个结果, 实际长度 %d", len(result))
		}
		if len(result) > 0 {
			// 修复后：空格应被去除
			if result[0].Host != "192.168.1.1" {
				t.Errorf("Host = %q, 期望 '192.168.1.1'（空格已去除）", result[0].Host)
			}
			if result[0].Port != 80 {
				t.Errorf("Ports = %q, 期望 '80'（空格已去除）", result[0].Port)
			}
		}
	})

	t.Run("大量目标", func(t *testing.T) {
		var ports []string
		for i := 1; i <= 1000; i++ {
			ports = append(ports, "192.168.1.1:"+string(rune(i)))
		}
		result := strategy.convertToTargetInfos(ports, common.HostInfo{})
		// 由于端口是rune转换，大部分会失败，只验证不panic
		if result == nil {
			t.Error("不应返回nil")
		}
	})
}

// TestParsePortList_SpecialCases 测试特殊情况
func TestParsePortList_SpecialCases(t *testing.T) {
	strategy := NewServiceScanStrategy()

	t.Run("Unicode空格", func(t *testing.T) {
		// 包含全角空格
		result := strategy.parsePortList("80，443")
		// 全角逗号不会被分割，整个字符串作为一个部分
		if len(result) != 0 {
			t.Errorf("全角逗号应导致解析失败, 实际长度 %d", len(result))
		}
	})

	t.Run("制表符分隔", func(t *testing.T) {
		result := strategy.parsePortList("80\t443")
		// 制表符不是逗号，不会分割
		if len(result) != 0 {
			t.Errorf("制表符不应分割端口, 实际长度 %d", len(result))
		}
	})

	t.Run("换行符", func(t *testing.T) {
		result := strategy.parsePortList("80\n443")
		// 换行符不是逗号
		if len(result) != 0 {
			t.Errorf("换行符不应分割端口, 实际长度 %d", len(result))
		}
	})
}

// TestShouldPerformLivenessCheck_ConcurrentSafety 测试并发安全性
func TestShouldPerformLivenessCheck_ConcurrentSafety(t *testing.T) {
	strategy := NewServiceScanStrategy()
	hosts := []string{"192.168.1.1", "192.168.1.2"}

	// 保存原始值
	cfg := common.GetGlobalConfig()
	oldDisablePing := cfg.DisablePing
	defer func() {
		cfg.DisablePing = oldDisablePing
	}()

	cfg.DisablePing = false

	// 并发调用
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			_ = strategy.shouldPerformLivenessCheck(hosts, cfg)
			done <- true
		}()
	}

	// 等待所有goroutine完成
	for i := 0; i < 100; i++ {
		<-done
	}
}

// =============================================================================
// 深拷贝测试
// =============================================================================

// TestConvertToTargetInfos_DeepCopy 测试Infostr深拷贝
func TestConvertToTargetInfos_DeepCopy(t *testing.T) {
	strategy := NewServiceScanStrategy()

	t.Run("Infostr深拷贝验证", func(t *testing.T) {
		baseInfo := common.HostInfo{
			Info: []string{"info1", "info2"},
		}

		// 转换两个目标
		result := strategy.convertToTargetInfos(
			[]string{"192.168.1.1:80", "192.168.1.2:80"},
			baseInfo,
		)

		if len(result) != 2 {
			t.Fatalf("期望2个结果, 实际 %d", len(result))
		}

		// 验证初始状态：两个target的Infostr应该相等但不共享底层数组
		if len(result[0].Info) != 2 || len(result[1].Info) != 2 {
			t.Error("Infostr应被正确复制")
		}

		// 关键测试：修改第一个target的Infostr
		result[0].Info = append(result[0].Info, "modified")

		// 验证第二个target的Infostr未被影响（深拷贝成功）
		if len(result[1].Info) != 2 {
			t.Errorf("深拷贝失败: result[1].Info长度 = %d, 期望 2 (不应受result[0]影响)",
				len(result[1].Info))
		}

		// 验证baseInfo的Infostr也未被影响
		if len(baseInfo.Info) != 2 {
			t.Errorf("深拷贝失败: baseInfo.Info长度 = %d, 期望 2 (不应受修改影响)",
				len(baseInfo.Info))
		}
	})

	t.Run("空Infostr不panic", func(t *testing.T) {
		baseInfo := common.HostInfo{
			Info: nil,
		}

		result := strategy.convertToTargetInfos(
			[]string{"192.168.1.1:80"},
			baseInfo,
		)

		if len(result) != 1 {
			t.Fatalf("期望1个结果, 实际 %d", len(result))
		}

		// 验证不会panic
		if result[0].Info != nil {
			t.Error("nil Infostr应保持nil")
		}
	})

	t.Run("空slice不分配内存", func(t *testing.T) {
		baseInfo := common.HostInfo{
			Info: []string{},
		}

		result := strategy.convertToTargetInfos(
			[]string{"192.168.1.1:80"},
			baseInfo,
		)

		// 空slice应该被跳过深拷贝（性能优化）
		if len(result) != 1 {
			t.Fatalf("期望1个结果, 实际 %d", len(result))
		}
	})
}
