package core

import (
	"fmt"
	"testing"
)

/*
port_scan_test.go - EnhancedPortScan 核心逻辑测试

注意：EnhancedPortScan 是一个228行的"上帝函数"，耦合了：
- 网络IO (TCP连接)
- 并发控制 (errgroup, semaphore)
- 全局状态 (common.*全局变量)
- 进度条管理
- 服务识别
- 结果保存

这种设计无法进行真正的单元测试。本测试文件：
1. 验证核心算法逻辑的正确性（通过独立函数模拟）
2. 测试关键计算逻辑（任务数计算、排除端口）
3. 不测试网络IO和并发控制（需要集成测试）

"这函数需要重构，不是测试。200行代码做了太多事情。
但既然现在无法重构，我们至少验证算法逻辑是对的。"
*/

// =============================================================================
// 核心算法逻辑测试（从EnhancedPortScan提取）
// =============================================================================

// calculateTotalTasks 计算总扫描任务数（从EnhancedPortScan:34-42行提取）
// 这是纯函数，可以独立测试
func calculateTotalTasks(hosts []string, portList []int, exclude map[int]struct{}) int {
	totalTasks := 0
	for range hosts {
		for _, port := range portList {
			if _, excluded := exclude[port]; !excluded {
				totalTasks++
			}
		}
	}
	return totalTasks
}

// TestCalculateTotalTasks 测试总任务数计算逻辑
func TestCalculateTotalTasks(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		portList []int
		exclude  map[int]struct{}
		expected int
	}{
		{
			name:     "单主机单端口-无排除",
			hosts:    []string{"192.168.1.1"},
			portList: []int{80},
			exclude:  map[int]struct{}{},
			expected: 1,
		},
		{
			name:     "单主机多端口-无排除",
			hosts:    []string{"192.168.1.1"},
			portList: []int{80, 443, 8080},
			exclude:  map[int]struct{}{},
			expected: 3,
		},
		{
			name:     "多主机单端口-无排除",
			hosts:    []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			portList: []int{80},
			exclude:  map[int]struct{}{},
			expected: 3,
		},
		{
			name:     "多主机多端口-无排除",
			hosts:    []string{"192.168.1.1", "192.168.1.2"},
			portList: []int{80, 443, 8080},
			exclude:  map[int]struct{}{},
			expected: 6, // 2 hosts * 3 ports
		},
		{
			name:     "单主机多端口-排除一个",
			hosts:    []string{"192.168.1.1"},
			portList: []int{80, 443, 8080},
			exclude:  map[int]struct{}{443: {}},
			expected: 2, // 80, 8080
		},
		{
			name:     "多主机多端口-排除多个",
			hosts:    []string{"192.168.1.1", "192.168.1.2"},
			portList: []int{80, 443, 8080, 3306},
			exclude:  map[int]struct{}{443: {}, 3306: {}},
			expected: 4, // 2 hosts * 2 ports (80, 8080)
		},
		{
			name:     "空主机列表",
			hosts:    []string{},
			portList: []int{80, 443},
			exclude:  map[int]struct{}{},
			expected: 0,
		},
		{
			name:     "空端口列表",
			hosts:    []string{"192.168.1.1"},
			portList: []int{},
			exclude:  map[int]struct{}{},
			expected: 0,
		},
		{
			name:     "所有端口都被排除",
			hosts:    []string{"192.168.1.1"},
			portList: []int{80, 443},
			exclude:  map[int]struct{}{80: {}, 443: {}},
			expected: 0,
		},
		{
			name:     "大规模扫描",
			hosts:    []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"},
			portList: []int{21, 22, 23, 80, 443, 3306, 3389, 8080, 8443, 9090},
			exclude:  map[int]struct{}{},
			expected: 50, // 5 hosts * 10 ports
		},
		{
			name:     "大规模扫描-部分排除",
			hosts:    []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			portList: []int{80, 443, 8080, 8443, 3000, 3001, 3002, 3003, 3004, 3005},
			exclude:  map[int]struct{}{8080: {}, 8443: {}},
			expected: 24, // 3 hosts * 8 ports
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateTotalTasks(tt.hosts, tt.portList, tt.exclude)
			if result != tt.expected {
				t.Errorf("calculateTotalTasks() = %d, 期望 %d", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// 地址格式化逻辑测试（从EnhancedPortScan:67行提取）
// =============================================================================

// formatAddress 格式化主机:端口地址（从EnhancedPortScan提取）
func formatAddress(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// TestFormatAddress 测试地址格式化
func TestFormatAddress(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		expected string
	}{
		{
			name:     "标准IPv4地址",
			host:     "192.168.1.1",
			port:     80,
			expected: "192.168.1.1:80",
		},
		{
			name:     "域名",
			host:     "example.com",
			port:     443,
			expected: "example.com:443",
		},
		{
			name:     "localhost",
			host:     "localhost",
			port:     8080,
			expected: "localhost:8080",
		},
		{
			name:     "高端口号",
			host:     "10.0.0.1",
			port:     65535,
			expected: "10.0.0.1:65535",
		},
		{
			name:     "低端口号",
			host:     "10.0.0.1",
			port:     1,
			expected: "10.0.0.1:1",
		},
		{
			name:     "常见HTTP端口",
			host:     "192.168.1.100",
			port:     80,
			expected: "192.168.1.100:80",
		},
		{
			name:     "常见HTTPS端口",
			host:     "192.168.1.100",
			port:     443,
			expected: "192.168.1.100:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAddress(tt.host, tt.port)
			if result != tt.expected {
				t.Errorf("formatAddress() = %q, 期望 %q", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// 排除端口逻辑测试（从EnhancedPortScan:28-32行提取）
// =============================================================================

// buildExcludeMap 构建排除端口映射（从EnhancedPortScan提取）
func buildExcludeMap(excludePorts []int) map[int]struct{} {
	exclude := make(map[int]struct{}, len(excludePorts))
	for _, p := range excludePorts {
		exclude[p] = struct{}{}
	}
	return exclude
}

// TestBuildExcludeMap 测试排除端口映射构建
func TestBuildExcludeMap(t *testing.T) {
	tests := []struct {
		name          string
		excludePorts  []int
		testPort      int
		shouldExclude bool
	}{
		{
			name:          "空排除列表",
			excludePorts:  []int{},
			testPort:      80,
			shouldExclude: false,
		},
		{
			name:          "单个排除端口-匹配",
			excludePorts:  []int{443},
			testPort:      443,
			shouldExclude: true,
		},
		{
			name:          "单个排除端口-不匹配",
			excludePorts:  []int{443},
			testPort:      80,
			shouldExclude: false,
		},
		{
			name:          "多个排除端口-匹配第一个",
			excludePorts:  []int{80, 443, 8080},
			testPort:      80,
			shouldExclude: true,
		},
		{
			name:          "多个排除端口-匹配中间",
			excludePorts:  []int{80, 443, 8080},
			testPort:      443,
			shouldExclude: true,
		},
		{
			name:          "多个排除端口-匹配最后",
			excludePorts:  []int{80, 443, 8080},
			testPort:      8080,
			shouldExclude: true,
		},
		{
			name:          "多个排除端口-不匹配",
			excludePorts:  []int{80, 443, 8080},
			testPort:      3306,
			shouldExclude: false,
		},
		{
			name:          "大量排除端口",
			excludePorts:  []int{21, 22, 23, 25, 53, 110, 143, 445, 3389},
			testPort:      3389,
			shouldExclude: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			excludeMap := buildExcludeMap(tt.excludePorts)

			// 验证映射大小
			if len(excludeMap) != len(tt.excludePorts) {
				t.Errorf("excludeMap长度 = %d, 期望 %d", len(excludeMap), len(tt.excludePorts))
			}

			// 验证端口是否被正确排除
			_, excluded := excludeMap[tt.testPort]
			if excluded != tt.shouldExclude {
				t.Errorf("端口 %d 排除状态 = %v, 期望 %v", tt.testPort, excluded, tt.shouldExclude)
			}
		})
	}
}

// TestBuildExcludeMap_DuplicatePorts 测试重复端口处理
func TestBuildExcludeMap_DuplicatePorts(t *testing.T) {
	excludePorts := []int{80, 443, 80, 443, 80}
	excludeMap := buildExcludeMap(excludePorts)

	// 重复端口应该被去重（map自动去重）
	if len(excludeMap) != 2 {
		t.Errorf("excludeMap应自动去重, 期望长度2, 实际 %d", len(excludeMap))
	}

	// 验证两个端口都存在
	if _, ok := excludeMap[80]; !ok {
		t.Error("端口80应在排除列表中")
	}
	if _, ok := excludeMap[443]; !ok {
		t.Error("端口443应在排除列表中")
	}
}

// =============================================================================
// 集成逻辑测试（任务数计算 + 排除端口）
// =============================================================================

// TestIntegratedTaskCalculation 测试任务计算与排除端口的集成
func TestIntegratedTaskCalculation(t *testing.T) {
	tests := []struct {
		name         string
		hosts        []string
		portList     []int
		excludePorts []int
		expected     int
	}{
		{
			name:         "无排除-小规模",
			hosts:        []string{"192.168.1.1", "192.168.1.2"},
			portList:     []int{80, 443, 8080},
			excludePorts: []int{},
			expected:     6, // 2*3
		},
		{
			name:         "有排除-小规模",
			hosts:        []string{"192.168.1.1", "192.168.1.2"},
			portList:     []int{80, 443, 8080},
			excludePorts: []int{443},
			expected:     4, // 2*2
		},
		{
			name:         "大规模C段扫描",
			hosts:        make([]string, 254), // 模拟254个主机
			portList:     []int{80, 443, 22, 3389, 3306},
			excludePorts: []int{22}, // 排除SSH
			expected:     1016,      // 254 * 4
		},
		{
			name:         "端口全排除",
			hosts:        []string{"192.168.1.1"},
			portList:     []int{80, 443},
			excludePorts: []int{80, 443},
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 填充大规模测试的hosts
			if len(tt.hosts) == 254 && tt.hosts[0] == "" {
				for i := range tt.hosts {
					tt.hosts[i] = fmt.Sprintf("192.168.1.%d", i+1)
				}
			}

			excludeMap := buildExcludeMap(tt.excludePorts)
			result := calculateTotalTasks(tt.hosts, tt.portList, excludeMap)

			if result != tt.expected {
				t.Errorf("集成测试失败: calculateTotalTasks() = %d, 期望 %d", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// 边界情况和错误处理测试
// =============================================================================

// TestCalculateTotalTasks_EdgeCases 测试边界情况
func TestCalculateTotalTasks_EdgeCases(t *testing.T) {
	t.Run("nil主机列表", func(t *testing.T) {
		result := calculateTotalTasks(nil, []int{80}, map[int]struct{}{})
		if result != 0 {
			t.Errorf("nil主机列表应返回0, 实际 %d", result)
		}
	})

	t.Run("nil端口列表", func(t *testing.T) {
		result := calculateTotalTasks([]string{"192.168.1.1"}, nil, map[int]struct{}{})
		if result != 0 {
			t.Errorf("nil端口列表应返回0, 实际 %d", result)
		}
	})

	t.Run("nil排除映射", func(t *testing.T) {
		result := calculateTotalTasks([]string{"192.168.1.1"}, []int{80}, nil)
		if result != 1 {
			t.Errorf("nil排除映射应视为无排除, 期望1, 实际 %d", result)
		}
	})

	t.Run("极大端口号", func(t *testing.T) {
		excludeMap := buildExcludeMap([]int{65535})
		if _, ok := excludeMap[65535]; !ok {
			t.Error("应支持最大端口号65535")
		}
	})

	t.Run("端口号0", func(t *testing.T) {
		excludeMap := buildExcludeMap([]int{0})
		if _, ok := excludeMap[0]; !ok {
			t.Error("应支持端口号0")
		}
	})
}

// =============================================================================
// 性能基准测试
// =============================================================================

// BenchmarkCalculateTotalTasks 基准测试任务计算性能
func BenchmarkCalculateTotalTasks(b *testing.B) {
	// 模拟C段扫描: 254个主机 * 10个端口
	hosts := make([]string, 254)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("192.168.1.%d", i+1)
	}
	portList := []int{21, 22, 80, 443, 3306, 3389, 8080, 8443, 9090, 9200}
	exclude := map[int]struct{}{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateTotalTasks(hosts, portList, exclude)
	}
}

// BenchmarkBuildExcludeMap 基准测试排除映射构建性能
func BenchmarkBuildExcludeMap(b *testing.B) {
	excludePorts := []int{21, 22, 23, 25, 53, 110, 143, 445, 3389, 1433}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildExcludeMap(excludePorts)
	}
}

// =============================================================================
// 重构后函数的单元测试
// =============================================================================

// TestBuildServiceLogMessage 测试服务日志消息构建
// 新格式: "addr service version/banner"
func TestBuildServiceLogMessage(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		serviceInfo *ServiceInfo
		isWeb       bool
		wantContain []string // 期望包含的字符串片段
	}{
		{
			name: "基础HTTP服务",
			addr: "192.168.1.1:80",
			serviceInfo: &ServiceInfo{
				Name:    "http",
				Version: "1.1",
				Banner:  "",
				Extras:  map[string]string{},
			},
			isWeb:       true,
			wantContain: []string{"192.168.1.1:80", "http", "1.1"},
		},
		{
			name: "带Banner的SSH服务",
			addr: "10.0.0.1:22",
			serviceInfo: &ServiceInfo{
				Name:    "ssh",
				Version: "OpenSSH_8.0",
				Banner:  "SSH-2.0-OpenSSH_8.0",
				Extras:  map[string]string{},
			},
			isWeb:       false,
			wantContain: []string{"10.0.0.1:22", "ssh", "SSH-2.0-OpenSSH_8.0"}, // Banner优先于Version
		},
		{
			name: "带扩展信息的服务",
			addr: "172.16.0.1:3306",
			serviceInfo: &ServiceInfo{
				Name:    "mysql",
				Version: "5.7.30",
				Banner:  "",
				Extras: map[string]string{
					"vendor_product": "MySQL Community Server",
					"os":             "Linux",
					"info":           "utf8_general_ci",
				},
			},
			isWeb:       false,
			wantContain: []string{"172.16.0.1:3306", "mysql", "5.7.30"}, // 简化格式不包含Extras
		},
		{
			name: "未知服务",
			addr: "192.168.1.1:8888",
			serviceInfo: &ServiceInfo{
				Name:    "unknown",
				Version: "",
				Banner:  "",
				Extras:  map[string]string{},
			},
			isWeb:       false,
			wantContain: []string{"192.168.1.1:8888"}, // unknown服务不显示名称
		},
		{
			name: "过长Banner使用Version",
			addr: "10.0.0.1:21",
			serviceInfo: &ServiceInfo{
				Name:    "ftp",
				Version: "2.0",
				Banner:  string(make([]byte, 200)), // 超过100字符的banner
				Extras:  map[string]string{},
			},
			isWeb:       false,
			wantContain: []string{"10.0.0.1:21", "ftp", "2.0"}, // Banner超长则用Version
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildServiceLogMessage(tt.addr, tt.serviceInfo, tt.isWeb)

			// 验证所有期望的字符串片段都存在
			for _, want := range tt.wantContain {
				if !contains(result, want) {
					t.Errorf("buildServiceLogMessage() 结果缺少期望内容\n期望包含: %q\n实际结果: %q", want, result)
				}
			}
		})
	}
}

// contains 检查字符串是否包含子串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

// indexOf 查找子串位置
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// =============================================================================
// 资源耗尽错误检测测试
// =============================================================================

/*
资源耗尽错误检测 - isResourceExhaustedError 函数测试

测试价值：资源耗尽检测是生产环境的关键逻辑，错误分类影响重试策略

"这是真正的业务逻辑。错误分类错了，扫描就会失败或死循环。
这种函数必须测试，而且要测真实的错误场景。"
*/

// TestIsResourceExhaustedError_ActualErrors 测试真实的资源耗尽错误
func TestIsResourceExhaustedError_ActualErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "文件描述符耗尽-Linux",
			err:      fmt.Errorf("socket: too many open files"),
			expected: true,
		},
		{
			name:     "文件描述符耗尽-直接错误",
			err:      fmt.Errorf("too many open files"),
			expected: true,
		},
		{
			name:     "缓冲区耗尽",
			err:      fmt.Errorf("write: no buffer space available"),
			expected: true,
		},
		{
			name:     "本地端口耗尽",
			err:      fmt.Errorf("dial tcp: cannot assign requested address"),
			expected: true,
		},
		{
			name:     "连接重置-高并发",
			err:      fmt.Errorf("read tcp 192.168.1.1:1234->10.0.0.1:80: connection reset by peer"),
			expected: true,
		},
		{
			name:     "自定义发包限制",
			err:      fmt.Errorf("发包受限"),
			expected: true,
		},
		{
			name:     "nil错误",
			err:      nil,
			expected: false,
		},
		{
			name:     "普通网络错误-超时",
			err:      fmt.Errorf("dial tcp: i/o timeout"),
			expected: false,
		},
		{
			name:     "普通网络错误-拒绝连接",
			err:      fmt.Errorf("connection refused"),
			expected: false,
		},
		{
			name:     "认证错误",
			err:      fmt.Errorf("authentication failed"),
			expected: false,
		},
		{
			name:     "空字符串错误",
			err:      fmt.Errorf(""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isResourceExhaustedError(tt.err)
			if result != tt.expected {
				t.Errorf("isResourceExhaustedError() = %v, want %v (error: %v)",
					result, tt.expected, tt.err)
			}
		})
	}
}

// TestIsResourceExhaustedError_EdgeCases 测试边界情况
func TestIsResourceExhaustedError_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "大小写混合",
			err:      fmt.Errorf("Too Many Open Files"),
			expected: true, // containsFold 不区分大小写
		},
		{
			name:     "错误信息包含但不完全匹配",
			err:      fmt.Errorf("some error with no buffer space available suffix"),
			expected: true, // strings.Contains会匹配完整短语
		},
		{
			name:     "多个错误特征-只需匹配一个",
			err:      fmt.Errorf("too many open files and no buffer space available"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isResourceExhaustedError(tt.err)
			if result != tt.expected {
				t.Errorf("isResourceExhaustedError() = %v, want %v (error: %v)",
					result, tt.expected, tt.err)
			}
		})
	}
}

// TestIsResourceExhaustedError_ProductionScenarios 测试生产环境真实场景
func TestIsResourceExhaustedError_ProductionScenarios(t *testing.T) {
	// 场景1：ulimit设置太低
	t.Run("ulimit限制触发", func(t *testing.T) {
		err := fmt.Errorf("dial tcp 10.0.0.1:22: socket: too many open files")
		if !isResourceExhaustedError(err) {
			t.Error("应该识别出ulimit限制错误")
		}
	})

	// 场景2：Windows端口耗尽
	t.Run("Windows端口耗尽", func(t *testing.T) {
		err := fmt.Errorf("dial tcp :0: bind: cannot assign requested address")
		if !isResourceExhaustedError(err) {
			t.Error("应该识别出端口耗尽错误")
		}
	})

	// 场景3：并发扫描导致的连接重置
	t.Run("高并发连接重置", func(t *testing.T) {
		err := fmt.Errorf("read tcp: connection reset by peer")
		if !isResourceExhaustedError(err) {
			t.Error("应该识别出高并发导致的连接重置")
		}
	})

	// 场景4：正常的认证失败不应被识别为资源耗尽
	t.Run("认证失败-不是资源问题", func(t *testing.T) {
		err := fmt.Errorf("ssh: handshake failed: ssh: unable to authenticate")
		if isResourceExhaustedError(err) {
			t.Error("认证失败不应被识别为资源耗尽")
		}
	})
}
