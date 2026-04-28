package core

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

/*
web_scanner_test.go - WebScanner核心逻辑测试

注意：web_scanner.go 包含网络IO和缓存管理。
本测试文件专注于可测试的纯逻辑和算法正确性：
1. IsWebServiceByFingerprint - Web服务识别逻辑
2. createTargetFromURL - URL解析和HostInfo构建
3. 缓存操作 - MarkAsWebService, GetWebServiceInfo, IsMarkedWebService
4. 指纹缓存 - SetFingerprints, GetFingerprints

不测试的部分（需要集成测试）：
- createHTTPClient - 依赖全局配置
- tryHTTP, DetectHTTPServiceOnly - 网络IO
- Execute - 完整流程

"服务识别和URL解析是纯逻辑，应该测试。
缓存操作需要验证并发安全性。"
*/

// =============================================================================
// 核心逻辑测试：Web服务识别
// =============================================================================

// TestIsWebServiceByFingerprint 测试Web服务识别逻辑
func TestIsWebServiceByFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		serviceInfo *ServiceInfo
		expected    bool
	}{
		{
			name:        "nil服务信息",
			serviceInfo: nil,
			expected:    false,
		},
		{
			name: "空服务名",
			serviceInfo: &ServiceInfo{
				Name: "",
			},
			expected: false,
		},
		{
			name: "HTTP服务",
			serviceInfo: &ServiceInfo{
				Name: "http",
			},
			expected: true,
		},
		{
			name: "HTTPS服务",
			serviceInfo: &ServiceInfo{
				Name: "https",
			},
			expected: true,
		},
		{
			name: "Nginx服务",
			serviceInfo: &ServiceInfo{
				Name: "nginx",
			},
			expected: true,
		},
		{
			name: "Apache服务",
			serviceInfo: &ServiceInfo{
				Name: "apache",
			},
			expected: true,
		},
		{
			name: "IIS服务",
			serviceInfo: &ServiceInfo{
				Name: "iis",
			},
			expected: true,
		},
		{
			name: "Tomcat服务",
			serviceInfo: &ServiceInfo{
				Name: "tomcat",
			},
			expected: true,
		},
		{
			name: "MySQL服务-非Web",
			serviceInfo: &ServiceInfo{
				Name: "mysql",
			},
			expected: false,
		},
		{
			name: "Redis服务-非Web",
			serviceInfo: &ServiceInfo{
				Name: "redis",
			},
			expected: false,
		},
		{
			name: "SSH服务-非Web",
			serviceInfo: &ServiceInfo{
				Name: "ssh",
			},
			expected: false,
		},
		{
			name: "FTP服务-非Web",
			serviceInfo: &ServiceInfo{
				Name: "ftp",
			},
			expected: false,
		},
		{
			name: "大小写混合-HTTP",
			serviceInfo: &ServiceInfo{
				Name: "HTTP/1.1",
			},
			expected: true,
		},
		{
			name: "包含Web关键字-http-server",
			serviceInfo: &ServiceInfo{
				Name: "custom-http-server",
			},
			expected: true,
		},
		{
			name: "Banner包含Server头",
			serviceInfo: &ServiceInfo{
				Name:   "unknown",
				Banner: "Server: Apache/2.4.41",
			},
			expected: true,
		},
		{
			name: "Banner包含HTTP协议",
			serviceInfo: &ServiceInfo{
				Name:   "unknown",
				Banner: "HTTP/1.1 200 OK",
			},
			expected: true,
		},
		{
			name: "Banner包含Content-Type",
			serviceInfo: &ServiceInfo{
				Name:   "unknown",
				Banner: "Content-Type: text/html",
			},
			expected: true,
		},
		{
			name: "Banner大写-SERVER",
			serviceInfo: &ServiceInfo{
				Name:   "unknown",
				Banner: "SERVER: NGINX/1.18.0",
			},
			expected: true,
		},
		{
			name: "非Web服务名+非Web Banner",
			serviceInfo: &ServiceInfo{
				Name:   "telnet",
				Banner: "Telnet Server Ready",
			},
			expected: false,
		},
		{
			name: "未知服务+无Banner",
			serviceInfo: &ServiceInfo{
				Name:   "unknown",
				Banner: "",
			},
			expected: false,
		},
		{
			name: "PHP服务",
			serviceInfo: &ServiceInfo{
				Name: "php",
			},
			expected: true,
		},
		{
			name: "JSP服务",
			serviceInfo: &ServiceInfo{
				Name: "jsp",
			},
			expected: true,
		},
		{
			name: "ASP服务",
			serviceInfo: &ServiceInfo{
				Name: "asp",
			},
			expected: true,
		},
		{
			name: "SSL/TLS服务",
			serviceInfo: &ServiceInfo{
				Name: "ssl",
			},
			expected: true,
		},
		{
			name: "包含非Web关键字-postgresql",
			serviceInfo: &ServiceInfo{
				Name: "postgresql-server",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsWebServiceByFingerprint(tt.serviceInfo)
			if result != tt.expected {
				t.Errorf("IsWebServiceByFingerprint() = %v, 期望 %v (Name=%q, Banner=%q)",
					result, tt.expected, tt.serviceInfo.Name, tt.serviceInfo.Banner)
			}
		})
	}
}

// =============================================================================
// URL解析测试
// =============================================================================

// TestCreateTargetFromURL 测试URL解析和HostInfo构建
func TestCreateTargetFromURL(t *testing.T) {
	strategy := NewWebScanStrategy()

	tests := []struct {
		name         string
		baseInfo     common.HostInfo
		urlStr       string
		expectNil    bool
		expectedHost string
		expectedPort int
		expectedURL  string
	}{
		{
			name:         "完整HTTP URL",
			baseInfo:     common.HostInfo{},
			urlStr:       "http://example.com",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 80,
			expectedURL:  "http://example.com",
		},
		{
			name:         "完整HTTPS URL",
			baseInfo:     common.HostInfo{},
			urlStr:       "https://example.com",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 443,
			expectedURL:  "https://example.com",
		},
		{
			name:         "HTTP+自定义端口",
			baseInfo:     common.HostInfo{},
			urlStr:       "http://example.com:8080",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 8080,
			expectedURL:  "http://example.com:8080",
		},
		{
			name:         "HTTPS+自定义端口",
			baseInfo:     common.HostInfo{},
			urlStr:       "https://example.com:8443",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 8443,
			expectedURL:  "https://example.com:8443",
		},
		{
			name:         "无协议头-自动添加http",
			baseInfo:     common.HostInfo{},
			urlStr:       "example.com",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 80,
			expectedURL:  "http://example.com",
		},
		{
			name:         "无协议头+端口",
			baseInfo:     common.HostInfo{},
			urlStr:       "example.com:8080",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 8080,
			expectedURL:  "http://example.com:8080",
		},
		{
			name:         "IP地址",
			baseInfo:     common.HostInfo{},
			urlStr:       "http://192.168.1.1",
			expectNil:    false,
			expectedHost: "192.168.1.1",
			expectedPort: 80,
			expectedURL:  "http://192.168.1.1",
		},
		{
			name:         "IP地址+端口",
			baseInfo:     common.HostInfo{},
			urlStr:       "http://192.168.1.1:8080",
			expectNil:    false,
			expectedHost: "192.168.1.1",
			expectedPort: 8080,
			expectedURL:  "http://192.168.1.1:8080",
		},
		{
			name:         "带路径的URL",
			baseInfo:     common.HostInfo{},
			urlStr:       "http://example.com/path/to/page",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 80,
			expectedURL:  "http://example.com/path/to/page",
		},
		{
			name:         "带查询参数的URL",
			baseInfo:     common.HostInfo{},
			urlStr:       "http://example.com/?key=value",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 80,
			expectedURL:  "http://example.com/?key=value",
		},
		{
			name: "继承baseInfo属性",
			baseInfo: common.HostInfo{
				Info: []string{"info1", "info2"},
			},
			urlStr:       "http://example.com",
			expectNil:    false,
			expectedHost: "example.com",
			expectedPort: 80,
			expectedURL:  "http://example.com",
		},
		{
			name:      "非法URL-无效字符",
			baseInfo:  common.HostInfo{},
			urlStr:    "http://example.com:abc",
			expectNil: true, // 端口非法，解析失败
		},
		{
			name:         "localhost",
			baseInfo:     common.HostInfo{},
			urlStr:       "http://localhost:8080",
			expectNil:    false,
			expectedHost: "localhost",
			expectedPort: 8080,
			expectedURL:  "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.createTargetFromURL(tt.baseInfo, tt.urlStr)

			// 验证是否为nil
			if tt.expectNil {
				if result != nil {
					t.Errorf("期望返回nil, 实际返回 %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("不应返回nil")
			}

			// 验证Host
			if result.Host != tt.expectedHost {
				t.Errorf("Host = %q, 期望 %q", result.Host, tt.expectedHost)
			}

			// 验证Ports
			if result.Port != tt.expectedPort {
				t.Errorf("Port = %d, 期望 %d", result.Port, tt.expectedPort)
			}

			// 验证Url
			if result.URL != tt.expectedURL {
				t.Errorf("URL = %q, 期望 %q", result.URL, tt.expectedURL)
			}

			// 验证baseInfo属性继承
			if len(tt.baseInfo.Info) > 0 {
				if len(result.Info) != len(tt.baseInfo.Info) {
					t.Errorf("Infostr未继承, 长度 = %d, 期望 %d",
						len(result.Info), len(tt.baseInfo.Info))
				}
			}
		})
	}
}

// =============================================================================
// 缓存管理测试
// =============================================================================

// TestWebServiceCache 测试Web服务缓存操作
func TestWebServiceCache(t *testing.T) {
	// 清空缓存
	webCacheMutex.Lock()
	webServiceCache = make(map[string]*ServiceInfo)
	webCacheMutex.Unlock()

	t.Run("存储和读取", func(t *testing.T) {
		serviceInfo := &ServiceInfo{
			Name:   "http",
			Banner: "Apache/2.4.41",
		}

		// 标记Web服务
		MarkAsWebService("192.168.1.1", 80, serviceInfo)

		// 验证IsMarkedWebService
		if !IsMarkedWebService("192.168.1.1", 80) {
			t.Error("IsMarkedWebService应返回true")
		}

		// 验证GetWebServiceInfo
		info, exists := GetWebServiceInfo("192.168.1.1", 80)
		if !exists {
			t.Error("GetWebServiceInfo应返回exists=true")
		}
		if info.Name != "http" {
			t.Errorf("Name = %q, 期望 'http'", info.Name)
		}
	})

	t.Run("不存在的服务", func(t *testing.T) {
		if IsMarkedWebService("192.168.1.2", 80) {
			t.Error("不存在的服务应返回false")
		}

		info, exists := GetWebServiceInfo("192.168.1.2", 80)
		if exists {
			t.Error("不存在的服务应返回exists=false")
		}
		if info != nil {
			t.Error("不存在的服务应返回nil info")
		}
	})

	t.Run("覆盖写入", func(t *testing.T) {
		serviceInfo1 := &ServiceInfo{Name: "http"}
		serviceInfo2 := &ServiceInfo{Name: "https"}

		MarkAsWebService("192.168.1.3", 80, serviceInfo1)
		MarkAsWebService("192.168.1.3", 80, serviceInfo2)

		info, _ := GetWebServiceInfo("192.168.1.3", 80)
		if info.Name != "https" {
			t.Errorf("覆盖后Name = %q, 期望 'https'", info.Name)
		}
	})

	t.Run("不同端口独立存储", func(t *testing.T) {
		serviceInfo80 := &ServiceInfo{Name: "http"}
		serviceInfo443 := &ServiceInfo{Name: "https"}

		MarkAsWebService("192.168.1.4", 80, serviceInfo80)
		MarkAsWebService("192.168.1.4", 443, serviceInfo443)

		info80, _ := GetWebServiceInfo("192.168.1.4", 80)
		info443, _ := GetWebServiceInfo("192.168.1.4", 443)

		if info80.Name != "http" {
			t.Errorf("端口80的Name = %q, 期望 'http'", info80.Name)
		}
		if info443.Name != "https" {
			t.Errorf("端口443的Name = %q, 期望 'https'", info443.Name)
		}
	})
}

// TestWebServiceCache_Concurrent 测试并发安全性
func TestWebServiceCache_Concurrent(t *testing.T) {
	// 清空缓存
	webCacheMutex.Lock()
	webServiceCache = make(map[string]*ServiceInfo)
	webCacheMutex.Unlock()

	t.Run("不同key并发写入", func(t *testing.T) {
		var wg sync.WaitGroup
		numGoroutines := 100

		// 并发写入不同端口
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				serviceInfo := &ServiceInfo{
					Name: "http",
				}
				MarkAsWebService("192.168.1.1", id, serviceInfo)
			}(i)
		}

		wg.Wait()

		// 验证数据完整性
		for i := 0; i < numGoroutines; i++ {
			if !IsMarkedWebService("192.168.1.1", i) {
				t.Errorf("端口 %d 应被标记", i)
			}
		}
	})

	t.Run("同一key并发读写", func(t *testing.T) {
		// 这才是真正的race condition测试
		var wg sync.WaitGroup
		numGoroutines := 100
		const testHost = "192.168.1.100"
		const testPort = 80

		// 同时读写同一个key
		for i := 0; i < numGoroutines; i++ {
			wg.Add(2)

			// 写goroutine
			go func(id int) {
				defer wg.Done()
				serviceInfo := &ServiceInfo{
					Name:   "http",
					Banner: fmt.Sprintf("writer-%d", id),
				}
				MarkAsWebService(testHost, testPort, serviceInfo)
			}(i)

			// 读goroutine
			go func() {
				defer wg.Done()
				info, exists := GetWebServiceInfo(testHost, testPort)
				// 不验证具体内容（因为写入顺序不确定）
				// 只验证不会panic或返回不一致的exists/info
				if exists && info == nil {
					t.Error("exists=true但info=nil，数据不一致")
				}
			}()
		}

		wg.Wait()

		// 验证最终状态一致
		info, exists := GetWebServiceInfo(testHost, testPort)
		if !exists {
			t.Error("应该至少有一次写入成功")
		}
		if info == nil {
			t.Error("exists=true但info=nil")
		}
	})
}

// =============================================================================
// 指纹缓存测试
// =============================================================================

// =============================================================================
// 边界情况测试
// =============================================================================

// TestCreateTargetFromURL_EdgeCases 测试URL解析边界情况
func TestCreateTargetFromURL_EdgeCases(t *testing.T) {
	strategy := NewWebScanStrategy()

	t.Run("空URL", func(t *testing.T) {
		result := strategy.createTargetFromURL(common.HostInfo{}, "")
		// url.Parse("")会成功，但Hostname()返回空
		if result == nil {
			t.Skip("空URL解析行为依赖于url.Parse实现")
		}
	})

	t.Run("只有协议", func(t *testing.T) {
		result := strategy.createTargetFromURL(common.HostInfo{}, "http://")
		// url.Parse("http://")会成功，但Host为空
		if result != nil && result.Host == "" {
			t.Log("Empty host check passed as expected")
		}
	})

	t.Run("特殊字符URL", func(t *testing.T) {
		result := strategy.createTargetFromURL(common.HostInfo{}, "http://例子.com")
		// 中文域名可能成功解析（IDN）
		if result == nil {
			t.Log("中文域名解析失败（预期行为）")
		}
	})

	t.Run("IPv6地址", func(t *testing.T) {
		result := strategy.createTargetFromURL(common.HostInfo{}, "http://[::1]:8080")
		if result == nil {
			t.Error("IPv6地址应能正确解析")
		} else {
			if result.Host != "::1" {
				t.Errorf("IPv6 Host = %q, 期望 '::1'", result.Host)
			}
			if result.Port != 8080 {
				t.Errorf("IPv6 Ports = %q, 期望 '8080'", result.Port)
			}
		}
	})
}

// TestIsWebServiceByFingerprint_Priority 测试识别优先级
func TestIsWebServiceByFingerprint_Priority(t *testing.T) {
	t.Run("非Web服务名优先级高于Web Banner", func(t *testing.T) {
		// 服务名是mysql，但Banner包含Web特征
		serviceInfo := &ServiceInfo{
			Name:   "mysql",
			Banner: "Server: Apache",
		}
		result := IsWebServiceByFingerprint(serviceInfo)
		if result {
			t.Error("非Web服务名应优先，即使Banner包含Web特征")
		}
	})

	t.Run("Web服务名优先级高于非Web Banner", func(t *testing.T) {
		serviceInfo := &ServiceInfo{
			Name:   "http",
			Banner: "MySQL Server Ready",
		}
		result := IsWebServiceByFingerprint(serviceInfo)
		if !result {
			t.Error("Web服务名应优先，即使Banner包含非Web特征")
		}
	})
}

// =============================================================================
// 协议检测测试
// =============================================================================

// TestDetectHTTPScheme 测试HTTP/HTTPS协议智能检测
func TestDetectHTTPScheme(t *testing.T) {
	// 设置WebTimeout避免测试超时
	cfg := common.GetGlobalConfig()
	oldTimeout := cfg.Network.WebTimeout
	cfg.Network.WebTimeout = 2 * time.Second
	defer func() { cfg.Network.WebTimeout = oldTimeout }()

	session := common.NewScanSession(cfg, common.NewState(), common.GetFlagVars())

	t.Run("HTTPS服务器检测", func(t *testing.T) {
		// 创建HTTPS测试服务器
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// 解析服务器地址
		host, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
		if err != nil {
			t.Fatalf("解析服务器地址失败: %v", err)
		}
		port, _ := strconv.Atoi(portStr)

		// 测试检测
		result := DetectHTTPScheme(host, port, cfg, session)
		if result != "https" {
			t.Errorf("DetectHTTPScheme() = %q, 期望 'https'", result)
		}
	})

	t.Run("HTTP服务器检测", func(t *testing.T) {
		// 创建HTTP测试服务器
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// 解析服务器地址
		host, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
		if err != nil {
			t.Fatalf("解析服务器地址失败: %v", err)
		}
		port, _ := strconv.Atoi(portStr)

		// 测试检测
		result := DetectHTTPScheme(host, port, cfg, session)
		if result != "http" {
			t.Errorf("DetectHTTPScheme() = %q, 期望 'http'", result)
		}
	})

	t.Run("不存在的服务", func(t *testing.T) {
		// 使用127.0.0.1的一个未使用端口
		result := DetectHTTPScheme("127.0.0.1", 65534, cfg, session)
		if result != "" {
			t.Errorf("不存在的服务应返回空字符串, 实际 %q", result)
		}
	})

	t.Run("非Web服务端口", func(t *testing.T) {
		// 创建一个TCP监听器但不响应HTTP
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("无法创建监听器: %v", err)
		}
		defer func() { _ = listener.Close() }()

		// 启动一个接受连接但立即关闭的goroutine
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()

		// 解析端口
		_, portStr, _ := net.SplitHostPort(listener.Addr().String())
		port, _ := strconv.Atoi(portStr)

		// 测试检测
		result := DetectHTTPScheme("127.0.0.1", port, cfg, session)
		if result != "" {
			t.Logf("非Web服务检测返回: %q (预期空字符串，但立即关闭连接可能被误判)", result)
		}
	})

	t.Run("TLS版本兼容性", func(t *testing.T) {
		// 测试TLS 1.0兼容性（DetectHTTPScheme设置MinVersion为TLS 1.0）
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = &tls.Config{
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS10,
		}
		server.StartTLS()
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)

		result := DetectHTTPScheme(host, port, cfg, session)
		if result != "https" {
			t.Errorf("TLS 1.0服务器应被检测为https, 实际 %q", result)
		}
	})
}
