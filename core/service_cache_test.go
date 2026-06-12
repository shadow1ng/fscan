package core

import (
	"sync"
	"testing"

	"github.com/shadow1ng/fscan/plugins"
)

// registerTestPlugins 注册测试用插件（名字和服务识别结果一致）
func registerTestPlugins(t *testing.T) {
	t.Helper()
	plugins.RegisterWithOptions("ssh", func() plugins.Plugin { return nil }, []int{22, 2222}, nil, true)
	plugins.RegisterWithOptions("mysql", func() plugins.Plugin { return nil }, []int{3306}, nil, true)
	plugins.RegisterWithOptions("ftp", func() plugins.Plugin { return nil }, []int{21}, nil, true)
	plugins.RegisterWithOptions("redis", func() plugins.Plugin { return nil }, []int{6379}, nil, true)
	plugins.RegisterWithOptions("postgresql", func() plugins.Plugin { return nil }, []int{5432}, nil, true)
	plugins.RegisterWithOptions("telnet", func() plugins.Plugin { return nil }, []int{23}, nil, true)
	plugins.RegisterWithOptions("mssql", func() plugins.Plugin { return nil }, []int{1433}, nil, true)
	plugins.RegisterWithOptions("vnc", func() plugins.Plugin { return nil }, []int{5900}, nil, true)
	plugins.RegisterWithOptions("webtitle", func() plugins.Plugin { return nil }, []int{}, []string{plugins.PluginTypeWeb}, true)
}

func clearServiceCache() {
	serviceCacheMutex.Lock()
	serviceCache = make(map[string]*ServiceInfo)
	serviceCacheMutex.Unlock()
}

// =============================================================================
// 单元测试：CacheServiceInfo / GetCachedServiceInfo
// =============================================================================

func TestCacheServiceInfo_BasicCRUD(t *testing.T) {
	clearServiceCache()

	t.Run("缓存后可读取", func(t *testing.T) {
		CacheServiceInfo("10.0.0.1", 22, &ServiceInfo{Name: "ssh", Version: "OpenSSH_8.9"})
		info, ok := GetCachedServiceInfo("10.0.0.1", 22)
		if !ok {
			t.Fatal("缓存未命中")
		}
		if info.Name != "ssh" || info.Version != "OpenSSH_8.9" {
			t.Errorf("got Name=%q Version=%q", info.Name, info.Version)
		}
	})

	t.Run("不同端口独立", func(t *testing.T) {
		CacheServiceInfo("10.0.0.1", 3306, &ServiceInfo{Name: "mysql"})
		CacheServiceInfo("10.0.0.1", 5432, &ServiceInfo{Name: "postgresql"})
		i1, _ := GetCachedServiceInfo("10.0.0.1", 3306)
		i2, _ := GetCachedServiceInfo("10.0.0.1", 5432)
		if i1.Name != "mysql" || i2.Name != "postgresql" {
			t.Errorf("端口混淆: 3306=%q 5432=%q", i1.Name, i2.Name)
		}
	})

	t.Run("不同主机独立", func(t *testing.T) {
		CacheServiceInfo("10.0.0.1", 22, &ServiceInfo{Name: "ssh"})
		CacheServiceInfo("10.0.0.2", 22, &ServiceInfo{Name: "telnet"})
		i1, _ := GetCachedServiceInfo("10.0.0.1", 22)
		i2, _ := GetCachedServiceInfo("10.0.0.2", 22)
		if i1.Name != "ssh" || i2.Name != "telnet" {
			t.Errorf("主机混淆: .1=%q .2=%q", i1.Name, i2.Name)
		}
	})

	t.Run("覆盖写入", func(t *testing.T) {
		CacheServiceInfo("10.0.0.5", 80, &ServiceInfo{Name: "unknown"})
		CacheServiceInfo("10.0.0.5", 80, &ServiceInfo{Name: "http"})
		info, _ := GetCachedServiceInfo("10.0.0.5", 80)
		if info.Name != "http" {
			t.Errorf("覆盖失败: %q", info.Name)
		}
	})

	t.Run("未缓存返回 false", func(t *testing.T) {
		if _, ok := GetCachedServiceInfo("192.168.99.99", 12345); ok {
			t.Error("应返回 false")
		}
	})
}

// =============================================================================
// 单元测试：Web 服务过滤
// =============================================================================

func TestWebServiceFiltering(t *testing.T) {
	clearServiceCache()

	webNames := []string{"http", "https", "ssl", "tls", "nginx", "apache", "iis", "tomcat"}
	nonWebNames := []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "ftp", "smtp", "telnet", "vnc", "rdp"}

	for _, name := range webNames {
		clearServiceCache()
		CacheServiceInfo("10.0.0.1", 443, &ServiceInfo{Name: name})
		if !IsMarkedWebService("10.0.0.1", 443) {
			t.Errorf("%q 应被识别为 Web 服务", name)
		}
	}

	for _, name := range nonWebNames {
		clearServiceCache()
		CacheServiceInfo("10.0.0.1", 9999, &ServiceInfo{Name: name})
		if IsMarkedWebService("10.0.0.1", 9999) {
			t.Errorf("%q 不应被识别为 Web 服务", name)
		}
	}

	t.Run("GetWebServiceInfo 过滤非 Web", func(t *testing.T) {
		clearServiceCache()
		CacheServiceInfo("10.0.0.1", 3306, &ServiceInfo{Name: "mysql"})
		if _, ok := GetWebServiceInfo("10.0.0.1", 3306); ok {
			t.Error("mysql 不应通过 GetWebServiceInfo")
		}
	})

	t.Run("GetWebServiceInfo 返回 Web", func(t *testing.T) {
		clearServiceCache()
		CacheServiceInfo("10.0.0.1", 8080, &ServiceInfo{Name: "nginx"})
		info, ok := GetWebServiceInfo("10.0.0.1", 8080)
		if !ok || info.Name != "nginx" {
			t.Error("nginx 应通过 GetWebServiceInfo")
		}
	})
}

// =============================================================================
// 集成测试：指纹驱动插件匹配
// =============================================================================

func TestIntegration_FingerprintDrivenPluginMatch(t *testing.T) {
	clearServiceCache()
	registerTestPlugins(t)

	CacheServiceInfo("10.0.0.1", 22, &ServiceInfo{Name: "ssh"})
	CacheServiceInfo("10.0.0.1", 8881, &ServiceInfo{Name: "ssh"})
	CacheServiceInfo("10.0.0.1", 13306, &ServiceInfo{Name: "mysql"})
	CacheServiceInfo("10.0.0.1", 80, &ServiceInfo{Name: "http"})
	CacheServiceInfo("10.0.0.1", 9443, &ServiceInfo{Name: "https"})
	CacheServiceInfo("10.0.0.1", 2121, &ServiceInfo{Name: "ftp"})
	CacheServiceInfo("10.0.0.1", 6380, &ServiceInfo{Name: "redis"})

	strategy := NewServiceScanStrategy()

	tests := []struct {
		plugin, host string
		port         int
		want         bool
		desc         string
	}{
		{"ssh", "10.0.0.1", 22, true, "SSH 标准端口"},
		{"ssh", "10.0.0.1", 8881, true, "SSH 非标准端口（指纹匹配）"},
		{"mysql", "10.0.0.1", 13306, true, "MySQL 非标准端口"},
		{"ftp", "10.0.0.1", 2121, true, "FTP 非标准端口"},
		{"redis", "10.0.0.1", 6380, true, "Redis 非标准端口"},
		{"ssh", "10.0.0.1", 13306, false, "SSH 不匹配 MySQL 端口"},
		{"mysql", "10.0.0.1", 8881, false, "MySQL 不匹配 SSH 端口"},
		{"redis", "10.0.0.1", 22, false, "Redis 不匹配 SSH 标准端口"},
		{"ssh", "10.0.0.1", 65000, false, "SSH 不匹配未识别端口"},
		{"webtitle", "10.0.0.1", 80, true, "Web 匹配 http"},
		{"webtitle", "10.0.0.1", 9443, true, "Web 匹配 https 非标准"},
		{"webtitle", "10.0.0.1", 22, false, "Web 不匹配 SSH"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := strategy.isPluginApplicableToPortWithHost(tt.plugin, tt.host, tt.port)
			if got != tt.want {
				t.Errorf("plugin=%q port=%d: got %v, want %v", tt.plugin, tt.port, got, tt.want)
			}
		})
	}
}

// =============================================================================
// 集成测试：非标准端口完整流程
// =============================================================================

func TestIntegration_NonStandardPortScanFlow(t *testing.T) {
	clearServiceCache()
	registerTestPlugins(t)

	host := "172.16.0.100"
	CacheServiceInfo(host, 8881, &ServiceInfo{
		Name: "ssh", Version: "OpenSSH_8.2p1",
		Banner: "SSH-2.0-OpenSSH_8.2p1", Extras: map[string]string{"os": "Linux"},
	})

	strategy := NewServiceScanStrategy()

	if !strategy.isPluginApplicableToPortWithHost("ssh", host, 8881) {
		t.Error("SSH 应匹配 8881")
	}
	if strategy.isPluginApplicableToPortWithHost("mysql", host, 8881) {
		t.Error("MySQL 不应匹配 8881 上的 SSH")
	}
	if IsMarkedWebService(host, 8881) {
		t.Error("SSH 不应标记为 Web")
	}
}

// =============================================================================
// 集成测试：同一主机多服务
// =============================================================================

func TestIntegration_MultiServiceSameHost(t *testing.T) {
	clearServiceCache()
	registerTestPlugins(t)

	host := "192.168.1.100"
	CacheServiceInfo(host, 2222, &ServiceInfo{Name: "ssh"})
	CacheServiceInfo(host, 33060, &ServiceInfo{Name: "mysql"})
	CacheServiceInfo(host, 8080, &ServiceInfo{Name: "http"})
	CacheServiceInfo(host, 63790, &ServiceInfo{Name: "redis"})

	strategy := NewServiceScanStrategy()

	checks := []struct {
		plugin string
		port   int
		want   bool
	}{
		{"ssh", 2222, true}, {"ssh", 33060, false}, {"ssh", 8080, false},
		{"mysql", 33060, true}, {"mysql", 2222, false},
		{"redis", 63790, true}, {"redis", 2222, false},
		{"webtitle", 8080, true}, {"webtitle", 2222, false},
	}

	for _, c := range checks {
		got := strategy.isPluginApplicableToPortWithHost(c.plugin, host, c.port)
		if got != c.want {
			t.Errorf("plugin=%q port=%d: got %v, want %v", c.plugin, c.port, got, c.want)
		}
	}
}

// =============================================================================
// 边界测试
// =============================================================================

func TestServiceCache_EdgeCases(t *testing.T) {
	clearServiceCache()
	registerTestPlugins(t)
	strategy := NewServiceScanStrategy()

	t.Run("空服务名不匹配", func(t *testing.T) {
		CacheServiceInfo("10.0.0.1", 9999, &ServiceInfo{Name: ""})
		if strategy.isPluginApplicableToPortWithHost("ssh", "10.0.0.1", 9999) {
			t.Error("空服务名不应匹配")
		}
	})

	t.Run("unknown 不匹配", func(t *testing.T) {
		CacheServiceInfo("10.0.0.1", 8888, &ServiceInfo{Name: "unknown"})
		if strategy.isPluginApplicableToPortWithHost("ssh", "10.0.0.1", 8888) {
			t.Error("unknown 不应匹配")
		}
	})

	t.Run("大小写不敏感", func(t *testing.T) {
		clearServiceCache()
		CacheServiceInfo("10.0.0.1", 5555, &ServiceInfo{Name: "SSH"})
		if !strategy.isPluginApplicableToPortWithHost("ssh", "10.0.0.1", 5555) {
			t.Error("SSH 大写应匹配 ssh 插件")
		}
	})

	t.Run("host 为空不查缓存", func(t *testing.T) {
		CacheServiceInfo("10.0.0.1", 8881, &ServiceInfo{Name: "ssh"})
		if strategy.isPluginApplicableToPortWithHost("ssh", "", 8881) {
			t.Error("host 为空不应匹配")
		}
	})

	t.Run("nil ServiceInfo 不 panic", func(t *testing.T) {
		CacheServiceInfo("10.0.0.1", 7777, nil)
		got := strategy.isPluginApplicableToPortWithHost("ssh", "10.0.0.1", 7777)
		if got {
			t.Error("nil ServiceInfo 不应匹配")
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		clearServiceCache()
		CacheServiceInfo("::1", 22, &ServiceInfo{Name: "ssh"})
		if _, ok := GetCachedServiceInfo("::1", 22); !ok {
			t.Error("IPv6 缓存失败")
		}
	})
}

// =============================================================================
// 并发安全
// =============================================================================

func TestServiceCache_ConcurrentSafety(t *testing.T) {
	clearServiceCache()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func(p int) { defer wg.Done(); CacheServiceInfo("10.0.0.1", p, &ServiceInfo{Name: "ssh"}) }(i)
		go func(p int) { defer wg.Done(); GetCachedServiceInfo("10.0.0.1", p) }(i)
		go func(p int) { defer wg.Done(); IsMarkedWebService("10.0.0.1", p) }(i)
	}
	wg.Wait()

	for i := 0; i < 100; i++ {
		if _, ok := GetCachedServiceInfo("10.0.0.1", i); !ok {
			t.Errorf("并发写入丢失: port=%d", i)
		}
	}
}

// =============================================================================
// 回归测试：#588
// =============================================================================

func TestRegression_Issue588(t *testing.T) {
	clearServiceCache()
	registerTestPlugins(t)

	CacheServiceInfo("192.168.1.50", 8881, &ServiceInfo{Name: "ssh", Version: "OpenSSH_7.4"})
	strategy := NewServiceScanStrategy()

	if !strategy.isPluginApplicableToPortWithHost("ssh", "192.168.1.50", 8881) {
		t.Fatal("#588: SSH 应匹配 8881")
	}
	for _, p := range []string{"mysql", "ftp", "redis", "postgresql", "telnet", "vnc", "mssql"} {
		if strategy.isPluginApplicableToPortWithHost(p, "192.168.1.50", 8881) {
			t.Errorf("#588: %q 不应匹配 8881 上的 SSH", p)
		}
	}
}

// =============================================================================
// 端口匹配优先于缓存
// =============================================================================

func TestIntegration_PortMatchPrecedence(t *testing.T) {
	clearServiceCache()
	registerTestPlugins(t)

	CacheServiceInfo("10.0.0.1", 22, &ServiceInfo{Name: "http"})
	strategy := NewServiceScanStrategy()

	if !strategy.isPluginApplicableToPortWithHost("ssh", "10.0.0.1", 22) {
		t.Error("SSH 应通过端口匹配命中 22（即使缓存是 http）")
	}
	if !IsMarkedWebService("10.0.0.1", 22) {
		t.Error("缓存是 http，应标记为 Web")
	}
}
