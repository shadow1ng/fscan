package common

import (
	"testing"
	"time"

	"scanner/common/logging"
	"scanner/common/proxy"
)

func TestGetLogLevelFromString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected logging.LogLevel
	}{
		// 标准情况
		{"all lowercase", "all", logging.LevelAll},
		{"ALL uppercase", "ALL", logging.LevelAll},
		{"error lowercase", "error", logging.LevelError},
		{"ERROR uppercase", "ERROR", logging.LevelError},
		{"base lowercase", "base", logging.LevelBase},
		{"BASE uppercase", "BASE", logging.LevelBase},
		{"info lowercase", "info", logging.LevelInfo},
		{"INFO uppercase", "INFO", logging.LevelInfo},
		{"success lowercase", "success", logging.LevelSuccess},
		{"SUCCESS uppercase", "SUCCESS", logging.LevelSuccess},
		{"debug lowercase", "debug", logging.LevelDebug},
		{"DEBUG uppercase", "DEBUG", logging.LevelDebug},

		// 组合情况
		{"info,success", "info,success", logging.LevelInfoSuccess},
		{"base,info,success", "base,info,success", logging.LevelBaseInfoSuccess},
		{"BASE_INFO_SUCCESS", "BASE_INFO_SUCCESS", logging.LevelBaseInfoSuccess},

		// 边界情况
		{"empty string", "", logging.LevelInfoSuccess},
		{"unknown value", "unknown", logging.LevelInfoSuccess},
		{"random string", "foobar", logging.LevelInfoSuccess},
		{"mixed case", "InFo", logging.LevelInfo}, // ToLower后匹配"info"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLogLevelFromString(tt.input)
			if result != tt.expected {
				t.Errorf("getLogLevelFromString(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCreateProxyConfig(t *testing.T) {
	fv := GetFlagVars()
	// 保存原始值并在测试后恢复
	origSocks5 := fv.Socks5Proxy
	origHTTP := fv.HTTPProxy
	defer func() {
		fv.Socks5Proxy = origSocks5
		fv.HTTPProxy = origHTTP
	}()

	tests := []struct {
		name         string
		socks5Proxy  string
		httpProxy    string
		timeout      time.Duration
		expectedType proxy.ProxyType
		expectedAddr string
		expectedUser string
		expectedPass string
	}{
		{
			name:         "no proxy",
			socks5Proxy:  "",
			httpProxy:    "",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeNone,
			expectedAddr: "",
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "socks5 simple address",
			socks5Proxy:  "127.0.0.1:1080",
			httpProxy:    "",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeSOCKS5,
			expectedAddr: "127.0.0.1:1080",
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "socks5 with protocol prefix",
			socks5Proxy:  "socks5://127.0.0.1:1080",
			httpProxy:    "",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeSOCKS5,
			expectedAddr: "127.0.0.1:1080",
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "socks5 with auth",
			socks5Proxy:  "socks5://user:pass@127.0.0.1:1080",
			httpProxy:    "",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeSOCKS5,
			expectedAddr: "127.0.0.1:1080",
			expectedUser: "user",
			expectedPass: "pass",
		},
		{
			name:         "socks5 with auth no protocol",
			socks5Proxy:  "user:pass@127.0.0.1:1080",
			httpProxy:    "",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeSOCKS5,
			expectedAddr: "127.0.0.1:1080",
			expectedUser: "user",
			expectedPass: "pass",
		},
		{
			name:         "http proxy simple",
			socks5Proxy:  "",
			httpProxy:    "http://127.0.0.1:8080",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeHTTP,
			expectedAddr: "127.0.0.1:8080",
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "https proxy",
			socks5Proxy:  "",
			httpProxy:    "https://127.0.0.1:8443",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeHTTPS,
			expectedAddr: "127.0.0.1:8443",
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "http proxy with auth",
			socks5Proxy:  "",
			httpProxy:    "http://user:pass@127.0.0.1:8080",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeHTTP,
			expectedAddr: "127.0.0.1:8080",
			expectedUser: "user",
			expectedPass: "pass",
		},
		{
			name:         "socks5 priority over http",
			socks5Proxy:  "127.0.0.1:1080",
			httpProxy:    "http://127.0.0.1:8080",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeSOCKS5,
			expectedAddr: "127.0.0.1:1080",
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "socks5 with username only",
			socks5Proxy:  "socks5://user@127.0.0.1:1080",
			httpProxy:    "",
			timeout:      5 * time.Second,
			expectedType: proxy.ProxyTypeSOCKS5,
			expectedAddr: "127.0.0.1:1080",
			expectedUser: "user",
			expectedPass: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置FlagVars
			fv.Socks5Proxy = tt.socks5Proxy
			fv.HTTPProxy = tt.httpProxy

			// 调用函数
			config := createProxyConfig(tt.timeout)

			// 验证结果
			if config.Type != tt.expectedType {
				t.Errorf("Type = %v, want %v", config.Type, tt.expectedType)
			}
			if config.Address != tt.expectedAddr {
				t.Errorf("Address = %q, want %q", config.Address, tt.expectedAddr)
			}
			if config.Username != tt.expectedUser {
				t.Errorf("Username = %q, want %q", config.Username, tt.expectedUser)
			}
			if config.Password != tt.expectedPass {
				t.Errorf("Password = %q, want %q", config.Password, tt.expectedPass)
			}
			if config.Timeout != tt.timeout {
				t.Errorf("Timeout = %v, want %v", config.Timeout, tt.timeout)
			}
		})
	}
}

func TestCreateProxyConfigEdgeCases(t *testing.T) {
	fv := GetFlagVars()
	origSocks5 := fv.Socks5Proxy
	origHTTP := fv.HTTPProxy
	defer func() {
		fv.Socks5Proxy = origSocks5
		fv.HTTPProxy = origHTTP
	}()

	t.Run("invalid socks5 url fallback", func(t *testing.T) {
		fv.Socks5Proxy = "://invalid"
		fv.HTTPProxy = ""

		config := createProxyConfig(5 * time.Second)

		// 即使 URL 解析失败，也应该回退到原始值或解析后的 Host
		if config.Type != proxy.ProxyTypeSOCKS5 {
			t.Errorf("Type = %v, want %v", config.Type, proxy.ProxyTypeSOCKS5)
		}
		// URL 解析后提取 Host，对于 "://invalid" 会得到 ":"
		if config.Address == "" {
			t.Error("Address should not be empty")
		}
	})

	t.Run("invalid http url fallback", func(t *testing.T) {
		fv.Socks5Proxy = ""
		fv.HTTPProxy = "://invalid"

		config := createProxyConfig(5 * time.Second)

		if config.Type != proxy.ProxyTypeHTTP {
			t.Errorf("Type = %v, want %v", config.Type, proxy.ProxyTypeHTTP)
		}
		// URL 解析后提取 Host，对于无效 URL 可能得到非预期值
		if config.Address == "" {
			t.Error("Address should not be empty")
		}
	})

	t.Run("empty password with username", func(t *testing.T) {
		fv.Socks5Proxy = "socks5://user:@127.0.0.1:1080"
		fv.HTTPProxy = ""

		config := createProxyConfig(5 * time.Second)

		if config.Username != "user" {
			t.Errorf("Username = %q, want %q", config.Username, "user")
		}
		if config.Password != "" {
			t.Errorf("Password = %q, want empty string", config.Password)
		}
	})
}
