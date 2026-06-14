package common

import (
	"testing"
	"time"
)

// =============================================================================
// FlagVars 默认值测试
// =============================================================================

func TestFlagVars_DefaultValues(t *testing.T) {
	// 测试全局 flagVars 初始化
	fv := GetFlagVars()
	if fv == nil {
		t.Fatal("GetFlagVars() 返回 nil")
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - 扫描控制参数
// =============================================================================

func TestBuildConfigFromFlags_ScanControl(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "默认扫描模式",
			fv: &FlagVars{
				ScanMode:        "all",
				ThreadNum:       600,
				ModuleThreadNum: 20,
				TimeoutSec:      3,
				GlobalTimeout:   180,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Mode != "all" {
					t.Errorf("Mode = %q, want %q", cfg.Mode, "all")
				}
				if cfg.ThreadNum != 600 {
					t.Errorf("ThreadNum = %d, want %d", cfg.ThreadNum, 600)
				}
				if cfg.ModuleThreadNum != 20 {
					t.Errorf("ModuleThreadNum = %d, want %d", cfg.ModuleThreadNum, 20)
				}
				if cfg.Timeout != 3*time.Second {
					t.Errorf("Timeout = %v, want %v", cfg.Timeout, 3*time.Second)
				}
			},
		},
		{
			name: "自定义线程数",
			fv: &FlagVars{
				ThreadNum:       100,
				ModuleThreadNum: 10,
				TimeoutSec:      5,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.ThreadNum != 100 {
					t.Errorf("ThreadNum = %d, want %d", cfg.ThreadNum, 100)
				}
				if cfg.ModuleThreadNum != 10 {
					t.Errorf("ModuleThreadNum = %d, want %d", cfg.ModuleThreadNum, 10)
				}
				if cfg.Timeout != 5*time.Second {
					t.Errorf("Timeout = %v, want %v", cfg.Timeout, 5*time.Second)
				}
			},
		},
		{
			name: "禁用Ping",
			fv: &FlagVars{
				DisablePing: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.DisablePing {
					t.Error("DisablePing 应该为 true")
				}
			},
		},
		{
			name: "仅存活检测模式",
			fv: &FlagVars{
				AliveOnly: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.AliveOnly {
					t.Error("AliveOnly 应该为 true")
				}
			},
		},
		{
			name: "禁用暴力破解",
			fv: &FlagVars{
				DisableBrute: true,
				MaxRetries:   5,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.DisableBrute {
					t.Error("DisableBrute 应该为 true")
				}
				if cfg.MaxRetries != 5 {
					t.Errorf("MaxRetries = %d, want %d", cfg.MaxRetries, 5)
				}
			},
		},
		{
			name: "本地插件模式",
			fv: &FlagVars{
				LocalPlugin: "systeminfo",
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.LocalMode {
					t.Error("LocalMode 应该为 true")
				}
				if cfg.LocalPlugin != "systeminfo" {
					t.Errorf("LocalPlugin = %q, want %q", cfg.LocalPlugin, "systeminfo")
				}
			},
		},
		{
			name: "扫描模式组合",
			fv: &FlagVars{
				ScanMode: "ssh,ftp,mysql",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Mode != "ssh,ftp,mysql" {
					t.Errorf("Mode = %q, want %q", cfg.Mode, "ssh,ftp,mysql")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - Web扫描参数
// =============================================================================

func TestBuildConfigFromFlags_WebScan(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "Web超时设置",
			fv: &FlagVars{
				WebTimeout: 10,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.WebTimeout != 10*time.Second {
					t.Errorf("WebTimeout = %v, want %v", cfg.Network.WebTimeout, 10*time.Second)
				}
			},
		},
		{
			name: "最大重定向次数",
			fv: &FlagVars{
				MaxRedirects: 5,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.MaxRedirects != 5 {
					t.Errorf("MaxRedirects = %d, want %d", cfg.Network.MaxRedirects, 5)
				}
			},
		},
		{
			name: "Cookie设置",
			fv: &FlagVars{
				Cookie: "session=abc123; token=xyz",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.HTTP.Cookie != "session=abc123; token=xyz" {
					t.Errorf("Cookie = %q, want %q", cfg.HTTP.Cookie, "session=abc123; token=xyz")
				}
			},
		},
		{
			name: "UserAgent设置",
			fv: &FlagVars{
				UserAgent: "CustomAgent/1.0",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.HTTP.UserAgent != "CustomAgent/1.0" {
					t.Errorf("UserAgent = %q, want %q", cfg.HTTP.UserAgent, "CustomAgent/1.0")
				}
			},
		},
		{
			name: "HTTP代理设置",
			fv: &FlagVars{
				HTTPProxy: "http://127.0.0.1:8080",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.HTTPProxy != "http://127.0.0.1:8080" {
					t.Errorf("HTTPProxy = %q, want %q", cfg.Network.HTTPProxy, "http://127.0.0.1:8080")
				}
			},
		},
		{
			name: "SOCKS5代理设置",
			fv: &FlagVars{
				Socks5Proxy: "socks5://127.0.0.1:1080",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.Socks5Proxy != "socks5://127.0.0.1:1080" {
					t.Errorf("Socks5Proxy = %q, want %q", cfg.Network.Socks5Proxy, "socks5://127.0.0.1:1080")
				}
			},
		},
		{
			name: "网络接口设置",
			fv: &FlagVars{
				Iface: "eth0",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.Iface != "eth0" {
					t.Errorf("Iface = %q, want %q", cfg.Network.Iface, "eth0")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - POC参数
// =============================================================================

func TestBuildConfigFromFlags_POC(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "POC路径设置",
			fv: &FlagVars{
				PocPath: "/path/to/pocs",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.POC.PocPath != "/path/to/pocs" {
					t.Errorf("PocPath = %q, want %q", cfg.POC.PocPath, "/path/to/pocs")
				}
			},
		},
		{
			name: "POC名称过滤",
			fv: &FlagVars{
				PocName: "struts,spring",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.POC.PocName != "struts,spring" {
					t.Errorf("PocName = %q, want %q", cfg.POC.PocName, "struts,spring")
				}
			},
		},
		{
			name: "全量POC扫描",
			fv: &FlagVars{
				PocFull: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.POC.Full {
					t.Error("POC.Full 应该为 true")
				}
			},
		},
		{
			name: "DNSLog启用",
			fv: &FlagVars{
				DNSLog: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.DNSLog {
					t.Error("DNSLog 应该为 true")
				}
			},
		},
		{
			name: "POC并发数",
			fv: &FlagVars{
				PocNum: 50,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.POC.Num != 50 {
					t.Errorf("PocNum = %d, want %d", cfg.POC.Num, 50)
				}
			},
		},
		{
			name: "禁用POC扫描",
			fv: &FlagVars{
				DisablePocScan: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.POC.Disabled {
					t.Error("POC.Disabled 应该为 true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - Redis参数
// =============================================================================

func TestBuildConfigFromFlags_Redis(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "Redis文件设置",
			fv: &FlagVars{
				RedisFile: "/path/to/redis.txt",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Redis.File != "/path/to/redis.txt" {
					t.Errorf("RedisFile = %q, want %q", cfg.Redis.File, "/path/to/redis.txt")
				}
			},
		},
		{
			name: "Redis Shell设置",
			fv: &FlagVars{
				RedisShell: "192.168.1.1:4444",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Redis.Shell != "192.168.1.1:4444" {
					t.Errorf("RedisShell = %q, want %q", cfg.Redis.Shell, "192.168.1.1:4444")
				}
			},
		},
		{
			name: "Redis写入路径",
			fv: &FlagVars{
				RedisWritePath: "/var/spool/cron/",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Redis.WritePath != "/var/spool/cron/" {
					t.Errorf("RedisWritePath = %q, want %q", cfg.Redis.WritePath, "/var/spool/cron/")
				}
			},
		},
		{
			name: "Redis写入内容",
			fv: &FlagVars{
				RedisWriteContent: "* * * * * /bin/bash -c 'whoami'",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Redis.WriteContent != "* * * * * /bin/bash -c 'whoami'" {
					t.Errorf("RedisWriteContent 不匹配")
				}
			},
		},
		{
			name: "Redis写入文件",
			fv: &FlagVars{
				RedisWriteFile: "root",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Redis.WriteFile != "root" {
					t.Errorf("RedisWriteFile = %q, want %q", cfg.Redis.WriteFile, "root")
				}
			},
		},
		{
			name: "禁用Redis利用",
			fv: &FlagVars{
				DisableRedis: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Redis.Disabled {
					t.Error("Redis.Disabled 应该为 true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - 输出显示参数
// =============================================================================

func TestBuildConfigFromFlags_Output(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "输出文件设置",
			fv: &FlagVars{
				Outputfile: "scan_result.txt",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Output.File != "scan_result.txt" {
					t.Errorf("Output.File = %q, want %q", cfg.Output.File, "scan_result.txt")
				}
			},
		},
		{
			name: "JSON输出格式",
			fv: &FlagVars{
				OutputFormat: "json",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Output.Format != "json" {
					t.Errorf("Output.Format = %q, want %q", cfg.Output.Format, "json")
				}
			},
		},
		{
			name: "CSV输出格式",
			fv: &FlagVars{
				OutputFormat: "csv",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Output.Format != "csv" {
					t.Errorf("Output.Format = %q, want %q", cfg.Output.Format, "csv")
				}
			},
		},
		{
			name: "禁用保存",
			fv: &FlagVars{
				DisableSave: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Output.DisableSave {
					t.Error("Output.DisableSave 应该为 true")
				}
			},
		},
		{
			name: "静默模式",
			fv: &FlagVars{
				Silent: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Output.Silent {
					t.Error("Output.Silent 应该为 true")
				}
			},
		},
		{
			name: "禁用颜色",
			fv: &FlagVars{
				NoColor: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Output.NoColor {
					t.Error("Output.NoColor 应该为 true")
				}
			},
		},
		{
			name: "日志级别设置",
			fv: &FlagVars{
				LogLevel: "debug",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Output.LogLevel != "debug" {
					t.Errorf("Output.LogLevel = %q, want %q", cfg.Output.LogLevel, "debug")
				}
			},
		},
		{
			name: "禁用进度条",
			fv: &FlagVars{
				DisableProgress: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Output.DisableProgress {
					t.Error("Output.DisableProgress 应该为 true")
				}
				if cfg.Output.ShowProgress {
					t.Error("Output.ShowProgress 应该为 false")
				}
			},
		},
		{
			name: "启用性能统计",
			fv: &FlagVars{
				PerfStats: true,
			},
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Output.PerfStats {
					t.Error("Output.PerfStats 应该为 true")
				}
			},
		},
		{
			name: "语言设置-中文",
			fv: &FlagVars{
				Language: "zh",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Output.Language != "zh" {
					t.Errorf("Output.Language = %q, want %q", cfg.Output.Language, "zh")
				}
			},
		},
		{
			name: "语言设置-英文",
			fv: &FlagVars{
				Language: "en",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Output.Language != "en" {
					t.Errorf("Output.Language = %q, want %q", cfg.Output.Language, "en")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - 频率控制参数
// =============================================================================

func TestBuildConfigFromFlags_RateLimit(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "数据包速率限制",
			fv: &FlagVars{
				PacketRateLimit: 1000,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.PacketRateLimit != 1000 {
					t.Errorf("PacketRateLimit = %d, want %d", cfg.Network.PacketRateLimit, 1000)
				}
			},
		},
		{
			name: "最大数据包数量",
			fv: &FlagVars{
				MaxPacketCount: 100000,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.MaxPacketCount != 100000 {
					t.Errorf("MaxPacketCount = %d, want %d", cfg.Network.MaxPacketCount, 100000)
				}
			},
		},
		{
			name: "ICMP发送速率",
			fv: &FlagVars{
				ICMPRate: 0.5,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.ICMPRate != 0.5 {
					t.Errorf("ICMPRate = %f, want %f", cfg.Network.ICMPRate, 0.5)
				}
			},
		},
		{
			name: "无速率限制",
			fv: &FlagVars{
				PacketRateLimit: 0,
				MaxPacketCount:  0,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.PacketRateLimit != 0 {
					t.Errorf("PacketRateLimit = %d, want %d", cfg.Network.PacketRateLimit, 0)
				}
				if cfg.Network.MaxPacketCount != 0 {
					t.Errorf("MaxPacketCount = %d, want %d", cfg.Network.MaxPacketCount, 0)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - 凭据参数
// =============================================================================

func TestBuildConfigFromFlags_Credentials(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "用户名密码设置",
			fv: &FlagVars{
				Username: "admin",
				Password: "password123",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Credentials.Username != "admin" {
					t.Errorf("Username = %q, want %q", cfg.Credentials.Username, "admin")
				}
				if cfg.Credentials.Password != "password123" {
					t.Errorf("Password = %q, want %q", cfg.Credentials.Password, "password123")
				}
			},
		},
		{
			name: "域设置",
			fv: &FlagVars{
				Domain: "WORKGROUP",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Credentials.Domain != "WORKGROUP" {
					t.Errorf("Domain = %q, want %q", cfg.Credentials.Domain, "WORKGROUP")
				}
			},
		},
		{
			name: "SSH密钥路径",
			fv: &FlagVars{
				SSHKeyPath: "/home/user/.ssh/id_rsa",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Credentials.SSHKeyPath != "/home/user/.ssh/id_rsa" {
					t.Errorf("SSHKeyPath = %q, want %q", cfg.Credentials.SSHKeyPath, "/home/user/.ssh/id_rsa")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - 高级功能参数
// =============================================================================

func TestBuildConfigFromFlags_Advanced(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "Shellcode设置",
			fv: &FlagVars{
				Shellcode: "4831c048...",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Shellcode != "4831c048..." {
					t.Errorf("Shellcode = %q, want %q", cfg.Shellcode, "4831c048...")
				}
			},
		},
		{
			name: "反向Shell目标",
			fv: &FlagVars{
				ReverseShellTarget: "192.168.1.100:4444",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.LocalExploit.ReverseShellTarget != "192.168.1.100:4444" {
					t.Errorf("ReverseShellTarget = %q, want %q", cfg.LocalExploit.ReverseShellTarget, "192.168.1.100:4444")
				}
			},
		},
		{
			name: "SOCKS5代理端口",
			fv: &FlagVars{
				Socks5ProxyPort: 1080,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Socks5ProxyPort != 1080 {
					t.Errorf("Socks5ProxyPort = %d, want %d", cfg.Socks5ProxyPort, 1080)
				}
			},
		},
		{
			name: "正向Shell端口",
			fv: &FlagVars{
				ForwardShellPort: 5555,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.LocalExploit.ForwardShellPort != 5555 {
					t.Errorf("ForwardShellPort = %d, want %d", cfg.LocalExploit.ForwardShellPort, 5555)
				}
			},
		},
		{
			name: "持久化目标文件",
			fv: &FlagVars{
				PersistenceTargetFile: "/etc/crontab",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.PersistenceTargetFile != "/etc/crontab" {
					t.Errorf("PersistenceTargetFile = %q, want %q", cfg.PersistenceTargetFile, "/etc/crontab")
				}
			},
		},
		{
			name: "Windows PE文件",
			fv: &FlagVars{
				WinPEFile: "C:\\Windows\\Temp\\payload.exe",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.WinPEFile != "C:\\Windows\\Temp\\payload.exe" {
					t.Errorf("WinPEFile = %q, want %q", cfg.WinPEFile, "C:\\Windows\\Temp\\payload.exe")
				}
			},
		},
		{
			name: "键盘记录输出文件",
			fv: &FlagVars{
				KeyloggerOutputFile: "keylog.txt",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.LocalExploit.KeyloggerOutputFile != "keylog.txt" {
					t.Errorf("KeyloggerOutputFile = %q, want %q", cfg.LocalExploit.KeyloggerOutputFile, "keylog.txt")
				}
			},
		},
		{
			name: "下载URL和路径",
			fv: &FlagVars{
				DownloadURL:      "http://example.com/file.txt",
				DownloadSavePath: "/tmp/downloaded.txt",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.LocalExploit.DownloadURL != "http://example.com/file.txt" {
					t.Errorf("DownloadURL = %q, want %q", cfg.LocalExploit.DownloadURL, "http://example.com/file.txt")
				}
				if cfg.LocalExploit.DownloadSavePath != "/tmp/downloaded.txt" {
					t.Errorf("DownloadSavePath = %q, want %q", cfg.LocalExploit.DownloadSavePath, "/tmp/downloaded.txt")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// BuildConfigFromFlags 测试 - 目标配置参数
// =============================================================================

func TestBuildConfigFromFlags_Target(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "端口设置",
			fv: &FlagVars{
				Ports: "22,80,443,8080",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Target.Ports != "22,80,443,8080" {
					t.Errorf("Ports = %q, want %q", cfg.Target.Ports, "22,80,443,8080")
				}
			},
		},
		{
			name: "端口范围设置",
			fv: &FlagVars{
				Ports: "1-1000",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Target.Ports != "1-1000" {
					t.Errorf("Ports = %q, want %q", cfg.Target.Ports, "1-1000")
				}
			},
		},
		{
			name: "排除端口设置",
			fv: &FlagVars{
				ExcludePorts: "22,23",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Target.ExcludePorts != "22,23" {
					t.Errorf("ExcludePorts = %q, want %q", cfg.Target.ExcludePorts, "22,23")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// 参数边界值测试
// =============================================================================

func TestBuildConfigFromFlags_BoundaryValues(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "最小线程数",
			fv: &FlagVars{
				ThreadNum: 1,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.ThreadNum != 1 {
					t.Errorf("ThreadNum = %d, want %d", cfg.ThreadNum, 1)
				}
			},
		},
		{
			name: "大线程数",
			fv: &FlagVars{
				ThreadNum: 10000,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.ThreadNum != 10000 {
					t.Errorf("ThreadNum = %d, want %d", cfg.ThreadNum, 10000)
				}
			},
		},
		{
			name: "零超时值",
			fv: &FlagVars{
				TimeoutSec: 0,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Timeout != 0 {
					t.Errorf("Timeout = %v, want %v", cfg.Timeout, 0)
				}
			},
		},
		{
			name: "大超时值",
			fv: &FlagVars{
				TimeoutSec: 300,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Timeout != 300*time.Second {
					t.Errorf("Timeout = %v, want %v", cfg.Timeout, 300*time.Second)
				}
			},
		},
		{
			name: "零重定向次数",
			fv: &FlagVars{
				MaxRedirects: 0,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.MaxRedirects != 0 {
					t.Errorf("MaxRedirects = %d, want %d", cfg.Network.MaxRedirects, 0)
				}
			},
		},
		{
			name: "空字符串参数",
			fv: &FlagVars{
				Username:  "",
				Password:  "",
				Cookie:    "",
				UserAgent: "",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Credentials.Username != "" {
					t.Errorf("Username 应该为空")
				}
				if cfg.Credentials.Password != "" {
					t.Errorf("Password 应该为空")
				}
				if cfg.HTTP.Cookie != "" {
					t.Errorf("Cookie 应该为空")
				}
				// 空输入回退到默认 UA，避免发送空 User-Agent
				if cfg.HTTP.UserAgent == "" {
					t.Errorf("UserAgent 空输入应回退到默认 UA")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// 参数组合测试
// =============================================================================

func TestBuildConfigFromFlags_Combinations(t *testing.T) {
	tests := []struct {
		name     string
		fv       *FlagVars
		validate func(*testing.T, *Config)
	}{
		{
			name: "完整扫描配置",
			fv: &FlagVars{
				ScanMode:        "all",
				ThreadNum:       500,
				ModuleThreadNum: 15,
				TimeoutSec:      5,
				DisablePing:     true,
				DisableBrute:    false,
				MaxRetries:      3,
				Ports:           "1-65535",
				WebTimeout:      10,
				MaxRedirects:    5,
				PocFull:         true,
				PocNum:          30,
				Outputfile:      "result.json",
				OutputFormat:    "json",
				Language:        "zh",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Mode != "all" {
					t.Errorf("Mode = %q, want %q", cfg.Mode, "all")
				}
				if cfg.ThreadNum != 500 {
					t.Errorf("ThreadNum = %d, want %d", cfg.ThreadNum, 500)
				}
				if !cfg.DisablePing {
					t.Error("DisablePing 应该为 true")
				}
				if cfg.POC.Full != true {
					t.Error("POC.Full 应该为 true")
				}
				if cfg.Output.Format != "json" {
					t.Errorf("Output.Format = %q, want %q", cfg.Output.Format, "json")
				}
			},
		},
		{
			name: "最小配置",
			fv:   &FlagVars{},
			validate: func(t *testing.T, cfg *Config) {
				// 验证空配置不会导致崩溃
				if cfg == nil {
					t.Fatal("空配置返回nil")
				}
			},
		},
		{
			name: "代理组合配置",
			fv: &FlagVars{
				HTTPProxy:   "http://127.0.0.1:8080",
				Socks5Proxy: "socks5://127.0.0.1:1080",
				WebTimeout:  30,
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Network.HTTPProxy != "http://127.0.0.1:8080" {
					t.Errorf("HTTPProxy = %q, want %q", cfg.Network.HTTPProxy, "http://127.0.0.1:8080")
				}
				if cfg.Network.Socks5Proxy != "socks5://127.0.0.1:1080" {
					t.Errorf("Socks5Proxy = %q, want %q", cfg.Network.Socks5Proxy, "socks5://127.0.0.1:1080")
				}
			},
		},
		{
			name: "Redis利用组合",
			fv: &FlagVars{
				RedisShell:        "192.168.1.100:4444",
				RedisWritePath:    "/var/spool/cron/",
				RedisWriteFile:    "root",
				RedisWriteContent: "* * * * * bash -i",
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Redis.Shell != "192.168.1.100:4444" {
					t.Errorf("Redis.Shell = %q", cfg.Redis.Shell)
				}
				if cfg.Redis.WritePath != "/var/spool/cron/" {
					t.Errorf("Redis.WritePath = %q", cfg.Redis.WritePath)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildConfigFromFlags(tt.fv)
			if cfg == nil {
				t.Fatal("BuildConfigFromFlags 返回 nil")
			}
			tt.validate(t, cfg)
		})
	}
}

// =============================================================================
// checkParameterConflicts 测试
// =============================================================================

func TestCheckParameterConflicts(t *testing.T) {
	// 保存原始flagVars
	originalFlagVars := flagVars

	tests := []struct {
		name      string
		fv        *FlagVars
		wantError bool
	}{
		{
			name: "无冲突",
			fv: &FlagVars{
				ScanMode: "all",
			},
			wantError: false,
		},
		{
			name: "本地插件包含逗号",
			fv: &FlagVars{
				LocalPlugin: "systeminfo,avdetect",
			},
			wantError: true,
		},
		{
			name: "本地插件包含分号",
			fv: &FlagVars{
				LocalPlugin: "systeminfo;avdetect",
			},
			wantError: true,
		},
		{
			name: "本地插件包含空格",
			fv: &FlagVars{
				LocalPlugin: "systeminfo avdetect",
			},
			wantError: true,
		},
		{
			name: "本地插件包含管道符",
			fv: &FlagVars{
				LocalPlugin: "systeminfo|avdetect",
			},
			wantError: true,
		},
		{
			name: "单个本地插件-正常",
			fv: &FlagVars{
				LocalPlugin: "systeminfo",
			},
			wantError: false,
		},
		{
			name: "AliveOnly和ICMP模式同时指定",
			fv: &FlagVars{
				AliveOnly: true,
				ScanMode:  "icmp",
			},
			wantError: false, // 只是警告，不是错误
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置测试flagVars
			flagVars = tt.fv

			err := checkParameterConflicts()

			if tt.wantError && err == nil {
				t.Error("期望返回错误，但没有")
			}
			if !tt.wantError && err != nil {
				t.Errorf("不期望错误，但返回: %v", err)
			}
		})
	}

	// 恢复原始flagVars
	flagVars = originalFlagVars
}
