package common

import (
	"time"

	"github.com/shadow1ng/fscan/common/config"
)

/*
config_struct.go - 配置结构体定义

简化后的结构：
- 高频字段平铺到顶层
- 子配置使用值类型（非指针）
- 删除过度分类的 AdvancedConfig
*/

// =============================================================================
// Config - 扫描器配置
// =============================================================================

// Config 扫描器完整配置 - 初始化后只读，可安全共享
type Config struct {
	// 高频访问字段 - 平铺到顶层
	Timeout                 time.Duration // 通用超时
	TimeoutExplicit         bool          // 用户显式指定了 -time
	ThreadNum               int           // 主线程数
	ThreadCeiling           int           // 线程数上限（自适应池允许的最大值）
	ThreadNumExplicit       bool          // 用户显式指定了 -t
	ModuleThreadNum         int           // 模块线程数
	ModuleThreadNumExplicit bool          // 用户显式指定了 -mt
	DisableBrute            bool          // 禁用暴力破解
	DisablePing             bool          // 禁用Ping检测
	DisableTcpProbe         bool          // 禁用TCP补充探测
	DisableSubnetProbe      bool          // 禁用网段预筛

	// 扫描模式
	Mode               string // 扫描模式
	LocalMode          bool   // 本地模式
	LocalPlugin        string // 本地插件名
	AliveOnly          bool   // 仅存活检测
	MaxRetries         int    // 最大重试次数
	MaxRetriesExplicit bool   // 用户显式指定了 -retry
	DetectedNetworkEnv int    // 探测到的网络环境（来自 core.NetworkEnv）

	// 高级功能（从AdvancedConfig合并）
	Shellcode             string           // Shellcode
	LocalPluginsList      []string         // 本地插件列表
	DNSLog                bool             // DNSLog检测
	PersistenceTargetFile string           // 持久化目标文件
	WinPEFile             string           // WinPE文件
	PortMap               map[int][]string // 端口映射
	DefaultMap            []string         // 默认映射

	// 分组配置 - 值类型
	Credentials  CredentialConfig
	Network      NetworkConfig
	Output       OutputConfig
	POC          POCConfig
	Redis        RedisConfig
	HTTP         HTTPConfig
	LocalExploit LocalExploitConfig
	Target       TargetConfig // 扫描目标配置

	// 全局超时
	GlobalTimeout time.Duration

	// SOCKS5代理端口配置
	Socks5ProxyPort int // SOCKS5代理端口
}

// TargetConfig 扫描目标配置
type TargetConfig struct {
	Ports        string // 端口范围字符串
	ExcludePorts string // 排除端口字符串
}

// CredentialConfig 认证相关配置
type CredentialConfig struct {
	Username      string
	Password      string
	Domain        string
	Userdict      map[string][]string
	Passwords     []string
	UserPassPairs []config.CredentialPair
	HashValues    []string
	HashBytes     [][]byte
	SSHKeyPath    string
}

// NetworkConfig 网络相关配置
type NetworkConfig struct {
	HTTPProxy        string
	Socks5Proxy      string
	Iface            string
	WebTimeout       time.Duration
	MaxRedirects     int
	PacketRateLimit  int64
	MaxPacketCount   int64
	ICMPRate         float64
	ICMPRateExplicit bool
}

// OutputConfig 输出相关配置
type OutputConfig struct {
	File            string
	Format          string
	DisableSave     bool
	NoColor         bool
	Silent          bool
	DisableProgress bool
	ShowProgress    bool
	LogLevel        string
	Language        string
	PerfStats       bool
}

// POCConfig POC扫描相关配置
type POCConfig struct {
	PocPath     string // POC路径
	PocName     string // 指定POC名称
	Full        bool   // 完整POC扫描
	Num         int    // POC并发数
	NumExplicit bool   // 用户显式指定了 -num
	Disabled    bool   // 禁用POC扫描
}

// RedisConfig Redis利用相关配置
type RedisConfig struct {
	Disabled     bool   // 禁用Redis利用
	File         string // SSH密钥文件
	Shell        string // 反弹Shell地址
	WritePath    string // 写入路径
	WriteContent string // 写入内容
	WriteFile    string // 本地文件路径
}

// HTTPConfig HTTP请求相关配置
type HTTPConfig struct {
	Cookie    string // Cookie
	UserAgent string // User-Agent
	Accept    string // Accept头
}

// LocalExploitConfig 本地利用相关配置
type LocalExploitConfig struct {
	ReverseShellTarget  string // 反弹Shell目标
	ForwardShellPort    int    // 正向Shell端口
	KeyloggerOutputFile string // 键盘记录输出文件
	DownloadURL         string // 下载URL
	DownloadSavePath    string // 下载保存路径
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneStringSliceMap(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string][]string, len(values))
	for key, value := range values {
		cloned[key] = cloneStringSlice(value)
	}
	return cloned
}

func clonePortMap(values map[int][]string) map[int][]string {
	if values == nil {
		return nil
	}
	cloned := make(map[int][]string, len(values))
	for key, value := range values {
		cloned[key] = cloneStringSlice(value)
	}
	return cloned
}

const minModuleTimeout = 3 * time.Second

// ModuleTimeout 返回插件级超时（用于弱口令测试、服务交互等多轮协议）
// 保证下限 3s，避免自适应把端口扫描超时压低后影响 SSH/SNMP 等交互型协议
func (c *Config) ModuleTimeout() time.Duration {
	if c.Timeout >= minModuleTimeout {
		return c.Timeout
	}
	return minModuleTimeout
}

// NewConfig 创建带默认值的Config（后备用，正常流程使用BuildConfigFromFlags）
func NewConfig() *Config {
	return &Config{
		// 高频字段 - 使用默认常量
		Timeout:         time.Duration(DefaultTimeout) * time.Second,
		ThreadNum:       DefaultThreadNum,
		ThreadCeiling:   DefaultThreadNum,
		ModuleThreadNum: 10,
		DisableBrute:    false,
		DisablePing:     false,
		DisableTcpProbe:    false,
		DisableSubnetProbe: false,

		// 扫描模式
		Mode:       DefaultScanMode,
		LocalMode:  false,
		AliveOnly:  false,
		MaxRetries: 3,

		// 高级功能 - 使用默认配置
		PortMap:    clonePortMap(config.DefaultPortMap),
		DefaultMap: cloneStringSlice(config.DefaultProbeMap),

		// 分组配置 - 使用默认字典
		Credentials: CredentialConfig{
			Userdict:      cloneStringSliceMap(config.DefaultUserDict),
			Passwords:     cloneStringSlice(config.DefaultPasswords),
			UserPassPairs: nil,
		},
		Network: NetworkConfig{
			WebTimeout:   time.Duration(5) * time.Second,
			MaxRedirects: 10,
			ICMPRate:     0.1,
		},
		Output: OutputConfig{
			File:         "result.txt",
			Format:       "txt",
			ShowProgress: true,
			LogLevel:     DefaultLogLevel,
			Language:     DefaultLanguage,
		},
		POC: POCConfig{
			Num: 20,
		},
		LocalExploit: LocalExploitConfig{
			ForwardShellPort: 4444,
		},
	}
}
