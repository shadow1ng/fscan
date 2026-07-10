package common

import (
	"os"
	"time"

	"scanner/common/config"
	"golang.org/x/term"
)

/*
flag_config.go - 命令行参数直接解析到Config

flag直接写入配置结构。
*/

// =============================================================================
// FlagVars - 命令行参数原始值
// =============================================================================

// FlagVars 存储命令行解析的原始值
// 某些字段需要类型转换（如 int64 秒 → time.Duration）
type FlagVars struct {
	// 目标配置
	Host             string
	ExcludeHosts     string
	ExcludeHostsFile string
	Ports            string
	ExcludePorts     string
	HostsFile        string
	PortsFile        string

	// 扫描控制
	ScanMode                string
	ThreadNum               int
	ThreadNumExplicit       bool // 用户显式指定了 -t
	ModuleThreadNum         int
	ModuleThreadNumExplicit bool
	TimeoutSec              int64 // 秒，需转换为 time.Duration
	TimeoutExplicit         bool
	GlobalTimeout           int64
	GlobalTimeoutExplicit   bool
	DisablePing             bool
	DisableTcpProbe         bool
	DisableSubnetProbe      bool
	AliveOnly               bool
	DisableBrute            bool
	MaxRetries              int
	MaxRetriesExplicit      bool

	// 认证凭据
	Username      string
	Password      string
	AddUsers      string
	AddPasswords  string
	UsersFile     string
	PasswordsFile string
	UserPassFile  string
	HashFile      string
	HashValue     string
	Domain        string
	SSHKeyPath    string

	// Web扫描
	TargetURL    string
	URLsFile     string
	Cookie       string
	UserAgent    string
	Accept       string
	WebTimeout   int64 // 秒
	MaxRedirects int
	HTTPProxy    string
	Socks5Proxy  string
	Iface        string

	// POC测试
	PocPath        string
	PocName        string
	PocFull        bool
	DNSLog         bool
	PocNum         int
	PocNumExplicit bool
	DisablePocScan bool

	// Redis利用
	RedisFile         string
	RedisShell        string
	RedisWritePath    string
	RedisWriteContent string
	RedisWriteFile    string
	DisableRedis      bool

	// 发包频率
	PacketRateLimit  int64
	MaxPacketCount   int64
	ICMPRate         float64
	ICMPRateExplicit bool

	// 输出控制
	Outputfile         string
	OutputFileExplicit bool
	OutputFormat       string
	DisableSave        bool
	Silent             bool
	NoColor            bool
	LogLevel           string
	Debug              bool
	DisableProgress    bool
	PerfStats          bool
	Language           string

	// 帮助
	ShowHelp bool
}

// =============================================================================
// 全局 FlagVars 实例（仅在解析阶段使用）
// =============================================================================

var flagVars = &FlagVars{}

// GetFlagVars 获取解析后的命令行参数（供 parse.go 等使用）
func GetFlagVars() *FlagVars {
	return flagVars
}

// =============================================================================
// BuildConfigFromFlags - 从 FlagVars 构建 Config
// =============================================================================

// BuildConfigFromFlags 从命令行参数构建配置对象
func BuildConfigFromFlags(fv *FlagVars) *Config {
	return &Config{
		// 高频字段
		Timeout:                 time.Duration(fv.TimeoutSec) * time.Second,
		TimeoutExplicit:         fv.TimeoutExplicit,
		ThreadNum:               fv.ThreadNum,
		ThreadNumExplicit:       fv.ThreadNumExplicit,
		ModuleThreadNum:         fv.ModuleThreadNum,
		ModuleThreadNumExplicit: fv.ModuleThreadNumExplicit,
		DisableBrute:            fv.DisableBrute,
		DisablePing:             fv.DisablePing,
		DisableTcpProbe:         fv.DisableTcpProbe,
		DisableSubnetProbe:      fv.DisableSubnetProbe,

		// 扫描模式
		Mode:               fv.ScanMode,
		AliveOnly:          fv.AliveOnly,
		MaxRetries:         fv.MaxRetries,
		MaxRetriesExplicit: fv.MaxRetriesExplicit,

		// 高级功能
		DNSLog:     fv.DNSLog,
		PortMap:    clonePortMap(config.DefaultPortMap),
		DefaultMap: cloneStringSlice(config.DefaultProbeMap),

		// 全局超时
		GlobalTimeout:         time.Duration(fv.GlobalTimeout) * time.Second,
		GlobalTimeoutExplicit: fv.GlobalTimeoutExplicit,

		// 分组配置
		Credentials: CredentialConfig{
			Username:      fv.Username,
			Password:      fv.Password,
			Domain:        fv.Domain,
			Userdict:      cloneStringSliceMap(config.DefaultUserDict),
			Passwords:     cloneStringSlice(config.DefaultPasswords),
			UserPassPairs: nil, // 后续解析
			SSHKeyPath:    fv.SSHKeyPath,
		},
		Network: NetworkConfig{
			HTTPProxy:        fv.HTTPProxy,
			Socks5Proxy:      fv.Socks5Proxy,
			Iface:            fv.Iface,
			WebTimeout:       time.Duration(fv.WebTimeout) * time.Second,
			MaxRedirects:     fv.MaxRedirects,
			PacketRateLimit:  fv.PacketRateLimit,
			MaxPacketCount:   fv.MaxPacketCount,
			ICMPRate:         fv.ICMPRate,
			ICMPRateExplicit: fv.ICMPRateExplicit,
		},
		Output: OutputConfig{
			File:            fv.Outputfile,
			Format:          fv.OutputFormat,
			DisableSave:     fv.DisableSave,
			NoColor:         fv.NoColor || !isStdoutTerminal(),
			Silent:          fv.Silent,
			DisableProgress: fv.DisableProgress,
			ShowProgress:    !fv.DisableProgress,
			LogLevel:        fv.LogLevel,
			Language:        fv.Language,
			PerfStats:       fv.PerfStats,
		},
		POC: POCConfig{
			PocPath:     fv.PocPath,
			PocName:     fv.PocName,
			Full:        fv.PocFull,
			Num:         fv.PocNum,
			NumExplicit: fv.PocNumExplicit,
			Disabled:    fv.DisablePocScan,
		},
		Redis: RedisConfig{
			Disabled:     fv.DisableRedis,
			File:         fv.RedisFile,
			Shell:        fv.RedisShell,
			WritePath:    fv.RedisWritePath,
			WriteContent: fv.RedisWriteContent,
			WriteFile:    fv.RedisWriteFile,
		},
		HTTP: HTTPConfig{
			Cookie:    fv.Cookie,
			UserAgent: defaultUserAgent(fv.UserAgent),
			Accept:    fv.Accept,
		},
		Target: TargetConfig{
			Ports:        fv.Ports,
			ExcludePorts: fv.ExcludePorts,
		},
	}
}

func isStdoutTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// defaultUserAgent 用户未通过 -ua 指定时使用稳定默认值。
func defaultUserAgent(ua string) string {
	if ua != "" {
		return ua
	}
	return DefaultHTTPUserAgent
}
