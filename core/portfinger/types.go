package portfinger

import (
	"regexp"
)

// VScan 主扫描器结构体
type VScan struct {
	Exclude        string
	AllProbes      []Probe
	UDPProbes      []Probe
	Probes         []Probe
	ProbesMapKName map[string]Probe
}

// MaxFallbacks 最大 fallback 数量（与 Nmap 一致）
const MaxFallbacks = 20

// Probe 探测器结构体
type Probe struct {
	Name     string // 探测器名称
	Data     string // 探测数据
	DecodedData []byte // 预解码的探测数据
	Protocol string // 协议
	Ports    string // 端口范围
	SSLPorts string // SSL端口范围

	TotalWaitMS  int    // 总等待时间
	TCPWrappedMS int    // TCP包装等待时间
	Rarity       int    // 稀有度
	Fallback     string // 回退探测器名称（原始字符串）

	// Fallbacks 编译后的 fallback 探测器数组
	// 顺序: [自身, fallback指令中的探测器..., NULL探测器(TCP)]
	Fallbacks [MaxFallbacks + 1]*Probe

	Matchs *[]Match // 匹配规则列表
}

// Match 匹配规则结构体
type Match struct {
	IsSoft          bool           // 是否为软匹配
	Service         string         // 服务名称
	Pattern         string         // 匹配模式
	VersionInfo     string         // 版本信息格式
	FoundItems      []string       // 找到的项目
	PatternCompiled *regexp.Regexp // 编译后的正则表达式
}

// Directive 指令结构体
type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

// Extras 额外信息结构体
type Extras struct {
	VendorProduct   string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	CPE             string
}

// Target 目标结构体
type Target struct {
	Host    string
	Port    int
	Timeout int
}
