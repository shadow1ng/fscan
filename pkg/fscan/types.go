package fscan

import (
	"time"
)

const (
	// PluginTypeWeb marks web-facing plugins.
	PluginTypeWeb = "web"
	// PluginTypeLocal marks plugins that operate on the local host.
	PluginTypeLocal = "local"
	// PluginTypeService marks network service plugins.
	PluginTypeService = "service"
	// PluginTypeUDP marks UDP protocol plugins that bypass TCP port scanning.
	PluginTypeUDP = "udp"
)

const (
	// PluginCapabilityDetect marks passive or low-impact detection behavior.
	PluginCapabilityDetect = "detect"
	// PluginCapabilityAuthCheck marks credential validation behavior.
	PluginCapabilityAuthCheck = "auth-check"
	// PluginCapabilityBrute marks dictionary-style credential attempts.
	PluginCapabilityBrute = "brute"
	// PluginCapabilityPOC marks active vulnerability checks or exploitation.
	PluginCapabilityPOC = "poc"
	// PluginCapabilityLocalEffect marks plugins that change or inspect local host state.
	PluginCapabilityLocalEffect = "local-effect"
)

const (
	// ResultTypeHost reports a live host.
	ResultTypeHost = "HOST"
	// ResultTypePort reports an open port.
	ResultTypePort = "PORT"
	// ResultTypeService reports a service fingerprint or service plugin result.
	ResultTypeService = "SERVICE"
	// ResultTypeVuln reports a vulnerability or credential finding.
	ResultTypeVuln = "VULN"
)

// Target describes one scan target. Use Host for host/IP/CIDR/range service
// scans, or URL for web scans. Ports applies only to Host scans.
type Target struct {
	Host  string
	URL   string
	Ports []int
}

// CredentialPair pins one username/password pair.
type CredentialPair struct {
	Username string
	Password string
}

// PluginInfo describes one registered scanner plugin.
type PluginInfo struct {
	Name         string   `json:"name"`
	Types        []string `json:"types,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Ports        []int    `json:"ports,omitempty"`
	Safe         bool     `json:"safe"`
	Default      bool     `json:"default"`
}

// ResultSummary counts common result categories.
type ResultSummary struct {
	Total       int `json:"total"`
	Hosts       int `json:"hosts"`
	Ports       int `json:"ports"`
	Services    int `json:"services"`
	Vulns       int `json:"vulns"`
	Web         int `json:"web"`
	Credentials int `json:"credentials"`
}

// ScanStats reports runtime counters for one embedded scan call.
type ScanStats struct {
	Duration          time.Duration `json:"duration"`
	TasksTotal        int64         `json:"tasks_total"`
	TasksCompleted    int64         `json:"tasks_completed"`
	Packets           int64         `json:"packets"`
	TCPPackets        int64         `json:"tcp_packets"`
	TCPSuccessPackets int64         `json:"tcp_success_packets"`
	TCPFailedPackets  int64         `json:"tcp_failed_packets"`
	UDPPackets        int64         `json:"udp_packets"`
	HTTPPackets       int64         `json:"http_packets"`
	ResourceExhausted int64         `json:"resource_exhausted"`
}

// ScanProgress reports live scan progress for Agent integrations.
type ScanProgress struct {
	TasksTotal     int64         `json:"tasks_total"`
	TasksCompleted int64         `json:"tasks_completed"`
	Duration       time.Duration `json:"duration"`
	Packets        int64         `json:"packets"`
	TCPPackets     int64         `json:"tcp_packets"`
	HTTPPackets    int64         `json:"http_packets"`
	Paused         bool          `json:"paused"`
}

// ScanReport returns structured results with summary and runtime counters.
type ScanReport struct {
	Results []Result      `json:"results"`
	Summary ResultSummary `json:"summary"`
	Stats   ScanStats     `json:"stats"`
}

// ResultHandler receives one structured result. Calls are serialized by the
// scanner. Returning an error asks the scanner to stop and returns that error
// to the caller.
type ResultHandler func(Result) error

// Config controls an embedded scan. Zero values use the same conservative
// defaults as the CLI, except output is silent and file saving is disabled.
type Config struct {
	Targets []Target

	Plugins []string
	Ports   []int
	// AllowUnsafePlugins permits plugins with local side effects or long-lived
	// behavior. It is false by default for embedded endpoint use.
	AllowUnsafePlugins bool
	// OnResult is called for every structured result as it is discovered.
	OnResult func(Result)
	// OnProgress is called periodically with live scan progress.
	OnProgress func(ScanProgress)
	// TaskID is injected into every Result.Details["task_id"] when non-empty.
	TaskID string

	Timeout       time.Duration
	Threads       int
	ModuleThreads int
	MaxRetries    int

	DisablePing     bool
	DisableTCPProbe bool
	DisableBrute    bool

	Usernames       []string
	Passwords       []string
	UserPassPairs   []CredentialPair
	Domain          string
	SSHKeyPath      string
	HTTPProxy       string
	Socks5Proxy     string
	Interface       string
	WebTimeout      time.Duration
	MaxRedirects    int
	DisablePOCScan  bool
	POCPath         string
	POCName         string
	POCFull         bool
	POCConcurrency  int
	PacketRateLimit int64
	MaxPacketCount  int64
	ICMPRate        float64
	Language        string
}

// Result is the structured scan result returned to embedded callers.
type Result struct {
	Time    time.Time              `json:"time"`
	Type    string                 `json:"type"`
	Target  string                 `json:"target"`
	Status  string                 `json:"status"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// PortResult is a typed view over an open port result.
type PortResult struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
}

// ServiceResult is a typed view over a service or web detection result.
type ServiceResult struct {
	Target   string `json:"target"`
	Port     int    `json:"port,omitempty"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	URL      string `json:"url,omitempty"`
	IsWeb    bool   `json:"is_web,omitempty"`
}

// CredentialResult is a typed view over a weak credential result.
type CredentialResult struct {
	Target   string `json:"target"`
	Service  string `json:"service,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// VulnerabilityResult is a typed view over a vulnerability result.
type VulnerabilityResult struct {
	Target        string `json:"target"`
	Service       string `json:"service,omitempty"`
	Vulnerability string `json:"vulnerability"`
}
