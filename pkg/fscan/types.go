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
	Name    string   `json:"name"`
	Types   []string `json:"types,omitempty"`
	Ports   []int    `json:"ports,omitempty"`
	Safe    bool     `json:"safe"`
	Default bool     `json:"default"`
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
