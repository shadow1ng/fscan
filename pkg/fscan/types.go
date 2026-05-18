package fscan

import (
	"time"
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

// Config controls an embedded scan. Zero values use the same conservative
// defaults as the CLI, except output is silent and file saving is disabled.
type Config struct {
	Targets []Target

	Plugins []string
	Ports   []int

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
