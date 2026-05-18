package fscan

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	commonconfig "github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/core"
	"github.com/shadow1ng/fscan/plugins"

	_ "github.com/shadow1ng/fscan/plugins/local"
	_ "github.com/shadow1ng/fscan/plugins/services"
	_ "github.com/shadow1ng/fscan/plugins/web"
)

var scanMu sync.Mutex

// Scanner runs fscan from another Go process.
type Scanner struct {
	config Config
}

// NewScanner creates an embedded scanner.
func NewScanner(config Config) *Scanner {
	return &Scanner{config: config}
}

// Scan runs the scanner for the provided targets and returns structured
// findings. If no targets are provided, Config.Targets is used.
func (s *Scanner) Scan(ctx context.Context, targets ...Target) ([]Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(targets) == 0 {
		targets = s.config.Targets
	}
	if err := validateConfig(s.config, targets); err != nil {
		return nil, err
	}

	scanMu.Lock()
	defer scanMu.Unlock()

	var (
		mu      sync.Mutex
		results []Result
	)
	restoreCallback := common.ReplaceResultCallback(func(raw interface{}) {
		if result, ok := decodeCallbackResult(raw); ok {
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}
	})
	defer restoreCallback()

	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return snapshotResults(&mu, results), err
		}
		if err := s.scanOne(ctx, target); err != nil {
			return snapshotResults(&mu, results), err
		}
	}

	return snapshotResults(&mu, results), ctx.Err()
}

func (s *Scanner) scanOne(ctx context.Context, target Target) error {
	fv := buildFlagVars(s.config, target)
	globalFV := common.GetFlagVars()
	*globalFV = *fv
	info := common.HostInfo{Host: strings.TrimSpace(target.Host), URL: strings.TrimSpace(target.URL)}

	i18n.SetLanguage(globalFV.Language)

	cfg, state, err := common.BuildConfig(globalFV, &info)
	if err != nil {
		return err
	}
	if len(s.config.UserPassPairs) > 0 {
		cfg.Credentials.UserPassPairs = make([]commonconfig.CredentialPair, 0, len(s.config.UserPassPairs))
		for _, pair := range s.config.UserPassPairs {
			cfg.Credentials.UserPassPairs = append(cfg.Credentials.UserPassPairs, commonconfig.CredentialPair{
				Username: pair.Username,
				Password: pair.Password,
			})
		}
	}
	cfg.Output.DisableSave = true
	cfg.Output.Silent = true
	cfg.Output.DisableProgress = true
	cfg.Output.ShowProgress = false

	common.SetGlobalConfig(cfg)
	common.SetGlobalState(state)
	common.ResetLogger()
	common.InitLogger()

	session := common.NewScanSession(cfg, state, globalFV)
	core.RunScan(ctx, info, session)
	return nil
}

func validateConfig(config Config, targets []Target) error {
	if len(targets) == 0 {
		return fmt.Errorf("fscan: at least one target is required")
	}
	for _, plugin := range config.Plugins {
		name := strings.TrimSpace(plugin)
		if name == "" {
			continue
		}
		if !plugins.Exists(name) {
			return fmt.Errorf("fscan: plugin %q not found", name)
		}
	}
	for _, target := range targets {
		if strings.TrimSpace(target.Host) == "" && strings.TrimSpace(target.URL) == "" {
			return fmt.Errorf("fscan: target host or URL is required")
		}
		if strings.TrimSpace(target.Host) != "" && strings.TrimSpace(target.URL) != "" {
			return fmt.Errorf("fscan: target cannot set both Host and URL")
		}
		for _, port := range target.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("fscan: invalid port %d", port)
			}
		}
	}
	for _, port := range config.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("fscan: invalid port %d", port)
		}
	}
	return nil
}

func buildFlagVars(config Config, target Target) *common.FlagVars {
	timeout := secondsOrDefault(config.Timeout, common.DefaultTimeout)
	webTimeout := secondsOrDefault(config.WebTimeout, 5)

	threadNum := config.Threads
	if threadNum <= 0 {
		threadNum = common.DefaultThreadNum
	}
	moduleThreads := config.ModuleThreads
	if moduleThreads <= 0 {
		moduleThreads = 20
	}
	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	maxRedirects := config.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}
	pocConcurrency := config.POCConcurrency
	if pocConcurrency <= 0 {
		pocConcurrency = 20
	}
	icmpRate := config.ICMPRate
	if icmpRate <= 0 {
		icmpRate = 0.1
	}
	language := config.Language
	if language == "" {
		language = common.DefaultLanguage
	}

	ports := config.Ports
	if len(target.Ports) > 0 {
		ports = target.Ports
	}

	return &common.FlagVars{
		Host:                strings.TrimSpace(target.Host),
		Ports:               formatPorts(ports),
		ScanMode:            formatPlugins(config.Plugins),
		ThreadNum:           threadNum,
		ModuleThreadNum:     moduleThreads,
		TimeoutSec:          timeout,
		GlobalTimeout:       180,
		DisablePing:         config.DisablePing,
		DisableTcpProbe:     config.DisableTCPProbe,
		AliveOnly:           false,
		DisableBrute:        config.DisableBrute,
		MaxRetries:          maxRetries,
		Username:            strings.Join(config.Usernames, ","),
		Password:            strings.Join(config.Passwords, ","),
		Domain:              config.Domain,
		SSHKeyPath:          config.SSHKeyPath,
		TargetURL:           strings.TrimSpace(target.URL),
		WebTimeout:          webTimeout,
		MaxRedirects:        maxRedirects,
		HTTPProxy:           config.HTTPProxy,
		Socks5Proxy:         config.Socks5Proxy,
		Iface:               config.Interface,
		PocPath:             config.POCPath,
		PocName:             config.POCName,
		PocFull:             config.POCFull,
		PocNum:              pocConcurrency,
		DisablePocScan:      config.DisablePOCScan,
		PacketRateLimit:     config.PacketRateLimit,
		MaxPacketCount:      config.MaxPacketCount,
		ICMPRate:            icmpRate,
		Outputfile:          "result.txt",
		OutputFormat:        "txt",
		DisableSave:         true,
		Silent:              true,
		NoColor:             true,
		LogLevel:            common.LogLevelError,
		DisableProgress:     true,
		Language:            language,
		ForwardShellPort:    4444,
		KeyloggerOutputFile: "keylog.txt",
	}
}

func formatPlugins(plugins []string) string {
	if len(plugins) == 0 {
		return "all"
	}
	parts := make([]string, 0, len(plugins))
	for _, plugin := range plugins {
		plugin = strings.TrimSpace(plugin)
		if plugin != "" {
			parts = append(parts, plugin)
		}
	}
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, ",")
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return commonconfig.MainPorts
	}
	ports = append([]int(nil), ports...)
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

func secondsOrDefault(value time.Duration, fallback int) int64 {
	if value <= 0 {
		return int64(fallback)
	}
	seconds := int64(value.Round(time.Second) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func decodeCallbackResult(raw interface{}) (Result, bool) {
	item, ok := raw.(map[string]interface{})
	if !ok {
		return Result{}, false
	}

	result := Result{
		Type:    stringValue(item["type"]),
		Target:  stringValue(item["target"]),
		Status:  stringValue(item["status"]),
		Details: mapValue(item["details"]),
	}
	if t, ok := item["time"].(time.Time); ok {
		result.Time = t
	}
	return result, result.Target != "" || result.Status != ""
}

func stringValue(value interface{}) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func mapValue(value interface{}) map[string]interface{} {
	if value == nil {
		return nil
	}
	if m, ok := value.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func snapshotResults(mu *sync.Mutex, results []Result) []Result {
	mu.Lock()
	defer mu.Unlock()
	return append([]Result(nil), results...)
}
