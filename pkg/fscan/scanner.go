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
	"github.com/shadow1ng/fscan/common/output"
	"github.com/shadow1ng/fscan/core"
	"github.com/shadow1ng/fscan/plugins"

	_ "github.com/shadow1ng/fscan/plugins/local"
	_ "github.com/shadow1ng/fscan/plugins/services"
	_ "github.com/shadow1ng/fscan/plugins/web"
)

var scanMu sync.Mutex

var defaultSafePlugins = []string{
	"activemq",
	"cassandra",
	"elasticsearch",
	"ftp",
	"kafka",
	"ldap",
	"memcached",
	"mongodb",
	"mssql",
	"mysql",
	"neo4j",
	"netbios",
	"oracle",
	"postgresql",
	"rabbitmq",
	"rdp",
	"redis",
	"rsync",
	"smb",
	"smtp",
	"ssh",
	"telnet",
	"vnc",
	"webtitle",
}

var unsafePlugins = map[string]struct{}{
	"cleaner":        {},
	"crontask":       {},
	"download":       {},
	"forwardshell":   {},
	"keylogger":      {},
	"ldpreload":      {},
	"minidump":       {},
	"reverseshell":   {},
	"socks5proxy":    {},
	"sshkey":         {},
	"systemdservice": {},
	"winbits":        {},
	"winifeo":        {},
	"winlogon":       {},
	"winregistry":    {},
	"winschtask":     {},
	"winservice":     {},
	"winstartup":     {},
	"winwmi":         {},
	"webpoc":         {},
}

// Scanner runs fscan from another Go process.
type Scanner struct {
	config Config
}

// NewScanner creates an embedded scanner.
func NewScanner(config Config) *Scanner {
	return &Scanner{config: config}
}

// DefaultSafePlugins returns the plugin set used by the SDK when Config.Plugins
// is empty. The returned slice can be modified by callers.
func DefaultSafePlugins() []string {
	return append([]string(nil), defaultSafePlugins...)
}

// ListPlugins returns metadata for all registered plugins, sorted by name.
func ListPlugins() []PluginInfo {
	names := plugins.All()
	sort.Strings(names)

	items := make([]PluginInfo, 0, len(names))
	for _, name := range names {
		if info, ok := GetPlugin(name); ok {
			items = append(items, info)
		}
	}
	return items
}

// GetPlugin returns metadata for a registered plugin.
func GetPlugin(name string) (PluginInfo, bool) {
	name = strings.TrimSpace(name)
	if name == "" || !plugins.Exists(name) {
		return PluginInfo{}, false
	}
	return PluginInfo{
		Name:    name,
		Types:   pluginTypes(name),
		Ports:   pluginPorts(name),
		Safe:    IsSafePlugin(name),
		Default: isDefaultSafePlugin(name),
	}, true
}

// ValidateConfig checks whether a config and target set can be used for an
// embedded scan. If no targets are passed, Config.Targets is validated.
func ValidateConfig(config Config, targets ...Target) error {
	if len(targets) == 0 {
		targets = config.Targets
	}
	return validateConfig(config, targets)
}

// IsSafePlugin reports whether a plugin may be used while AllowUnsafePlugins is
// false. Unknown plugin names are not safe.
func IsSafePlugin(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || !plugins.Exists(name) {
		return false
	}
	if plugins.HasType(name, plugins.PluginTypeLocal) {
		return false
	}
	if _, bad := unsafePlugins[name]; bad {
		return false
	}
	return true
}

// Scan runs the scanner for the provided targets and returns structured
// findings. If no targets are provided, Config.Targets is used.
func (s *Scanner) Scan(ctx context.Context, targets ...Target) ([]Result, error) {
	var (
		mu      sync.Mutex
		results []Result
	)
	err := s.ScanEach(ctx, func(result Result) error {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
		return nil
	}, targets...)
	return snapshotResults(&mu, results), err
}

// ScanEach runs the scanner and calls handle serially for each structured
// result without retaining all results in memory. If handle returns an error,
// the scan context is canceled and that error is returned.
func (s *Scanner) ScanEach(ctx context.Context, handle ResultHandler, targets ...Target) error {
	if handle == nil {
		return fmt.Errorf("fscan: result handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(targets) == 0 {
		targets = s.config.Targets
	}
	if err := validateConfig(s.config, targets); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	scanMu.Lock()
	defer scanMu.Unlock()

	previous := captureRuntime()
	defer previous.restore()

	var (
		errMu      sync.Mutex
		handleMu   sync.Mutex
		handlerErr error
	)

	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			if stored := getHandlerError(&errMu, &handlerErr); stored != nil {
				return stored
			}
			return err
		}
		sink := func(raw *output.ScanResult) error {
			if result, ok := convertOutputResult(raw); ok {
				handleMu.Lock()
				if err := handle(result); err != nil {
					handleMu.Unlock()
					setHandlerError(&errMu, &handlerErr, err)
					cancel()
					return err
				}
				if s.config.OnResult != nil {
					s.config.OnResult(result)
				}
				handleMu.Unlock()
			}
			return nil
		}
		if err := s.scanOne(ctx, target, sink); err != nil {
			return err
		}
		if stored := getHandlerError(&errMu, &handlerErr); stored != nil {
			return stored
		}
	}

	if stored := getHandlerError(&errMu, &handlerErr); stored != nil {
		return stored
	}
	return ctx.Err()
}

func (s *Scanner) scanOne(ctx context.Context, target Target, sink common.ResultSink) error {
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
	session.ResultSink = sink
	core.RunScan(ctx, info, session)
	return nil
}

func validateConfig(config Config, targets []Target) error {
	if len(targets) == 0 {
		return fmt.Errorf("fscan: at least one target is required")
	}
	for _, name := range normalizePlugins(config.Plugins) {
		if !plugins.Exists(name) {
			return fmt.Errorf("fscan: plugin %q not found", name)
		}
		if !config.AllowUnsafePlugins && !IsSafePlugin(name) {
			return fmt.Errorf("fscan: plugin %q is not enabled for embedded safe mode", name)
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
		ScanMode:            formatPlugins(config),
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

func formatPlugins(config Config) string {
	parts := normalizePlugins(config.Plugins)
	if len(parts) == 0 {
		if config.AllowUnsafePlugins {
			return "all"
		}
		parts = defaultSafePlugins
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

func normalizePlugins(pluginNames []string) []string {
	parts := make([]string, 0, len(pluginNames))
	for _, plugin := range pluginNames {
		plugin = strings.TrimSpace(plugin)
		if plugin != "" {
			parts = append(parts, plugin)
		}
	}
	return parts
}

func pluginTypes(name string) []string {
	types := make([]string, 0, 3)
	for _, pluginType := range []string{PluginTypeService, PluginTypeWeb, PluginTypeLocal} {
		if plugins.HasType(name, pluginType) {
			types = append(types, pluginType)
		}
	}
	return types
}

func pluginPorts(name string) []int {
	ports := plugins.GetPluginPorts(name)
	ports = append([]int(nil), ports...)
	sort.Ints(ports)
	return ports
}

func isDefaultSafePlugin(name string) bool {
	for _, plugin := range defaultSafePlugins {
		if plugin == name {
			return true
		}
	}
	return false
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

func convertOutputResult(raw *output.ScanResult) (Result, bool) {
	if raw == nil {
		return Result{}, false
	}
	result := Result{
		Time:    raw.Time,
		Type:    string(raw.Type),
		Target:  raw.Target,
		Status:  raw.Status,
		Details: raw.Details,
	}
	return result, result.Target != "" || result.Status != ""
}

func snapshotResults(mu *sync.Mutex, results []Result) []Result {
	mu.Lock()
	defer mu.Unlock()
	return append([]Result(nil), results...)
}

func setHandlerError(mu *sync.Mutex, target *error, err error) {
	mu.Lock()
	defer mu.Unlock()
	if *target == nil {
		*target = err
	}
}

func getHandlerError(mu *sync.Mutex, err *error) error {
	mu.Lock()
	defer mu.Unlock()
	return *err
}

type runtimeSnapshot struct {
	flagVars common.FlagVars
	config   *common.Config
	state    *common.State
}

func captureRuntime() runtimeSnapshot {
	return runtimeSnapshot{
		flagVars: *common.GetFlagVars(),
		config:   common.GetGlobalConfig(),
		state:    common.GetGlobalState(),
	}
}

func (s runtimeSnapshot) restore() {
	*common.GetFlagVars() = s.flagVars
	common.SetGlobalConfig(s.config)
	common.SetGlobalState(s.state)
	common.ResetLogger()
}
