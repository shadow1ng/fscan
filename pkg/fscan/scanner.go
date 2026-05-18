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
	"imap",
	"jdwp",
	"pop3",
	"rsync",
	"smb",
	"smtp",
	"snmp",
	"ssh",
	"telnet",
	"vnc",
	"webtitle",
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
		Name:         name,
		Types:        pluginTypes(name),
		Capabilities: PluginCapabilities(name),
		Ports:        pluginPorts(name),
		Safe:         IsSafePlugin(name),
		Default:      isDefaultSafePlugin(name),
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
	return plugins.IsSafe(name) && !hasPluginCapability(name, PluginCapabilityPOC, PluginCapabilityLocalEffect)
}

// PluginCapabilities returns the SDK-facing behavior classes for a plugin.
func PluginCapabilities(name string) []string {
	name = strings.TrimSpace(name)
	if name == "" || !plugins.Exists(name) {
		return nil
	}
	return pluginCapabilities(name)
}

type scanOpts struct {
	controller *ScanController
}

// Scan runs the scanner for the provided targets and returns structured
// findings. If no targets are provided, Config.Targets is used.
func (s *Scanner) Scan(ctx context.Context, targets ...Target) ([]Result, error) {
	report, err := s.ScanReport(ctx, targets...)
	return report.Results, err
}

// ScanReport runs the scanner and returns results with summary and runtime stats.
func (s *Scanner) ScanReport(ctx context.Context, targets ...Target) (ScanReport, error) {
	return s.collectReport(ctx, scanOpts{}, targets...)
}

// ScanEach runs the scanner and calls handle serially for each structured
// result without retaining all results in memory. If handle returns an error,
// the scan context is canceled and that error is returned.
func (s *Scanner) ScanEach(ctx context.Context, handle ResultHandler, targets ...Target) error {
	_, err := s.scanEach(ctx, scanOpts{}, handle, targets...)
	return err
}

// ScanWithController starts a scan and returns a controller for pause/resume
// and live stats. The scan runs in a background goroutine; read the returned
// channels to get the report and error when the scan completes.
func (s *Scanner) ScanWithController(ctx context.Context, targets ...Target) (*ScanController, <-chan ScanReport, <-chan error) {
	ctrl := newScanController()
	reportCh := make(chan ScanReport, 1)
	errCh := make(chan error, 1)

	go func() {
		report, err := s.collectReport(ctx, scanOpts{controller: ctrl}, targets...)
		reportCh <- report
		errCh <- err
	}()

	return ctrl, reportCh, errCh
}

func (s *Scanner) collectReport(ctx context.Context, opts scanOpts, targets ...Target) (ScanReport, error) {
	var (
		mu      sync.Mutex
		results []Result
	)
	stats, err := s.scanEach(ctx, opts, func(result Result) error {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
		return nil
	}, targets...)
	results = snapshotResults(&mu, results)
	return ScanReport{
		Results: results,
		Summary: SummarizeResults(results),
		Stats:   stats,
	}, err
}

func (s *Scanner) scanEach(ctx context.Context, opts scanOpts, handle ResultHandler, targets ...Target) (ScanStats, error) {
	if handle == nil {
		return ScanStats{}, fmt.Errorf("fscan: result handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(targets) == 0 {
		targets = s.config.Targets
	}
	if err := validateConfig(s.config, targets); err != nil {
		return ScanStats{}, err
	}

	ctrl := opts.controller
	if ctrl == nil && s.config.OnProgress != nil {
		ctrl = newScanController()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	restoreLogger := common.PushSilentLogger()
	defer restoreLogger()

	if ctrl != nil && s.config.OnProgress != nil {
		progressCtx, progressCancel := context.WithCancel(ctx)
		defer progressCancel()
		onProgress := s.config.OnProgress
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					onProgress(ctrl.progress())
				case <-progressCtx.Done():
					return
				}
			}
		}()
	}

	var (
		errMu      sync.Mutex
		handleMu   sync.Mutex
		handlerErr error
	)
	var stats ScanStats

	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			if stored := getHandlerError(&errMu, &handlerErr); stored != nil {
				return stats, stored
			}
			return stats, err
		}
		sink := func(raw *output.ScanResult) error {
			if result, ok := convertOutputResult(raw); ok {
				s.injectTaskID(&result)
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
		report, err := s.scanOne(ctx, target, sink, opts)
		stats.add(coreStatsToSDK(report))
		if err != nil {
			if stored := getHandlerError(&errMu, &handlerErr); stored != nil {
				return stats, stored
			}
			return stats, err
		}
		if stored := getHandlerError(&errMu, &handlerErr); stored != nil {
			return stats, stored
		}
	}

	if stored := getHandlerError(&errMu, &handlerErr); stored != nil {
		return stats, stored
	}
	return stats, ctx.Err()
}

func (s *Scanner) injectTaskID(result *Result) {
	if s.config.TaskID == "" {
		return
	}
	if result.Details == nil {
		result.Details = make(map[string]interface{})
	}
	result.Details["task_id"] = s.config.TaskID
}

func (s *Scanner) scanOne(ctx context.Context, target Target, sink common.ResultSink, opts scanOpts) (core.ScanReport, error) {
	fv := buildFlagVars(s.config, target)
	info := common.HostInfo{Host: strings.TrimSpace(target.Host), URL: strings.TrimSpace(target.URL)}

	if strings.TrimSpace(s.config.Language) != "" {
		previousLanguage := i18n.GetLanguage()
		i18n.SetLanguage(fv.Language)
		defer i18n.SetLanguage(previousLanguage)
	}

	cfg, state, err := common.BuildConfig(fv, &info)
	if err != nil {
		return core.ScanReport{}, err
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

	session := common.NewScanSession(cfg, state, fv)
	session.ResultSink = sink

	if opts.controller != nil {
		session.PauseGate = opts.controller.pauseGate
		opts.controller.addState(state)
	}

	return core.RunScan(ctx, info, session)
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
	types := make([]string, 0, 4)
	for _, pluginType := range []string{PluginTypeService, PluginTypeWeb, PluginTypeLocal, PluginTypeUDP} {
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

func pluginCapabilities(name string) []string {
	capSet := map[string]struct{}{}
	add := func(capability string) {
		capSet[capability] = struct{}{}
	}

	if plugins.HasType(name, PluginTypeService) || plugins.HasType(name, PluginTypeWeb) || plugins.HasType(name, PluginTypeUDP) {
		add(PluginCapabilityDetect)
	}
	if serviceAuthPlugins[name] {
		add(PluginCapabilityAuthCheck)
		add(PluginCapabilityBrute)
	}
	if activePOCPlugins[name] || strings.Contains(name, "poc") {
		add(PluginCapabilityPOC)
	}
	if plugins.HasType(name, PluginTypeLocal) {
		add(PluginCapabilityLocalEffect)
	}

	capabilities := make([]string, 0, len(capSet))
	for capability := range capSet {
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	return capabilities
}

func hasPluginCapability(name string, capabilities ...string) bool {
	pluginCaps := pluginCapabilities(name)
	for _, want := range capabilities {
		for _, got := range pluginCaps {
			if got == want {
				return true
			}
		}
	}
	return false
}

var serviceAuthPlugins = map[string]bool{
	"activemq":      true,
	"cassandra":     true,
	"elasticsearch": true,
	"ftp":           true,
	"imap":          true,
	"kafka":         true,
	"ldap":          true,
	"memcached":     true,
	"mongodb":       true,
	"mssql":         true,
	"mysql":         true,
	"neo4j":         true,
	"oracle":        true,
	"pop3":          true,
	"postgresql":    true,
	"rabbitmq":      true,
	"redis":         true,
	"rsync":         true,
	"smb":           true,
	"smtp":          true,
	"snmp":          true,
	"ssh":           true,
	"telnet":        true,
	"vnc":           true,
}

var activePOCPlugins = map[string]bool{
	"ms17010": true,
	"webpoc":  true,
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

func coreStatsToSDK(report core.ScanReport) ScanStats {
	return ScanStats{
		Duration:          report.Duration,
		TasksTotal:        report.TasksTotal,
		TasksCompleted:    report.TasksCompleted,
		Packets:           report.Packets,
		TCPPackets:        report.TCPPackets,
		TCPSuccessPackets: report.TCPSuccessPackets,
		TCPFailedPackets:  report.TCPFailedPackets,
		UDPPackets:        report.UDPPackets,
		HTTPPackets:       report.HTTPPackets,
		ResourceExhausted: report.ResourceExhausted,
	}
}

func (s *ScanStats) add(other ScanStats) {
	s.Duration += other.Duration
	s.TasksTotal += other.TasksTotal
	s.TasksCompleted += other.TasksCompleted
	s.Packets += other.Packets
	s.TCPPackets += other.TCPPackets
	s.TCPSuccessPackets += other.TCPSuccessPackets
	s.TCPFailedPackets += other.TCPFailedPackets
	s.UDPPackets += other.UDPPackets
	s.HTTPPackets += other.HTTPPackets
	s.ResourceExhausted += other.ResourceExhausted
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
