package Core

import (
	"fmt"
	"github.com/schollz/progressbar/v3"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Global variable definitions
var (
	LocalScan bool // Local scan mode identifier
	WebScan   bool // Web scan mode identifier
)

// Scan executes the main scanning process
// info: Host information structure, contains basic information about the scan target
func Scan(info Common.HostInfo) {
	Common.LogInfo("Starting information scan")

	// Initialize HTTP client configuration
	lib.Inithttp()

	// Initialize concurrency control
	ch := make(chan struct{}, Common.ThreadNum)
	wg := sync.WaitGroup{}

	// Execute different scanning strategies based on scan mode
	switch {
	case Common.LocalMode:
		// Local information collection mode
		LocalScan = true
		executeLocalScan(info, &ch, &wg)
	case len(Common.URLs) > 0:
		// Web scanning mode
		WebScan = true
		executeWebScan(info, &ch, &wg)
	default:
		// Host scanning mode
		executeHostScan(info, &ch, &wg)
	}

	// Wait for all scanning tasks to complete
	finishScan(&wg)
}

// executeLocalScan executes local scanning
// info: Host information
// ch: Concurrency control channel
// wg: Wait group
func executeLocalScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("Executing local information collection")

	// Get list of plugins supported by local mode
	validLocalPlugins := getValidPlugins(Common.ModeLocal)

	// Validate scan mode legality
	if err := validateScanMode(validLocalPlugins, Common.ModeLocal); err != nil {
		Common.LogError(err.Error())
		return
	}

	// Output plugin information being used
	if Common.ScanMode == Common.ModeLocal {
		Common.LogInfo("Using all local plugins")
		Common.ParseScanMode(Common.ScanMode)
	} else {
		Common.LogInfo(fmt.Sprintf("Using plugin: %s", Common.ScanMode))
	}

	// Execute scanning tasks
	executeScans([]Common.HostInfo{info}, ch, wg)
}

// executeWebScan executes Web scanning
// info: Host information
// ch: Concurrency control channel
// wg: Wait group
func executeWebScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("Starting Web scanning")

	// Get list of plugins supported by Web mode
	validWebPlugins := getValidPlugins(Common.ModeWeb)

	// Validate scan mode legality
	if err := validateScanMode(validWebPlugins, Common.ModeWeb); err != nil {
		Common.LogError(err.Error())
		return
	}

	// Process target URL list
	var targetInfos []Common.HostInfo
	for _, url := range Common.URLs {
		urlInfo := info
		// Ensure URL contains protocol header
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}

	// Output plugin information being used
	if Common.ScanMode == Common.ModeWeb {
		Common.LogInfo("Using all Web plugins")
		Common.ParseScanMode(Common.ScanMode)
	} else {
		Common.LogInfo(fmt.Sprintf("Using plugin: %s", Common.ScanMode))
	}

	// Execute scanning tasks
	executeScans(targetInfos, ch, wg)
}

// executeHostScan executes host scanning
// info: Host information
// ch: Concurrency control channel
// wg: Wait group
func executeHostScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	// Validate scan target
	if info.Host == "" {
		Common.LogError("Scan target not specified")
		return
	}

	// Parse target host
	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		Common.LogError(fmt.Sprintf("Host parsing error: %v", err))
		return
	}

	Common.LogInfo("Starting host scanning")
	executeScan(hosts, info, ch, wg)
}

// getValidPlugins gets list of valid plugins for the specified mode
// mode: Scan mode
// returns: Valid plugins mapping table
func getValidPlugins(mode string) map[string]bool {
	validPlugins := make(map[string]bool)
	for _, plugin := range Common.PluginGroups[mode] {
		validPlugins[plugin] = true
	}
	return validPlugins
}

// validateScanMode validates the legality of scan mode
// validPlugins: Valid plugin list
// mode: Scan mode
// returns: Error information
func validateScanMode(validPlugins map[string]bool, mode string) error {
	if Common.ScanMode == "" || Common.ScanMode == "All" {
		Common.ScanMode = mode
	} else if _, exists := validPlugins[Common.ScanMode]; !exists {
		return fmt.Errorf("Invalid %s plugin: %s", mode, Common.ScanMode)
	}
	return nil
}

// executeScan executes main scanning process
// hosts: Target host list
// info: Host information
// ch: Concurrency control channel
// wg: Wait group
func executeScan(hosts []string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	var targetInfos []Common.HostInfo

	// Process host and port scanning
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		// Check host liveness
		if shouldPingScan(hosts) {
			hosts = CheckLive(hosts, Common.UsePing)
			Common.LogInfo(fmt.Sprintf("Number of live hosts: %d", len(hosts)))
			if Common.IsICMPScan() {
				return
			}
		}

		// Get alive ports
		alivePorts := getAlivePorts(hosts)
		if len(alivePorts) > 0 {
			targetInfos = prepareTargetInfos(alivePorts, info)
		}
	}

	// Add URL scanning targets
	targetInfos = appendURLTargets(targetInfos, info)

	// Execute vulnerability scanning
	if len(targetInfos) > 0 {
		Common.LogInfo("Starting vulnerability scanning")
		executeScans(targetInfos, ch, wg)
	}
}

// shouldPingScan determines if ping scanning should be executed
// hosts: Target host list
// returns: Whether ping scanning is needed
func shouldPingScan(hosts []string) bool {
	return (Common.DisablePing == false && len(hosts) > 1) || Common.IsICMPScan()
}

// getAlivePorts gets list of alive ports
// hosts: Target host list
// returns: List of alive ports
func getAlivePorts(hosts []string) []string {
	var alivePorts []string

	// Choose port scanning method based on scan mode
	if Common.IsWebScan() {
		alivePorts = NoPortScan(hosts, Common.Ports)
	} else if len(hosts) > 0 {
		alivePorts = PortScan(hosts, Common.Ports, Common.Timeout)
		Common.LogInfo(fmt.Sprintf("Number of alive ports: %d", len(alivePorts)))
		if Common.IsPortScan() {
			return nil
		}
	}

	// Merge additional specified ports
	if len(Common.HostPort) > 0 {
		alivePorts = append(alivePorts, Common.HostPort...)
		alivePorts = Common.RemoveDuplicate(alivePorts)
		Common.HostPort = nil
		Common.LogInfo(fmt.Sprintf("Number of alive ports: %d", len(alivePorts)))
	}

	return alivePorts
}

// appendURLTargets adds URL scanning targets
// targetInfos: Existing target list
// baseInfo: Base host information
// returns: Updated target list
func appendURLTargets(targetInfos []Common.HostInfo, baseInfo Common.HostInfo) []Common.HostInfo {
	for _, url := range Common.URLs {
		urlInfo := baseInfo
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}
	return targetInfos
}

// prepareTargetInfos prepares scanning target information
// alivePorts: Alive port list
// baseInfo: Base host information
// returns: Target information list
func prepareTargetInfos(alivePorts []string, baseInfo Common.HostInfo) []Common.HostInfo {
	var infos []Common.HostInfo
	for _, targetIP := range alivePorts {
		hostParts := strings.Split(targetIP, ":")
		if len(hostParts) != 2 {
			Common.LogError(fmt.Sprintf("Invalid target address format: %s", targetIP))
			continue
		}
		info := baseInfo
		info.Host = hostParts[0]
		info.Ports = hostParts[1]
		infos = append(infos, info)
	}
	return infos
}

// ScanTask scan task structure
type ScanTask struct {
	pluginName string          // Plugin name
	target     Common.HostInfo // Target information
}

// executeScans executes scanning tasks
// targets: Target list
// ch: Concurrency control channel
// wg: Wait group
func executeScans(targets []Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	mode := Common.GetScanMode()

	// Get list of plugins to execute
	pluginsToRun, isSinglePlugin := getPluginsToRun(mode)

	var tasks []ScanTask
	actualTasks := 0
	loadedPlugins := make([]string, 0)

	// Collect scanning tasks
	for _, target := range targets {
		targetPort, _ := strconv.Atoi(target.Ports)
		for _, pluginName := range pluginsToRun {
			plugin, exists := Common.PluginManager[pluginName]
			if !exists {
				continue
			}
			taskAdded, newTasks := collectScanTasks(plugin, target, targetPort, pluginName, isSinglePlugin)
			if taskAdded {
				actualTasks += len(newTasks)
				loadedPlugins = append(loadedPlugins, pluginName)
				tasks = append(tasks, newTasks...)
			}
		}
	}

	// Process plugin list
	finalPlugins := getUniquePlugins(loadedPlugins)
	Common.LogInfo(fmt.Sprintf("Loaded plugins: %s", strings.Join(finalPlugins, ", ")))

	// Initialize progress bar
	initializeProgressBar(actualTasks)

	// Execute scanning tasks
	for _, task := range tasks {
		AddScan(task.pluginName, task.target, ch, wg)
	}
}

// getPluginsToRun gets list of plugins to execute
// mode: Scan mode
// returns: Plugin list and whether it's single plugin mode
func getPluginsToRun(mode string) ([]string, bool) {
	var pluginsToRun []string
	isSinglePlugin := false

	if plugins := Common.GetPluginsForMode(mode); plugins != nil {
		pluginsToRun = plugins
	} else {
		pluginsToRun = []string{mode}
		isSinglePlugin = true
	}

	return pluginsToRun, isSinglePlugin
}

// collectScanTasks collects scanning tasks
// plugin: Plugin information
// target: Target information
// targetPort: Target port
// pluginName: Plugin name
// isSinglePlugin: Whether it's single plugin mode
// returns: Whether task was added and task list
func collectScanTasks(plugin Common.ScanPlugin, target Common.HostInfo, targetPort int, pluginName string, isSinglePlugin bool) (bool, []ScanTask) {
	var tasks []ScanTask
	taskAdded := false

	if WebScan || LocalScan || isSinglePlugin || len(plugin.Ports) == 0 || plugin.HasPort(targetPort) {
		taskAdded = true
		tasks = append(tasks, ScanTask{
			pluginName: pluginName,
			target:     target,
		})
	}

	return taskAdded, tasks
}

// getUniquePlugins gets deduplicated plugin list
// loadedPlugins: Already loaded plugin list
// returns: Deduplicated and sorted plugin list
func getUniquePlugins(loadedPlugins []string) []string {
	uniquePlugins := make(map[string]struct{})
	for _, p := range loadedPlugins {
		uniquePlugins[p] = struct{}{}
	}

	finalPlugins := make([]string, 0, len(uniquePlugins))
	for p := range uniquePlugins {
		finalPlugins = append(finalPlugins, p)
	}

	sort.Strings(finalPlugins)
	return finalPlugins
}

// initializeProgressBar initializes progress bar
// actualTasks: Actual number of tasks
func initializeProgressBar(actualTasks int) {
	if Common.ShowProgress {
		Common.ProgressBar = progressbar.NewOptions(actualTasks,
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(15),
			progressbar.OptionSetDescription("[cyan]Scanning progress:[reset]"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionThrottle(65*time.Millisecond),
			progressbar.OptionUseANSICodes(true),
			progressbar.OptionSetRenderBlankState(true),
		)
	}
}

// finishScan completes scanning tasks
// wg: Wait group
func finishScan(wg *sync.WaitGroup) {
	wg.Wait()
	if Common.ProgressBar != nil {
		Common.ProgressBar.Finish()
		fmt.Println()
	}
	Common.LogSuccess(fmt.Sprintf("Scanning completed: %v/%v", Common.End, Common.Num))
}

// Mutex for protecting concurrent access to shared resources
var Mutex = &sync.Mutex{}

// AddScan adds scanning task and starts scanning
// plugin: Plugin name
// info: Target information
// ch: Concurrency control channel
// wg: Wait group
func AddScan(plugin string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)

	go func() {
		defer func() {
			wg.Done()
			<-*ch
		}()

		atomic.AddInt64(&Common.Num, 1)
		ScanFunc(&plugin, &info)
		updateScanProgress(&info)
	}()
}

// ScanFunc executes scanning plugin
// name: Plugin name
// info: Target information
func ScanFunc(name *string, info *Common.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			Common.LogError(fmt.Sprintf("Scanning error %v:%v - %v", info.Host, info.Ports, err))
		}
	}()

	plugin, exists := Common.PluginManager[*name]
	if !exists {
		Common.LogInfo(fmt.Sprintf("Scan type %v has no corresponding plugin, skipped", *name))
		return
	}

	if err := plugin.ScanFunc(info); err != nil {
		Common.LogError(fmt.Sprintf("Scanning error %v:%v - %v", info.Host, info.Ports, err))
	}
}

// updateScanProgress updates scanning progress
// info: Target information
func updateScanProgress(info *Common.HostInfo) {
	Common.OutputMutex.Lock()
	atomic.AddInt64(&Common.End, 1)
	if Common.ProgressBar != nil {
		fmt.Print("\033[2K\r")
		Common.ProgressBar.Add(1)
	}
	Common.OutputMutex.Unlock()
}