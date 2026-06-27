package WebScan

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/webscan/lib"
)

// 常量定义
const (
	protocolHTTP     = "http://"
	protocolHTTPS    = "https://"
	yamlExt          = ".yaml"
	ymlExt           = ".yml"
	defaultTimeout   = 30 * time.Second
	concurrencyLimit = 10 // 并发加载POC的限制
)

// 错误定义
var (
	ErrInvalidURL    = errors.New(i18n.GetText("webscan_err_invalid_url"))
	ErrEmptyTarget   = errors.New(i18n.GetText("webscan_err_empty_target"))
	ErrPocNotFound   = errors.New(i18n.GetText("webscan_err_poc_not_found"))
	ErrPocLoadFailed = errors.New(i18n.GetText("webscan_err_poc_load_failed"))
)

//go:embed pocs
var pocsFS embed.FS

// pocStore 按 PocPath 缓存已加载的 POC 集合，支持多 session 使用不同 POC 路径
type pocStore struct {
	mu    sync.Mutex
	cache map[string][]*lib.Poc // key: pocPath（空字符串表示内嵌 POC）
}

var globalPocStore = &pocStore{cache: make(map[string][]*lib.Poc)}

// WebScan 执行Web漏洞扫描
func WebScan(ctx context.Context, info *common.HostInfo, cfg *common.Config, session *common.ScanSession) {
	// 初始化POC配置（用于CEL回调函数）
	lib.InitPOCConfig(cfg.DNSLog)

	// 加载POC（按 PocPath 缓存，不同路径独立加载）
	pocs := globalPocStore.getOrLoad(cfg.POC.PocPath)

	// 验证输入
	if info == nil {
		session.LogError(i18n.GetText("invalid_scan_target"))
		return
	}

	if len(pocs) == 0 {
		session.LogError(i18n.GetText("poc_load_failed"))
		return
	}

	// 构建目标URL
	target, err := buildTargetURL(info)
	if err != nil {
		session.LogError(i18n.Tr("webscan_target_url_failed", err))
		return
	}

	// 超时兜底：如果调用方 ctx 没有 deadline，加一个默认超时
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	// 根据扫描策略执行POC
	if cfg.POC.PocName == "" && len(info.Info) == 0 {
		executePOCs(ctx, config.PocInfo{Target: target}, cfg, session, pocs)
	} else if len(info.Info) > 0 {
		scanByFingerprints(ctx, target, info.Info, cfg, session, pocs)
	} else if cfg.POC.PocName != "" {
		executePOCs(ctx, config.PocInfo{Target: target, PocName: cfg.POC.PocName}, cfg, session, pocs)
	}
}

// buildTargetURL 构建规范的目标URL
func buildTargetURL(info *common.HostInfo) (string, error) {
	// 自动构建URL
	if info.URL == "" {
		protocol := protocolHTTP
		if isTLSPort(info.Port) {
			protocol = protocolHTTPS
		}
		info.URL = protocol + net.JoinHostPort(info.Host, fmt.Sprint(info.Port))
	} else if !hasProtocolPrefix(info.URL) {
		info.URL = protocolHTTP + normalizeSchemelessWebTarget(info.URL)
	}

	// 解析URL以提取基础部分
	parsedURL, err := url.Parse(info.URL)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	if parsedURL.Hostname() == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidURL)
	}
	portStr := parsedURL.Port()
	if portStr == "" {
		if hasMalformedWebURLPort(parsedURL.Host) {
			return "", fmt.Errorf("%w: invalid port", ErrInvalidURL)
		}
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("%w: invalid port %q", ErrInvalidURL, portStr)
		}
	}
	parsedURL.Host = normalizeWebURLHost(parsedURL.Host)

	return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host), nil
}

// hasProtocolPrefix 检查URL是否包含协议前缀
func hasProtocolPrefix(urlStr string) bool {
	urlStr = strings.ToLower(urlStr)
	return strings.HasPrefix(urlStr, protocolHTTP) || strings.HasPrefix(urlStr, protocolHTTPS)
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 4443, 9443:
		return true
	default:
		return false
	}
}

func normalizeSchemelessWebTarget(rawURL string) string {
	authority := rawURL
	suffix := ""
	if idx := strings.IndexAny(rawURL, "/?#"); idx >= 0 {
		authority = rawURL[:idx]
		suffix = rawURL[idx:]
	}
	if strings.HasPrefix(authority, "[") {
		return authority + suffix
	}
	if ip := net.ParseIP(authority); ip != nil && strings.Contains(authority, ":") {
		return "[" + authority + "]" + suffix
	}
	return rawURL
}

func normalizeWebURLHost(host string) string {
	if strings.HasPrefix(host, "[") {
		return host
	}
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func hasMalformedWebURLPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndexByte(host, ']')
		return end >= 0 && len(host) > end+1 && host[end+1] == ':'
	}
	return strings.Contains(host, ":")
}

// getOrLoad 获取或加载指定路径的 POC 集合
func (s *pocStore) getOrLoad(pocPath string) []*lib.Poc {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pocs, ok := s.cache[pocPath]; ok {
		return pocs
	}

	pocs := loadPocs(pocPath)
	if len(pocs) > 0 {
		s.cache[pocPath] = pocs
	}
	return pocs
}

// scanByFingerprints 根据指纹执行POC
func scanByFingerprints(ctx context.Context, target string, fingerprints []string, cfg *common.Config, session *common.ScanSession, pocs []*lib.Poc) {
	for _, fingerprint := range fingerprints {
		if fingerprint == "" {
			continue
		}

		pocName := lib.CheckInfoPoc(fingerprint)
		if pocName == "" {
			continue
		}

		executePOCs(ctx, config.PocInfo{Target: target, PocName: pocName}, cfg, session, pocs)
	}
}

// executePOCs 执行POC检测
func executePOCs(ctx context.Context, pocInfo config.PocInfo, cfg *common.Config, session *common.ScanSession, pocs []*lib.Poc) {
	// 验证目标
	if pocInfo.Target == "" {
		session.LogError(ErrEmptyTarget.Error())
		return
	}

	// 确保URL格式正确
	if !hasProtocolPrefix(pocInfo.Target) {
		pocInfo.Target = protocolHTTP + pocInfo.Target
	}

	// 验证URL
	_, err := url.Parse(pocInfo.Target)
	if err != nil {
		session.LogError(i18n.Tr("webscan_invalid_url", ErrInvalidURL, pocInfo.Target, err))
		return
	}

	// 创建基础请求
	req, err := createBaseRequest(ctx, pocInfo.Target, cfg)
	if err != nil {
		session.LogError(i18n.Tr("webscan_request_create_failed", err))
		return
	}

	// 筛选POC
	matchedPocs := filterPocs(pocInfo.PocName, pocs)
	if len(matchedPocs) == 0 {
		session.LogDebug(fmt.Sprintf("%v: %s", ErrPocNotFound, pocInfo.PocName))
		return
	}

	// 构建POC执行上下文
	pocCtx := &lib.POCContext{
		DNSLog:  cfg.DNSLog,
		POCFull: cfg.POC.Full,
		Session: session,
	}

	// 执行POC检测
	lib.CheckMultiPoc(req, matchedPocs, cfg.POC.Num, pocCtx)
}

// createBaseRequest 创建带上下文的HTTP请求
func createBaseRequest(ctx context.Context, target string, cfg *common.Config) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	req.Header.Set("User-agent", cfg.HTTP.UserAgent)
	req.Header.Set("Accept", cfg.HTTP.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if cfg.HTTP.Cookie != "" {
		req.Header.Set("Cookie", cfg.HTTP.Cookie)
	}

	return req, nil
}

// loadPocs 加载指定路径的 POC（空路径表示内嵌 POC）
func loadPocs(pocPath string) []*lib.Poc {
	if pocPath == "" {
		return loadEmbeddedPocs()
	}
	return loadExternalPocs(pocPath)
}

// loadEmbeddedPocs 加载内置POC
func loadEmbeddedPocs() []*lib.Poc {
	entries, err := pocsFS.ReadDir("pocs")
	if err != nil {
		common.LogError(i18n.Tr("webscan_builtin_poc_failed", err))
		return nil
	}

	var pocFiles []string
	for _, entry := range entries {
		if isPocFile(entry.Name()) {
			pocFiles = append(pocFiles, entry.Name())
		}
	}

	return loadPocsConcurrently(pocFiles, true, "")
}

// loadExternalPocs 从外部路径加载POC
func loadExternalPocs(pocPath string) []*lib.Poc {
	if !directoryExists(pocPath) {
		common.LogError(i18n.Tr("webscan_poc_dir_not_exist", pocPath))
		return nil
	}

	var pocFiles []string
	err := filepath.Walk(pocPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if isPocFile(info.Name()) {
			pocFiles = append(pocFiles, path)
		}
		return nil
	})

	if err != nil {
		common.LogError(i18n.Tr("webscan_poc_dir_walk_failed", err))
		return nil
	}

	return loadPocsConcurrently(pocFiles, false, pocPath)
}

// loadPocsConcurrently 并发加载POC文件，返回加载结果
func loadPocsConcurrently(pocFiles []string, isEmbedded bool, pocPath string) []*lib.Poc {
	pocCount := len(pocFiles)
	if pocCount == 0 {
		return nil
	}

	var wg sync.WaitGroup
	results := make(chan *lib.Poc, pocCount)
	semaphore := make(chan struct{}, concurrencyLimit)

	for _, file := range pocFiles {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(filename string) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			var poc *lib.Poc
			var err error
			if isEmbedded {
				poc, err = lib.LoadPoc(filename, pocsFS)
			} else {
				poc, err = lib.LoadPocbyPath(filename)
			}

			if err == nil && poc != nil {
				results <- poc
			}
		}(file)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	pocs := make([]*lib.Poc, 0, pocCount)
	for poc := range results {
		pocs = append(pocs, poc)
	}

	failCount := pocCount - len(pocs)
	common.LogInfo(i18n.Tr("poc_load_complete", pocCount, len(pocs), failCount))
	return pocs
}

// directoryExists 检查目录是否存在
func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// isPocFile 检查文件是否为POC文件
func isPocFile(filename string) bool {
	lowerName := strings.ToLower(filename)
	return strings.HasSuffix(lowerName, yamlExt) || strings.HasSuffix(lowerName, ymlExt)
}

// filterPocs 根据POC名称筛选
func filterPocs(pocName string, pocs []*lib.Poc) []*lib.Poc {
	if pocName == "" {
		return pocs
	}

	searchName := strings.ToLower(pocName)

	var matchedPocs []*lib.Poc
	for _, poc := range pocs {
		if poc != nil && strings.Contains(strings.ToLower(poc.Name), searchName) {
			matchedPocs = append(matchedPocs, poc)
		}
	}

	return matchedPocs
}
