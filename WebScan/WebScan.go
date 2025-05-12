package WebScan

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/lib"
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
	ErrInvalidURL    = errors.New("无效的URL格式")
	ErrEmptyTarget   = errors.New("目标URL为空")
	ErrPocNotFound   = errors.New("未找到匹配的POC")
	ErrPocLoadFailed = errors.New("POC加载失败")
)

//go:embed pocs
var pocsFS embed.FS
var (
	once    sync.Once
	allPocs []*lib.Poc
)

// WebScan 执行Web漏洞扫描
func WebScan(info *Common.HostInfo) {
	// 初始化POC
	once.Do(initPocs)

	// 验证输入
	if info == nil {
		Common.LogError("无效的扫描目标")
		return
	}

	if len(allPocs) == 0 {
		Common.LogError("POC加载失败，无法执行扫描")
		return
	}

	// 构建目标URL
	target, err := buildTargetURL(info)
	if err != nil {
		Common.LogError(fmt.Sprintf("构建目标URL失败: %v", err))
		return
	}

	// 使用带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// 根据扫描策略执行POC
	if Common.Pocinfo.PocName == "" && len(info.Infostr) == 0 {
		// 执行所有POC
		executePOCs(ctx, Common.PocInfo{Target: target})
	} else if len(info.Infostr) > 0 {
		// 基于指纹信息执行POC
		scanByFingerprints(ctx, target, info.Infostr)
	} else if Common.Pocinfo.PocName != "" {
		// 基于指定POC名称执行
		executePOCs(ctx, Common.PocInfo{Target: target, PocName: Common.Pocinfo.PocName})
	}
}

// buildTargetURL 构建规范的目标URL
func buildTargetURL(info *Common.HostInfo) (string, error) {
	// 自动构建URL
	if info.Url == "" {
		info.Url = fmt.Sprintf("%s%s:%s", protocolHTTP, info.Host, info.Ports)
	} else if !hasProtocolPrefix(info.Url) {
		info.Url = protocolHTTP + info.Url
	}

	// 解析URL以提取基础部分
	parsedURL, err := url.Parse(info.Url)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host), nil
}

// hasProtocolPrefix 检查URL是否包含协议前缀
func hasProtocolPrefix(urlStr string) bool {
	return strings.HasPrefix(urlStr, protocolHTTP) || strings.HasPrefix(urlStr, protocolHTTPS)
}

// scanByFingerprints 根据指纹执行POC
func scanByFingerprints(ctx context.Context, target string, fingerprints []string) {
	for _, fingerprint := range fingerprints {
		if fingerprint == "" {
			continue
		}

		pocName := lib.CheckInfoPoc(fingerprint)
		if pocName == "" {
			continue
		}

		executePOCs(ctx, Common.PocInfo{Target: target, PocName: pocName})
	}
}

// executePOCs 执行POC检测
func executePOCs(ctx context.Context, pocInfo Common.PocInfo) {
	// 验证目标
	if pocInfo.Target == "" {
		Common.LogError(ErrEmptyTarget.Error())
		return
	}

	// 确保URL格式正确
	if !hasProtocolPrefix(pocInfo.Target) {
		pocInfo.Target = protocolHTTP + pocInfo.Target
	}

	// 验证URL
	_, err := url.Parse(pocInfo.Target)
	if err != nil {
		Common.LogError(fmt.Sprintf("%v %s: %v", ErrInvalidURL, pocInfo.Target, err))
		return
	}

	// 创建基础请求
	req, err := createBaseRequest(ctx, pocInfo.Target)
	if err != nil {
		Common.LogError(fmt.Sprintf("创建HTTP请求失败: %v", err))
		return
	}

	// 筛选POC
	matchedPocs := filterPocs(pocInfo.PocName)
	if len(matchedPocs) == 0 {
		Common.LogDebug(fmt.Sprintf("%v: %s", ErrPocNotFound, pocInfo.PocName))
		return
	}

	// 执行POC检测
	lib.CheckMultiPoc(req, matchedPocs, Common.PocNum)
}

// createBaseRequest 创建带上下文的HTTP请求
func createBaseRequest(ctx context.Context, target string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	req.Header.Set("User-agent", Common.UserAgent)
	req.Header.Set("Accept", Common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if Common.Cookie != "" {
		req.Header.Set("Cookie", Common.Cookie)
	}

	return req, nil
}

// initPocs 初始化并加载POC
func initPocs() {
	allPocs = make([]*lib.Poc, 0)

	if Common.PocPath == "" {
		loadEmbeddedPocs()
	} else {
		loadExternalPocs(Common.PocPath)
	}
}

// loadEmbeddedPocs 加载内置POC
func loadEmbeddedPocs() {
	entries, err := pocsFS.ReadDir("pocs")
	if err != nil {
		Common.LogError(fmt.Sprintf("加载内置POC目录失败: %v", err))
		return
	}

	// 收集所有POC文件
	var pocFiles []string
	for _, entry := range entries {
		if isPocFile(entry.Name()) {
			pocFiles = append(pocFiles, entry.Name())
		}
	}

	// 并发加载POC文件
	loadPocsConcurrently(pocFiles, true, "")
}

// loadExternalPocs 从外部路径加载POC
func loadExternalPocs(pocPath string) {
	if !directoryExists(pocPath) {
		Common.LogError(fmt.Sprintf("POC目录不存在: %s", pocPath))
		return
	}

	// 收集所有POC文件路径
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
		Common.LogError(fmt.Sprintf("遍历POC目录失败: %v", err))
		return
	}

	// 并发加载POC文件
	loadPocsConcurrently(pocFiles, false, pocPath)
}

// loadPocsConcurrently 并发加载POC文件
func loadPocsConcurrently(pocFiles []string, isEmbedded bool, pocPath string) {
	pocCount := len(pocFiles)
	if pocCount == 0 {
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var successCount, failCount int

	// 使用信号量控制并发数
	semaphore := make(chan struct{}, concurrencyLimit)

	for _, file := range pocFiles {
		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量

		go func(filename string) {
			defer func() {
				<-semaphore // 释放信号量
				wg.Done()
			}()

			var poc *lib.Poc
			var err error

			// 根据不同的来源加载POC
			if isEmbedded {
				poc, err = lib.LoadPoc(filename, pocsFS)
			} else {
				poc, err = lib.LoadPocbyPath(filename)
			}

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				failCount++
				return
			}

			if poc != nil {
				allPocs = append(allPocs, poc)
				successCount++
			}
		}(file)
	}

	wg.Wait()
	Common.LogBase(fmt.Sprintf("POC加载完成: 总共%d个，成功%d个，失败%d个",
		pocCount, successCount, failCount))
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
func filterPocs(pocName string) []*lib.Poc {
	if pocName == "" {
		return allPocs
	}

	// 转换为小写以进行不区分大小写的匹配
	searchName := strings.ToLower(pocName)

	var matchedPocs []*lib.Poc
	for _, poc := range allPocs {
		if poc != nil && strings.Contains(strings.ToLower(poc.Name), searchName) {
			matchedPocs = append(matchedPocs, poc)
		}
	}

	return matchedPocs
}
