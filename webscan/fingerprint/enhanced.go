package fingerprint

import (
	"crypto/md5" //nolint:gosec
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/shadow1ng/fscan/common/i18n"
)

//go:embed web_fingerprint_v4.json
var fingerprintHubData []byte

// EnhancedFingerprint FingerprintHub增强指纹结构
type EnhancedFingerprint struct {
	ID   string `json:"id"`
	Info struct {
		Name     string                 `json:"name"`
		Author   string                 `json:"author"`
		Tags     string                 `json:"tags"`
		Severity string                 `json:"severity"`
		Metadata map[string]interface{} `json:"metadata"`
	} `json:"info"`
	HTTP []struct {
		Method   string   `json:"method"`
		Path     []string `json:"path"`
		Matchers []struct {
			Type            string   `json:"type"`
			Words           []string `json:"words"`
			Regex           []string `json:"regex"`
			Hash            []string `json:"hash"` // favicon hash
			Part            string   `json:"part"` // header, body
			CaseInsensitive bool     `json:"case-insensitive"`
			Condition       string   `json:"condition"` // and, or
		} `json:"matchers"`
	} `json:"http"`
}

// EnhancedFingerprintDB 增强指纹数据库
type EnhancedFingerprintDB struct {
	Fingerprints []*EnhancedFingerprint
	regexCache   sync.Map // pattern → *regexp.Regexp，无锁并发安全
}

var (
	enhancedDB     *EnhancedFingerprintDB
	enhancedDBOnce sync.Once // 保证只初始化一次
)

// LoadEnhancedFingerprints 加载增强指纹库
func LoadEnhancedFingerprints() error {
	var fps []*EnhancedFingerprint
	if err := json.Unmarshal(fingerprintHubData, &fps); err != nil {
		return fmt.Errorf("%s: %w", i18n.GetText("fingerprint_enhanced_parse_failed"), err)
	}

	// 预处理：CaseInsensitive 的 matcher 预先小写化 Words，避免匹配时重复分配
	for _, fp := range fps {
		for hi := range fp.HTTP {
			for mi := range fp.HTTP[hi].Matchers {
				m := &fp.HTTP[hi].Matchers[mi]
				if m.CaseInsensitive && m.Type == "word" {
					for wi, w := range m.Words {
						m.Words[wi] = strings.ToLower(w)
					}
				}
			}
		}
	}

	enhancedDB = &EnhancedFingerprintDB{
		Fingerprints: fps,
	}

	return nil
}

// fingerprintMatch 指纹匹配结果（带优先级）
type fingerprintMatch struct {
	Name     string
	Priority int // 优先级分数，越高越优先
}

// MatchEnhancedFingerprints 匹配增强指纹（并发版本，结果按优先级排序）
func MatchEnhancedFingerprints(body []byte, headers string, favicon FaviconHashes) []string {
	// 使用 sync.Once 保证只初始化一次，线程安全
	enhancedDBOnce.Do(func() {
		_ = LoadEnhancedFingerprints() // 忽略错误，enhancedDB 为 nil 时下面会返回 nil
	})

	if enhancedDB == nil || len(enhancedDB.Fingerprints) == 0 {
		return nil
	}

	bodyStr := string(body)
	fingerprints := enhancedDB.Fingerprints
	total := len(fingerprints)

	// 根据 CPU 核心数决定并发数，但不超过指纹数量
	workers := runtime.NumCPU()
	if workers > total {
		workers = total
	}
	if workers < 1 {
		workers = 1
	}

	// 每个 worker 处理的指纹数量
	chunkSize := (total + workers - 1) / workers

	// 结果收集 channel（带优先级信息）
	resultCh := make(chan fingerprintMatch, total)
	var wg sync.WaitGroup

	// 启动 worker
	for i := 0; i < workers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > total {
			end = total
		}
		if start >= total {
			break
		}

		wg.Add(1)
		go func(fps []*EnhancedFingerprint) {
			defer wg.Done()
			for _, fp := range fps {
				if len(fp.HTTP) == 0 {
					continue
				}
				httpRule := fp.HTTP[0]
				for _, matcher := range httpRule.Matchers {
					if matchMatcher(matcher, bodyStr, headers, favicon) {
						resultCh <- fingerprintMatch{
							Name:     fp.Info.Name,
							Priority: calcPriority(fp, matcher.Type),
						}
						break
					}
				}
			}
		}(fingerprints[start:end])
	}

	// 等待所有 worker 完成后关闭 channel
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 收集结果
	var matches []fingerprintMatch
	for m := range resultCh {
		matches = append(matches, m)
	}

	// 按优先级排序（降序）
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		return matches[i].Name < matches[j].Name // 同优先级按名称排序
	})

	// 提取名称
	result := make([]string, len(matches))
	for i, m := range matches {
		result[i] = m.Name
	}

	return result
}

// calcPriority 计算指纹优先级分数
func calcPriority(fp *EnhancedFingerprint, matcherType string) int {
	priority := 0

	// 匹配类型权重（favicon 最精确）
	switch matcherType {
	case "favicon":
		priority += 100
	case "regex":
		priority += 50
	case "word":
		priority += 30
	}

	// verified 状态加分
	if fp.Info.Metadata != nil {
		if verified, ok := fp.Info.Metadata["verified"].(bool); ok && verified {
			priority += 20
		}
	}

	return priority
}

// matchMatcher 匹配单个matcher
func matchMatcher(matcher struct {
	Type            string   `json:"type"`
	Words           []string `json:"words"`
	Regex           []string `json:"regex"`
	Hash            []string `json:"hash"`
	Part            string   `json:"part"`
	CaseInsensitive bool     `json:"case-insensitive"`
	Condition       string   `json:"condition"`
}, body, headers string, favicon FaviconHashes) bool {

	switch matcher.Type {
	case "word":
		return matchWords(matcher, body, headers)
	case "regex":
		return matchRegex(matcher, body, headers)
	case "favicon":
		return matchFavicon(matcher, favicon)
	default:
		return false
	}
}

// matchWords 匹配关键词
func matchWords(matcher struct {
	Type            string   `json:"type"`
	Words           []string `json:"words"`
	Regex           []string `json:"regex"`
	Hash            []string `json:"hash"`
	Part            string   `json:"part"`
	CaseInsensitive bool     `json:"case-insensitive"`
	Condition       string   `json:"condition"`
}, body, headers string) bool {

	// 确定匹配目标
	target := body
	if matcher.Part == "header" {
		target = headers
	}

	// CaseInsensitive: target 转小写一次，Words 已在加载时预处理（直接调用时也兼容未预处理的词）
	if matcher.CaseInsensitive {
		target = strings.ToLower(target)
	}

	// 默认condition为or
	isAnd := matcher.Condition == "and"
	matchCount := 0

	for _, searchWord := range matcher.Words {
		if matcher.CaseInsensitive {
			searchWord = strings.ToLower(searchWord)
		}
		if strings.Contains(target, searchWord) {
			if !isAnd {
				// OR条件：匹配任一即可
				return true
			}
			matchCount++
		} else if isAnd {
			// AND条件：任一不匹配即失败
			return false
		}
	}

	// AND条件：全部匹配
	return isAnd && matchCount == len(matcher.Words)
}

// matchRegex 匹配正则表达式
func matchRegex(matcher struct {
	Type            string   `json:"type"`
	Words           []string `json:"words"`
	Regex           []string `json:"regex"`
	Hash            []string `json:"hash"`
	Part            string   `json:"part"`
	CaseInsensitive bool     `json:"case-insensitive"`
	Condition       string   `json:"condition"`
}, body, headers string) bool {

	// 确定匹配目标
	target := body
	if matcher.Part == "header" {
		target = headers
	}

	// 默认condition为or
	isAnd := matcher.Condition == "and"

	for _, pattern := range matcher.Regex {
		// CaseInsensitive 正则需要前缀
		cacheKey := pattern
		if matcher.CaseInsensitive {
			cacheKey = "(?i)" + pattern
		}

		// 从 sync.Map 缓存获取或编译正则
		var re *regexp.Regexp
		if cached, ok := enhancedDB.regexCache.Load(cacheKey); ok {
			if r, ok := cached.(*regexp.Regexp); ok {
				re = r
			}
		} else {
			compiled, err := regexp.Compile(cacheKey)
			if err != nil {
				continue
			}
			actual, _ := enhancedDB.regexCache.LoadOrStore(cacheKey, compiled)
			if r, ok := actual.(*regexp.Regexp); ok {
				re = r
			}
		}

		// 确保 re 不为 nil（防止并发场景下的 nil panic）
		if re != nil && re.MatchString(target) {
			if !isAnd {
				return true
			}
		} else if isAnd {
			return false
		}
	}

	// AND条件需要全部匹配
	return isAnd && len(matcher.Regex) > 0
}

// matchFavicon 匹配favicon hash（同时支持 mmh3 和 MD5 格式）
func matchFavicon(matcher struct {
	Type            string   `json:"type"`
	Words           []string `json:"words"`
	Regex           []string `json:"regex"`
	Hash            []string `json:"hash"`
	Part            string   `json:"part"`
	CaseInsensitive bool     `json:"case-insensitive"`
	Condition       string   `json:"condition"`
}, favicon FaviconHashes) bool {

	if favicon.MMH3 == "" && favicon.MD5 == "" {
		return false
	}

	for _, hash := range matcher.Hash {
		// 同时匹配 mmh3（数字格式）和 MD5（十六进制格式）
		if hash == favicon.MMH3 || hash == favicon.MD5 {
			return true
		}
	}

	return false
}

// FaviconHashes 包含 mmh3 和 MD5 两种格式的 hash
type FaviconHashes struct {
	MMH3 string // Shodan/FOFA 风格: 有符号32位整数
	MD5  string // 传统 MD5 十六进制
}

// VersionInfo 版本提取结果
type VersionInfo struct {
	Name    string // 产品名称
	Version string // 版本号
}

// 通用版本提取正则（预编译）
var versionExtractors = []struct {
	pattern *regexp.Regexp
	name    string // 产品名称（空表示从匹配中提取）
}{
	// Server header: nginx/1.18.0, Apache/2.4.41, IIS/10.0
	{regexp.MustCompile(`(?i)(?:^|[\s,])(?P<name>nginx|apache|iis|lighttpd|openresty|tengine)[/\s]?(?P<ver>[\d.]+)`), ""},

	// X-Powered-By: PHP/7.4.3, ASP.NET/4.0
	{regexp.MustCompile(`(?i)(?:x-powered-by[:\s]*)?(?P<name>php|asp\.net|express|servlet)[/\s]?(?P<ver>[\d.]+)`), ""},

	// Generator meta: WordPress 6.0, Drupal 9.0
	{regexp.MustCompile(`(?i)(?:generator|powered[\s-]*by)["\s:]*(?P<name>wordpress|drupal|joomla|typo3|hugo|jekyll|ghost)[\s/]*(?P<ver>[\d.]+)?`), ""},

	// jQuery/Vue/React
	{regexp.MustCompile(`(?i)(?P<name>jquery|vue|react|angular)[\s./-]*(?:v|version)?[\s]*(?P<ver>\d+(?:\.\d+)+)`), ""},

	// 通用 version= 或 ver= 模式
	{regexp.MustCompile(`(?i)(?P<name>[a-z][\w-]*?)[\s_-]*(?:version|ver)[=:\s"']*(?P<ver>[\d]+(?:\.[\d]+)+)`), ""},

	// Tomcat, WebLogic, WebSphere
	{regexp.MustCompile(`(?i)(?P<name>tomcat|weblogic|websphere|jetty|jboss|wildfly)[/\s-]*(?P<ver>[\d.]+)`), ""},

	// 数据库版本
	{regexp.MustCompile(`(?i)(?P<name>mysql|mariadb|postgresql|mongodb|redis|elasticsearch)[/\s-]*(?P<ver>[\d.]+)`), ""},

	// OpenSSL, OpenSSH
	{regexp.MustCompile(`(?i)(?P<name>openssl|openssh)[/\s-]*(?P<ver>[\d.]+[a-z]?)`), ""},
}

// ExtractVersions 从 HTTP 响应中提取软件版本信息
func ExtractVersions(body string, headers string) []VersionInfo {
	content := headers + "\n" + body
	var results []VersionInfo
	seen := make(map[string]struct{})

	for _, extractor := range versionExtractors {
		matches := extractor.pattern.FindAllStringSubmatch(content, 5)
		for _, match := range matches {
			var name, version string

			// 提取命名捕获组
			for i, groupName := range extractor.pattern.SubexpNames() {
				if i > 0 && i < len(match) {
					switch groupName {
					case "name":
						name = strings.ToLower(match[i])
					case "ver":
						version = match[i]
					}
				}
			}

			// 跳过空结果或已存在的
			if name == "" || version == "" {
				continue
			}

			key := name + ":" + version
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			results = append(results, VersionInfo{
				Name:    name,
				Version: version,
			})
		}
	}

	return results
}

// CalculateFaviconHashes 计算 favicon 的 hash（同时返回 mmh3 和 MD5）
func CalculateFaviconHashes(data []byte) FaviconHashes {
	if len(data) == 0 {
		return FaviconHashes{}
	}

	// mmh3: base64编码后计算（Shodan/FOFA 标准）
	b64 := base64.StdEncoding.EncodeToString(data)
	mmh3Hash := mmh3Hash32([]byte(b64))

	// MD5: 直接计算原始数据
	//nolint:gosec
	md5Hash := md5.Sum(data)

	return FaviconHashes{
		MMH3: fmt.Sprintf("%d", mmh3Hash),
		MD5:  fmt.Sprintf("%x", md5Hash),
	}
}

// mmh3Hash32 计算 MurmurHash3 32位 hash（有符号整数）
func mmh3Hash32(data []byte) int32 {
	const (
		c1   uint32 = 0xcc9e2d51
		c2   uint32 = 0x1b873593
		seed uint32 = 0
	)

	length := len(data)
	nblocks := length / 4
	h1 := seed

	// 处理4字节块
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24

		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	// 处理剩余字节
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// 最终混合
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}
