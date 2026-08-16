package WebScan

import (
	"crypto/md5" //nolint:gosec // G501: MD5用于内容指纹识别，非加密用途
	"fmt"
	"net/http"
	"strings"

	"scanner/webscan/fingerprint"
)

// CheckDatas 存储HTTP响应的检查数据
type CheckDatas struct {
	Body        []byte                    // 响应体
	Headers     string                    // 格式化后的响应头，供现有规则使用
	HTTPHeaders http.Header               // 原始响应头，供结构化技术识别使用
	Favicon     fingerprint.FaviconHashes // Favicon hash（mmh3 + MD5）
}

// InfoCheck 检查URL的指纹信息
func InfoCheck(URL string, CheckData *[]CheckDatas) []string {
	var matchedInfos []string

	// 遍历检查数据
	for _, data := range *CheckData {
		// 基础指纹库：正则规则匹配 (272条)
		matchedInfos = append(matchedInfos, matchByRegex(data)...)

		// 基础指纹库：MD5指纹匹配 (30条)
		if md5Name := matchByMd5(data.Body); md5Name != "" {
			matchedInfos = append(matchedInfos, md5Name)
		}

		// 增强指纹库：FingerprintHub (3139条)
		// 支持favicon hash、多种matcher类型、更丰富的匹配规则
		enhanced := fingerprint.MatchEnhancedFingerprints(data.Body, data.Headers, data.Favicon)
		matchedInfos = append(matchedInfos, enhanced...)

		// Wappalyzer 技术栈识别：覆盖中间件、框架、CMS、前端库和托管平台。
		// 优先使用原始 http.Header；保留对仅提供 Headers 字符串的嵌入调用兼容性。
		wappalyzerMatches := fingerprint.MatchWappalyzerFingerprints(data.Body, checkDataHTTPHeaders(data))
		matchedInfos = append(matchedInfos, wappalyzerMatches...)

		// 版本提取：从响应中提取软件版本信息
		versions := fingerprint.ExtractVersions(string(data.Body), data.Headers)
		for _, v := range versions {
			matchedInfos = append(matchedInfos, fmt.Sprintf("%s/%s", v.Name, v.Version))
		}
	}

	// 合并同名技术。不同指纹库的命名大小写和版本分隔符可能不同，
	// 例如 nginx、Nginx 和 Nginx:1.24.0；优先保留带版本的结果。
	matchedInfos = mergeFingerprintResults(matchedInfos)

	// 指纹信息已在 WebTitle 日志中统一输出，此处不再单独输出

	return matchedInfos
}

func mergeFingerprintResults(items []string) []string {
	result := make([]string, 0, len(items))
	indexByKey := make(map[string]int, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key, versioned := fingerprintResultKey(item)
		if index, exists := indexByKey[key]; exists {
			_, existingVersioned := fingerprintResultKey(result[index])
			if versioned && !existingVersioned {
				result[index] = item
			}
			continue
		}
		indexByKey[key] = len(result)
		result = append(result, item)
	}
	return result
}

func fingerprintResultKey(item string) (string, bool) {
	name := item
	versioned := false
	for _, separator := range []byte{':', '/'} {
		if index := strings.LastIndexByte(item, separator); index > 0 && looksLikeVersion(item[index+1:]) {
			name = item[:index]
			versioned = true
			break
		}
	}
	return strings.ToLower(strings.TrimSpace(name)), versioned
}

func looksLikeVersion(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	return value[0] >= '0' && value[0] <= '9'
}

func checkDataHTTPHeaders(data CheckDatas) http.Header {
	if len(data.HTTPHeaders) > 0 {
		return data.HTTPHeaders
	}

	headers := make(http.Header)
	for line := range strings.SplitSeq(data.Headers, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return headers
}

// matchByRegex 使用正则规则匹配指纹
func matchByRegex(data CheckDatas) []string {
	var matched []string

	for _, rule := range fingerprint.RuleDatas {
		// 跳过编译失败的规则
		if rule.Compiled == nil {
			continue
		}

		// 根据规则类型选择匹配内容
		var isMatch bool
		switch rule.Type {
		case "code":
			isMatch = rule.Compiled.MatchString(string(data.Body))
		default:
			isMatch = rule.Compiled.MatchString(data.Headers)
		}

		if isMatch {
			matched = append(matched, rule.Name)
		}
	}

	return matched
}

// matchByMd5 使用MD5指纹匹配
func matchByMd5(body []byte) string {
	//nolint:gosec // G401: MD5用于内容指纹，非加密用途
	contentMd5 := fmt.Sprintf("%x", md5.Sum(body))

	for _, md5Info := range fingerprint.Md5Datas {
		if contentMd5 == md5Info.Md5Str {
			return md5Info.Name
		}
	}

	return ""
}

// removeDuplicateElement 移除切片中的重复元素
func removeDuplicateElement(items []string) []string {
	// 预分配空间
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))

	// 使用map去重
	for _, item := range items {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
