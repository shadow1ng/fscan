package lib

import (
	"crypto/md5" //nolint:gosec // G501: MD5用于POC规则去重，非加密用途
	"fmt"
	"math/rand" //nolint:gosec // G404: math/rand用于生成测试数据，非加密用途
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/output"
	"github.com/shadow1ng/fscan/webscan/fingerprint"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Ceye平台凭据（通过环境变量配置，避免将密钥硬编码在源码中）
// CEYE_API: Ceye API令牌
// CEYE_DOMAIN: Ceye平台域名（可选，默认使用api.ceye.io）
var ceyeAPI, ceyeDomain string

func init() {
	ceyeAPI = os.Getenv("CEYE_API")
	ceyeDomain = os.Getenv("CEYE_DOMAIN")
	if ceyeDomain == "" {
		ceyeDomain = "api.ceye.io"
	}
}

// Task 定义单个POC检测任务的结构体
type Task struct {
	Req *http.Request // HTTP请求对象
	Poc *Poc          // POC检测脚本
}

// VulnResult 漏洞结果结构体
type VulnResult struct {
	Poc     *Poc                   // POC脚本
	VulName string                 // 漏洞名称
	Target  string                 // 目标URL
	Details map[string]interface{} // 详细信息
}

// POCContext POC执行上下文配置
// 显式传递配置
type POCContext struct {
	DNSLog  bool // 是否启用DNSLog检测
	POCFull bool // 是否完整POC扫描
	Session *common.ScanSession
}

// CheckMultiPoc 并发执行多个POC检测
// 参数说明:
// - req: HTTP请求对象
// - pocs: POC检测脚本列表
// - workers: 并发工作协程数量
// - pocCtx: POC执行上下文配置
func CheckMultiPoc(req *http.Request, pocs []*Poc, workers int, pocCtx *POCContext) {
	// 确保至少有一个工作协程
	if workers <= 0 {
		workers = 1
	}

	// 创建任务通道，缓冲区大小为POC列表长度
	tasks := make(chan Task, len(pocs))
	var wg sync.WaitGroup

	// 启动指定数量的工作协程池
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 从任务通道循环获取任务
			for task := range tasks {
				// 执行POC检测，返回是否存在漏洞、错误信息和漏洞名称
				isVulnerable, vulName, err := executePoc(task.Req, task.Poc, pocCtx)

				// 处理执行过程中的错误
				if err != nil {
					pocCtx.Session.LogError(i18n.Tr("webscan_poc_exec_error", task.Poc.Name, err))
					continue
				}

				// 仅当通过普通POC规则(非clusterpoc)检测到漏洞时，才创建结果
				// 因为clusterpoc已在内部处理了漏洞输出
				if isVulnerable && vulName != "" {
					// 构造漏洞详细信息
					details := make(map[string]interface{})
					details["vulnerability_type"] = task.Poc.Name
					details["vulnerability_name"] = vulName

					// 添加作者信息（如果有）
					if task.Poc.Detail.Author != "" {
						details["author"] = task.Poc.Detail.Author
					}

					// 添加参考链接（如果有）
					if len(task.Poc.Detail.Links) != 0 {
						details["references"] = task.Poc.Detail.Links
					}

					// 添加漏洞描述（如果有）
					if task.Poc.Detail.Description != "" {
						details["description"] = task.Poc.Detail.Description
					}

					// 创建并保存扫描结果
					result := &output.ScanResult{
						Time:    time.Now(),
						Type:    output.TypeVuln,
						Target:  task.Req.URL.String(),
						Status:  "vulnerable",
						Details: details,
					}
					_ = pocCtx.Session.SaveResult(result)

					// 构造控制台输出的日志信息
					logMsg := i18n.Tr("webscan_vuln_detail_header",
						task.Req.URL,
						task.Poc.Name,
						vulName)

					// 添加作者信息到日志
					if task.Poc.Detail.Author != "" {
						logMsg += "\n\t" + i18n.Tr("webscan_vuln_author", task.Poc.Detail.Author)
					}

					// 添加参考链接到日志
					if len(task.Poc.Detail.Links) != 0 {
						logMsg += "\n\t" + i18n.Tr("webscan_vuln_references", strings.Join(task.Poc.Detail.Links, "\n"))
					}

					// 添加描述信息到日志
					if task.Poc.Detail.Description != "" {
						logMsg += "\n\t" + i18n.Tr("webscan_vuln_description", task.Poc.Detail.Description)
					}

					// 输出成功日志
					pocCtx.Session.LogVuln(logMsg)
				}
			}
		}()
	}

	// 分发所有POC任务到通道
	for _, poc := range pocs {
		tasks <- Task{
			Req: req,
			Poc: poc,
		}
	}

	// 关闭任务通道
	close(tasks)

	// 等待所有POC检测任务完成
	wg.Wait()
}

// collectVarDeclarations 收集POC的变量声明
func collectVarDeclarations(p *Poc) []*exprpb.Decl {
	var decls []*exprpb.Decl

	// 收集 Set 中的变量声明
	for _, item := range p.Set {
		decls = append(decls, MakeVarDecl(item.Key, item.Value))
	}

	// 收集 Sets 中的变量声明
	for _, item := range p.Sets {
		value := ""
		if len(item.Value) > 0 {
			value = item.Value[0]
		}
		decls = append(decls, MakeVarDecl(item.Key, value))
	}

	return decls
}

// executePoc 执行单个POC检测
func executePoc(oReq *http.Request, p *Poc, pocCtx *POCContext) (bool, string, error) {
	// 收集POC变量声明
	varDecls := collectVarDeclarations(p)

	// 从基础环境扩展（复用缓存的基础环境，仅添加变量声明）
	env, err := ExtendEnvWithVars(varDecls)
	if err != nil {
		return false, "", fmt.Errorf("%s %s: %w", i18n.GetText("webscan_exec_env_error"), p.Name, err)
	}

	// 解析请求
	req, err := ParseRequest(oReq)
	if err != nil {
		return false, "", fmt.Errorf("%s %s: %w", i18n.GetText("webscan_request_parse_error"), p.Name, err)
	}

	// 初始化变量映射
	variableMap := make(map[string]interface{})
	defer func() { variableMap = nil }()
	variableMap["request"] = req

	// 处理设置项
	for _, item := range p.Set {
		key, expression := item.Key, item.Value
		if expression == "newReverse()" {
			if !pocCtx.DNSLog {
				return false, "", nil
			}
			variableMap[key] = newReverse(pocCtx.DNSLog)
			continue
		}
		if _, err = evalset(env, variableMap, key, expression); err != nil {
			pocCtx.Session.LogError(i18n.Tr("webscan_set_exec_error", p.Name, err))
		}
	}

	// 处理爆破模式
	if len(p.Sets) > 0 {
		success, err := clusterpoc(oReq, p, variableMap, req, env, pocCtx)
		return success, "", err
	}

	return executeRules(oReq, p, variableMap, req, env, pocCtx.Session)
}

// executeRules 执行POC规则并返回结果
func executeRules(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env, session *common.ScanSession) (bool, string, error) {
	// 处理单个规则的函数
	executeRule := func(rule Rules) (bool, error) {
		Headers := cloneMap(rule.Headers)

		// 替换变量
		for varName, varValue := range variableMap {
			if _, isMap := varValue.(map[string]string); isMap {
				continue
			}
			strValue := fmt.Sprintf("%v", varValue)

			// 替换Header中的变量
			for headerKey, headerValue := range Headers {
				Headers[headerKey] = strings.ReplaceAll(headerValue, "{{"+varName+"}}", strValue)
			}

			// 替换Path和Body中的变量
			rule.Path = strings.ReplaceAll(rule.Path, "{{"+varName+"}}", strValue)
			rule.Body = strings.ReplaceAll(rule.Body, "{{"+varName+"}}", strValue)
		}

		// 构建请求路径
		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.URL.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
		} else {
			req.URL.Path = rule.Path
		}
		req.URL.Path = strings.ReplaceAll(req.URL.Path, " ", "%20")

		// 创建新请求（传递原始请求的Context以支持超时控制）
		newRequest, err := http.NewRequestWithContext(
			oReq.Context(),
			rule.Method,
			fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, req.URL.Path),
			strings.NewReader(rule.Body),
		)
		if err != nil {
			return false, fmt.Errorf("%s: %w", i18n.GetText("webscan_request_create_error"), err)
		}

		// 设置请求头
		newRequest.Header = oReq.Header.Clone()
		for k, v := range Headers {
			newRequest.Header.Set(k, v)
		}
		_ = Headers // 清空Headers

		// 发送请求
		resp, err := DoRequest(newRequest, rule.FollowRedirects, session)
		newRequest = nil
		if err != nil {
			return false, err
		}

		variableMap["response"] = resp

		// 执行搜索规则
		if rule.Search != "" {
			result := doSearch(rule.Search, GetHeader(resp.Headers)+string(resp.Body))
			if len(result) == 0 {
				return false, nil
			}
			for k, v := range result {
				variableMap[k] = v
			}
		}

		// 执行表达式
		out, err := Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			return false, err
		}

		if flag, ok := out.Value().(bool); ok {
			return flag, nil
		}
		return false, nil
	}

	// 处理规则组的函数
	executeRuleSet := func(rules []Rules) bool {
		for _, rule := range rules {
			flag, err := executeRule(rule)
			if err != nil || !flag {
				return false
			}
		}
		return true
	}

	// 执行检测规则
	success := false
	if len(p.Rules) > 0 {
		success = executeRuleSet(p.Rules)
		return success, "", nil
	}
	for _, item := range p.Groups {
		name, rules := item.Key, item.Value
		if success = executeRuleSet(rules); success {
			return true, name, nil
		}
	}

	return false, "", nil
}

// doSearch 在响应体中执行正则匹配并提取命名捕获组
func doSearch(re string, body string) map[string]string {
	// 编译正则表达式
	r, err := regexp.Compile(re)
	// 正则表达式编译
	if err != nil {
		common.LogError(i18n.Tr("webscan_regex_compile_error", err))
		return nil
	}

	// 执行正则匹配
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()

	// 处理匹配结果
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				// 特殊处理Set-Cookie头：剥离Path/Expires等属性，仅保留key=value
				if strings.HasPrefix(re, "Set-Cookie:") {
					paramsMap[name] = optimizeCookies(result[i])
				} else {
					paramsMap[name] = result[i]
				}
			}
		}
		return paramsMap
	}
	return nil
}

// optimizeCookies 优化Cookie字符串，移除不必要的属性
func optimizeCookies(rawCookie string) string {
	var output strings.Builder

	// 解析Cookie键值对
	pairs := strings.Split(rawCookie, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		nameVal := strings.SplitN(pair, "=", 2)
		if len(nameVal) < 2 {
			continue
		}
		name := strings.TrimSpace(nameVal[0])

		// 跳过Cookie属性
		switch strings.ToLower(name) {
		case "expires", "max-age", "path", "domain",
			"version", "comment", "secure", "samesite", "httponly":
			continue
		}

		// 构建Cookie键值对
		if output.Len() > 0 {
			output.WriteString("; ")
		}
		output.WriteString(name)
		output.WriteString("=")
		output.WriteString(nameVal[1])
	}

	return output.String()
}

// newReverse 创建新的反连检测对象
// dnsLog参数：显式传入配置
func newReverse(dnsLog bool) *Reverse {
	// 检查DNS日志功能是否启用
	if !dnsLog {
		return &Reverse{}
	}

	// 生成随机子域名
	const (
		letters         = "1234567890abcdefghijklmnopqrstuvwxyz"
		subdomainLength = 8
	)
	//nolint:gosec,govet // G404: 用于生成测试子域名，非加密用途; shadow: 局部randSource不影响全局
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	subdomain := RandomStr(randSource, letters, subdomainLength)

	// 构建URL
	urlStr := fmt.Sprintf("http://%s.%s", subdomain, ceyeDomain)
	u, err := url.Parse(urlStr)
	// 解析反连URL
	if err != nil {
		common.LogError(i18n.Tr("webscan_reverse_url_error", err))
		return &Reverse{}
	}

	// 返回反连检测配置
	return &Reverse{
		URL:                urlStr,
		Domain:             u.Hostname(),
		Ip:                 u.Host,
		IsDomainNameServer: false,
	}
}

// clusterpoc 执行集群POC检测，支持批量参数组合测试
func clusterpoc(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env, pocCtx *POCContext) (success bool, err error) {
	var strMap StrMap     // 存储成功的参数组合
	var shiroKeyCount int // shiro key测试计数

	// 遍历POC规则
	for ruleIndex, rule := range p.Rules {
		// 检查是否需要进行参数Fuzz测试
		if !isFuzz(rule, p.Sets) {
			// 不需要Fuzz,直接发送请求
			success, err = clustersend(oReq, variableMap, req, env, rule, pocCtx.Session)
			if err != nil {
				return false, err
			}
			if !success {
				return false, err
			}
			continue
		}

		// 生成参数组合
		setsMap := Combo(p.Sets)
		ruleHash := make(map[string]struct{}) // 用于去重的规则哈希表

		// 遍历参数组合
	paramLoop:
		for comboIndex, paramCombo := range setsMap {
			// Shiro Key测试特殊处理:默认只测试10个key
			if p.Name == "poc-yaml-shiro-key" && !pocCtx.POCFull && comboIndex >= 10 {
				if paramCombo[1] == "cbc" {
					continue
				}
				if shiroKeyCount == 0 {
					shiroKeyCount = comboIndex
				}
				if comboIndex-shiroKeyCount >= 10 {
					break
				}
			}

			// 克隆规则以避免相互影响
			currentRule := cloneRules(rule)
			var hasReplacement bool
			var currentParams StrMap
			payloads := make(map[string]interface{})
			var payloadExpr string

			// 计算所有参数的实际值
			for i, set := range p.Sets {
				key, expr := set.Key, paramCombo[i]
				if key == "payload" {
					payloadExpr = expr
				}
				output, err := evalset1(env, variableMap, key, expr)
				if err != nil {
					pocCtx.Session.LogError(i18n.Tr("webscan_set_exec_error", key, err))
				}
				payloads[key] = output
			}

			// 替换规则中的参数（使用提取的函数）
			hasReplacement, currentParams = applyParametersToRule(&currentRule, p.Sets, payloads, variableMap, payloadExpr)

			// 如果没有参数被替换，跳过当前组合
			if !hasReplacement {
				continue
			}

			// 规则去重
			ruleMD5 := getRuleHash(&currentRule)
			if _, exists := ruleHash[ruleMD5]; exists {
				continue
			}
			ruleHash[ruleMD5] = struct{}{}

			// 发送请求并处理结果
			success, err = clustersend(oReq, variableMap, req, env, currentRule, pocCtx.Session)
			if err != nil {
				return false, err
			}

			if success {
				targetURL := fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, req.URL.Path)

				// 处理成功情况
				if currentRule.Continue {
					// 使用Continue标志时，记录但继续测试其他参数
					recordVulnerabilityResult(targetURL, p, currentParams, false, pocCtx.Session)
					continue
				}

				// 记录成功的参数组合
				strMap = append(strMap, currentParams...)
				if ruleIndex == len(p.Rules)-1 {
					// 最终规则成功，记录完整的结果并返回
					recordVulnerabilityResult(targetURL, p, strMap, false, pocCtx.Session)
					return false, nil
				}
				break paramLoop
			}
		}

		if !success {
			break
		}
		if rule.Continue {
			return false, nil
		}
	}

	return success, nil
}

// applyParametersToRule 将参数应用到规则中，返回是否有替换发生和替换的参数列表
// 这是一个纯函数，不修改原始规则，而是修改传入的currentRule指针
func applyParametersToRule(
	currentRule *Rules,
	sets ListMap,
	payloads map[string]interface{},
	variableMap map[string]interface{},
	payloadExpr string,
) (hasReplacement bool, replacedParams StrMap) {
	// 遍历所有参数集
	for _, set := range sets {
		paramReplaced := false
		key := set.Key
		value := fmt.Sprintf("%v", payloads[key])
		paramPattern := "{{" + key + "}}"

		// 替换Header中的参数
		for headerKey, headerVal := range currentRule.Headers {
			if strings.Contains(headerVal, paramPattern) {
				currentRule.Headers[headerKey] = strings.ReplaceAll(headerVal, paramPattern, value)
				paramReplaced = true
			}
		}

		// 替换Path中的参数
		if strings.Contains(currentRule.Path, paramPattern) {
			currentRule.Path = strings.ReplaceAll(currentRule.Path, paramPattern, value)
			paramReplaced = true
		}

		// 替换Body中的参数
		if strings.Contains(currentRule.Body, paramPattern) {
			currentRule.Body = strings.ReplaceAll(currentRule.Body, paramPattern, value)
			paramReplaced = true
		}

		// 记录替换的参数
		if paramReplaced {
			hasReplacement = true
			if key == "payload" {
				// 处理payload的特殊情况：检查payload表达式中是否包含变量
				hasVarInPayload := false
				for varKey, varVal := range variableMap {
					if strings.Contains(payloadExpr, varKey) {
						hasVarInPayload = true
						replacedParams = append(replacedParams, StrItem{varKey, fmt.Sprintf("%v", varVal)})
					}
				}
				if hasVarInPayload {
					continue
				}
			}
			replacedParams = append(replacedParams, StrItem{key, value})
		}
	}

	return hasReplacement, replacedParams
}

// getRuleHash 计算规则的MD5哈希值用于去重
func getRuleHash(rule *Rules) string {
	//nolint:gosec // G401: MD5用于规则去重，非加密用途
	ruleDigest := md5.Sum([]byte(fmt.Sprintf("%v", rule)))
	return fmt.Sprintf("%x", ruleDigest)
}

// recordVulnerabilityResult 记录漏洞检测结果
func recordVulnerabilityResult(targetURL string, pocDef *Poc, params StrMap, skipSave bool, session *common.ScanSession) {
	// 构造详细信息
	details := make(map[string]interface{})
	details["vulnerability_type"] = pocDef.Name
	details["vulnerability_name"] = pocDef.Name // 使用POC名称作为漏洞名称

	// 添加作者信息（如果有）
	if pocDef.Detail.Author != "" {
		details["author"] = pocDef.Detail.Author
	}

	// 添加参考链接（如果有）
	if len(pocDef.Detail.Links) != 0 {
		details["references"] = pocDef.Detail.Links
	}

	// 添加漏洞描述（如果有）
	if pocDef.Detail.Description != "" {
		details["description"] = pocDef.Detail.Description
	}

	// 添加参数信息（如果有）
	if len(params) > 0 {
		paramMap := make(map[string]string)
		for _, item := range params {
			paramMap[item.Key] = item.Value
		}
		details["parameters"] = paramMap
	}

	// 保存漏洞结果（除非明确指示跳过）
	if !skipSave {
		result := &output.ScanResult{
			Time:    time.Now(),
			Type:    output.TypeVuln,
			Target:  targetURL,
			Status:  "vulnerable",
			Details: details,
		}
		_ = session.SaveResult(result)
	}

	// 生成日志消息
	var logMsg string
	if pocDef.Name == "poc-yaml-backup-file" || pocDef.Name == "poc-yaml-sql-file" {
		logMsg = i18n.Tr("webscan_vuln_detected", targetURL, pocDef.Name)
	} else {
		logMsg = i18n.Tr("webscan_vuln_detected_params", targetURL, pocDef.Name, params)
	}

	// 输出成功日志
	session.LogVuln(logMsg)
}

// isFuzz 检查规则是否包含需要Fuzz测试的参数
func isFuzz(rule Rules, Sets ListMap) bool {
	// 遍历所有参数
	for _, param := range Sets {
		key := param.Key
		paramPattern := "{{" + key + "}}"

		// 检查Headers中是否包含参数
		for _, headerValue := range rule.Headers {
			if strings.Contains(headerValue, paramPattern) {
				return true
			}
		}

		// 检查Path中是否包含参数
		if strings.Contains(rule.Path, paramPattern) {
			return true
		}

		// 检查Body中是否包含参数
		if strings.Contains(rule.Body, paramPattern) {
			return true
		}
	}
	return false
}

// Combo 生成参数组合
func Combo(input ListMap) [][]string {
	if len(input) == 0 {
		return nil
	}

	// 处理只有一个参数的情况
	if len(input) == 1 {
		output := make([][]string, 0, len(input[0].Value))
		for _, value := range input[0].Value {
			output = append(output, []string{value})
		}
		return output
	}

	// 递归处理多个参数的情况
	subCombos := Combo(input[1:])
	return MakeData(subCombos, input[0].Value)
}

// MakeData 将新的参数值与已有的组合进行组合
func MakeData(base [][]string, nextData []string) [][]string {
	// 预分配足够的空间
	output := make([][]string, 0, len(base)*len(nextData))

	// 遍历已有组合和新参数值
	for _, existingCombo := range base {
		for _, newValue := range nextData {
			// 创建新组合
			newCombo := make([]string, 0, len(existingCombo)+1)
			newCombo = append(newCombo, newValue)
			newCombo = append(newCombo, existingCombo...)
			output = append(output, newCombo)
		}
	}

	return output
}

// clustersend 执行单个规则的HTTP请求和响应检测
func clustersend(oReq *http.Request, variableMap map[string]interface{}, req *Request, env *cel.Env, rule Rules, session *common.ScanSession) (bool, error) {
	// 替换请求中的变量
	for varName, varValue := range variableMap {
		// 跳过map类型的变量
		if _, isMap := varValue.(map[string]string); isMap {
			continue
		}

		strValue := fmt.Sprintf("%v", varValue)
		varPattern := "{{" + varName + "}}"

		// 替换Headers中的变量
		for headerKey, headerValue := range rule.Headers {
			if strings.Contains(headerValue, varPattern) {
				rule.Headers[headerKey] = strings.ReplaceAll(headerValue, varPattern, strValue)
			}
		}

		// 替换Path和Body中的变量
		rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), varPattern, strValue)
		rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), varPattern, strValue)
	}

	// 构建完整请求路径
	if oReq.URL.Path != "" && oReq.URL.Path != "/" {
		req.URL.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		req.URL.Path = rule.Path
	}

	// URL编码处理
	req.URL.Path = strings.ReplaceAll(req.URL.Path, " ", "%20")

	// 创建新的HTTP请求（传递原始请求的Context以支持超时控制）
	reqURL := fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, req.URL.Path)
	newRequest, err := http.NewRequestWithContext(oReq.Context(), rule.Method, reqURL, strings.NewReader(rule.Body))
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.GetText("webscan_http_request_error"), err)
	}
	defer func() { newRequest = nil }()

	// 设置请求头
	newRequest.Header = oReq.Header.Clone()
	for key, value := range rule.Headers {
		newRequest.Header.Set(key, value)
	}

	// 发送请求
	resp, err := DoRequest(newRequest, rule.FollowRedirects, session)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.GetText("webscan_request_send_error"), err)
	}

	// 更新响应到变量映射
	variableMap["response"] = resp

	// 执行搜索规则
	if rule.Search != "" {
		searchContent := GetHeader(resp.Headers) + string(resp.Body)
		result := doSearch(rule.Search, searchContent)

		if len(result) > 0 {
			// 将搜索结果添加到变量映射
			for key, value := range result {
				variableMap[key] = value
			}
		} else {
			return false, nil
		}
	}

	// 执行CEL表达式
	out, err := Evaluate(env, rule.Expression, variableMap)
	if err != nil {
		if strings.Contains(err.Error(), "Syntax error") {
			common.LogError(i18n.Tr("webscan_cel_syntax_error", rule.Expression, err))
		}
		return false, err
	}

	// 检查表达式执行结果
	if fmt.Sprintf("%v", out) == "false" {
		return false, nil
	}

	return true, nil
}

// cloneRules 深度复制Rules结构体
// 参数:
// - tags: 原始Rules结构体
// 返回: 复制后的新Rules结构体
func cloneRules(tags Rules) Rules {
	return Rules{
		Method:          tags.Method,
		Path:            tags.Path,
		Body:            tags.Body,
		Search:          tags.Search,
		FollowRedirects: tags.FollowRedirects,
		Expression:      tags.Expression,
		Headers:         cloneMap(tags.Headers),
		Continue:        tags.Continue,
	}
}

// cloneMap 深度复制字符串映射
func cloneMap(tags map[string]string) map[string]string {
	if tags == nil {
		return nil
	}
	cloneTags := make(map[string]string, len(tags))
	for key, value := range tags {
		cloneTags[key] = value
	}
	return cloneTags
}

// evalset 执行CEL表达式并处理特殊类型结果
func evalset(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (string, error) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
		return expression, err
	}

	// 根据不同类型处理输出
	switch value := out.Value().(type) {
	case *UrlType:
		variableMap[k] = URLTypeToString(value)
	case int64:
		variableMap[k] = int(value)
	default:
		variableMap[k] = fmt.Sprintf("%v", out)
	}

	return fmt.Sprintf("%v", variableMap[k]), nil
}

// evalset1 执行CEL表达式的简化版本
func evalset1(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (string, error) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		variableMap[k] = fmt.Sprintf("%v", out)
	}
	return fmt.Sprintf("%v", variableMap[k]), err
}

// CheckInfoPoc 检查POC信息并返回别名
func CheckInfoPoc(infostr string) string {
	for _, poc := range fingerprint.PocDatas {
		if strings.Contains(infostr, poc.Name) {
			return poc.Alias
		}
	}
	return ""
}

// GetHeader 将HTTP头转换为字符串格式
func GetHeader(header map[string]string) string {
	var builder strings.Builder
	for name, values := range header {
		fmt.Fprintf(&builder, "%s: %s\n", name, values)
	}
	builder.WriteString("\r\n")
	return builder.String()
}
