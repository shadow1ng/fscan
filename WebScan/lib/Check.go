package lib

import (
	"crypto/md5"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/info"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// API配置常量
const (
	ceyeApi    = "a78a1cb49d91fe09e01876078d1868b2" // Ceye平台的API密钥
	ceyeDomain = "7wtusr.ceye.io"                   // Ceye平台的域名
)

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

// CheckMultiPoc 并发执行多个POC检测
// 参数说明:
// - req: HTTP请求对象
// - pocs: POC检测脚本列表
// - workers: 并发工作协程数量
func CheckMultiPoc(req *http.Request, pocs []*Poc, workers int) {
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
				isVulnerable, err, vulName := executePoc(task.Req, task.Poc)

				// 处理执行过程中的错误
				if err != nil {
					Common.LogError(fmt.Sprintf("执行POC错误 %s: %v", task.Poc.Name, err))
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
					result := &Common.ScanResult{
						Time:    time.Now(),
						Type:    Common.VULN,
						Target:  task.Req.URL.String(),
						Status:  "vulnerable",
						Details: details,
					}
					Common.SaveResult(result)

					// 构造控制台输出的日志信息
					logMsg := fmt.Sprintf("目标: %s\n  漏洞类型: %s\n  漏洞名称: %s\n  详细信息:",
						task.Req.URL,
						task.Poc.Name,
						vulName)

					// 添加作者信息到日志
					if task.Poc.Detail.Author != "" {
						logMsg += "\n\t作者:" + task.Poc.Detail.Author
					}

					// 添加参考链接到日志
					if len(task.Poc.Detail.Links) != 0 {
						logMsg += "\n\t参考链接:" + strings.Join(task.Poc.Detail.Links, "\n")
					}

					// 添加描述信息到日志
					if task.Poc.Detail.Description != "" {
						logMsg += "\n\t描述:" + task.Poc.Detail.Description
					}

					// 输出成功日志
					Common.LogSuccess(logMsg)
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

// createVulnDetails 创建漏洞详情信息
func createVulnDetails(poc *Poc, vulName string) map[string]interface{} {
	details := make(map[string]interface{})
	details["vulnerability_type"] = poc.Name
	details["vulnerability_name"] = vulName

	// 添加作者信息（如果有）
	if poc.Detail.Author != "" {
		details["author"] = poc.Detail.Author
	}

	// 添加参考链接（如果有）
	if len(poc.Detail.Links) != 0 {
		details["references"] = poc.Detail.Links
	}

	// 添加漏洞描述（如果有）
	if poc.Detail.Description != "" {
		details["description"] = poc.Detail.Description
	}

	return details
}

// buildLogMessage 构建漏洞日志消息
func buildLogMessage(result *VulnResult) string {
	logMsg := fmt.Sprintf("目标: %s\n  漏洞类型: %s\n  漏洞名称: %s\n  详细信息:",
		result.Target,
		result.Poc.Name,
		result.VulName)

	// 添加作者信息到日志
	if result.Poc.Detail.Author != "" {
		logMsg += "\n\t作者:" + result.Poc.Detail.Author
	}

	// 添加参考链接到日志
	if len(result.Poc.Detail.Links) != 0 {
		logMsg += "\n\t参考链接:" + strings.Join(result.Poc.Detail.Links, "\n")
	}

	// 添加描述信息到日志
	if result.Poc.Detail.Description != "" {
		logMsg += "\n\t描述:" + result.Poc.Detail.Description
	}

	return logMsg
}

// executePoc 执行单个POC检测
func executePoc(oReq *http.Request, p *Poc) (bool, error, string) {
	// 初始化环境配置
	config := NewEnvOption()
	config.UpdateCompileOptions(p.Set)

	// 处理额外的设置项
	if len(p.Sets) > 0 {
		var setMap StrMap
		for _, item := range p.Sets {
			value := ""
			if len(item.Value) > 0 {
				value = item.Value[0]
			}
			setMap = append(setMap, StrItem{item.Key, value})
		}
		config.UpdateCompileOptions(setMap)
	}

	// 创建执行环境
	env, err := NewEnv(&config)
	if err != nil {
		return false, fmt.Errorf("执行环境错误 %s: %v", p.Name, err), ""
	}

	// 解析请求
	req, err := ParseRequest(oReq)
	if err != nil {
		return false, fmt.Errorf("请求解析错误 %s: %v", p.Name, err), ""
	}

	// 初始化变量映射
	variableMap := make(map[string]interface{})
	defer func() { variableMap = nil }()
	variableMap["request"] = req

	// 处理设置项
	for _, item := range p.Set {
		key, expression := item.Key, item.Value
		if expression == "newReverse()" {
			if !Common.DnsLog {
				return false, nil, ""
			}
			variableMap[key] = newReverse()
			continue
		}
		if err, _ = evalset(env, variableMap, key, expression); err != nil {
			Common.LogError(fmt.Sprintf("设置项执行错误 %s: %v", p.Name, err))
		}
	}

	// 处理爆破模式
	if len(p.Sets) > 0 {
		success, err := clusterpoc(oReq, p, variableMap, req, env)
		return success, err, ""
	}

	return executeRules(oReq, p, variableMap, req, env)
}

// executeRules 执行POC规则并返回结果
func executeRules(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env) (bool, error, string) {
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
				if strings.Contains(headerValue, "{{"+varName+"}}") {
					Headers[headerKey] = strings.ReplaceAll(headerValue, "{{"+varName+"}}", strValue)
				}
			}

			// 替换Path和Body中的变量
			rule.Path = strings.ReplaceAll(rule.Path, "{{"+varName+"}}", strValue)
			rule.Body = strings.ReplaceAll(rule.Body, "{{"+varName+"}}", strValue)
		}

		// 构建请求路径
		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
		} else {
			req.Url.Path = rule.Path
		}
		req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")

		// 创建新请求
		newRequest, err := http.NewRequest(
			rule.Method,
			fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, string([]rune(req.Url.Path))),
			strings.NewReader(rule.Body),
		)
		if err != nil {
			return false, fmt.Errorf("请求创建错误: %v", err)
		}

		// 设置请求头
		newRequest.Header = oReq.Header.Clone()
		for k, v := range Headers {
			newRequest.Header.Set(k, v)
		}
		Headers = nil

		// 发送请求
		resp, err := DoRequest(newRequest, rule.FollowRedirects)
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
		return success, nil, ""
	} else {
		for _, item := range p.Groups {
			name, rules := item.Key, item.Value
			if success = executeRuleSet(rules); success {
				return true, nil, name
			}
		}
	}

	return false, nil, ""
}

// doSearch 在响应体中执行正则匹配并提取命名捕获组
func doSearch(re string, body string) map[string]string {
	// 编译正则表达式
	r, err := regexp.Compile(re)
	// 正则表达式编译
	if err != nil {
		Common.LogError(fmt.Sprintf("正则编译错误: %v", err))
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
				// 特殊处理Cookie头
				if strings.HasPrefix(re, "Set-Cookie:") && strings.Contains(name, "cookie") {
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
	pairs := strings.Split(rawCookie, "; ")
	for _, pair := range pairs {
		nameVal := strings.SplitN(pair, "=", 2)
		if len(nameVal) < 2 {
			continue
		}

		// 跳过Cookie属性
		switch strings.ToLower(nameVal[0]) {
		case "expires", "max-age", "path", "domain",
			"version", "comment", "secure", "samesite", "httponly":
			continue
		}

		// 构建Cookie键值对
		if output.Len() > 0 {
			output.WriteString("; ")
		}
		output.WriteString(nameVal[0])
		output.WriteString("=")
		output.WriteString(strings.Join(nameVal[1:], "="))
	}

	return output.String()
}

// newReverse 创建新的反连检测对象
func newReverse() *Reverse {
	// 检查DNS日志功能是否启用
	if !Common.DnsLog {
		return &Reverse{}
	}

	// 生成随机子域名
	const (
		letters         = "1234567890abcdefghijklmnopqrstuvwxyz"
		subdomainLength = 8
	)
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	subdomain := RandomStr(randSource, letters, subdomainLength)

	// 构建URL
	urlStr := fmt.Sprintf("http://%s.%s", subdomain, ceyeDomain)
	u, err := url.Parse(urlStr)
	// 解析反连URL
	if err != nil {
		Common.LogError(fmt.Sprintf("反连URL解析错误: %v", err))
		return &Reverse{}
	}

	// 返回反连检测配置
	return &Reverse{
		Url:                urlStr,
		Domain:             u.Hostname(),
		Ip:                 u.Host,
		IsDomainNameServer: false,
	}
}

// clusterpoc 执行集群POC检测，支持批量参数组合测试
func clusterpoc(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env) (success bool, err error) {
	var strMap StrMap     // 存储成功的参数组合
	var shiroKeyCount int // shiro key测试计数

	// 记录漏洞的辅助函数，统一保存结果和输出日志
	recordVulnerability := func(targetURL string, params StrMap, skipSave bool) {
		// 构造详细信息
		details := make(map[string]interface{})
		details["vulnerability_type"] = p.Name
		details["vulnerability_name"] = p.Name // 使用POC名称作为漏洞名称

		// 添加作者信息（如果有）
		if p.Detail.Author != "" {
			details["author"] = p.Detail.Author
		}

		// 添加参考链接（如果有）
		if len(p.Detail.Links) != 0 {
			details["references"] = p.Detail.Links
		}

		// 添加漏洞描述（如果有）
		if p.Detail.Description != "" {
			details["description"] = p.Detail.Description
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
			result := &Common.ScanResult{
				Time:    time.Now(),
				Type:    Common.VULN,
				Target:  targetURL,
				Status:  "vulnerable",
				Details: details,
			}
			Common.SaveResult(result)
		}

		// 生成日志消息
		var logMsg string
		if p.Name == "poc-yaml-backup-file" || p.Name == "poc-yaml-sql-file" {
			logMsg = fmt.Sprintf("检测到漏洞 %s %s", targetURL, p.Name)
		} else {
			logMsg = fmt.Sprintf("检测到漏洞 %s %s 参数:%v", targetURL, p.Name, params)
		}

		// 输出成功日志
		Common.LogSuccess(logMsg)
	}

	// 遍历POC规则
	for ruleIndex, rule := range p.Rules {
		// 检查是否需要进行参数Fuzz测试
		if !isFuzz(rule, p.Sets) {
			// 不需要Fuzz,直接发送请求
			success, err = clustersend(oReq, variableMap, req, env, rule)
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
			if p.Name == "poc-yaml-shiro-key" && !Common.PocFull && comboIndex >= 10 {
				if paramCombo[1] == "cbc" {
					continue
				} else {
					if shiroKeyCount == 0 {
						shiroKeyCount = comboIndex
					}
					if comboIndex-shiroKeyCount >= 10 {
						break
					}
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
				_, output := evalset1(env, variableMap, key, expr)
				payloads[key] = output
			}

			// 替换规则中的参数
			for _, set := range p.Sets {
				paramReplaced := false
				key := set.Key
				value := fmt.Sprintf("%v", payloads[key])

				// 替换Header中的参数
				for headerKey, headerVal := range currentRule.Headers {
					if strings.Contains(headerVal, "{{"+key+"}}") {
						currentRule.Headers[headerKey] = strings.ReplaceAll(headerVal, "{{"+key+"}}", value)
						paramReplaced = true
					}
				}

				// 替换Path中的参数
				if strings.Contains(currentRule.Path, "{{"+key+"}}") {
					currentRule.Path = strings.ReplaceAll(currentRule.Path, "{{"+key+"}}", value)
					paramReplaced = true
				}

				// 替换Body中的参数
				if strings.Contains(currentRule.Body, "{{"+key+"}}") {
					currentRule.Body = strings.ReplaceAll(currentRule.Body, "{{"+key+"}}", value)
					paramReplaced = true
				}

				// 记录替换的参数
				if paramReplaced {
					hasReplacement = true
					if key == "payload" {
						// 处理payload的特殊情况
						hasVarInPayload := false
						for varKey, varVal := range variableMap {
							if strings.Contains(payloadExpr, varKey) {
								hasVarInPayload = true
								currentParams = append(currentParams, StrItem{varKey, fmt.Sprintf("%v", varVal)})
							}
						}
						if hasVarInPayload {
							continue
						}
					}
					currentParams = append(currentParams, StrItem{key, value})
				}
			}

			// 如果没有参数被替换，跳过当前组合
			if !hasReplacement {
				continue
			}

			// 规则去重
			ruleDigest := md5.Sum([]byte(fmt.Sprintf("%v", currentRule)))
			ruleMD5 := fmt.Sprintf("%x", ruleDigest)
			if _, exists := ruleHash[ruleMD5]; exists {
				continue
			}
			ruleHash[ruleMD5] = struct{}{}

			// 发送请求并处理结果
			success, err = clustersend(oReq, variableMap, req, env, currentRule)
			if err != nil {
				return false, err
			}

			if success {
				targetURL := fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path)

				// 处理成功情况
				if currentRule.Continue {
					// 使用Continue标志时，记录但继续测试其他参数
					recordVulnerability(targetURL, currentParams, false)
					continue
				}

				// 记录成功的参数组合
				strMap = append(strMap, currentParams...)
				if ruleIndex == len(p.Rules)-1 {
					// 最终规则成功，记录完整的结果并返回
					recordVulnerability(targetURL, strMap, false)
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
func clustersend(oReq *http.Request, variableMap map[string]interface{}, req *Request, env *cel.Env, rule Rules) (bool, error) {
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
		req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		req.Url.Path = rule.Path
	}

	// URL编码处理
	req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")

	// 创建新的HTTP请求
	reqURL := fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path)
	newRequest, err := http.NewRequest(rule.Method, reqURL, strings.NewReader(rule.Body))
	if err != nil {
		return false, fmt.Errorf("HTTP请求错误: %v", err)
	}
	defer func() { newRequest = nil }()

	// 设置请求头
	newRequest.Header = oReq.Header.Clone()
	for key, value := range rule.Headers {
		newRequest.Header.Set(key, value)
	}

	// 发送请求
	resp, err := DoRequest(newRequest, rule.FollowRedirects)
	if err != nil {
		return false, fmt.Errorf("请求发送错误: %v", err)
	}

	// 更新响应到变量映射
	variableMap["response"] = resp

	// 执行搜索规则
	if rule.Search != "" {
		searchContent := GetHeader(resp.Headers) + string(resp.Body)
		result := doSearch(rule.Search, searchContent)

		if result != nil && len(result) > 0 {
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
			Common.LogError(fmt.Sprintf("CEL语法错误 [%s]: %v", rule.Expression, err))
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
func evalset(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (error, string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
		return err, expression
	}

	// 根据不同类型处理输出
	switch value := out.Value().(type) {
	case *UrlType:
		variableMap[k] = UrlTypeToString(value)
	case int64:
		variableMap[k] = int(value)
	default:
		variableMap[k] = fmt.Sprintf("%v", out)
	}

	return nil, fmt.Sprintf("%v", variableMap[k])
}

// evalset1 执行CEL表达式的简化版本
func evalset1(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (error, string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		variableMap[k] = fmt.Sprintf("%v", out)
	}
	return err, fmt.Sprintf("%v", variableMap[k])
}

// CheckInfoPoc 检查POC信息并返回别名
func CheckInfoPoc(infostr string) string {
	for _, poc := range info.PocDatas {
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
		builder.WriteString(fmt.Sprintf("%s: %s\n", name, values))
	}
	builder.WriteString("\r\n")
	return builder.String()
}
