package lib

import (
	"crypto/md5"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/shadow1ng/fscan/WebScan/info"
	"github.com/shadow1ng/fscan/common"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ceyeApi    = "a78a1cb49d91fe09e01876078d1868b2"
	ceyeDomain = "7wtusr.ceye.io"
)

type Task struct {
	Req *http.Request
	Poc *Poc
}

func CheckMultiPoc(req *http.Request, pocs []*Poc, workers int) {
	tasks := make(chan Task)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		go func() {
			for task := range tasks {
				isVul, _, name := executePoc(task.Req, task.Poc)
				if isVul {
					result := fmt.Sprintf("[+] PocScan %s %s %s", task.Req.URL, task.Poc.Name, name)
					common.LogSuccess(result)
				}
				wg.Done()
			}
		}()
	}
	for _, poc := range pocs {
		task := Task{
			Req: req,
			Poc: poc,
		}
		wg.Add(1)
		tasks <- task
	}
	wg.Wait()
	close(tasks)
}

func executePoc(oReq *http.Request, p *Poc) (bool, error, string) {
	c := NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	if len(p.Sets) > 0 {
		var setMap StrMap
		for _, item := range p.Sets {
			if len(item.Value) > 0 {
				setMap = append(setMap, StrItem{item.Key, item.Value[0]})
			} else {
				setMap = append(setMap, StrItem{item.Key, ""})
			}
		}
		c.UpdateCompileOptions(setMap)
	}
	env, err := NewEnv(&c)
	if err != nil {
		fmt.Printf("[-] %s environment creation error: %s\n", p.Name, err)
		return false, err, ""
	}
	req, err := ParseRequest(oReq)
	if err != nil {
		fmt.Printf("[-] %s ParseRequest error: %s\n", p.Name, err)
		return false, err, ""
	}
	variableMap := make(map[string]interface{})
	defer func() { variableMap = nil }()
	variableMap["request"] = req
	for _, item := range p.Set {
		k, expression := item.Key, item.Value
		if expression == "newReverse()" {
			if !common.DnsLog {
				return false, nil, ""
			}
			variableMap[k] = newReverse()
			continue
		}
		err, _ = evalset(env, variableMap, k, expression)
		if err != nil {
			fmt.Printf("[-] %s evalset error: %v\n", p.Name, err)
		}
	}
	success := false
	//爆破模式,比如tomcat弱口令
	if len(p.Sets) > 0 {
		success, err = clusterpoc(oReq, p, variableMap, req, env)
		return success, nil, ""
	}

	DealWithRule := func(rule Rules) (bool, error) {
		Headers := cloneMap(rule.Headers)
		var (
			flag, ok bool
		)
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range Headers {
				if !strings.Contains(v2, "{{"+k1+"}}") {
					continue
				}
				Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(rule.Path, "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(rule.Body, "{{"+k1+"}}", value)
		}

		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
		} else {
			req.Url.Path = rule.Path
		}
		// 某些poc没有区分path和query，需要处理
		req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
		//req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

		newRequest, err := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, string([]rune(req.Url.Path))), strings.NewReader(rule.Body))
		if err != nil {
			//fmt.Println("[-] newRequest error: ",err)
			return false, err
		}
		newRequest.Header = oReq.Header.Clone()
		for k, v := range Headers {
			newRequest.Header.Set(k, v)
		}
		Headers = nil
		resp, err := DoRequest(newRequest, rule.FollowRedirects)
		newRequest = nil
		if err != nil {
			return false, err
		}
		variableMap["response"] = resp
		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := doSearch(rule.Search, GetHeader(resp.Headers)+string(resp.Body))
			if len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap[k] = v
				}
			} else {
				return false, nil
			}
		}
		out, err := Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			return false, err
		}
		//如果false不继续执行后续rule
		// 如果最后一步执行失败，就算前面成功了最终依旧是失败
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}
		return flag, nil
	}

	DealWithRules := func(rules []Rules) bool {
		successFlag := false
		for _, rule := range rules {
			flag, err := DealWithRule(rule)
			if err != nil || !flag { //如果false不继续执行后续rule
				successFlag = false // 如果其中一步为flag，则直接break
				break
			}
			successFlag = true
		}
		return successFlag
	}

	if len(p.Rules) > 0 {
		success = DealWithRules(p.Rules)
	} else {
		for _, item := range p.Groups {
			name, rules := item.Key, item.Value
			success = DealWithRules(rules)
			if success {
				return success, nil, name
			}
		}
	}

	return success, nil, ""
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		fmt.Println("[-] regexp.Compile error: ", err)
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
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

func optimizeCookies(rawCookie string) (output string) {
	// Parse the cookies
	parsedCookie := strings.Split(rawCookie, "; ")
	for _, c := range parsedCookie {
		nameVal := strings.Split(c, "=")
		if len(nameVal) >= 2 {
			switch strings.ToLower(nameVal[0]) {
			case "expires", "max-age", "path", "domain", "version", "comment", "secure", "samesite", "httponly":
				continue
			}
			output += fmt.Sprintf("%s=%s; ", nameVal[0], strings.Join(nameVal[1:], "="))
		}
	}

	return
}

func newReverse() *Reverse {
	if !common.DnsLog {
		return &Reverse{}
	}
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	sub := RandomStr(randSource, letters, 8)
	//if true {
	//	//默认不开启dns解析
	//	return &Reverse{}
	//}
	urlStr := fmt.Sprintf("http://%s.%s", sub, ceyeDomain)
	u, _ := url.Parse(urlStr)
	return &Reverse{
		Url:                urlStr,
		Domain:             u.Hostname(),
		Ip:                 u.Host,
		IsDomainNameServer: false,
	}
}

func clusterpoc(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env) (success bool, err error) {
	var strMap StrMap
	var tmpnum int
	for i, rule := range p.Rules {
		if !isFuzz(rule, p.Sets) {
			success, err = clustersend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success {
				continue
			} else {
				return false, err
			}
		}
		setsMap := Combo(p.Sets)
		ruleHash := make(map[string]struct{})
	look:
		for j, item := range setsMap {
			//shiro默认只跑10key
			if p.Name == "poc-yaml-shiro-key" && !common.PocFull && j >= 10 {
				if item[1] == "cbc" {
					continue
				} else {
					if tmpnum == 0 {
						tmpnum = j
					}
					if j-tmpnum >= 10 {
						break
					}
				}
			}
			rule1 := cloneRules(rule)
			var flag1 bool
			var tmpMap StrMap
			var payloads = make(map[string]interface{})
			var tmpexpression string
			for i, one := range p.Sets {
				key, expression := one.Key, item[i]
				if key == "payload" {
					tmpexpression = expression
				}
				_, output := evalset1(env, variableMap, key, expression)
				payloads[key] = output
			}
			for _, one := range p.Sets {
				flag := false
				key := one.Key
				value := fmt.Sprintf("%v", payloads[key])
				for k2, v2 := range rule1.Headers {
					if strings.Contains(v2, "{{"+key+"}}") {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+key+"}}", value)
						flag = true
					}
				}
				if strings.Contains(rule1.Path, "{{"+key+"}}") {
					rule1.Path = strings.ReplaceAll(rule1.Path, "{{"+key+"}}", value)
					flag = true
				}
				if strings.Contains(rule1.Body, "{{"+key+"}}") {
					rule1.Body = strings.ReplaceAll(rule1.Body, "{{"+key+"}}", value)
					flag = true
				}
				if flag {
					flag1 = true
					if key == "payload" {
						var flag2 bool
						for k, v := range variableMap {
							if strings.Contains(tmpexpression, k) {
								flag2 = true
								tmpMap = append(tmpMap, StrItem{k, fmt.Sprintf("%v", v)})
							}
						}
						if flag2 {
							continue
						}
					}
					tmpMap = append(tmpMap, StrItem{key, value})
				}
			}
			if !flag1 {
				continue
			}
			has := md5.Sum([]byte(fmt.Sprintf("%v", rule1)))
			md5str := fmt.Sprintf("%x", has)
			if _, ok := ruleHash[md5str]; ok {
				continue
			}
			ruleHash[md5str] = struct{}{}
			success, err = clustersend(oReq, variableMap, req, env, rule1)
			if err != nil {
				return false, err
			}
			if success {
				if rule.Continue {
					if p.Name == "poc-yaml-backup-file" || p.Name == "poc-yaml-sql-file" {
						common.LogSuccess(fmt.Sprintf("[+] PocScan %s://%s%s %s", req.Url.Scheme, req.Url.Host, req.Url.Path, p.Name))
					} else {
						common.LogSuccess(fmt.Sprintf("[+] PocScan %s://%s%s %s %v", req.Url.Scheme, req.Url.Host, req.Url.Path, p.Name, tmpMap))
					}
					continue
				}
				strMap = append(strMap, tmpMap...)
				if i == len(p.Rules)-1 {
					common.LogSuccess(fmt.Sprintf("[+] PocScan %s://%s%s %s %v", req.Url.Scheme, req.Url.Host, req.Url.Path, p.Name, strMap))
					//防止后续继续打印poc成功信息
					return false, nil
				}
				break look
			}
		}
		if !success {
			break
		}
		if rule.Continue {
			//防止后续继续打印poc成功信息
			return false, nil
		}
	}
	return success, nil
}

func isFuzz(rule Rules, Sets ListMap) bool {
	for _, one := range Sets {
		key := one.Key
		for _, v := range rule.Headers {
			if strings.Contains(v, "{{"+key+"}}") {
				return true
			}
		}
		if strings.Contains(rule.Path, "{{"+key+"}}") {
			return true
		}
		if strings.Contains(rule.Body, "{{"+key+"}}") {
			return true
		}
	}
	return false
}

func Combo(input ListMap) (output [][]string) {
	if len(input) > 1 {
		output = Combo(input[1:])
		output = MakeData(output, input[0].Value)
	} else {
		for _, i := range input[0].Value {
			output = append(output, []string{i})
		}
	}
	return
}

func MakeData(base [][]string, nextData []string) (output [][]string) {
	for i := range base {
		for _, j := range nextData {
			output = append(output, append([]string{j}, base[i]...))
		}
	}
	return
}

func clustersend(oReq *http.Request, variableMap map[string]interface{}, req *Request, env *cel.Env, rule Rules) (bool, error) {
	for k1, v1 := range variableMap {
		_, isMap := v1.(map[string]string)
		if isMap {
			continue
		}
		value := fmt.Sprintf("%v", v1)
		for k2, v2 := range rule.Headers {
			if strings.Contains(v2, "{{"+k1+"}}") {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
		}
		rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
		rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
	}
	if oReq.URL.Path != "" && oReq.URL.Path != "/" {
		req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		req.Url.Path = rule.Path
	}
	// 某些poc没有区分path和query，需要处理
	req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
	//req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")
	//
	newRequest, err := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
	if err != nil {
		//fmt.Println("[-] newRequest error:",err)
		return false, err
	}
	newRequest.Header = oReq.Header.Clone()
	for k, v := range rule.Headers {
		newRequest.Header.Set(k, v)
	}
	resp, err := DoRequest(newRequest, rule.FollowRedirects)
	newRequest = nil
	if err != nil {
		return false, err
	}
	variableMap["response"] = resp
	// 先判断响应页面是否匹配search规则
	if rule.Search != "" {
		result := doSearch(rule.Search, GetHeader(resp.Headers)+string(resp.Body))
		if result != nil && len(result) > 0 { // 正则匹配成功
			for k, v := range result {
				variableMap[k] = v
			}
			//return false, nil
		} else {
			return false, nil
		}
	}
	out, err := Evaluate(env, rule.Expression, variableMap)
	if err != nil {
		if strings.Contains(err.Error(), "Syntax error") {
			fmt.Println(rule.Expression, err)
		}
		return false, err
	}
	//fmt.Println(fmt.Sprintf("%v, %s", out, out.Type().TypeName()))
	if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
		return false, err // 如果最后一步执行失败，就算前面成功了最终依旧是失败
	}
	return true, err
}

func cloneRules(tags Rules) Rules {
	cloneTags := Rules{}
	cloneTags.Method = tags.Method
	cloneTags.Path = tags.Path
	cloneTags.Body = tags.Body
	cloneTags.Search = tags.Search
	cloneTags.FollowRedirects = tags.FollowRedirects
	cloneTags.Expression = tags.Expression
	cloneTags.Headers = cloneMap(tags.Headers)
	return cloneTags
}

func cloneMap(tags map[string]string) map[string]string {
	cloneTags := make(map[string]string)
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func evalset(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (err error, output string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		switch value := out.Value().(type) {
		case *UrlType:
			variableMap[k] = UrlTypeToString(value)
		case int64:
			variableMap[k] = int(value)
		default:
			variableMap[k] = fmt.Sprintf("%v", out)
		}
	}
	return err, fmt.Sprintf("%v", variableMap[k])
}

func evalset1(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (err error, output string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		variableMap[k] = fmt.Sprintf("%v", out)
	}
	return err, fmt.Sprintf("%v", variableMap[k])
}

func CheckInfoPoc(infostr string) string {
	for _, poc := range info.PocDatas {
		if strings.Contains(infostr, poc.Name) {
			return poc.Alias
		}
	}
	return ""
}

func GetHeader(header map[string]string) (output string) {
	for name, values := range header {
		line := fmt.Sprintf("%s: %s\n", name, values)
		output = output + line
	}
	output = output + "\r\n"
	return
}
