package lib

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
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

func CheckMultiPoc(req *http.Request, Pocs embed.FS, workers int, pocname string) {
	tasks := make(chan Task)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		go func() {
			wg.Add(1)
			for task := range tasks {
				isVul, err := executePoc(task.Req, task.Poc)
				if err != nil {
					continue
				}
				if isVul {
					result := fmt.Sprintf("%s %s", task.Req.URL, task.Poc.Name)
					common.LogSuccess(result)
				}
			}
			wg.Done()
		}()
	}
	for _, poc := range LoadMultiPoc(Pocs, pocname) {
		task := Task{
			Req: req,
			Poc: poc,
		}
		tasks <- task
	}
	close(tasks)
	wg.Wait()
}

func executePoc(oReq *http.Request, p *Poc) (bool, error) {
	c := NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	env, err := NewEnv(&c)
	if err != nil {
		fmt.Println("environment creation error: %s\n", err)
		return false, err
	}
	variableMap := make(map[string]interface{})
	req, err := ParseRequest(oReq)
	if err != nil {
		//fmt.Println(err)
		return false, err
	}
	variableMap["request"] = req

	// 现在假定set中payload作为最后产出，那么先排序解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	keys := make([]string, 0)
	for k := range p.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		expression := p.Set[k]
		if k != "payload" {
			if expression == "newReverse()" {
				variableMap[k] = newReverse()
				continue
			}
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				//fmt.Println(err)
				continue
			}
			switch value := out.Value().(type) {
			case *UrlType:
				variableMap[k] = UrlTypeToString(value)
			case int64:
				variableMap[k] = int(value)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	if p.Set["payload"] != "" {
		out, err := Evaluate(env, p.Set["payload"], variableMap)
		if err != nil {
			return false, err
		}
		variableMap["payload"] = fmt.Sprintf("%v", out)
	}

	success := false
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
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
		req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

		newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
		newRequest.Header = oReq.Header.Clone()
		for k, v := range rule.Headers {
			newRequest.Header.Set(k, v)
		}
		resp, err := DoRequest(newRequest, rule.FollowRedirects)
		if err != nil {
			return false, err
		}
		variableMap["response"] = resp
		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
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
			return false, err
		}
		//fmt.Println(fmt.Sprintf("%v, %s", out, out.Type().TypeName()))
		if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
			success = false // 如果最后一步执行失败，就算前面成功了最终依旧是失败
			break
		}
		success = true
	}
	return success, nil
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}

func newReverse() *Reverse {
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	sub := RandomStr(randSource, letters, 8)
	if ceyeDomain == "" {
		return &Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", sub, ceyeDomain)
	u, _ := url.Parse(urlStr)
	return &Reverse{
		Url:                ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}
