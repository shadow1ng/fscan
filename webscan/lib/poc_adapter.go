package lib

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v2"
)

// PocFormat POC格式类型
type PocFormat string

const (
	// FormatFscan fscan原生格式
	FormatFscan PocFormat = "fscan"
	// FormatNuclei Nuclei格式
	FormatNuclei PocFormat = "nuclei"
	// FormatXray xray格式
	FormatXray PocFormat = "xray"
	// FormatAfrog afrog格式
	FormatAfrog PocFormat = "afrog"
	// FormatUnknown 未知格式
	FormatUnknown PocFormat = "unknown"
)

// UniversalPoc 通用POC接口 - 所有格式都要实现这个接口
type UniversalPoc interface {
	GetName() string           // 获取POC名称
	GetFormat() PocFormat      // 获取格式类型
	ToFscanPoc() (*Poc, error) // 转换为fscan内部格式
}

// DetectPocFormat 检测POC格式
// 根据YAML字段特征识别格式
func DetectPocFormat(data []byte) PocFormat {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return FormatUnknown
	}

	// afrog格式特征：id + info + rules(映射) + expression
	// 必须先检测 afrog，因为它同时有 id 和 info
	if _, hasID := raw["id"]; hasID {
		if _, hasInfo := raw["info"]; hasInfo {
			if rules, hasRules := raw["rules"]; hasRules {
				// 检查 rules 是否为映射（xray/afrog 风格）
				if _, isMap := rules.(map[interface{}]interface{}); isMap {
					return FormatAfrog
				}
			}
		}
	}

	// Nuclei格式特征：id + info + http(数组)
	if _, hasID := raw["id"]; hasID {
		if _, hasInfo := raw["info"]; hasInfo {
			if _, hasHTTP := raw["http"]; hasHTTP {
				return FormatNuclei
			}
		}
	}

	// xray格式特征：name + transport + rules(映射)
	if _, hasName := raw["name"]; hasName {
		if _, hasTransport := raw["transport"]; hasTransport {
			if rules, hasRules := raw["rules"]; hasRules {
				// 检查 rules 是否为映射
				if _, isMap := rules.(map[interface{}]interface{}); isMap {
					return FormatXray
				}
			}
			return FormatXray
		}
	}

	// fscan格式特征：name + rules(数组) 或 groups
	if _, hasName := raw["name"]; hasName {
		if rules, hasRules := raw["rules"]; hasRules {
			// 检查 rules 是否为数组（fscan 风格）
			if _, isArray := rules.([]interface{}); isArray {
				return FormatFscan
			}
		}
		if _, hasGroups := raw["groups"]; hasGroups {
			return FormatFscan
		}
	}

	return FormatUnknown
}

// LoadUniversalPoc 加载通用POC（自动识别格式）
func LoadUniversalPoc(filename string, data []byte) (UniversalPoc, error) {
	format := DetectPocFormat(data)

	switch format {
	case FormatFscan:
		return loadFscanPoc(data)
	case FormatNuclei:
		return loadNucleiPoc(data)
	case FormatXray:
		return loadXrayPoc(data)
	case FormatAfrog:
		return loadAfrogPoc(data)
	default:
		return nil, fmt.Errorf("未知POC格式: %s", filename)
	}
}

// ============= fscan格式适配器 =============

// FscanPocAdapter fscan原生格式适配器
type FscanPocAdapter struct {
	*Poc
}

func loadFscanPoc(data []byte) (*FscanPocAdapter, error) {
	var poc Poc
	if err := yaml.Unmarshal(data, &poc); err != nil {
		return nil, fmt.Errorf("fscan格式解析失败: %w", err)
	}
	return &FscanPocAdapter{&poc}, nil
}

// GetName 获取POC名称
func (f *FscanPocAdapter) GetName() string {
	return f.Name
}

// GetFormat 获取POC格式类型
func (f *FscanPocAdapter) GetFormat() PocFormat {
	return FormatFscan
}

// ToFscanPoc 转换为Fscan POC格式
func (f *FscanPocAdapter) ToFscanPoc() (*Poc, error) {
	return f.Poc, nil
}

// ============= Nuclei格式适配器 =============

// NucleiPoc Nuclei模板结构（简化版，仅支持HTTP协议）
type NucleiPoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Author      string   `yaml:"author"`
		Severity    string   `yaml:"severity"`
		Description string   `yaml:"description"`
		Reference   []string `yaml:"reference"`
	} `yaml:"info"`
	HTTP []struct {
		Method   string            `yaml:"method"`
		Path     []string          `yaml:"path"`
		Headers  map[string]string `yaml:"headers"`
		Body     string            `yaml:"body"`
		Matchers []struct {
			Type      string   `yaml:"type"`
			Words     []string `yaml:"words"`
			Status    []int    `yaml:"status"`
			Regex     []string `yaml:"regex"`
			Condition string   `yaml:"condition"`
			Part      string   `yaml:"part"`
		} `yaml:"matchers"`
		MatchersCondition string `yaml:"matchers-condition"`
	} `yaml:"http"`
}

// NucleiPocAdapter Nuclei格式适配器
type NucleiPocAdapter struct {
	*NucleiPoc
}

func loadNucleiPoc(data []byte) (*NucleiPocAdapter, error) {
	var poc NucleiPoc
	if err := yaml.Unmarshal(data, &poc); err != nil {
		return nil, fmt.Errorf("nuclei格式解析失败: %w", err)
	}
	return &NucleiPocAdapter{&poc}, nil
}

// GetName 获取POC名称（优先使用Info.Name，否则使用ID）
func (n *NucleiPocAdapter) GetName() string {
	if n.Info.Name != "" {
		return n.Info.Name
	}
	return n.ID
}

// GetFormat 获取POC格式类型
func (n *NucleiPocAdapter) GetFormat() PocFormat {
	return FormatNuclei
}

// ToFscanPoc 将Nuclei格式转换为fscan格式
func (n *NucleiPocAdapter) ToFscanPoc() (*Poc, error) {
	poc := &Poc{
		Name: n.GetName(),
		Detail: Detail{
			Author:      n.Info.Author,
			Description: n.Info.Description,
			Links:       n.Info.Reference,
		},
	}

	// 转换HTTP规则
	for _, httpReq := range n.HTTP {
		// Nuclei的method默认为GET
		method := httpReq.Method
		if method == "" {
			method = "GET"
		}

		// Nuclei支持多个path，需要为每个path创建一个rule
		paths := httpReq.Path
		if len(paths) == 0 {
			paths = []string{"{{BaseURL}}"}
		}

		for _, path := range paths {
			rule := Rules{
				Method:  method,
				Path:    path,
				Headers: httpReq.Headers,
				Body:    httpReq.Body,
			}

			// 转换matchers为expression
			if len(httpReq.Matchers) > 0 {
				expr := convertNucleiMatchers(httpReq.Matchers, httpReq.MatchersCondition)
				rule.Expression = expr
			} else {
				// 默认检查200状态码
				rule.Expression = "response.status == 200"
			}

			poc.Rules = append(poc.Rules, rule)
		}
	}

	if len(poc.Rules) == 0 {
		return nil, fmt.Errorf("nuclei模板没有有效的HTTP规则")
	}

	return poc, nil
}

// convertNucleiMatchers 转换Nuclei matchers为fscan expression
func convertNucleiMatchers(matchers []struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words"`
	Status    []int    `yaml:"status"`
	Regex     []string `yaml:"regex"`
	Condition string   `yaml:"condition"`
	Part      string   `yaml:"part"`
}, matchersCondition string) string {
	var conditions []string

	for _, m := range matchers {
		var matcherConds []string

		switch m.Type {
		case "word":
			for _, word := range m.Words {
				// 转义双引号
				escapedWord := strings.ReplaceAll(word, `"`, `\"`)
				matcherConds = append(matcherConds, fmt.Sprintf(`response.body.bcontains(b"%s")`, escapedWord))
			}
		case "status":
			for _, status := range m.Status {
				matcherConds = append(matcherConds, fmt.Sprintf("response.status == %d", status))
			}
		case "regex":
			for _, pattern := range m.Regex {
				// 简化处理：直接用bmatches
				escapedPattern := strings.ReplaceAll(pattern, `"`, `\"`)
				matcherConds = append(matcherConds, fmt.Sprintf(`response.body.bmatches(b"%s")`, escapedPattern))
			}
		case "dsl":
			// DSL类型暂不支持，使用默认匹配
			matcherConds = append(matcherConds, "response.status == 200")
		}

		// 单个matcher内的条件组合
		if len(matcherConds) > 0 {
			connector := " && "
			if m.Condition == "or" {
				connector = " || "
			}

			if len(matcherConds) == 1 {
				conditions = append(conditions, matcherConds[0])
			} else {
				combined := "(" + strings.Join(matcherConds, connector) + ")"
				conditions = append(conditions, combined)
			}
		}
	}

	// 默认返回
	if len(conditions) == 0 {
		return "response.status == 200"
	}
	if len(conditions) == 1 {
		return conditions[0]
	}

	// 多个matcher之间的条件组合
	connector := " && "
	if matchersCondition == "or" {
		connector = " || "
	}

	return strings.Join(conditions, connector)
}

// ============= xray格式适配器 =============

// XrayPoc xray POC结构
type XrayPoc struct {
	Name       string                 `yaml:"name"`
	Transport  string                 `yaml:"transport"`
	Set        map[string]interface{} `yaml:"set"`
	Rules      map[string]XrayRule    `yaml:"rules"`
	Expression string                 `yaml:"expression"`
	Detail     Detail                 `yaml:"detail"`
}

// XrayRule xray规则结构
type XrayRule struct {
	Request struct {
		Cache           bool              `yaml:"cache"`
		Method          string            `yaml:"method"`
		Path            string            `yaml:"path"`
		Headers         map[string]string `yaml:"headers"`
		Body            string            `yaml:"body"`
		FollowRedirects bool              `yaml:"follow_redirects"`
	} `yaml:"request"`
	Expression string                 `yaml:"expression"`
	Output     map[string]interface{} `yaml:"output"`
}

// XrayPocAdapter xray格式适配器
type XrayPocAdapter struct {
	*XrayPoc
}

func loadXrayPoc(data []byte) (*XrayPocAdapter, error) {
	var poc XrayPoc
	if err := yaml.Unmarshal(data, &poc); err != nil {
		return nil, fmt.Errorf("xray格式解析失败: %w", err)
	}
	return &XrayPocAdapter{&poc}, nil
}

// GetName 获取POC名称
func (x *XrayPocAdapter) GetName() string {
	return x.Name
}

// GetFormat 获取POC格式类型
func (x *XrayPocAdapter) GetFormat() PocFormat {
	return FormatXray
}

// ToFscanPoc 将xray格式转换为fscan格式
func (x *XrayPocAdapter) ToFscanPoc() (*Poc, error) {
	poc := &Poc{
		Name:   x.Name,
		Detail: x.Detail,
	}

	// xray的set字段转换
	if len(x.Set) > 0 {
		poc.Set = make(StrMap, 0, len(x.Set))
		for k, v := range x.Set {
			poc.Set = append(poc.Set, StrItem{
				Key:   k,
				Value: fmt.Sprintf("%v", v),
			})
		}
	}

	// 按顺序提取 rules (r0, r1, r2...)
	for i := 0; ; i++ {
		key := fmt.Sprintf("r%d", i)
		rule, exists := x.Rules[key]
		if !exists {
			break
		}

		// 展开 request 对象为 fscan Rule
		fscanRule := Rules{
			Method:          rule.Request.Method,
			Path:            rule.Request.Path,
			Headers:         rule.Request.Headers,
			Body:            rule.Request.Body,
			FollowRedirects: rule.Request.FollowRedirects,
			Expression:      rule.Expression,
		}

		// 转换 output 字段为 Search — 多步POC中从响应提取变量供后续步骤使用
		if searchVal, ok := rule.Output["search"]; ok {
			fscanRule.Search = fmt.Sprintf("%v", searchVal)
		}

		// 如果expression为空，默认检查200状态码
		if fscanRule.Expression == "" {
			fscanRule.Expression = "response.status == 200"
		}

		poc.Rules = append(poc.Rules, fscanRule)
	}

	if len(poc.Rules) == 0 {
		return nil, fmt.Errorf("xray POC没有有效的规则")
	}

	return poc, nil
}

// ============= afrog格式适配器 =============

// AfrogPoc afrog POC结构（混合 Nuclei + xray 风格）
type AfrogPoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Author      string   `yaml:"author"`
		Severity    string   `yaml:"severity"`
		Verified    bool     `yaml:"verified"`
		Description string   `yaml:"description"`
		Reference   []string `yaml:"reference"`
		Tags        string   `yaml:"tags"`
		Created     string   `yaml:"created"`
	} `yaml:"info"`
	Set        map[string]interface{} `yaml:"set"`
	Rules      map[string]XrayRule    `yaml:"rules"` // 复用 xray 的 rule 结构
	Expression string                 `yaml:"expression"`
}

// AfrogPocAdapter afrog格式适配器
type AfrogPocAdapter struct {
	*AfrogPoc
}

func loadAfrogPoc(data []byte) (*AfrogPocAdapter, error) {
	var poc AfrogPoc
	if err := yaml.Unmarshal(data, &poc); err != nil {
		return nil, fmt.Errorf("afrog格式解析失败: %w", err)
	}
	return &AfrogPocAdapter{&poc}, nil
}

// GetName 获取POC名称（优先使用Info.Name，否则使用ID）
func (a *AfrogPocAdapter) GetName() string {
	if a.Info.Name != "" {
		return a.Info.Name
	}
	return a.ID
}

// GetFormat 获取POC格式类型
func (a *AfrogPocAdapter) GetFormat() PocFormat {
	return FormatAfrog
}

// ToFscanPoc 将afrog格式转换为fscan格式
func (a *AfrogPocAdapter) ToFscanPoc() (*Poc, error) {
	// 转换元数据（使用 Nuclei 风格的 info）
	poc := &Poc{
		Name: a.GetName(),
		Detail: Detail{
			Author:      a.Info.Author,
			Description: a.Info.Description,
			Links:       a.Info.Reference,
		},
	}

	// afrog的set字段转换
	if len(a.Set) > 0 {
		poc.Set = make(StrMap, 0, len(a.Set))
		for k, v := range a.Set {
			poc.Set = append(poc.Set, StrItem{
				Key:   k,
				Value: fmt.Sprintf("%v", v),
			})
		}
	}

	// 转换 rules（和 xray 一样，按顺序提取）
	for i := 0; ; i++ {
		key := fmt.Sprintf("r%d", i)
		rule, exists := a.Rules[key]
		if !exists {
			break
		}

		fscanRule := Rules{
			Method:          rule.Request.Method,
			Path:            rule.Request.Path,
			Headers:         rule.Request.Headers,
			Body:            rule.Request.Body,
			FollowRedirects: rule.Request.FollowRedirects,
			Expression:      rule.Expression,
		}

		// 转换 output 字段为 Search — 多步POC中从响应提取变量供后续步骤使用
		if searchVal, ok := rule.Output["search"]; ok {
			fscanRule.Search = fmt.Sprintf("%v", searchVal)
		}

		// 如果expression为空，默认检查200状态码
		if fscanRule.Expression == "" {
			fscanRule.Expression = "response.status == 200"
		}

		poc.Rules = append(poc.Rules, fscanRule)
	}

	if len(poc.Rules) == 0 {
		return nil, fmt.Errorf("afrog POC没有有效的规则")
	}

	return poc, nil
}
