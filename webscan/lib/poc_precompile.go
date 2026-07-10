package lib

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// preparedPoc 是 POC 的只读执行计划。加载完成后不再修改，可安全地在多个目标间复用。
type preparedPoc struct {
	env      *cel.Env
	programs *CelProgCache
	searches map[string]*regexp.Regexp
}

// Prepare 在加载阶段构建 POC 的 CEL 环境、程序和搜索正则。
// 对手工构造的 POC 重复调用也是安全的，实际准备过程只执行一次。
func (p *Poc) Prepare() error {
	if p == nil {
		return fmt.Errorf("POC is nil")
	}
	p.prepareOnce.Do(func() {
		p.prepared, p.prepareErr = buildPreparedPoc(p)
	})
	return p.prepareErr
}

func (p *Poc) executionPlan() (*preparedPoc, error) {
	if err := p.Prepare(); err != nil {
		return nil, err
	}
	return p.prepared, nil
}

func buildPreparedPoc(p *Poc) (*preparedPoc, error) {
	searches, captureNames, err := compilePocSearches(p)
	if err != nil {
		return nil, err
	}

	declarations := collectPreparedVarDeclarations(p, captureNames)
	env, err := ExtendEnvWithVars(declarations)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	expressions := collectPocExpressions(p)
	programs := newCelProgCache(len(expressions))
	for _, expression := range expressions {
		// 编译错误也进入缓存。这样历史上无法执行的规则仍在执行时返回同类错误，
		// 但不会再针对每个目标重复尝试编译。
		_, _ = compileCachedProgram(env, expression, programs)
	}
	programs.seal()

	return &preparedPoc{
		env:      env,
		programs: programs,
		searches: searches,
	}, nil
}

func compileCachedProgram(env *cel.Env, expression string, cache *CelProgCache) (cel.Program, error) {
	if expression == "" {
		return nil, nil
	}
	if program, err, cached := cache.get(expression); cached {
		return program, err
	}
	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		return cache.putIfAbsent(expression, nil, issues.Err())
	}
	program, err := env.Program(ast, GetBaseProgramOptions()...)
	return cache.putIfAbsent(expression, program, err)
}

func compilePocSearches(p *Poc) (map[string]*regexp.Regexp, []string, error) {
	patterns := collectPocSearchPatterns(p)
	searches := make(map[string]*regexp.Regexp, len(patterns))
	captureNames := make([]string, 0)
	seenCaptures := make(map[string]struct{})
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, nil, fmt.Errorf("compile search expression %q: %w", compactExpression(pattern), err)
		}
		searches[pattern] = compiled
		for _, name := range compiled.SubexpNames() {
			if name == "" {
				continue
			}
			if _, exists := seenCaptures[name]; exists {
				continue
			}
			seenCaptures[name] = struct{}{}
			captureNames = append(captureNames, name)
		}
	}
	return searches, captureNames, nil
}

func collectPreparedVarDeclarations(p *Poc, captureNames []string) []*exprpb.Decl {
	baseDeclarations := collectVarDeclarations(p)
	declarations := make([]*exprpb.Decl, 0, len(baseDeclarations)+len(captureNames))
	seen := make(map[string]struct{}, cap(declarations))
	for _, declaration := range baseDeclarations {
		if declaration == nil || declaration.Name == "" {
			continue
		}
		if _, exists := seen[declaration.Name]; exists {
			continue
		}
		seen[declaration.Name] = struct{}{}
		declarations = append(declarations, declaration)
	}
	for _, name := range captureNames {
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		declarations = append(declarations, MakeVarDecl(name, ""))
	}
	return declarations
}

func collectPocExpressions(p *Poc) []string {
	expressions := make([]string, 0, len(p.Set)+len(p.Rules)+len(p.Sets))
	seen := make(map[string]struct{})
	add := func(expression string) {
		if expression == "" {
			return
		}
		if _, exists := seen[expression]; exists {
			return
		}
		seen[expression] = struct{}{}
		expressions = append(expressions, expression)
	}

	declaredVariables := make(map[string]interface{}, len(p.Set)+len(p.Sets))
	for _, item := range p.Set {
		declaredVariables[item.Key] = nil
		if item.Value != "newReverse()" {
			add(item.Value)
		}
	}
	for _, item := range p.Sets {
		declaredVariables[item.Key] = nil
	}
	for _, item := range p.Sets {
		for _, expression := range item.Value {
			if !isPlainLiteral(expression, declaredVariables) {
				add(expression)
			}
		}
	}
	forEachPocRule(p, func(rule Rules) {
		add(rule.Expression)
	})
	return expressions
}

func collectPocSearchPatterns(p *Poc) []string {
	patterns := make([]string, 0)
	seen := make(map[string]struct{})
	forEachPocRule(p, func(rule Rules) {
		if rule.Search == "" {
			return
		}
		if _, exists := seen[rule.Search]; exists {
			return
		}
		seen[rule.Search] = struct{}{}
		patterns = append(patterns, rule.Search)
	})
	return patterns
}

func forEachPocRule(p *Poc, fn func(Rules)) {
	for _, rule := range p.Rules {
		fn(rule)
	}
	for _, group := range p.Groups {
		for _, rule := range group.Value {
			fn(rule)
		}
	}
}

func compactExpression(expression string) string {
	const maxLength = 120
	compact := strings.Join(strings.Fields(expression), " ")
	if len(compact) <= maxLength {
		return compact
	}
	return compact[:maxLength] + "..."
}

func (p *preparedPoc) search(pattern, body string) map[string]string {
	if p != nil {
		if compiled := p.searches[pattern]; compiled != nil {
			return searchWithRegexp(compiled, body)
		}
	}
	return doSearch(pattern, body)
}
