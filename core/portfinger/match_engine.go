package portfinger

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/shadow1ng/fscan/common/i18n"
)

// BytesToRegexSafeString 将字节切片转换为 Go regexp 安全的正则表达式模式字符串
// 非打印字符和高位字节转换为 \x{NN} 形式，用于编译正则表达式
func BytesToRegexSafeString(b []byte) string {
	var result strings.Builder
	for _, c := range b {
		if c < 32 || c >= 128 {
			// 控制字符和高位字节转换为 \x{NN} 格式
			fmt.Fprintf(&result, "\\x{%02x}", c)
		} else {
			result.WriteByte(c)
		}
	}
	return result.String()
}

// bytesToLatin1String 将字节切片转换为 Latin-1 字符串
// 每个字节直接映射到对应的 Unicode 码点 U+0000-U+00FF
// 这样可以与使用 \x{NN} 格式的正则表达式正确匹配
func bytesToLatin1String(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

// parseMatchDirective 解析match/softmatch指令的通用实现
func (p *Probe) parseMatchDirective(data, prefix string, isSoft bool) (Match, error) {
	match := Match{IsSoft: isSoft}

	// 提取指令文本并解析语法
	matchText := data[len(prefix)+1:]
	directive := p.getDirectiveSyntax(matchText)

	// 分割文本获取pattern和版本信息
	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(textSplited) == 0 {
		return match, fmt.Errorf("%s", i18n.Tr("portfinger_match_directive_invalid", prefix))
	}

	pattern := textSplited[0]
	versionInfo := strings.Join(textSplited[1:], "")

	// versionInfo 格式是 "flags p/product/ v/version/ ..."
	// flags 是正则表达式修饰符(如 s、i、si)，后面跟空格和版本信息字段
	// 需要跳过 flags 部分，找到第一个空格开始的版本信息
	if idx := strings.Index(versionInfo, " "); idx != -1 {
		versionInfo = versionInfo[idx:]
	}

	// 解码并编译正则表达式
	patternUnescaped, decodeErr := DecodePattern(pattern)
	if decodeErr != nil {
		return match, decodeErr
	}

	// 将字节模式转换为 Go regexp 安全的字符串（处理高位字节）
	safePattern := BytesToRegexSafeString(patternUnescaped)
	patternCompiled, compileErr := regexp.Compile(safePattern)
	if compileErr != nil {
		return match, compileErr
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

// getMatch 解析match指令获取匹配规则
func (p *Probe) getMatch(data string) (Match, error) {
	return p.parseMatchDirective(data, "match", false)
}

// getSoftMatch 解析softmatch指令获取软匹配规则
func (p *Probe) getSoftMatch(data string) (Match, error) {
	return p.parseMatchDirective(data, "softmatch", true)
}

// MatchPattern 检查响应是否与匹配规则匹配
func (m *Match) MatchPattern(response []byte) bool {
	if m.PatternCompiled == nil {
		return false
	}

	// 将响应字节转换为 Latin-1 字符串，每个字节映射到对应的 Unicode 码点
	// 这样正则表达式中的 \x{NN} 可以正确匹配对应的字节值
	latin1Response := bytesToLatin1String(response)
	matched := m.PatternCompiled.MatchString(latin1Response)
	if matched {
		// 提取匹配到的子组
		submatches := m.PatternCompiled.FindStringSubmatch(latin1Response)
		if len(submatches) > 1 {
			m.FoundItems = submatches[1:] // 排除完整匹配，只保留分组
		}
	}

	return matched
}
