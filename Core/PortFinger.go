package Core

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"regexp"
	"strconv"
	"strings"
)

//go:embed nmap-service-probes.txt
var ProbeString string

var v VScan // 改为VScan类型而不是指针

type VScan struct {
	Exclude        string
	AllProbes      []Probe
	UdpProbes      []Probe
	Probes         []Probe
	ProbesMapKName map[string]Probe
}

type Probe struct {
	Name     string // 探测器名称
	Data     string // 探测数据
	Protocol string // 协议
	Ports    string // 端口范围
	SSLPorts string // SSL端口范围

	TotalWaitMS  int    // 总等待时间
	TCPWrappedMS int    // TCP包装等待时间
	Rarity       int    // 稀有度
	Fallback     string // 回退探测器名称

	Matchs *[]Match // 匹配规则列表
}

type Match struct {
	IsSoft          bool           // 是否为软匹配
	Service         string         // 服务名称
	Pattern         string         // 匹配模式
	VersionInfo     string         // 版本信息格式
	FoundItems      []string       // 找到的项目
	PatternCompiled *regexp.Regexp // 编译后的正则表达式
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

type Extras struct {
	VendorProduct   string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	CPE             string
}

func init() {
	Common.LogDebug("开始初始化全局变量")

	v = VScan{} // 直接初始化VScan结构体
	v.Init()

	// 获取并检查 NULL 探测器
	if nullProbe, ok := v.ProbesMapKName["NULL"]; ok {
		Common.LogDebug(fmt.Sprintf("成功获取NULL探测器，Data长度: %d", len(nullProbe.Data)))
		null = &nullProbe
	} else {
		Common.LogDebug("警告: 未找到NULL探测器")
	}

	// 获取并检查 GenericLines 探测器
	if commonProbe, ok := v.ProbesMapKName["GenericLines"]; ok {
		Common.LogDebug(fmt.Sprintf("成功获取GenericLines探测器，Data长度: %d", len(commonProbe.Data)))
		common = &commonProbe
	} else {
		Common.LogDebug("警告: 未找到GenericLines探测器")
	}

	Common.LogDebug("全局变量初始化完成")
}

// 解析指令语法,返回指令结构
func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	Common.LogDebug("开始解析指令语法，输入数据: " + data)

	directive = Directive{}
	// 查找第一个空格的位置
	blankIndex := strings.Index(data, " ")
	if blankIndex == -1 {
		Common.LogDebug("未找到空格分隔符")
		return directive
	}

	// 解析各个字段
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	Common.LogDebug(fmt.Sprintf("指令解析结果: 名称=%s, 标志=%s, 分隔符=%s, 内容=%s",
		directiveName, Flag, delimiter, directiveStr))

	return directive
}

// 解析探测器信息
func (p *Probe) parseProbeInfo(probeStr string) {
	Common.LogDebug("开始解析探测器信息，输入字符串: " + probeStr)

	// 提取协议和其他信息
	proto := probeStr[:4]
	other := probeStr[4:]

	// 验证协议类型
	if !(proto == "TCP " || proto == "UDP ") {
		errMsg := "探测器协议必须是 TCP 或 UDP"
		Common.LogDebug("错误: " + errMsg)
		panic(errMsg)
	}

	// 验证其他信息不为空
	if len(other) == 0 {
		errMsg := "nmap-service-probes - 探测器名称无效"
		Common.LogDebug("错误: " + errMsg)
		panic(errMsg)
	}

	// 解析指令
	directive := p.getDirectiveSyntax(other)

	// 设置探测器属性
	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))

	Common.LogDebug(fmt.Sprintf("探测器解析完成: 名称=%s, 数据=%s, 协议=%s",
		p.Name, p.Data, p.Protocol))
}

// 从字符串解析探测器信息
func (p *Probe) fromString(data string) error {
	Common.LogDebug("开始解析探测器字符串数据")
	var err error

	// 预处理数据
	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("输入数据为空")
	}

	probeStr := lines[0]
	p.parseProbeInfo(probeStr)

	// 解析匹配规则和其他配置
	var matchs []Match
	for _, line := range lines {
		Common.LogDebug("处理行: " + line)
		switch {
		case strings.HasPrefix(line, "match "):
			match, err := p.getMatch(line)
			if err != nil {
				Common.LogDebug("解析match失败: " + err.Error())
				continue
			}
			matchs = append(matchs, match)

		case strings.HasPrefix(line, "softmatch "):
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				Common.LogDebug("解析softmatch失败: " + err.Error())
				continue
			}
			matchs = append(matchs, softMatch)

		case strings.HasPrefix(line, "ports "):
			p.parsePorts(line)

		case strings.HasPrefix(line, "sslports "):
			p.parseSSLPorts(line)

		case strings.HasPrefix(line, "totalwaitms "):
			p.parseTotalWaitMS(line)

		case strings.HasPrefix(line, "tcpwrappedms "):
			p.parseTCPWrappedMS(line)

		case strings.HasPrefix(line, "rarity "):
			p.parseRarity(line)

		case strings.HasPrefix(line, "fallback "):
			p.parseFallback(line)
		}
	}
	p.Matchs = &matchs
	Common.LogDebug(fmt.Sprintf("解析完成，共有 %d 个匹配规则", len(matchs)))
	return err
}

// 解析端口配置
func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
	Common.LogDebug("解析端口: " + p.Ports)
}

// 解析SSL端口配置
func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
	Common.LogDebug("解析SSL端口: " + p.SSLPorts)
}

// 解析总等待时间
func (p *Probe) parseTotalWaitMS(data string) {
	waitMS, err := strconv.Atoi(strings.TrimSpace(data[len("totalwaitms")+1:]))
	if err != nil {
		Common.LogDebug("解析总等待时间失败: " + err.Error())
		return
	}
	p.TotalWaitMS = waitMS
	Common.LogDebug(fmt.Sprintf("总等待时间: %d ms", waitMS))
}

// 解析TCP包装等待时间
func (p *Probe) parseTCPWrappedMS(data string) {
	wrappedMS, err := strconv.Atoi(strings.TrimSpace(data[len("tcpwrappedms")+1:]))
	if err != nil {
		Common.LogDebug("解析TCP包装等待时间失败: " + err.Error())
		return
	}
	p.TCPWrappedMS = wrappedMS
	Common.LogDebug(fmt.Sprintf("TCP包装等待时间: %d ms", wrappedMS))
}

// 解析稀有度
func (p *Probe) parseRarity(data string) {
	rarity, err := strconv.Atoi(strings.TrimSpace(data[len("rarity")+1:]))
	if err != nil {
		Common.LogDebug("解析稀有度失败: " + err.Error())
		return
	}
	p.Rarity = rarity
	Common.LogDebug(fmt.Sprintf("稀有度: %d", rarity))
}

// 解析回退配置
func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
	Common.LogDebug("回退配置: " + p.Fallback)
}

// 判断是否为十六进制编码
func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

// 判断是否为八进制编码
func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

// 判断是否为结构化转义字符
func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

// 判断是否为正则表达式特殊字符
func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

// 判断是否为其他转义序列
func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

// 从内容解析探测器规则
func (v *VScan) parseProbesFromContent(content string) {
	Common.LogDebug("开始解析探测器规则文件内容")
	var probes []Probe
	var lines []string

	// 过滤注释和空行
	linesTemp := strings.Split(content, "\n")
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}

	// 验证文件内容
	if len(lines) == 0 {
		errMsg := "读取nmap-service-probes文件失败: 内容为空"
		Common.LogDebug("错误: " + errMsg)
		panic(errMsg)
	}

	// 检查Exclude指令
	excludeCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			excludeCount++
		}
		if excludeCount > 1 {
			errMsg := "nmap-service-probes文件中只允许有一个Exclude指令"
			Common.LogDebug("错误: " + errMsg)
			panic(errMsg)
		}
	}

	// 验证第一行格式
	firstLine := lines[0]
	if !(strings.HasPrefix(firstLine, "Exclude ") || strings.HasPrefix(firstLine, "Probe ")) {
		errMsg := "解析错误: 首行必须以\"Probe \"或\"Exclude \"开头"
		Common.LogDebug("错误: " + errMsg)
		panic(errMsg)
	}

	// 处理Exclude指令
	if excludeCount == 1 {
		v.Exclude = firstLine[len("Exclude")+1:]
		lines = lines[1:]
		Common.LogDebug("解析到Exclude规则: " + v.Exclude)
	}

	// 合并内容并分割探测器
	content = "\n" + strings.Join(lines, "\n")
	probeParts := strings.Split(content, "\nProbe")[1:]

	// 解析每个探测器
	for _, probePart := range probeParts {
		probe := Probe{}
		if err := probe.fromString(probePart); err != nil {
			Common.LogDebug(fmt.Sprintf("解析探测器失败: %v", err))
			continue
		}
		probes = append(probes, probe)
	}

	v.AllProbes = probes
	Common.LogDebug(fmt.Sprintf("成功解析 %d 个探测器规则", len(probes)))
}

// 将探测器转换为名称映射
func (v *VScan) parseProbesToMapKName() {
	Common.LogDebug("开始构建探测器名称映射")
	v.ProbesMapKName = map[string]Probe{}
	for _, probe := range v.AllProbes {
		v.ProbesMapKName[probe.Name] = probe
		Common.LogDebug("添加探测器映射: " + probe.Name)
	}
}

// 设置使用的探测器
func (v *VScan) SetusedProbes() {
	Common.LogDebug("开始设置要使用的探测器")

	for _, probe := range v.AllProbes {
		if strings.ToLower(probe.Protocol) == "tcp" {
			if probe.Name == "SSLSessionReq" {
				Common.LogDebug("跳过 SSLSessionReq 探测器")
				continue
			}

			v.Probes = append(v.Probes, probe)
			Common.LogDebug("添加TCP探测器: " + probe.Name)

			// 特殊处理TLS会话请求
			if probe.Name == "TLSSessionReq" {
				sslProbe := v.ProbesMapKName["SSLSessionReq"]
				v.Probes = append(v.Probes, sslProbe)
				Common.LogDebug("为TLSSessionReq添加SSL探测器")
			}
		} else {
			v.UdpProbes = append(v.UdpProbes, probe)
			Common.LogDebug("添加UDP探测器: " + probe.Name)
		}
	}

	Common.LogDebug(fmt.Sprintf("探测器设置完成，TCP: %d个, UDP: %d个",
		len(v.Probes), len(v.UdpProbes)))
}

// 解析match指令获取匹配规则
func (p *Probe) getMatch(data string) (match Match, err error) {
	Common.LogDebug("开始解析match指令：" + data)
	match = Match{}

	// 提取match文本并解析指令语法
	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	// 分割文本获取pattern和版本信息
	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(textSplited) == 0 {
		return match, fmt.Errorf("无效的match指令格式")
	}

	pattern := textSplited[0]
	versionInfo := strings.Join(textSplited[1:], "")

	// 解码并编译正则表达式
	patternUnescaped, decodeErr := DecodePattern(pattern)
	if decodeErr != nil {
		Common.LogDebug("解码pattern失败: " + decodeErr.Error())
		return match, decodeErr
	}

	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, compileErr := regexp.Compile(patternUnescapedStr)
	if compileErr != nil {
		Common.LogDebug("编译正则表达式失败: " + compileErr.Error())
		return match, compileErr
	}

	// 设置match对象属性
	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	Common.LogDebug(fmt.Sprintf("解析match成功: 服务=%s, Pattern=%s",
		match.Service, match.Pattern))
	return match, nil
}

// 解析softmatch指令获取软匹配规则
func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	Common.LogDebug("开始解析softmatch指令：" + data)
	softMatch = Match{IsSoft: true}

	// 提取softmatch文本并解析指令语法
	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	// 分割文本获取pattern和版本信息
	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(textSplited) == 0 {
		return softMatch, fmt.Errorf("无效的softmatch指令格式")
	}

	pattern := textSplited[0]
	versionInfo := strings.Join(textSplited[1:], "")

	// 解码并编译正则表达式
	patternUnescaped, decodeErr := DecodePattern(pattern)
	if decodeErr != nil {
		Common.LogDebug("解码pattern失败: " + decodeErr.Error())
		return softMatch, decodeErr
	}

	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, compileErr := regexp.Compile(patternUnescapedStr)
	if compileErr != nil {
		Common.LogDebug("编译正则表达式失败: " + compileErr.Error())
		return softMatch, compileErr
	}

	// 设置softMatch对象属性
	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	Common.LogDebug(fmt.Sprintf("解析softmatch成功: 服务=%s, Pattern=%s",
		softMatch.Service, softMatch.Pattern))
	return softMatch, nil
}

// 解码模式字符串，处理转义序列
func DecodePattern(s string) ([]byte, error) {
	Common.LogDebug("开始解码pattern: " + s)
	sByteOrigin := []byte(s)

	// 处理十六进制、八进制和结构化转义序列
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte

		// 处理十六进制转义
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}

		// 处理结构化转义字符
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a 响铃
				102: []byte{0x0c}, // \f 换页
				116: []byte{0x09}, // \t 制表符
				110: []byte{0x0a}, // \n 换行
				114: []byte{0x0d}, // \r 回车
				118: []byte{0x0b}, // \v 垂直制表符
			}
			replace = structCodeMap[int(match[1])]
		}

		// 处理八进制转义
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	// 处理其他转义序列
	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		if isOtherEscapeCode(match) {
			return match
		}
		return match
	})

	Common.LogDebug("pattern解码完成")
	return sByteDec2, nil
}

// ProbesRarity 用于按稀有度排序的探测器切片
type ProbesRarity []Probe

// Len 返回切片长度，实现 sort.Interface 接口
func (ps ProbesRarity) Len() int {
	return len(ps)
}

// Swap 交换切片中的两个元素，实现 sort.Interface 接口
func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

// Less 比较函数，按稀有度升序排序，实现 sort.Interface 接口
func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}

// Target 定义目标结构体
type Target struct {
	IP       string // 目标IP地址
	Port     int    // 目标端口
	Protocol string // 协议类型
}

// ContainsPort 检查指定端口是否在探测器的端口范围内
func (p *Probe) ContainsPort(testPort int) bool {
	Common.LogDebug(fmt.Sprintf("检查端口 %d 是否在探测器端口范围内: %s", testPort, p.Ports))

	// 检查单个端口
	ports := strings.Split(p.Ports, ",")
	for _, port := range ports {
		port = strings.TrimSpace(port)
		cmpPort, err := strconv.Atoi(port)
		if err == nil && testPort == cmpPort {
			Common.LogDebug(fmt.Sprintf("端口 %d 匹配单个端口", testPort))
			return true
		}
	}

	// 检查端口范围
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			if len(portRange) != 2 {
				Common.LogDebug("无效的端口范围格式: " + port)
				continue
			}

			start, err1 := strconv.Atoi(strings.TrimSpace(portRange[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(portRange[1]))

			if err1 != nil || err2 != nil {
				Common.LogDebug(fmt.Sprintf("解析端口范围失败: %s", port))
				continue
			}

			if testPort >= start && testPort <= end {
				Common.LogDebug(fmt.Sprintf("端口 %d 在范围 %d-%d 内", testPort, start, end))
				return true
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("端口 %d 不在探测器端口范围内", testPort))
	return false
}

// MatchPattern 使用正则表达式匹配响应内容
func (m *Match) MatchPattern(response []byte) bool {
	// 将响应转换为字符串并进行匹配
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	if len(foundItems) > 0 {
		m.FoundItems = foundItems
		Common.LogDebug(fmt.Sprintf("匹配成功，找到 %d 个匹配项", len(foundItems)))
		return true
	}
	
	return false
}

// ParseVersionInfo 解析版本信息并返回额外信息结构
func (m *Match) ParseVersionInfo(response []byte) Extras {
	Common.LogDebug("开始解析版本信息")
	var extras = Extras{}

	// 替换版本信息中的占位符
	foundItems := m.FoundItems[1:] // 跳过第一个完整匹配项
	versionInfo := m.VersionInfo
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}
	Common.LogDebug("替换后的版本信息: " + versionInfo)

	// 定义解析函数
	parseField := func(field, pattern string) string {
		patterns := []string{
			pattern + `/([^/]*)/`,   // 斜线分隔
			pattern + `\|([^|]*)\|`, // 竖线分隔
		}

		for _, p := range patterns {
			if strings.Contains(versionInfo, pattern) {
				regex := regexp.MustCompile(p)
				if matches := regex.FindStringSubmatch(versionInfo); len(matches) > 1 {
					Common.LogDebug(fmt.Sprintf("解析到%s: %s", field, matches[1]))
					return matches[1]
				}
			}
		}
		return ""
	}

	// 解析各个字段
	extras.VendorProduct = parseField("厂商产品", " p")
	extras.Version = parseField("版本", " v")
	extras.Info = parseField("信息", " i")
	extras.Hostname = parseField("主机名", " h")
	extras.OperatingSystem = parseField("操作系统", " o")
	extras.DeviceType = parseField("设备类型", " d")

	// 特殊处理CPE
	if strings.Contains(versionInfo, " cpe:/") || strings.Contains(versionInfo, " cpe:|") {
		cpePatterns := []string{`cpe:/([^/]*)`, `cpe:\|([^|]*)`}
		for _, pattern := range cpePatterns {
			regex := regexp.MustCompile(pattern)
			if cpeName := regex.FindStringSubmatch(versionInfo); len(cpeName) > 0 {
				if len(cpeName) > 1 {
					extras.CPE = cpeName[1]
				} else {
					extras.CPE = cpeName[0]
				}
				Common.LogDebug("解析到CPE: " + extras.CPE)
				break
			}
		}
	}

	return extras
}

// ToMap 将 Extras 转换为 map[string]string
func (e *Extras) ToMap() map[string]string {
	Common.LogDebug("开始转换Extras为Map")
	result := make(map[string]string)

	// 定义字段映射
	fields := map[string]string{
		"vendor_product": e.VendorProduct,
		"version":        e.Version,
		"info":           e.Info,
		"hostname":       e.Hostname,
		"os":             e.OperatingSystem,
		"device_type":    e.DeviceType,
		"cpe":            e.CPE,
	}

	// 添加非空字段到结果map
	for key, value := range fields {
		if value != "" {
			result[key] = value
			Common.LogDebug(fmt.Sprintf("添加字段 %s: %s", key, value))
		}
	}

	Common.LogDebug(fmt.Sprintf("转换完成，共有 %d 个字段", len(result)))
	return result
}

func DecodeData(s string) ([]byte, error) {
	if len(s) == 0 {
		Common.LogDebug("输入数据为空")
		return nil, fmt.Errorf("empty input")
	}

	Common.LogDebug(fmt.Sprintf("开始解码数据，长度: %d, 内容: %q", len(s), s))
	sByteOrigin := []byte(s)

	// 处理十六进制、八进制和结构化转义序列
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) []byte {
		// 处理十六进制转义
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, err := strconv.ParseInt(string(hexNum), 16, 32)
			if err != nil {
				return match
			}
			return []byte{uint8(byteNum)}
		}

		// 处理结构化转义字符
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a 响铃
				102: []byte{0x0c}, // \f 换页
				116: []byte{0x09}, // \t 制表符
				110: []byte{0x0a}, // \n 换行
				114: []byte{0x0d}, // \r 回车
				118: []byte{0x0b}, // \v 垂直制表符
			}
			if replace, ok := structCodeMap[int(match[1])]; ok {
				return replace
			}
			return match
		}

		// 处理八进制转义
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, err := strconv.ParseInt(string(octalNum), 8, 32)
			if err != nil {
				return match
			}
			return []byte{uint8(byteNum)}
		}

		Common.LogDebug(fmt.Sprintf("无法识别的转义序列: %s", string(match)))
		return match
	})

	// 处理其他转义序列
	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) []byte {
		if len(match) < 2 {
			return match
		}
		if isOtherEscapeCode(match) {
			return []byte{match[1]}
		}
		return match
	})

	if len(sByteDec2) == 0 {
		Common.LogDebug("解码后数据为空")
		return nil, fmt.Errorf("decoded data is empty")
	}

	Common.LogDebug(fmt.Sprintf("解码完成，结果长度: %d, 内容: %x", len(sByteDec2), sByteDec2))
	return sByteDec2, nil
}

// GetAddress 获取目标的完整地址（IP:端口）
func (t *Target) GetAddress() string {
	addr := t.IP + ":" + strconv.Itoa(t.Port)
	Common.LogDebug("获取目标地址: " + addr)
	return addr
}

// trimBanner 处理和清理横幅数据
func trimBanner(buf []byte) string {
	Common.LogDebug("开始处理横幅数据")
	bufStr := string(buf)

	// 特殊处理SMB协议
	if strings.Contains(bufStr, "SMB") {
		banner := hex.EncodeToString(buf)
		if len(banner) > 0xa+6 && banner[0xa:0xa+6] == "534d42" { // "SMB" in hex
			Common.LogDebug("检测到SMB协议数据")
			plain := banner[0xa2:]
			data, err := hex.DecodeString(plain)
			if err != nil {
				Common.LogDebug("SMB数据解码失败: " + err.Error())
				return bufStr
			}

			// 解析domain
			var domain string
			var index int
			for i, s := range data {
				if s != 0 {
					domain += string(s)
				} else if i+1 < len(data) && data[i+1] == 0 {
					index = i + 2
					break
				}
			}

			// 解析hostname
			var hostname string
			remainData := data[index:]
			for i, h := range remainData {
				if h != 0 {
					hostname += string(h)
				}
				if i+1 < len(remainData) && remainData[i+1] == 0 {
					break
				}
			}

			smbBanner := fmt.Sprintf("hostname: %s domain: %s", hostname, domain)
			Common.LogDebug("SMB横幅: " + smbBanner)
			return smbBanner
		}
	}

	// 处理常规数据
	var src string
	for _, ch := range bufStr {
		if ch > 32 && ch < 125 {
			src += string(ch)
		} else {
			src += " "
		}
	}

	// 清理多余空白
	re := regexp.MustCompile(`\s{2,}`)
	src = re.ReplaceAllString(src, ".")
	result := strings.TrimSpace(src)
	Common.LogDebug("处理后的横幅: " + result)
	return result
}

// Init 初始化VScan对象
func (v *VScan) Init() {
	Common.LogDebug("开始初始化VScan")
	v.parseProbesFromContent(ProbeString)
	v.parseProbesToMapKName()
	v.SetusedProbes()
	Common.LogDebug("VScan初始化完成")
}
