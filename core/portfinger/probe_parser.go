package portfinger

import (
	"fmt"
	"strconv"
	"strings"
)

// 解析指令语法,返回指令结构
func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}
	// 查找第一个空格的位置
	blankIndex := strings.Index(data, " ")
	if blankIndex == -1 {
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

	return directive
}

// parseProbeInfo 解析探测器信息，返回错误替代 panic
func (p *Probe) parseProbeInfo(probeStr string) error {
	// 提取协议和其他信息
	proto := probeStr[:4]
	other := probeStr[4:]

	// 验证协议类型
	if proto != "TCP " && proto != "UDP " {
		return fmt.Errorf("探测器协议必须是 TCP 或 UDP")
	}

	// 验证其他信息不为空
	if len(other) == 0 {
		return fmt.Errorf("nmap-service-probes - 探测器名称无效")
	}

	// 解析指令
	directive := p.getDirectiveSyntax(other)

	// 设置探测器属性
	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))

	return nil
}

// 从字符串解析探测器信息
func (p *Probe) fromString(data string) error {
	var err error

	// 预处理数据
	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("输入数据为空")
	}

	probeStr := lines[0]
	if err := p.parseProbeInfo(probeStr); err != nil {
		return err
	}

	// 解析匹配规则和其他配置
	var matchs []Match
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "match "):
			match, matchErr := p.getMatch(line)
			if matchErr != nil {
				continue
			}
			matchs = append(matchs, match)

		case strings.HasPrefix(line, "softmatch "):
			softMatch, matchErr := p.getSoftMatch(line)
			if matchErr != nil {
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
	return err
}

// 解析端口配置
func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
}

// 解析SSL端口配置
func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
}

// 解析总等待时间
func (p *Probe) parseTotalWaitMS(data string) {
	waitMS, err := strconv.Atoi(strings.TrimSpace(data[len("totalwaitms")+1:]))
	if err != nil {
		return
	}
	p.TotalWaitMS = waitMS
}

// 解析TCP包装等待时间
func (p *Probe) parseTCPWrappedMS(data string) {
	wrappedMS, err := strconv.Atoi(strings.TrimSpace(data[len("tcpwrappedms")+1:]))
	if err != nil {
		return
	}
	p.TCPWrappedMS = wrappedMS
}

// 解析稀有度
func (p *Probe) parseRarity(data string) {
	rarity, err := strconv.Atoi(strings.TrimSpace(data[len("rarity")+1:]))
	if err != nil {
		return
	}
	p.Rarity = rarity
}

// 解析回退配置
func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

// parseProbesFromContent 从内容解析探测器规则，返回错误替代 panic
func (v *VScan) parseProbesFromContent(content string) error {
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
		return fmt.Errorf("读取nmap-service-probes文件失败: 内容为空")
	}

	// 检查Exclude指令
	excludeCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			excludeCount++
		}
		if excludeCount > 1 {
			return fmt.Errorf("nmap-service-probes文件中只允许有一个Exclude指令")
		}
	}

	// 验证第一行格式
	firstLine := lines[0]
	if !strings.HasPrefix(firstLine, "Exclude ") && !strings.HasPrefix(firstLine, "Probe ") {
		return fmt.Errorf("解析错误: 首行必须以\"Probe \"或\"Exclude \"开头")
	}

	// 处理Exclude指令
	if excludeCount == 1 {
		v.Exclude = firstLine[len("Exclude")+1:]
		lines = lines[1:]
	}

	// 合并内容并分割探测器
	content = "\n" + strings.Join(lines, "\n")
	probeParts := strings.Split(content, "\nProbe")[1:]

	// 解析每个探测器
	for _, probePart := range probeParts {
		probe := Probe{}
		if err := probe.fromString(probePart); err != nil {
			continue
		}
		probes = append(probes, probe)
	}

	v.AllProbes = probes
	return nil
}

// 将探测器转换为名称映射
func (v *VScan) parseProbesToMapKName() {
	v.ProbesMapKName = map[string]Probe{}
	for _, probe := range v.AllProbes {
		v.ProbesMapKName[probe.Name] = probe
	}
}

// SetusedProbes 设置使用的探测器
func (v *VScan) SetusedProbes() {
	for _, probe := range v.AllProbes {
		if strings.ToLower(probe.Protocol) == "tcp" {
			if probe.Name == "SSLSessionReq" {
				continue
			}

			v.Probes = append(v.Probes, probe)
			// 特殊处理TLS会话请求
			if probe.Name == "TLSSessionReq" {
				sslProbe := v.ProbesMapKName["SSLSessionReq"]
				v.Probes = append(v.Probes, sslProbe)
			}
		} else {
			v.UDPProbes = append(v.UDPProbes, probe)
		}
	}

}
