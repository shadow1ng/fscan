package Common

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Parse 配置解析的总入口函数
// 协调调用各解析子函数，完成完整的配置处理流程
func Parse(Info *HostInfo) error {
	// 按照依赖顺序解析各类配置
	if err := ParseUser(); err != nil {
		return fmt.Errorf("用户名解析错误: %v", err)
	}

	if err := ParsePass(Info); err != nil {
		return fmt.Errorf("密码与目标解析错误: %v", err)
	}

	if err := ParseInput(Info); err != nil {
		return fmt.Errorf("输入参数解析错误: %v", err)
	}

	return nil
}

// ParseUser 解析用户名配置
// 处理直接指定的用户名和从文件加载的用户名，更新全局用户字典
func ParseUser() error {
	// 如果未指定用户名和用户名文件，无需处理
	if Username == "" && UsersFile == "" {
		return nil
	}

	// 收集所有用户名
	var usernames []string

	// 处理命令行参数指定的用户名列表
	if Username != "" {
		usernames = strings.Split(Username, ",")
		LogBase(GetText("no_username_specified", len(usernames)))
	}

	// 从文件加载用户名列表
	if UsersFile != "" {
		fileUsers, err := ReadFileLines(UsersFile)
		if err != nil {
			return fmt.Errorf("读取用户名文件失败: %v", err)
		}

		// 添加非空用户名
		for _, user := range fileUsers {
			if user != "" {
				usernames = append(usernames, user)
			}
		}
		LogBase(GetText("load_usernames_from_file", len(fileUsers)))
	}

	// 去重处理
	usernames = RemoveDuplicate(usernames)
	LogBase(GetText("total_usernames", len(usernames)))

	// 更新所有字典的用户名列表
	for name := range Userdict {
		Userdict[name] = usernames
	}

	return nil
}

// ParsePass 解析密码、URL、主机和端口等目标配置
// 处理多种输入源的配置，并更新全局目标信息
func ParsePass(Info *HostInfo) error {
	// 处理密码配置
	parsePasswords()

	// 处理哈希值配置
	parseHashes()

	// 处理URL配置
	parseURLs()

	// 处理主机配置
	if err := parseHosts(Info); err != nil {
		return err
	}

	// 处理端口配置
	if err := parsePorts(); err != nil {
		return err
	}

	return nil
}

// parsePasswords 解析密码配置
// 处理直接指定的密码和从文件加载的密码
func parsePasswords() {
	var pwdList []string

	// 处理命令行参数指定的密码列表
	if Password != "" {
		passes := strings.Split(Password, ",")
		for _, pass := range passes {
			if pass != "" {
				pwdList = append(pwdList, pass)
			}
		}
		Passwords = pwdList
		LogBase(GetText("load_passwords", len(pwdList)))
	}

	// 从文件加载密码列表
	if PasswordsFile != "" {
		passes, err := ReadFileLines(PasswordsFile)
		if err != nil {
			LogError(fmt.Sprintf("读取密码文件失败: %v", err))
			return
		}

		for _, pass := range passes {
			if pass != "" {
				pwdList = append(pwdList, pass)
			}
		}
		pwdList = append(pwdList, "")
		Passwords = pwdList
		LogBase(GetText("load_passwords_from_file", len(passes)))
	}
}

// parseHashes 解析哈希值配置
// 验证并处理哈希文件中的哈希值
func parseHashes() {
	// 处理哈希文件
	if HashFile == "" {
		return
	}

	hashes, err := ReadFileLines(HashFile)
	if err != nil {
		LogError(fmt.Sprintf("读取哈希文件失败: %v", err))
		return
	}

	validCount := 0
	for _, line := range hashes {
		if line == "" {
			continue
		}
		// 验证哈希长度(MD5哈希为32位)
		if len(line) == 32 {
			HashValues = append(HashValues, line)
			validCount++
		} else {
			LogError(GetText("invalid_hash", line))
		}
	}
	LogBase(GetText("load_valid_hashes", validCount))
}

// parseURLs 解析URL目标配置
// 处理命令行和文件指定的URL列表，去重后更新全局URL列表
func parseURLs() {
	urlMap := make(map[string]struct{})

	// 处理命令行参数指定的URL列表
	if TargetURL != "" {
		urls := strings.Split(TargetURL, ",")
		for _, url := range urls {
			if url != "" {
				urlMap[url] = struct{}{}
			}
		}
	}

	// 从文件加载URL列表
	if URLsFile != "" {
		urls, err := ReadFileLines(URLsFile)
		if err != nil {
			LogError(fmt.Sprintf("读取URL文件失败: %v", err))
			return
		}

		for _, url := range urls {
			if url != "" {
				urlMap[url] = struct{}{}
			}
		}
	}

	// 更新全局URL列表(已去重)
	URLs = make([]string, 0, len(urlMap))
	for u := range urlMap {
		URLs = append(URLs, u)
	}

	if len(URLs) > 0 {
		LogBase(GetText("load_urls", len(URLs)))
	}
}

// parseHosts 解析主机配置
// 从文件加载主机列表并更新目标信息
func parseHosts(Info *HostInfo) error {
	// 如果未指定主机文件，无需处理
	if HostsFile == "" {
		return nil
	}

	hosts, err := ReadFileLines(HostsFile)
	if err != nil {
		return fmt.Errorf("读取主机文件失败: %v", err)
	}

	// 去重处理
	hostMap := make(map[string]struct{})
	for _, host := range hosts {
		if host != "" {
			hostMap[host] = struct{}{}
		}
	}

	// 构建主机列表并更新Info.Host
	if len(hostMap) > 0 {
		var hostList []string
		for host := range hostMap {
			hostList = append(hostList, host)
		}

		hostStr := strings.Join(hostList, ",")
		if Info.Host == "" {
			Info.Host = hostStr
		} else {
			Info.Host += "," + hostStr
		}

		LogBase(GetText("load_hosts_from_file", len(hosts)))
	}

	return nil
}

// parsePorts 解析端口配置
// 从文件加载端口列表并更新全局端口配置
func parsePorts() error {
	// 如果未指定端口文件，无需处理
	if PortsFile == "" {
		return nil
	}

	ports, err := ReadFileLines(PortsFile)
	if err != nil {
		return fmt.Errorf("读取端口文件失败: %v", err)
	}

	// 构建端口列表字符串
	var portBuilder strings.Builder
	for _, port := range ports {
		if port != "" {
			portBuilder.WriteString(port)
			portBuilder.WriteString(",")
		}
	}

	// 更新全局端口配置
	Ports = portBuilder.String()
	LogBase(GetText("load_ports_from_file"))

	return nil
}

// parseExcludePorts 解析排除端口配置
// 更新全局排除端口配置
func parseExcludePorts() {
	if ExcludePorts != "" {
		LogBase(GetText("exclude_ports", ExcludePorts))
		// 确保排除端口被正确设置到全局配置中
		// 这将由PortScan函数在处理端口时使用
	}
}

// ReadFileLines 读取文件内容并返回非空行的切片
// 通用的文件读取函数，处理文件打开、读取和错误报告
func ReadFileLines(filename string) ([]string, error) {
	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		LogError(GetText("open_file_failed", filename, err))
		return nil, err
	}
	defer file.Close()

	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// 逐行读取文件内容，忽略空行
	lineCount := 0
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, text)
			lineCount++
		}
	}

	// 检查扫描过程中是否有错误
	if err := scanner.Err(); err != nil {
		LogError(GetText("read_file_failed", filename, err))
		return nil, err
	}

	LogBase(GetText("read_file_success", filename, lineCount))
	return content, nil
}

// ParseInput 解析和验证输入参数配置
// 处理多种配置的冲突检查、格式验证和参数处理
func ParseInput(Info *HostInfo) error {
	// 检查扫描模式冲突
	if err := validateScanMode(Info); err != nil {
		return err
	}

	// 处理端口配置组合
	processPortsConfig()

	// 处理排除端口配置
	parseExcludePorts()

	// 处理额外用户名和密码
	processExtraCredentials()

	// 处理代理配置
	if err := processProxySettings(); err != nil {
		return err
	}

	// 处理哈希值
	if err := processHashValues(); err != nil {
		return err
	}

	return nil
}

// validateScanMode 验证扫描模式
// 检查互斥的扫描模式配置，避免参数冲突
func validateScanMode(Info *HostInfo) error {
	// 检查互斥的扫描模式(主机扫描、URL扫描、本地模式)
	modes := 0
	if Info.Host != "" || HostsFile != "" {
		modes++
	}
	if len(URLs) > 0 || TargetURL != "" || URLsFile != "" {
		modes++
	}
	if LocalMode {
		modes++
	}

	// 处理扫描模式验证结果
	if modes == 0 {
		// 无参数时显示帮助
		flag.Usage()
		return fmt.Errorf(GetText("specify_scan_params"))
	} else if modes > 1 {
		return fmt.Errorf(GetText("params_conflict"))
	}

	return nil
}

// processPortsConfig 处理端口配置
// 合并默认端口和附加端口配置
func processPortsConfig() {
	// 如果使用主要端口，添加Web端口
	if Ports == MainPorts {
		Ports += "," + WebPorts
	}

	// 处理附加端口
	if AddPorts != "" {
		if strings.HasSuffix(Ports, ",") {
			Ports += AddPorts
		} else {
			Ports += "," + AddPorts
		}
		LogBase(GetText("extra_ports", AddPorts))
	}

	// 确保排除端口配置被记录
	if ExcludePorts != "" {
		LogBase(GetText("exclude_ports_applied", ExcludePorts))
	}
}

// processExtraCredentials 处理额外的用户名和密码
// 添加命令行指定的额外用户名和密码到现有配置
func processExtraCredentials() {
	// 处理额外用户名
	if AddUsers != "" {
		users := strings.Split(AddUsers, ",")
		for dict := range Userdict {
			Userdict[dict] = append(Userdict[dict], users...)
			Userdict[dict] = RemoveDuplicate(Userdict[dict])
		}
		LogBase(GetText("extra_usernames", AddUsers))
	}

	// 处理额外密码
	if AddPasswords != "" {
		passes := strings.Split(AddPasswords, ",")
		Passwords = append(Passwords, passes...)
		Passwords = RemoveDuplicate(Passwords)
		LogBase(GetText("extra_passwords", AddPasswords))
	}
}

// processProxySettings 处理代理设置
// 解析并验证Socks5和HTTP代理配置
func processProxySettings() error {
	// 处理Socks5代理
	if Socks5Proxy != "" {
		if err := setupSocks5Proxy(); err != nil {
			return err
		}
	}

	// 处理HTTP代理
	if HttpProxy != "" {
		if err := setupHttpProxy(); err != nil {
			return err
		}
	}

	return nil
}

// setupSocks5Proxy 设置Socks5代理
// 格式化和验证Socks5代理URL
func setupSocks5Proxy() error {
	// 规范化Socks5代理URL格式
	if !strings.HasPrefix(Socks5Proxy, "socks5://") {
		if !strings.Contains(Socks5Proxy, ":") {
			// 仅指定端口时使用本地地址
			Socks5Proxy = "socks5://127.0.0.1:" + Socks5Proxy
		} else {
			// 指定IP:PORT时添加协议前缀
			Socks5Proxy = "socks5://" + Socks5Proxy
		}
	}

	// 验证代理URL格式
	_, err := url.Parse(Socks5Proxy)
	if err != nil {
		return fmt.Errorf(GetText("socks5_proxy_error", err))
	}

	// 使用Socks5代理时禁用Ping(无法通过代理进行ICMP)
	DisablePing = true
	LogBase(GetText("socks5_proxy", Socks5Proxy))

	return nil
}

// setupHttpProxy 设置HTTP代理
// 处理多种HTTP代理简写形式并验证URL格式
func setupHttpProxy() error {
	// 处理HTTP代理简写形式
	switch HttpProxy {
	case "1":
		// 快捷方式1: 本地8080端口(常用代理工具默认端口)
		HttpProxy = "http://127.0.0.1:8080"
	case "2":
		// 快捷方式2: 本地1080端口(常见SOCKS端口)
		HttpProxy = "socks5://127.0.0.1:1080"
	default:
		// 仅指定端口时使用本地HTTP代理
		if !strings.Contains(HttpProxy, "://") {
			HttpProxy = "http://127.0.0.1:" + HttpProxy
		}
	}

	// 验证代理协议
	if !strings.HasPrefix(HttpProxy, "socks") && !strings.HasPrefix(HttpProxy, "http") {
		return fmt.Errorf(GetText("unsupported_proxy"))
	}

	// 验证代理URL格式
	_, err := url.Parse(HttpProxy)
	if err != nil {
		return fmt.Errorf(GetText("proxy_format_error", err))
	}

	LogBase(GetText("http_proxy", HttpProxy))

	return nil
}

// processHashValues 处理哈希值
// 验证单个哈希值并处理哈希列表
func processHashValues() error {
	// 处理单个哈希值
	if HashValue != "" {
		// MD5哈希必须是32位十六进制字符
		if len(HashValue) != 32 {
			return fmt.Errorf(GetText("hash_length_error"))
		}
		HashValues = append(HashValues, HashValue)
	}

	// 处理哈希值列表
	HashValues = RemoveDuplicate(HashValues)
	for _, hash := range HashValues {
		// 将十六进制字符串转换为字节数组
		hashByte, err := hex.DecodeString(hash)
		if err != nil {
			LogError(GetText("hash_decode_failed", hash))
			continue
		}
		HashBytes = append(HashBytes, hashByte)
	}

	// 清空原始哈希值列表，仅保留字节形式
	HashValues = []string{}

	return nil
}

// RemoveDuplicate 对字符串切片进行去重
func RemoveDuplicate(old []string) []string {
	temp := make(map[string]struct{})
	var result []string

	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
