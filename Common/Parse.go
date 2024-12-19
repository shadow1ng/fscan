package Common

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func Parse(Info *HostInfo) {
	ParseUser()
	ParsePass(Info)
	ParseInput(Info)
	ParseScantype(Info)
}

// ParseUser 解析用户名配置,支持直接指定用户名列表或从文件读取
func ParseUser() error {
	// 如果未指定用户名和用户名文件,直接返回
	if Username == "" && Userfile == "" {
		return nil
	}

	var usernames []string

	// 处理直接指定的用户名列表
	if Username != "" {
		usernames = strings.Split(Username, ",")
		fmt.Printf("[*] 已加载直接指定的用户名: %d 个\n", len(usernames))
	}

	// 从文件加载用户名列表
	if Userfile != "" {
		users, err := Readfile(Userfile)
		if err != nil {
			return fmt.Errorf("读取用户名文件失败: %v", err)
		}

		// 过滤空用户名
		for _, user := range users {
			if user != "" {
				usernames = append(usernames, user)
			}
		}
		fmt.Printf("[*] 已从文件加载用户名: %d 个\n", len(users))
	}

	// 去重处理
	usernames = RemoveDuplicate(usernames)
	fmt.Printf("[*] 去重后用户名总数: %d 个\n", len(usernames))

	// 更新用户字典
	for name := range Userdict {
		Userdict[name] = usernames
	}

	return nil
}

// ParsePass 解析密码、哈希值、URL和端口配置
func ParsePass(Info *HostInfo) error {
	// 处理直接指定的密码列表
	var pwdList []string
	if Password != "" {
		passes := strings.Split(Password, ",")
		for _, pass := range passes {
			if pass != "" {
				pwdList = append(pwdList, pass)
			}
		}
		Passwords = pwdList
		fmt.Printf("[*] 已加载直接指定的密码: %d 个\n", len(pwdList))
	}

	// 从文件加载密码列表
	if Passfile != "" {
		passes, err := Readfile(Passfile)
		if err != nil {
			return fmt.Errorf("读取密码文件失败: %v", err)
		}
		for _, pass := range passes {
			if pass != "" {
				pwdList = append(pwdList, pass)
			}
		}
		Passwords = pwdList
		fmt.Printf("[*] 已从文件加载密码: %d 个\n", len(passes))
	}

	// 处理哈希文件
	if Hashfile != "" {
		hashes, err := Readfile(Hashfile)
		if err != nil {
			return fmt.Errorf("读取哈希文件失败: %v", err)
		}

		validCount := 0
		for _, line := range hashes {
			if line == "" {
				continue
			}
			if len(line) == 32 {
				Hashs = append(Hashs, line)
				validCount++
			} else {
				fmt.Printf("[!] 无效的哈希值(长度!=32): %s\n", line)
			}
		}
		fmt.Printf("[*] 已加载有效哈希值: %d 个\n", validCount)
	}

	// 处理直接指定的URL列表
	if URL != "" {
		urls := strings.Split(URL, ",")
		tmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if url != "" {
				if _, ok := tmpUrls[url]; !ok {
					tmpUrls[url] = struct{}{}
					Urls = append(Urls, url)
				}
			}
		}
		fmt.Printf("[*] 已加载直接指定的URL: %d 个\n", len(Urls))
	}

	// 从文件加载URL列表
	if UrlFile != "" {
		urls, err := Readfile(UrlFile)
		if err != nil {
			return fmt.Errorf("读取URL文件失败: %v", err)
		}

		tmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if url != "" {
				if _, ok := tmpUrls[url]; !ok {
					tmpUrls[url] = struct{}{}
					Urls = append(Urls, url)
				}
			}
		}
		fmt.Printf("[*] 已从文件加载URL: %d 个\n", len(urls))
	}

	// 从文件加载端口列表
	if PortFile != "" {
		ports, err := Readfile(PortFile)
		if err != nil {
			return fmt.Errorf("读取端口文件失败: %v", err)
		}

		var newport strings.Builder
		for _, port := range ports {
			if port != "" {
				newport.WriteString(port)
				newport.WriteString(",")
			}
		}
		Ports = newport.String()
		fmt.Printf("[*] 已从文件加载端口配置\n")
	}

	return nil
}

// Readfile 读取文件内容并返回非空行的切片
func Readfile(filename string) ([]string, error) {
	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[!] 打开文件 %s 失败: %v\n", filename, err)
		return nil, err
	}
	defer file.Close()

	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// 逐行读取文件内容
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
		fmt.Printf("[!] 读取文件 %s 时出错: %v\n", filename, err)
		return nil, err
	}

	fmt.Printf("[*] 成功读取文件 %s: %d 行\n", filename, lineCount)
	return content, nil
}

// ParseInput 解析和验证输入参数配置
func ParseInput(Info *HostInfo) error {
	// 检查必要的目标参数
	if Info.Host == "" && HostFile == "" && URL == "" && UrlFile == "" {
		fmt.Println("[!] 未指定扫描目标")
		flag.Usage()
		return fmt.Errorf("必须指定扫描目标")
	}

	// 配置基本参数
	if BruteThread <= 0 {
		BruteThread = 1
		fmt.Printf("[*] 已将暴力破解线程数设置为: %d\n", BruteThread)
	}

	if TmpSave {
		IsSave = false
		fmt.Println("[*] 已启用临时保存模式")
	}

	// 处理端口配置
	if Ports == DefaultPorts {
		Ports += "," + Webport
	}

	if PortAdd != "" {
		if strings.HasSuffix(Ports, ",") {
			Ports += PortAdd
		} else {
			Ports += "," + PortAdd
		}
		fmt.Printf("[*] 已添加额外端口: %s\n", PortAdd)
	}

	// 处理用户名配置
	if UserAdd != "" {
		users := strings.Split(UserAdd, ",")
		for dict := range Userdict {
			Userdict[dict] = append(Userdict[dict], users...)
			Userdict[dict] = RemoveDuplicate(Userdict[dict])
		}
		fmt.Printf("[*] 已添加额外用户名: %s\n", UserAdd)
	}

	// 处理密码配置
	if PassAdd != "" {
		passes := strings.Split(PassAdd, ",")
		Passwords = append(Passwords, passes...)
		Passwords = RemoveDuplicate(Passwords)
		fmt.Printf("[*] 已添加额外密码: %s\n", PassAdd)
	}

	// 处理Socks5代理配置
	if Socks5Proxy != "" {
		if !strings.HasPrefix(Socks5Proxy, "socks5://") {
			if !strings.Contains(Socks5Proxy, ":") {
				Socks5Proxy = "socks5://127.0.0.1" + Socks5Proxy
			} else {
				Socks5Proxy = "socks5://" + Socks5Proxy
			}
		}

		_, err := url.Parse(Socks5Proxy)
		if err != nil {
			return fmt.Errorf("Socks5代理格式错误: %v", err)
		}
		NoPing = true
		fmt.Printf("[*] 使用Socks5代理: %s\n", Socks5Proxy)
	}

	// 处理HTTP代理配置
	if Proxy != "" {
		switch Proxy {
		case "1":
			Proxy = "http://127.0.0.1:8080"
		case "2":
			Proxy = "socks5://127.0.0.1:1080"
		default:
			if !strings.Contains(Proxy, "://") {
				Proxy = "http://127.0.0.1:" + Proxy
			}
		}

		if !strings.HasPrefix(Proxy, "socks") && !strings.HasPrefix(Proxy, "http") {
			return fmt.Errorf("不支持的代理类型")
		}

		_, err := url.Parse(Proxy)
		if err != nil {
			return fmt.Errorf("代理格式错误: %v", err)
		}
		fmt.Printf("[*] 使用代理: %s\n", Proxy)
	}

	// 处理Hash配置
	if Hash != "" {
		if len(Hash) != 32 {
			return fmt.Errorf("Hash长度必须为32位")
		}
		Hashs = append(Hashs, Hash)
	}

	// 处理Hash列表
	Hashs = RemoveDuplicate(Hashs)
	for _, hash := range Hashs {
		hashByte, err := hex.DecodeString(hash)
		if err != nil {
			fmt.Printf("[!] Hash解码失败: %s\n", hash)
			continue
		}
		HashBytes = append(HashBytes, hashByte)
	}
	Hashs = []string{}

	return nil
}

// ParseScantype 解析扫描类型并设置对应的端口
func ParseScantype(Info *HostInfo) error {
	// 先处理特殊扫描类型
	specialTypes := map[string]string{
		"hostname": "135,137,139,445",
		"webonly":  Webport,
		"webpoc":   Webport,
		"web":      Webport,
		"portscan": DefaultPorts + "," + Webport,
		"main":     DefaultPorts,
		"all":      DefaultPorts + "," + Webport,
		"icmp":     "", // ICMP不需要端口
	}

	// 如果是特殊扫描类型
	if customPorts, isSpecial := specialTypes[Scantype]; isSpecial {
		if Scantype != "all" && Ports == DefaultPorts+","+Webport {
			Ports = customPorts
		}
		fmt.Printf("[*] 扫描类型: %s, 目标端口: %s\n", Scantype, Ports)
		return nil
	}

	// 检查是否是注册的插件类型
	plugin, validType := PluginManager[Scantype]
	if !validType {
		showmode()
		return fmt.Errorf("无效的扫描类型: %s", Scantype)
	}

	// 如果是插件扫描且使用默认端口配置
	if Ports == DefaultPorts+","+Webport {
		if plugin.Port > 0 {
			Ports = strconv.Itoa(plugin.Port)
		}
		fmt.Printf("[*] 扫描类型: %s, 目标端口: %s\n", plugin.Name, Ports)
	}

	return nil
}

// showmode 显示所有支持的扫描类型
func showmode() {
	fmt.Println("[!] 指定的扫描类型不存在")
	fmt.Println("[*] 支持的扫描类型:")

	// 显示常规服务扫描类型
	fmt.Println("\n[+] 常规服务扫描:")
	for name, plugin := range PluginManager {
		if plugin.Port > 0 && plugin.Port < 1000000 {
			fmt.Printf("   - %-10s (端口: %d)\n", name, plugin.Port)
		}
	}

	// 显示特殊漏洞扫描类型
	fmt.Println("\n[+] 特殊漏洞扫描:")
	for name, plugin := range PluginManager {
		if plugin.Port >= 1000000 || plugin.Port == 0 {
			fmt.Printf("   - %-10s\n", name)
		}
	}

	// 显示其他扫描类型
	fmt.Println("\n[+] 其他扫描类型:")
	specialTypes := []string{"all", "portscan", "icmp", "main", "webonly", "webpoc"}
	for _, name := range specialTypes {
		fmt.Printf("   - %s\n", name)
	}

	os.Exit(0)
}
