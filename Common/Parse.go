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

func Parse(Info *HostInfo) {
	ParseUser()
	ParsePass(Info)
	ParseInput(Info)
}

// ParseUser 解析用户名配置,支持直接指定用户名列表或从文件读取
func ParseUser() error {
	// 如果未指定用户名和用户名文件,直接返回
	if Username == "" && UsersFile == "" {
		return nil
	}

	var usernames []string

	// 处理直接指定的用户名列表
	if Username != "" {
		usernames = strings.Split(Username, ",")
		fmt.Printf("[*] 已加载直接指定的用户名: %d 个\n", len(usernames))
	}

	// 从文件加载用户名列表
	if UsersFile != "" {
		users, err := Readfile(UsersFile)
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
	if PasswordsFile != "" {
		passes, err := Readfile(PasswordsFile)
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
	if HashFile != "" {
		hashes, err := Readfile(HashFile)
		if err != nil {
			return fmt.Errorf("读取哈希文件失败: %v", err)
		}

		validCount := 0
		for _, line := range hashes {
			if line == "" {
				continue
			}
			if len(line) == 32 {
				HashValues = append(HashValues, line)
				validCount++
			} else {
				fmt.Printf("[!] 无效的哈希值(长度!=32): %s\n", line)
			}
		}
		fmt.Printf("[*] 已加载有效哈希值: %d 个\n", validCount)
	}

	// 处理直接指定的URL列表
	if TargetURL != "" {
		urls := strings.Split(TargetURL, ",")
		tmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if url != "" {
				if _, ok := tmpUrls[url]; !ok {
					tmpUrls[url] = struct{}{}
					URLs = append(URLs, url)
				}
			}
		}
		fmt.Printf("[*] 已加载直接指定的URL: %d 个\n", len(URLs))
	}

	// 从文件加载URL列表
	if URLsFile != "" {
		urls, err := Readfile(URLsFile)
		if err != nil {
			return fmt.Errorf("读取URL文件失败: %v", err)
		}

		tmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if url != "" {
				if _, ok := tmpUrls[url]; !ok {
					tmpUrls[url] = struct{}{}
					URLs = append(URLs, url)
				}
			}
		}
		fmt.Printf("[*] 已从文件加载URL: %d 个\n", len(urls))
	}

	// 从文件加载端口列表
	if PortsFile != "" {
		ports, err := Readfile(PortsFile)
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
	if Info.Host == "" && HostsFile == "" && TargetURL == "" && URLsFile == "" {
		fmt.Println("[!] 未指定扫描目标")
		flag.Usage()
		return fmt.Errorf("必须指定扫描目标")
	}

	// 配置基本参数
	if BruteThreads <= 0 {
		BruteThreads = 1
		fmt.Printf("[*] 已将暴力破解线程数设置为: %d\n", BruteThreads)
	}

	if DisableSave {
		IsSave = false
		fmt.Println("[*] 已启用临时保存模式")
	}

	// 处理端口配置
	if Ports == MainPorts {
		Ports += "," + WebPorts
	}

	if AddPorts != "" {
		if strings.HasSuffix(Ports, ",") {
			Ports += AddPorts
		} else {
			Ports += "," + AddPorts
		}
		fmt.Printf("[*] 已添加额外端口: %s\n", AddPorts)
	}

	// 处理用户名配置
	if AddUsers != "" {
		users := strings.Split(AddUsers, ",")
		for dict := range Userdict {
			Userdict[dict] = append(Userdict[dict], users...)
			Userdict[dict] = RemoveDuplicate(Userdict[dict])
		}
		fmt.Printf("[*] 已添加额外用户名: %s\n", AddUsers)
	}

	// 处理密码配置
	if AddPasswords != "" {
		passes := strings.Split(AddPasswords, ",")
		Passwords = append(Passwords, passes...)
		Passwords = RemoveDuplicate(Passwords)
		fmt.Printf("[*] 已添加额外密码: %s\n", AddPasswords)
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
		DisablePing = true
		fmt.Printf("[*] 使用Socks5代理: %s\n", Socks5Proxy)
	}

	// 处理HTTP代理配置
	if HttpProxy != "" {
		switch HttpProxy {
		case "1":
			HttpProxy = "http://127.0.0.1:8080"
		case "2":
			HttpProxy = "socks5://127.0.0.1:1080"
		default:
			if !strings.Contains(HttpProxy, "://") {
				HttpProxy = "http://127.0.0.1:" + HttpProxy
			}
		}

		if !strings.HasPrefix(HttpProxy, "socks") && !strings.HasPrefix(HttpProxy, "http") {
			return fmt.Errorf("不支持的代理类型")
		}

		_, err := url.Parse(HttpProxy)
		if err != nil {
			return fmt.Errorf("代理格式错误: %v", err)
		}
		fmt.Printf("[*] 使用代理: %s\n", HttpProxy)
	}

	// 处理Hash配置
	if HashValue != "" {
		if len(HashValue) != 32 {
			return fmt.Errorf("Hash长度必须为32位")
		}
		HashValues = append(HashValues, HashValue)
	}

	// 处理Hash列表
	HashValues = RemoveDuplicate(HashValues)
	for _, hash := range HashValues {
		hashByte, err := hex.DecodeString(hash)
		if err != nil {
			fmt.Printf("[!] Hash解码失败: %s\n", hash)
			continue
		}
		HashBytes = append(HashBytes, hashByte)
	}
	HashValues = []string{}

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
