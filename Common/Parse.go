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

func Parse(Info *HostInfo) error {
	ParseUser()
	ParsePass(Info)
	if err := ParseInput(Info); err != nil {
		return err
	}
	return nil
}

// ParseUser 解析用户名配置
func ParseUser() error {
	// 如果未指定用户名和用户名文件,直接返回
	if Username == "" && UsersFile == "" {
		return nil
	}

	var usernames []string

	// 处理直接指定的用户名列表
	if Username != "" {
		usernames = strings.Split(Username, ",")
		LogInfo(GetText("no_username_specified", len(usernames)))
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
		LogInfo(GetText("load_usernames_from_file", len(users)))
	}

	// 去重处理
	usernames = RemoveDuplicate(usernames)
	LogInfo(GetText("total_usernames", len(usernames)))

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
		LogInfo(GetText("load_passwords", len(pwdList)))
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
		LogInfo(GetText("load_passwords_from_file", len(passes)))
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
				LogError(GetText("invalid_hash", line))
			}
		}
		LogInfo(GetText("load_valid_hashes", validCount))
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
		LogInfo(GetText("load_urls", len(URLs)))
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
		LogInfo(GetText("load_urls_from_file", len(urls)))
	}

	// 从文件加载主机列表
	if HostsFile != "" {
		hosts, err := Readfile(HostsFile)
		if err != nil {
			return fmt.Errorf("读取主机文件失败: %v", err)
		}

		tmpHosts := make(map[string]struct{})
		for _, host := range hosts {
			if host != "" {
				if _, ok := tmpHosts[host]; !ok {
					tmpHosts[host] = struct{}{}
					if Info.Host == "" {
						Info.Host = host
					} else {
						Info.Host += "," + host
					}
				}
			}
		}
		LogInfo(GetText("load_hosts_from_file", len(hosts)))
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
		LogInfo(GetText("load_ports_from_file"))
	}

	return nil
}

// Readfile 读取文件内容并返回非空行的切片
func Readfile(filename string) ([]string, error) {
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
		LogError(GetText("read_file_failed", filename, err))
		return nil, err
	}

	LogInfo(GetText("read_file_success", filename, lineCount))
	return content, nil
}

// ParseInput 解析和验证输入参数配置
func ParseInput(Info *HostInfo) error {
	// 检查互斥的扫描模式
	modes := 0
	if Info.Host != "" || HostsFile != "" {
		modes++
	}
	if TargetURL != "" || URLsFile != "" {
		modes++
	}
	if LocalMode {
		modes++
	}

	if modes == 0 {
		// 无参数时显示帮助
		flag.Usage()
		return fmt.Errorf(GetText("specify_scan_params"))
	} else if modes > 1 {
		return fmt.Errorf(GetText("params_conflict"))
	}

	// 处理爆破线程配置
	if BruteThreads <= 0 {
		BruteThreads = 1
		LogInfo(GetText("brute_threads", BruteThreads))
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
		LogInfo(GetText("extra_ports", AddPorts))
	}

	// 处理用户名配置
	if AddUsers != "" {
		users := strings.Split(AddUsers, ",")
		for dict := range Userdict {
			Userdict[dict] = append(Userdict[dict], users...)
			Userdict[dict] = RemoveDuplicate(Userdict[dict])
		}
		LogInfo(GetText("extra_usernames", AddUsers))
	}

	// 处理密码配置
	if AddPasswords != "" {
		passes := strings.Split(AddPasswords, ",")
		Passwords = append(Passwords, passes...)
		Passwords = RemoveDuplicate(Passwords)
		LogInfo(GetText("extra_passwords", AddPasswords))
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
			return fmt.Errorf(GetText("socks5_proxy_error", err))
		}
		DisablePing = true
		LogInfo(GetText("socks5_proxy", Socks5Proxy))
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
			return fmt.Errorf(GetText("unsupported_proxy"))
		}

		_, err := url.Parse(HttpProxy)
		if err != nil {
			return fmt.Errorf(GetText("proxy_format_error", err))
		}
		LogInfo(GetText("http_proxy", HttpProxy))
	}

	// 处理Hash配置
	if HashValue != "" {
		if len(HashValue) != 32 {
			return fmt.Errorf(GetText("hash_length_error"))
		}
		HashValues = append(HashValues, HashValue)
	}

	// 处理Hash列表
	HashValues = RemoveDuplicate(HashValues)
	for _, hash := range HashValues {
		hashByte, err := hex.DecodeString(hash)
		if err != nil {
			LogError(GetText("hash_decode_failed", hash))
			continue
		}
		HashBytes = append(HashBytes, hashByte)
	}
	HashValues = []string{}

	return nil
}
