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
// 完成所有配置解析流程并更新相关数据结构
func Parse(Info *HostInfo) error {
	// 解析用户名配置
	if Username != "" || UsersFile != "" {
		// 收集所有用户名
		var usernames []string

		// 处理命令行指定的用户名
		if Username != "" {
			usernames = strings.Split(Username, ",")
			LogInfo(GetText("no_username_specified", len(usernames)))
		}

		// 从文件加载用户名
		if UsersFile != "" {
			fileUsers, err := readLines(UsersFile)
			if err != nil {
				return fmt.Errorf("用户名文件读取失败: %v", err)
			}

			// 添加非空用户名
			for _, user := range fileUsers {
				if user != "" {
					usernames = append(usernames, user)
				}
			}
			LogInfo(GetText("load_usernames_from_file", len(fileUsers)))
		}

		// 去重处理
		usernames = removeDuplicates(usernames)
		LogInfo(GetText("total_usernames", len(usernames)))

		// 更新用户字典
		for name := range Userdict {
			Userdict[name] = usernames
		}
	}

	// 解析密码配置
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

	if PasswordsFile != "" {
		passes, err := readLines(PasswordsFile)
		if err != nil {
			LogError(fmt.Sprintf("读取密码文件失败: %v", err))
		} else {
			for _, pass := range passes {
				if pass != "" {
					pwdList = append(pwdList, pass)
				}
			}
			Passwords = pwdList
			LogInfo(GetText("load_passwords_from_file", len(passes)))
		}
	}

	// 解析哈希配置
	if HashFile != "" {
		hashes, err := readLines(HashFile)
		if err != nil {
			LogError(fmt.Sprintf("读取哈希文件失败: %v", err))
		} else {
			validCount := 0
			for _, line := range hashes {
				if line != "" && len(line) == 32 {
					HashValues = append(HashValues, line)
					validCount++
				} else if line != "" {
					LogError(GetText("invalid_hash", line))
				}
			}
			LogInfo(GetText("load_valid_hashes", validCount))
		}
	}

	// 解析URL目标
	urlMap := make(map[string]struct{})

	// 处理命令行参数指定的URL
	if TargetURL != "" {
		for _, u := range strings.Split(TargetURL, ",") {
			if u != "" {
				urlMap[u] = struct{}{}
			}
		}
	}

	// 从文件加载URL
	if URLsFile != "" {
		urls, err := readLines(URLsFile)
		if err != nil {
			LogError(fmt.Sprintf("读取URL文件失败: %v", err))
		} else {
			for _, u := range urls {
				if u != "" {
					urlMap[u] = struct{}{}
				}
			}
		}
	}

	// 更新全局URL列表
	URLs = make([]string, 0, len(urlMap))
	for u := range urlMap {
		URLs = append(URLs, u)
	}

	if len(URLs) > 0 {
		LogInfo(GetText("load_urls", len(URLs)))
	}

	// 解析主机配置
	if HostsFile != "" {
		hosts, err := readLines(HostsFile)
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

		// 构建主机列表
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

			LogInfo(GetText("load_hosts_from_file", len(hosts)))
		}
	}

	// 解析端口配置
	if PortsFile != "" {
		ports, err := readLines(PortsFile)
		if err != nil {
			return fmt.Errorf("读取端口文件失败: %v", err)
		}

		var portBuilder strings.Builder
		for _, port := range ports {
			if port != "" {
				portBuilder.WriteString(port)
				portBuilder.WriteString(",")
			}
		}

		Ports = portBuilder.String()
		LogInfo(GetText("load_ports_from_file"))
	}

	// 检查扫描模式冲突
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

	if modes == 0 {
		flag.Usage()
		return fmt.Errorf(GetText("specify_scan_params"))
	} else if modes > 1 {
		return fmt.Errorf(GetText("params_conflict"))
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

	if ExcludePorts != "" {
		LogInfo(GetText("exclude_ports_applied", ExcludePorts))
	}

	// 处理额外用户名和密码
	if AddUsers != "" {
		users := strings.Split(AddUsers, ",")
		for dict := range Userdict {
			Userdict[dict] = append(Userdict[dict], users...)
			Userdict[dict] = removeDuplicates(Userdict[dict])
		}
		LogInfo(GetText("extra_usernames", AddUsers))
	}

	if AddPasswords != "" {
		passes := strings.Split(AddPasswords, ",")
		Passwords = append(Passwords, passes...)
		Passwords = removeDuplicates(Passwords)
		LogInfo(GetText("extra_passwords", AddPasswords))
	}

	// 处理代理设置
	if Socks5Proxy != "" {
		// 规范化Socks5代理URL
		if !strings.HasPrefix(Socks5Proxy, "socks5://") {
			if !strings.Contains(Socks5Proxy, ":") {
				Socks5Proxy = "socks5://127.0.0.1:" + Socks5Proxy
			} else {
				Socks5Proxy = "socks5://" + Socks5Proxy
			}
		}

		// 验证代理URL
		if _, err := url.Parse(Socks5Proxy); err != nil {
			return fmt.Errorf(GetText("socks5_proxy_error", err))
		}

		DisablePing = true
		LogInfo(GetText("socks5_proxy", Socks5Proxy))
	}

	if HttpProxy != "" {
		// 处理HTTP代理简写形式
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

		// 验证代理协议
		if !strings.HasPrefix(HttpProxy, "socks") && !strings.HasPrefix(HttpProxy, "http") {
			return fmt.Errorf(GetText("unsupported_proxy"))
		}

		// 验证代理URL
		if _, err := url.Parse(HttpProxy); err != nil {
			return fmt.Errorf(GetText("proxy_format_error", err))
		}

		LogInfo(GetText("http_proxy", HttpProxy))
	}

	// 处理哈希值
	if HashValue != "" {
		if len(HashValue) != 32 {
			return fmt.Errorf(GetText("hash_length_error"))
		}
		HashValues = append(HashValues, HashValue)
	}

	HashValues = removeDuplicates(HashValues)
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

// readLines 读取文件内容并返回非空行的切片
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		LogError(GetText("open_file_failed", filename, err))
		return nil, err
	}
	defer file.Close()

	var content []string
	scanner := bufio.NewScanner(file)

	lineCount := 0
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, text)
			lineCount++
		}
	}

	if err := scanner.Err(); err != nil {
		LogError(GetText("read_file_failed", filename, err))
		return nil, err
	}

	LogInfo(GetText("read_file_success", filename, lineCount))
	return content, nil
}

// removeDuplicates 对字符串切片进行去重
func removeDuplicates(list []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, item := range list {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
