package common

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/shadow1ng/fscan/Config"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func Parse(Info *Config.HostInfo) {
	ParseUser()
	ParsePass(Info)
	ParseInput(Info)
	ParseScantype(Info)
}

func ParseUser() {
	if Username == "" && Userfile == "" {
		return
	}
	var Usernames []string
	if Username != "" {
		Usernames = strings.Split(Username, ",")
	}

	if Userfile != "" {
		users, err := Readfile(Userfile)
		if err == nil {
			for _, user := range users {
				if user != "" {
					Usernames = append(Usernames, user)
				}
			}
		}
	}

	Usernames = RemoveDuplicate(Usernames)
	for name := range Userdict {
		Userdict[name] = Usernames
	}
}

func ParsePass(Info *Config.HostInfo) {
	var PwdList []string
	if Password != "" {
		passs := strings.Split(Password, ",")
		for _, pass := range passs {
			if pass != "" {
				PwdList = append(PwdList, pass)
			}
		}
		Passwords = PwdList
	}
	if Passfile != "" {
		passs, err := Readfile(Passfile)
		if err == nil {
			for _, pass := range passs {
				if pass != "" {
					PwdList = append(PwdList, pass)
				}
			}
			Passwords = PwdList
		}
	}
	if Hashfile != "" {
		hashs, err := Readfile(Hashfile)
		if err == nil {
			for _, line := range hashs {
				if line == "" {
					continue
				}
				if len(line) == 32 {
					Hashs = append(Hashs, line)
				} else {
					fmt.Println("[-] len(hash) != 32 " + line)
				}
			}
		}
	}
	if URL != "" {
		urls := strings.Split(URL, ",")
		TmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if _, ok := TmpUrls[url]; !ok {
				TmpUrls[url] = struct{}{}
				if url != "" {
					Urls = append(Urls, url)
				}
			}
		}
	}
	if UrlFile != "" {
		urls, err := Readfile(UrlFile)
		if err == nil {
			TmpUrls := make(map[string]struct{})
			for _, url := range urls {
				if _, ok := TmpUrls[url]; !ok {
					TmpUrls[url] = struct{}{}
					if url != "" {
						Urls = append(Urls, url)
					}
				}
			}
		}
	}
	if PortFile != "" {
		ports, err := Readfile(PortFile)
		if err == nil {
			newport := ""
			for _, port := range ports {
				if port != "" {
					newport += port + ","
				}
			}
			Ports = newport
		}
	}
}

func Readfile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, scanner.Text())
		}
	}
	return content, nil
}

func ParseInput(Info *Config.HostInfo) {
	if Info.Host == "" && HostFile == "" && URL == "" && UrlFile == "" {
		fmt.Println("Host is none")
		flag.Usage()
		os.Exit(0)
	}

	if BruteThread <= 0 {
		BruteThread = 1
	}

	if TmpSave == true {
		IsSave = false
	}

	if Ports == DefaultPorts {
		Ports += "," + Webport
	}

	if PortAdd != "" {
		if strings.HasSuffix(Ports, ",") {
			Ports += PortAdd
		} else {
			Ports += "," + PortAdd
		}
	}

	if UserAdd != "" {
		user := strings.Split(UserAdd, ",")
		for a := range Userdict {
			Userdict[a] = append(Userdict[a], user...)
			Userdict[a] = RemoveDuplicate(Userdict[a])
		}
	}

	if PassAdd != "" {
		pass := strings.Split(PassAdd, ",")
		Passwords = append(Passwords, pass...)
		Passwords = RemoveDuplicate(Passwords)
	}
	if Socks5Proxy != "" && !strings.HasPrefix(Socks5Proxy, "socks5://") {
		if !strings.Contains(Socks5Proxy, ":") {
			Socks5Proxy = "socks5://127.0.0.1" + Socks5Proxy
		} else {
			Socks5Proxy = "socks5://" + Socks5Proxy
		}
	}
	if Socks5Proxy != "" {
		fmt.Println("Socks5Proxy:", Socks5Proxy)
		_, err := url.Parse(Socks5Proxy)
		if err != nil {
			fmt.Println("Socks5Proxy parse error:", err)
			os.Exit(0)
		}
		NoPing = true
	}
	if Proxy != "" {
		if Proxy == "1" {
			Proxy = "http://127.0.0.1:8080"
		} else if Proxy == "2" {
			Proxy = "socks5://127.0.0.1:1080"
		} else if !strings.Contains(Proxy, "://") {
			Proxy = "http://127.0.0.1:" + Proxy
		}
		fmt.Println("Proxy:", Proxy)
		if !strings.HasPrefix(Proxy, "socks") && !strings.HasPrefix(Proxy, "http") {
			fmt.Println("no support this proxy")
			os.Exit(0)
		}
		_, err := url.Parse(Proxy)
		if err != nil {
			fmt.Println("Proxy parse error:", err)
			os.Exit(0)
		}
	}

	if Hash != "" && len(Hash) != 32 {
		fmt.Println("[-] Hash is error,len(hash) must be 32")
		os.Exit(0)
	} else {
		Hashs = append(Hashs, Hash)
	}
	Hashs = RemoveDuplicate(Hashs)
	for _, hash := range Hashs {
		hashbyte, err := hex.DecodeString(Hash)
		if err != nil {
			fmt.Println("[-] Hash is error,hex decode error ", hash)
			continue
		} else {
			HashBytes = append(HashBytes, hashbyte)
		}
	}
	Hashs = []string{}
}

// ParseScantype 解析扫描类型并设置对应的端口
func ParseScantype(Info *Config.HostInfo) error {
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
	plugin, validType := Config.PluginManager[Scantype]
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
	for name, plugin := range Config.PluginManager {
		if plugin.Port > 0 && plugin.Port < 1000000 {
			fmt.Printf("   - %-10s (端口: %d)\n", name, plugin.Port)
		}
	}

	// 显示特殊漏洞扫描类型
	fmt.Println("\n[+] 特殊漏洞扫描:")
	for name, plugin := range Config.PluginManager {
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
