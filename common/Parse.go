package common

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

func Parse(inputConfig *InConfig) {
	ParseUser(&inputConfig.Flags)
	ParsePass(&inputConfig.HostInfo, &inputConfig.Flags)
	ParseInput(&inputConfig.HostInfo, &inputConfig.Flags)
	ParseScantype(&inputConfig.HostInfo, &inputConfig.Flags)

	Outputfile = inputConfig.LogConfig.Outputfile
	IsSave = !inputConfig.LogConfig.TmpSave
	Cookie = inputConfig.Cookie
}

func ParseUser(flags *Flags) {
	if flags.Username == "" && flags.Userfile == "" {
		return
	}
	var Usernames []string
	if flags.Username != "" {
		Usernames = strings.Split(flags.Username, ",")
	}

	if flags.Userfile != "" {
		users, err := Readfile(flags.Userfile)
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

func ParsePass(Info *HostInfo, flags *Flags) {
	var PwdList []string
	if flags.Password != "" {
		passs := strings.Split(flags.Password, ",")
		for _, pass := range passs {
			if pass != "" {
				PwdList = append(PwdList, pass)
			}
		}
		Passwords = PwdList
	}
	if flags.Passfile != "" {
		passs, err := Readfile(flags.Passfile)
		if err == nil {
			for _, pass := range passs {
				if pass != "" {
					PwdList = append(PwdList, pass)
				}
			}
			Passwords = PwdList
		}
	}

	if flags.URL != "" {
		urls := strings.Split(flags.URL, ",")
		TmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if _, ok := TmpUrls[url]; !ok {
				TmpUrls[url] = struct{}{}
				if url != "" {
					flags.Urls = append(flags.Urls, url)
				}
			}
		}
	}
	if flags.UrlFile != "" {
		urls, err := Readfile(flags.UrlFile)
		if err == nil {
			TmpUrls := make(map[string]struct{})
			for _, url := range urls {
				if _, ok := TmpUrls[url]; !ok {
					TmpUrls[url] = struct{}{}
					if url != "" {
						flags.Urls = append(flags.Urls, url)
					}
				}
			}
		}
	}
	if flags.PortFile != "" {
		ports, err := Readfile(flags.PortFile)
		if err == nil {
			newport := ""
			for _, port := range ports {
				if port != "" {
					newport += port + ","
				}
			}
			Info.Ports = newport
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

func ParseInput(Info *HostInfo, flags *Flags) {
	if Info.Host == "" && flags.HostFile == "" && flags.URL == "" && flags.UrlFile == "" {
		fmt.Println("Host is none")
		flag.Usage()
		os.Exit(0)
	}

	if flags.BruteThread <= 0 {
		flags.BruteThread = 1
	}

	if Info.Ports == DefaultPorts {
		Info.Ports += "," + Webport
	}

	if flags.PortAdd != "" {
		if strings.HasSuffix(Info.Ports, ",") {
			Info.Ports += flags.PortAdd
		} else {
			Info.Ports += "," + flags.PortAdd
		}
	}

	if flags.UserAdd != "" {
		user := strings.Split(flags.UserAdd, ",")
		for a := range Userdict {
			Userdict[a] = append(Userdict[a], user...)
			Userdict[a] = RemoveDuplicate(Userdict[a])
		}
	}

	if flags.PassAdd != "" {
		pass := strings.Split(flags.PassAdd, ",")
		Passwords = append(Passwords, pass...)
		Passwords = RemoveDuplicate(Passwords)
	}
	if flags.Socks5Proxy != "" && !strings.HasPrefix(flags.Socks5Proxy, "socks5://") {
		if !strings.Contains(flags.Socks5Proxy, ":") {
			flags.Socks5Proxy = "socks5://127.0.0.1" + flags.Socks5Proxy
		} else {
			flags.Socks5Proxy = "socks5://" + flags.Socks5Proxy
		}
	}
	if flags.Socks5Proxy != "" {
		fmt.Println("Socks5Proxy:", flags.Socks5Proxy)
		_, err := url.Parse(flags.Socks5Proxy)
		if err != nil {
			fmt.Println("Socks5Proxy parse error:", err)
			os.Exit(0)
		}
		flags.NoPing = true
	}
	if flags.Proxy != "" {
		if flags.Proxy == "1" {
			flags.Proxy = "http://127.0.0.1:8080"
		} else if flags.Proxy == "2" {
			flags.Proxy = "socks5://127.0.0.1:1080"
		} else if !strings.Contains(flags.Proxy, "://") {
			flags.Proxy = "http://127.0.0.1:" + flags.Proxy
		}
		fmt.Println("Proxy:", flags.Proxy)
		if !strings.HasPrefix(flags.Proxy, "socks") && !strings.HasPrefix(flags.Proxy, "http") {
			fmt.Println("no support this proxy")
			os.Exit(0)
		}
		_, err := url.Parse(flags.Proxy)
		if err != nil {
			fmt.Println("Proxy parse error:", err)
			os.Exit(0)
		}
	}

	if flags.Hash != "" && len(flags.Hash) != 32 {
		fmt.Println("[-] Hash is error,len(hash) must be 32")
		os.Exit(0)
	} else {
		var err error
		flags.HashBytes, err = hex.DecodeString(flags.Hash)
		if err != nil {
			fmt.Println("[-] Hash is error,hex decode error")
			os.Exit(0)
		}
	}
}

func ParseScantype(Info *HostInfo, flags *Flags) {
	_, ok := PORTList[flags.Scantype]
	if !ok {
		showmode()
	}
	if flags.Scantype != "all" && Info.Ports == DefaultPorts+","+Webport {
		switch flags.Scantype {
		case "wmiexec":
			Info.Ports = "135"
		case "wmiinfo":
			Info.Ports = "135"
		case "smbinfo":
			Info.Ports = "445"
		case "hostname":
			Info.Ports = "135,137,139,445"
		case "smb2":
			Info.Ports = "445"
		case "web":
			Info.Ports = Webport
		case "webonly":
			Info.Ports = Webport
		case "ms17010":
			Info.Ports = "445"
		case "cve20200796":
			Info.Ports = "445"
		case "portscan":
			Info.Ports = DefaultPorts + "," + Webport
		case "main":
			Info.Ports = DefaultPorts
		default:
			port, _ := PORTList[flags.Scantype]
			Info.Ports = strconv.Itoa(port)
		}
		fmt.Println("-m ", flags.Scantype, " start scan the port:", Info.Ports)
	}
}

func CheckErr(text string, err error, flag bool) {
	if err != nil {
		fmt.Println("Parse", text, "error: ", err.Error())
		if flag {
			if err != ParseIPErr {
				fmt.Println(ParseIPErr)
			}
			os.Exit(0)
		}
	}
}

func showmode() {
	fmt.Println("The specified scan type does not exist")
	fmt.Println("-m")
	for name := range PORTList {
		fmt.Println("   [" + name + "]")
	}
	os.Exit(0)
}
