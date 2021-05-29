package common

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func Parse(Info *HostInfo) {
	ParseScantype(Info)
	ParseUser(Info)
	ParsePass(Info)
	ParseInput(Info)
}

func ParseUser(Info *HostInfo) {
	if Info.Username != "" {
		users := strings.Split(Info.Username, ",")
		for _, user := range users {
			if user != "" {
				Info.Usernames = append(Info.Usernames, user)
			}
		}
		for name := range Userdict {
			Userdict[name] = Info.Usernames
		}
	}
	if Userfile != "" {
		users, err := Readfile(Userfile)
		if err == nil {
			for _, user := range users {
				if user != "" {
					Info.Usernames = append(Info.Usernames, user)
				}
			}
			for name := range Userdict {
				Userdict[name] = Info.Usernames
			}
		}
	}

}

func ParsePass(Info *HostInfo) {
	if Info.Password != "" {
		passs := strings.Split(Info.Password, ",")
		for _, pass := range passs {
			if pass != "" {
				Info.Passwords = append(Info.Passwords, pass)
			}
		}
		Passwords = Info.Passwords
	}
	if Passfile != "" {
		passs, err := Readfile(Passfile)
		if err == nil {
			for _, pass := range passs {
				if pass != "" {
					Info.Passwords = append(Info.Passwords, pass)
				}
			}
			Passwords = Info.Passwords
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

func ParseInput(Info *HostInfo) {
	if Info.Host == "" && HostFile == "" && URL == "" && UrlFile == "" {
		fmt.Println("Host is none")
		flag.Usage()
		os.Exit(0)
	}

	if TmpOutputfile != "" {
		if !strings.Contains(Outputfile, "/") && !strings.Contains(Outputfile, `\`) {
			Outputfile = getpath() + TmpOutputfile
		} else {
			Outputfile = TmpOutputfile
		}
	}
	if TmpSave == true {
		IsSave = false
	}
	if Info.Ports == DefaultPorts {
		Info.Ports += Webport
	}
}

func ParseScantype(Info *HostInfo) {
	_, ok := PORTList[Info.Scantype]
	if !ok {
		showmode()
	}
	if Info.Scantype != "all" {
		if Info.Ports == DefaultPorts {
			switch Info.Scantype {
			case "web":
				Info.Ports = Webport
			case "ms17010":
				Info.Ports = "445"
			case "cve20200796":
				Info.Ports = "445"
			case "main":
				Info.Ports = DefaultPorts
			default:
				port, _ := PORTList[Info.Scantype]
				Info.Ports = strconv.Itoa(port)
			}
			fmt.Println("-m ", Info.Scantype, " start scan the port:", Info.Ports)
		}
	}
}

func CheckErr(text string, err error) {
	if err != nil {
		fmt.Println(text, err.Error())
		os.Exit(0)
	}
}

func getpath() string {
	file, _ := exec.LookPath(os.Args[0])
	path1, _ := filepath.Abs(file)
	filename := filepath.Dir(path1)
	var path string
	if strings.Contains(filename, "/") {
		tmp := strings.Split(filename, `/`)
		tmp[len(tmp)-1] = ``
		path = strings.Join(tmp, `/`)
	} else if strings.Contains(filename, `\`) {
		tmp := strings.Split(filename, `\`)
		tmp[len(tmp)-1] = ``
		path = strings.Join(tmp, `\`)
	}
	return path
}

func showmode() {
	fmt.Println("The specified scan type does not exist")
	fmt.Println("-m")
	for name := range PORTList {
		fmt.Println("   [" + name + "]")
	}
	os.Exit(0)
}
