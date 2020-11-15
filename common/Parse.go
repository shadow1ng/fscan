package common

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func Parse(Info *HostInfo){
	ParseUser(Info)
	ParsePass(Info)
	ParseInput(Info)
	ParseScantype(Info)
}



func ParseUser(Info *HostInfo){
	if Info.Username!=""{
		uesrs := strings.Split(Info.Username, ",")
		for _,uesr := range uesrs{
			if uesr !=""{
				Info.Usernames = append(Info.Usernames,uesr)
			}
		}
		for name := range Userdict{
			Userdict[name] = Info.Usernames
		}
	}
	if Info.Userfile!=""{
		uesrs,err := Readfile(Info.Userfile)
		if err == nil {
			for _, uesr := range uesrs {
				if uesr != "" {
					Info.Usernames = append(Info.Usernames, uesr)
				}
			}
			for name := range Userdict {
				Userdict[name] = Info.Usernames
			}
		}
	}

}

func ParsePass(Info *HostInfo){
	if Info.Password!=""{
		passs := strings.Split(Info.Password, ",")
		for _,pass := range passs{
			if pass !=""{
				Info.Passwords = append(Info.Passwords,pass)
			}
		}
		Passwords = Info.Passwords
	}
	if Info.Passfile!=""{
		passs,err := Readfile(Info.Passfile)
		if err == nil{
			for _,pass := range passs{
				if pass !=""{
					Info.Passwords = append(Info.Passwords,pass)
				}
			}
			Passwords = Info.Passwords

		}
	}
}

func Readfile(filename string)([]string,error){
	file, err := os.Open(filename)
	if err!=nil{
		fmt.Println("Open %s error, %v", filename,err)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content=append(content,scanner.Text())
		}
	}
	return content,nil
}



func ParseInput(Info *HostInfo){
	if Info.Host=="" && Info.HostFile ==""{
		fmt.Println("Host is none")
		flag.Usage()
		os.Exit(0)
	}
	if Info.Outputfile != ""{
		Outputfile = Info.Outputfile
	}
	if Info.IsSave == true{
		IsSave = false
	}
}

func ParseScantype(Info *HostInfo){
	_,ok:=PORTList[Info.Scantype]
	if !ok{
		fmt.Println("The specified scan type does not exist")
		fmt.Println("-m")
		for name,_:=range PORTList{
			fmt.Println("   ["+name+"]")
		}
		os.Exit(0)
	}
	if Info.Scantype != "all" && Info.Ports != DefaultPorts{
		ScanPort := ParsePort(Info.Ports)[0]
		Info.Ports = strconv.Itoa(ScanPort)
		fmt.Println("if -m and -p only scan the first port:",Info.Ports)
		for name,_:=range PORTList{
			PORTList[name] = ScanPort
		}
	}
}


func CheckErr(text string,err error){
	if err!=nil{
		fmt.Println(text,err.Error())
		os.Exit(0)
	}
}