package common

import (
	"flag"
)

func Banner() {
	banner := `
   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` + "`" + ` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.6.3
`
	print(banner)
}

func Flag(Info *HostInfo) {
	Banner()
	flag.StringVar(&Info.Host, "h", "", "IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&Info.Ports, "p", DefaultPorts, "Select a port,for example: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&NoPorts, "pn", "", "the ports no scan,as: -pn 445")
	flag.StringVar(&Info.Command, "c", "", "exec command (ssh)")
	flag.StringVar(&Info.SshKey, "sshkey", "", "sshkey file (id_rsa)")
	flag.StringVar(&Info.Domain, "domain", "", "smb domain")
	flag.StringVar(&Info.Username, "user", "", "username")
	flag.StringVar(&Info.Password, "pwd", "", "password")
	flag.Int64Var(&Info.Timeout, "time", 3, "Set timeout")
	flag.StringVar(&Info.Scantype, "m", "all", "Select scan type ,as: -m ssh")
	flag.StringVar(&Info.Path, "path", "", "fcgi、smb romote file path")
	flag.IntVar(&Threads, "t", 600, "Thread nums")
	flag.StringVar(&HostFile, "hf", "", "host file, -hf ip.txt")
	flag.StringVar(&Userfile, "userf", "", "username file")
	flag.StringVar(&Passfile, "pwdf", "", "password file")
	flag.StringVar(&RedisFile, "rf", "", "redis file to write sshkey file (as: -rf id_rsa.pub) ")
	flag.StringVar(&RedisShell, "rs", "", "redis shell to write cron file (as: -rs 192.168.1.1:6666) ")
	flag.BoolVar(&IsWebCan, "nopoc", false, "not to scan web vul")
	flag.BoolVar(&IsPing, "np", false, "not to ping")
	flag.BoolVar(&Ping, "ping", false, "using ping replace icmp")
	flag.StringVar(&TmpOutputfile, "o", "result.txt", "Outputfile")
	flag.BoolVar(&TmpSave, "no", false, "not to save output log")
	flag.Int64Var(&WaitTime, "debug", 60, "every time to LogErr")
	flag.BoolVar(&Silent, "silent", false, "silent scan")
	flag.StringVar(&URL, "u", "", "url")
	flag.StringVar(&UrlFile, "uf", "", "urlfile")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "use the pocs these contain pocname, -pocname weblogic")
	flag.StringVar(&Pocinfo.Proxy, "proxy", "", "set poc proxy, -proxy http://127.0.0.1:8080")
	flag.StringVar(&Pocinfo.Cookie, "cookie", "", "set poc cookie")
	flag.Int64Var(&Pocinfo.Timeout, "wt", 5, "Set web timeout")
	flag.IntVar(&Pocinfo.Num, "num", 20, "poc rate")
	flag.Parse()
}
