package common

import (
	"flag"
)

// todo make function
type Flags struct {
	Path        string
	Scantype    string
	Command     string
	SshKey      string
	Domain      string
	Username    string
	Password    string
	Proxy       string
	Timeout     int64
	WebTimeout  int64
	NoPing      bool
	Ping        bool
	Pocinfo     PocInfo
	IsWebCan    bool
	IsBrute     bool
	RedisFile   string
	RedisShell  string
	Userfile    string
	Passfile    string
	HostFile    string
	PortFile    string
	PocPath     string
	Threads     int
	URL         string
	UrlFile     string
	Urls        []string
	NoPorts     string
	NoHosts     string
	SC          string
	PortAdd     string
	UserAdd     string
	PassAdd     string
	BruteThread int
	LiveTop     int
	Socks5Proxy string
	Hash        string
	HashBytes   []byte
	IsWmi       bool
	PocNum      int
	PocFull     bool
	DnsLog      bool
}

// todo make function
type LogConfig struct {
	Silent     bool
	Outputfile string
	TmpSave    bool
	WaitTime   int64
}

type InConfig struct {
	HostInfo  HostInfo
	Flags     Flags
	LogConfig LogConfig
	Cookie    string
}

func Flag(inConfig *InConfig) {
	flag.StringVar(&inConfig.HostInfo.Host, "h", "", "IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&inConfig.HostInfo.Ports, "p", DefaultPorts, "Select a port,for example: 22 | 1-65535 | 22,80,3306")

	flag.StringVar(&inConfig.Flags.NoHosts, "hn", "", "the hosts no scan,as: -hn 192.168.1.1/24")
	flag.StringVar(&inConfig.Flags.PortAdd, "pa", "", "add port base DefaultPorts,-pa 3389")
	flag.StringVar(&inConfig.Flags.UserAdd, "usera", "", "add a user base DefaultUsers,-usera user")
	flag.StringVar(&inConfig.Flags.PassAdd, "pwda", "", "add a password base DefaultPasses,-pwda password")
	flag.StringVar(&inConfig.Flags.NoPorts, "pn", "", "the ports no scan,as: -pn 445")
	flag.StringVar(&inConfig.Flags.Command, "c", "", "exec command (ssh|wmiexec)")
	flag.StringVar(&inConfig.Flags.SshKey, "sshkey", "", "sshkey file (id_rsa)")
	flag.StringVar(&inConfig.Flags.Domain, "domain", "", "smb domain")
	flag.StringVar(&inConfig.Flags.Username, "user", "", "username")
	flag.StringVar(&inConfig.Flags.Password, "pwd", "", "password")
	flag.Int64Var(&inConfig.Flags.Timeout, "time", 3, "Set timeout")
	flag.Int64Var(&inConfig.Flags.WebTimeout, "wt", 5, "Set web timeout")
	flag.StringVar(&inConfig.Flags.Scantype, "m", "all", "Select scan type ,as: -m ssh")
	flag.StringVar(&inConfig.Flags.Path, "path", "", "fcgi、smb romote file path")
	flag.IntVar(&inConfig.Flags.Threads, "t", 600, "Thread nums")
	flag.IntVar(&inConfig.Flags.LiveTop, "top", 10, "show live len top")
	flag.StringVar(&inConfig.Flags.HostFile, "hf", "", "host file, -hf ip.txt")
	flag.StringVar(&inConfig.Flags.Userfile, "userf", "", "username file")
	flag.StringVar(&inConfig.Flags.Passfile, "pwdf", "", "password file")
	flag.StringVar(&inConfig.Flags.PortFile, "portf", "", "Port File")
	flag.StringVar(&inConfig.Flags.PocPath, "pocpath", "", "poc file path")
	flag.StringVar(&inConfig.Flags.RedisFile, "rf", "", "redis file to write sshkey file (as: -rf id_rsa.pub)")
	flag.StringVar(&inConfig.Flags.RedisShell, "rs", "", "redis shell to write cron file (as: -rs 192.168.1.1:6666)")
	flag.BoolVar(&inConfig.Flags.IsWebCan, "nopoc", false, "not to scan web vul")
	flag.BoolVar(&inConfig.Flags.IsBrute, "nobr", false, "not to Brute password")
	flag.IntVar(&inConfig.Flags.BruteThread, "br", 1, "Brute threads")
	flag.BoolVar(&inConfig.Flags.NoPing, "np", false, "not to ping")
	flag.BoolVar(&inConfig.Flags.Ping, "ping", false, "using ping replace icmp")
	flag.StringVar(&inConfig.Flags.URL, "u", "", "url")
	flag.StringVar(&inConfig.Flags.UrlFile, "uf", "", "urlfile")
	flag.StringVar(&inConfig.Flags.Pocinfo.PocName, "pocname", "", "use the pocs these contain pocname, -pocname weblogic")
	flag.IntVar(&inConfig.Flags.PocNum, "num", 20, "poc rate")
	flag.StringVar(&inConfig.Flags.Proxy, "proxy", "", "set poc proxy, -proxy http://127.0.0.1:8080")
	flag.StringVar(&inConfig.Flags.Socks5Proxy, "socks5", "", "set socks5 proxy, will be used in tcp connection, timeout setting will not work")
	flag.StringVar(&inConfig.Flags.SC, "sc", "", "ms17 shellcode,as -sc add")
	flag.BoolVar(&inConfig.Flags.IsWmi, "wmi", false, "start wmi")
	flag.StringVar(&inConfig.Flags.Hash, "hash", "", "hash")
	flag.BoolVar(&inConfig.Flags.PocFull, "full", false, "poc full scan,as: shiro 100 key")
	flag.BoolVar(&inConfig.Flags.DnsLog, "dns", false, "using dnslog poc")

	flag.StringVar(&inConfig.LogConfig.Outputfile, "o", "result.txt", "Outputfile")
	flag.BoolVar(&inConfig.LogConfig.TmpSave, "no", false, "not to save output log")
	flag.Int64Var(&inConfig.LogConfig.WaitTime, "debug", 60, "every time to LogErr")
	flag.BoolVar(&inConfig.LogConfig.Silent, "silent", false, "silent scan")

	flag.StringVar(&inConfig.Cookie, "cookie", "", "set poc cookie,-cookie rememberMe=login")

	flag.Parse()
}
