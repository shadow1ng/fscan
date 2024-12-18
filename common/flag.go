package Common

import (
	"flag"
	"github.com/shadow1ng/fscan/Config"
)

func Banner() {
	banner := `
   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` + "`" + ` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: ` + version + `
`
	print(banner)
}

func Flag(Info *Config.HostInfo) {
	Banner()

	// 目标配置
	flag.StringVar(&Info.Host, "h", "", "目标主机IP，例如: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&NoHosts, "hn", "", "排除的主机范围，例如: -hn 192.168.1.1/24")
	flag.StringVar(&Ports, "p", DefaultPorts, "端口配置，例如: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&PortAdd, "pa", "", "在默认端口基础上添加端口，-pa 3389")
	flag.StringVar(&NoPorts, "pn", "", "排除的端口，例如: -pn 445")

	// 认证配置
	flag.StringVar(&UserAdd, "usera", "", "在默认用户列表基础上添加用户,-usera user")
	flag.StringVar(&PassAdd, "pwda", "", "在默认密码列表基础上添加密码,-pwda password")
	flag.StringVar(&Username, "user", "", "用户名")
	flag.StringVar(&Password, "pwd", "", "密码")
	flag.StringVar(&Domain, "domain", "", "域名(用于SMB)")
	flag.StringVar(&SshKey, "sshkey", "", "SSH密钥文件(id_rsa)")

	// 扫描配置
	flag.StringVar(&Scantype, "m", "all", "扫描类型，例如: -m ssh")
	flag.IntVar(&Threads, "t", 600, "线程数量")
	flag.Int64Var(&Timeout, "time", 3, "超时时间(秒)")
	flag.IntVar(&LiveTop, "top", 10, "显示存活主机数量")
	flag.BoolVar(&NoPing, "np", false, "禁用存活探测")
	flag.BoolVar(&Ping, "ping", false, "使用ping替代ICMP")
	flag.StringVar(&Command, "c", "", "执行命令(支持ssh|wmiexec)")

	// 文件配置
	flag.StringVar(&HostFile, "hf", "", "主机列表文件")
	flag.StringVar(&Userfile, "userf", "", "用户名字典")
	flag.StringVar(&Passfile, "pwdf", "", "密码字典")
	flag.StringVar(&Hashfile, "hashf", "", "Hash字典")
	flag.StringVar(&PortFile, "portf", "", "端口列表文件")

	// Web配置
	flag.StringVar(&URL, "u", "", "目标URL")
	flag.StringVar(&UrlFile, "uf", "", "URL列表文件")
	flag.StringVar(&Cookie, "cookie", "", "设置Cookie")
	flag.Int64Var(&WebTimeout, "wt", 5, "Web请求超时时间")
	flag.StringVar(&Proxy, "proxy", "", "设置HTTP代理")
	flag.StringVar(&Socks5Proxy, "socks5", "", "设置Socks5代理(将用于TCP连接,超时设置将失效)")

	// POC配置
	flag.StringVar(&PocPath, "pocpath", "", "POC文件路径")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "使用包含指定名称的POC,例如: -pocname weblogic")
	flag.BoolVar(&NoPoc, "nopoc", false, "禁用Web漏洞扫描")
	flag.BoolVar(&PocFull, "full", false, "完整POC扫描,如:shiro 100个key")
	flag.BoolVar(&DnsLog, "dns", false, "启用dnslog验证")
	flag.IntVar(&PocNum, "num", 20, "POC并发数")

	// Redis利用配置
	flag.StringVar(&RedisFile, "rf", "", "Redis写入SSH公钥文件")
	flag.StringVar(&RedisShell, "rs", "", "Redis写入计划任务")
	flag.BoolVar(&Noredistest, "noredis", false, "禁用Redis安全检测")

	// 暴力破解配置
	flag.BoolVar(&IsBrute, "nobr", false, "禁用密码爆破")
	flag.IntVar(&BruteThread, "br", 1, "密码爆破线程数")

	// 其他配置
	flag.StringVar(&Path, "path", "", "FCG/SMB远程文件路径")
	flag.StringVar(&Hash, "hash", "", "Hash值")
	flag.StringVar(&SC, "sc", "", "MS17漏洞shellcode")
	flag.BoolVar(&IsWmi, "wmi", false, "启用WMI")

	// 输出配置
	flag.StringVar(&Outputfile, "o", "result.txt", "结果输出文件")
	flag.BoolVar(&TmpSave, "no", false, "禁用结果保存")
	flag.BoolVar(&Silent, "silent", false, "静默扫描模式")
	flag.BoolVar(&Nocolor, "nocolor", false, "禁用彩色输出")
	flag.BoolVar(&JsonOutput, "json", false, "JSON格式输出")
	flag.Int64Var(&WaitTime, "debug", 60, "错误日志输出间隔")

	flag.Parse()
}
