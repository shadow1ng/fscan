package Common

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
                     fscan version: ` + version + `
`
	print(banner)
}

func Flag(Info *HostInfo) {
	Banner()

	// 目标配置
	flag.StringVar(&Info.Host, "h", "", "目标主机IP，例如: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&ExcludeHosts, "eh", "", "排除的主机范围，例如: -eh 192.168.1.1/24")
	flag.StringVar(&Ports, "p", MainPorts, "端口配置，例如: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&AddPorts, "pa", "", "在默认端口基础上添加端口，-pa 3389")
	flag.StringVar(&ExcludePorts, "pn", "", "排除的端口，例如: -pn 445")

	// 认证配置
	flag.StringVar(&AddUsers, "usera", "", "在默认用户列表基础上添加用户,-usera user")
	flag.StringVar(&AddPasswords, "pwda", "", "在默认密码列表基础上添加密码,-pwda password")
	flag.StringVar(&Username, "user", "", "用户名")
	flag.StringVar(&Password, "pwd", "", "密码")
	flag.StringVar(&Domain, "domain", "", "域名(用于SMB)")
	flag.StringVar(&SshKeyPath, "sshkey", "", "SSH密钥文件(id_rsa)")

	// 扫描配置
	flag.StringVar(&ScanMode, "m", "all", "扫描类型，例如: -m ssh")
	flag.IntVar(&ThreadNum, "t", 600, "线程数量")
	flag.Int64Var(&Timeout, "time", 3, "超时时间(秒)")
	flag.IntVar(&LiveTop, "top", 10, "显示存活主机数量")
	flag.BoolVar(&DisablePing, "np", false, "禁用存活探测")
	flag.BoolVar(&UsePing, "ping", false, "使用ping替代ICMP")
	flag.StringVar(&Command, "c", "", "执行命令(支持ssh|wmiexec)")

	// 文件配置
	flag.StringVar(&HostsFile, "hf", "", "主机列表文件")
	flag.StringVar(&UsersFile, "userf", "", "用户名字典")
	flag.StringVar(&PasswordsFile, "pwdf", "", "密码字典")
	flag.StringVar(&HashFile, "hashf", "", "Hash字典")
	flag.StringVar(&PortsFile, "portf", "", "端口列表文件")

	// Web配置
	flag.StringVar(&TargetURL, "u", "", "目标URL")
	flag.StringVar(&URLsFile, "uf", "", "URL列表文件")
	flag.StringVar(&Cookie, "cookie", "", "设置Cookie")
	flag.Int64Var(&WebTimeout, "wt", 5, "Web请求超时时间")
	flag.StringVar(&HttpProxy, "proxy", "", "设置HTTP代理")
	flag.StringVar(&Socks5Proxy, "socks5", "", "设置Socks5代理(将用于TCP连接,超时设置将失效)")

	// POC配置
	flag.StringVar(&PocPath, "pocpath", "", "POC文件路径")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "使用包含指定名称的POC,例如: -pocname weblogic")
	flag.BoolVar(&DisablePoc, "nopoc", false, "禁用Web漏洞扫描")
	flag.BoolVar(&PocFull, "full", false, "完整POC扫描,如:shiro 100个key")
	flag.BoolVar(&DnsLog, "dns", false, "启用dnslog验证")
	flag.IntVar(&PocNum, "num", 20, "POC并发数")

	// Redis利用配置
	flag.StringVar(&RedisFile, "rf", "", "Redis写入SSH公钥文件")
	flag.StringVar(&RedisShell, "rs", "", "Redis写入计划任务")
	flag.BoolVar(&DisableRedis, "noredis", false, "禁用Redis安全检测")

	// 暴力破解配置
	flag.BoolVar(&DisableBrute, "nobr", false, "禁用密码爆破")
	flag.IntVar(&BruteThreads, "br", 1, "密码爆破线程数")

	// 其他配置
	flag.StringVar(&RemotePath, "path", "", "FCG/SMB远程文件路径")
	flag.StringVar(&HashValue, "hash", "", "Hash值")
	flag.StringVar(&Shellcode, "sc", "", "MS17漏洞shellcode")
	flag.BoolVar(&EnableWmi, "wmi", false, "启用WMI")

	// 输出配置
	flag.StringVar(&Outputfile, "o", "result.txt", "结果输出文件")
	flag.BoolVar(&DisableSave, "no", false, "禁用结果保存")
	flag.BoolVar(&Silent, "silent", false, "静默扫描模式")
	flag.BoolVar(&Nocolor, "nocolor", false, "禁用彩色输出")
	flag.BoolVar(&JsonOutput, "json", false, "JSON格式输出")
	flag.Int64Var(&WaitTime, "debug", 60, "错误日志输出间隔")

	flag.Parse()
}
