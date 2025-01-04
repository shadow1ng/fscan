package Common

import (
	"flag"
	"fmt"
	"github.com/fatih/color"
	"strings"
	"time"
)

func Banner() {
	// 定义暗绿色系
	colors := []color.Attribute{
		color.FgGreen,   // 基础绿
		color.FgHiGreen, // 亮绿
	}

	lines := []string{
		"   ___                              _    ",
		"  / _ \\     ___  ___ _ __ __ _  ___| | __ ",
		" / /_\\/____/ __|/ __| '__/ _` |/ __| |/ /",
		"/ /_\\\\_____\\__ \\ (__| | | (_| | (__|   <    ",
		"\\____/     |___/\\___|_|  \\__,_|\\___|_|\\_\\   ",
	}

	// 获取最长行的长度
	maxLength := 0
	for _, line := range lines {
		if len(line) > maxLength {
			maxLength = len(line)
		}
	}

	// 清屏并隐藏光标
	fmt.Print("\033[H\033[2J\033[?25l")
	defer fmt.Print("\033[?25h")

	// 创建边框
	topBorder := "┌" + strings.Repeat("─", maxLength+2) + "┐"
	bottomBorder := "└" + strings.Repeat("─", maxLength+2) + "┘"

	// 呼吸灯效果循环
	for cycle := 0; cycle < 2; cycle++ { // 2个完整循环
		// 亮度由暗到亮
		for i := 0; i <= 10; i++ {
			fmt.Print("\033[H")
			dim := float64(i) / 10.0

			printDimmed(topBorder, colors[0], dim)
			fmt.Println()

			for lineNum, line := range lines {
				printDimmed("│ ", colors[0], dim)
				for _, char := range line {
					printDimmed(string(char), colors[lineNum%2], dim)
				}
				padding := maxLength - len(line)
				printDimmed(strings.Repeat(" ", padding)+" │", colors[0], dim)
				fmt.Println()
			}

			printDimmed(bottomBorder, colors[0], dim)
			fmt.Println()

			vStr := fmt.Sprintf("      Fscan Version: %s", version)
			printDimmed(vStr, colors[1], dim)
			fmt.Print("\n\n")

			time.Sleep(50 * time.Millisecond)
		}

		// 亮度由亮到暗
		for i := 10; i >= 0; i-- {
			fmt.Print("\033[H")
			dim := float64(i) / 10.0

			printDimmed(topBorder, colors[0], dim)
			fmt.Println()

			for lineNum, line := range lines {
				printDimmed("│ ", colors[0], dim)
				for _, char := range line {
					printDimmed(string(char), colors[lineNum%2], dim)
				}
				padding := maxLength - len(line)
				printDimmed(strings.Repeat(" ", padding)+" │", colors[0], dim)
				fmt.Println()
			}

			printDimmed(bottomBorder, colors[0], dim)
			fmt.Println()

			vStr := fmt.Sprintf("      Fscan Version: %s", version)
			printDimmed(vStr, colors[1], dim)
			fmt.Print("\n\n")

			time.Sleep(50 * time.Millisecond)
		}
	}

	// 最后显示完整亮度的版本
	fmt.Print("\033[H")
	printDimmed(topBorder, colors[0], 1.0)
	fmt.Println()

	for lineNum, line := range lines {
		printDimmed("│ ", colors[0], 1.0)
		for _, char := range line {
			printDimmed(string(char), colors[lineNum%2], 1.0)
		}
		padding := maxLength - len(line)
		printDimmed(strings.Repeat(" ", padding)+" │", colors[0], 1.0)
		fmt.Println()
	}

	printDimmed(bottomBorder, colors[0], 1.0)
	fmt.Println()

	vStr := fmt.Sprintf("      Fscan Version: %s", version)
	printDimmed(vStr, colors[1], 1.0)
	fmt.Print("\n\n")
}

// 辅助函数：打印带透明度的文字
func printDimmed(text string, col color.Attribute, dim float64) {
	if dim < 0.2 {
		fmt.Print(strings.Repeat(" ", len(text)))
		return
	}

	intensity := int(255 * dim)
	fmt.Printf("\033[38;2;%d;%d;%dm%s\033[0m",
		int(float64(0)*dim),
		intensity,
		int(float64(0)*dim),
		text)
}

func Flag(Info *HostInfo) {
	Banner()

	// 目标配置
	flag.StringVar(&Info.Host, "h", "", "指定目标主机,支持以下格式:\n"+
		"  - 单个IP: 192.168.11.11\n"+
		"  - IP范围: 192.168.11.11-255\n"+
		"  - 多个IP: 192.168.11.11,192.168.11.12")
	flag.StringVar(&ExcludeHosts, "eh", "", "排除指定主机范围,支持CIDR格式,如: 192.168.1.1/24")
	flag.StringVar(&Ports, "p", MainPorts, "指定扫描端口,支持以下格式:\n"+
		"端口格式:\n"+
		"  - 单个端口: 22\n"+
		"  - 端口范围: 1-65535\n"+
		"  - 多个端口: 22,80,3306\n\n"+
		"预定义端口组(别名):\n"+
		"  - main: 常用端口 (21,22,23,80,81,135,139,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017)\n"+
		"  - service: 服务端口 (21,22,23,135,139,445,1433,1521,2222,3306,3389,5432,6379,9000,11211,27017)\n"+
		"  - db: 数据库端口 (1433,1521,3306,5432,6379,11211,27017)\n"+
		"  - web: Web服务端口 (包含常见的 80-90,443,800-1080,2000-8000,8080-9000,9090-10000 等Web端口)\n"+
		"  - all: 全部端口 (1-65535)\n\n"+
		"示例:\n"+
		"  -p main         扫描常用端口\n"+
		"  -p web         扫描Web端口\n"+
		"  -p 80,443      扫描指定端口\n"+
		"  -p 1-1000      扫描1-1000端口范围\n"+
		"默认使用 main 端口组")
	flag.StringVar(&AddPorts, "pa", "", "在默认端口基础上额外添加端口,如: -pa 3389")
	flag.StringVar(&ExcludePorts, "pn", "", "排除指定端口,如: -pn 445")

	// 认证配置
	flag.StringVar(&AddUsers, "usera", "", "在默认用户列表基础上添加自定义用户名")
	flag.StringVar(&AddPasswords, "pwda", "", "在默认密码列表基础上添加自定义密码")
	flag.StringVar(&Username, "user", "", "指定单个用户名")
	flag.StringVar(&Password, "pwd", "", "指定单个密码")
	flag.StringVar(&Domain, "domain", "", "指定域名(仅用于SMB协议)")
	flag.StringVar(&SshKeyPath, "sshkey", "", "指定SSH私钥文件路径(默认为id_rsa)")

	// 扫描配置
	flag.StringVar(&ScanMode, "m", "All", "指定扫描模式:\n"+
		"预设扫描模式(大写开头):\n"+
		"  - All: 全量扫描，包含所有可用插件\n"+
		"  - Basic: 基础扫描，包含 web/ftp/ssh/smb/findnet\n"+
		"  - Database: 数据库扫描，包含 mysql/mssql/redis/mongodb/postgres/oracle/memcached\n"+
		"  - Web: Web服务扫描，包含 web/fcgi\n"+
		"  - Service: 常见服务扫描，包含 ftp/ssh/telnet/smb/rdp/vnc/netbios\n"+
		"  - Vul: 漏洞扫描，包含 ms17010/smbghost/smb2\n"+
		"  - Port: 端口扫描模式\n"+
		"  - ICMP: ICMP存活探测\n"+
		"  - Local: 本地信息收集\n\n"+
		"单个插件模式(小写):\n"+
		"  Web类: web, fcgi\n"+
		"  数据库类: mysql, mssql, redis, mongodb, postgres, oracle, memcached\n"+
		"  服务类: ftp, ssh, telnet, smb, rdp, vnc, netbios\n"+
		"  漏洞类: ms17010, smbghost, smb2\n"+
		"  其他: findnet, wmiexec, localinfo")
	flag.BoolVar(&UseSynScan, "sS", false, "使用SYN扫描替代TCP全连接扫描(需要root/管理员权限)")
	flag.IntVar(&ThreadNum, "t", 60, "设置扫描线程数")
	flag.Int64Var(&Timeout, "time", 3, "设置连接超时时间(单位:秒)")
	flag.IntVar(&LiveTop, "top", 10, "仅显示指定数量的存活主机")
	flag.BoolVar(&DisablePing, "np", false, "禁用主机存活探测")
	flag.BoolVar(&UsePing, "ping", false, "使用系统ping命令替代ICMP探测")
	flag.StringVar(&Command, "c", "", "指定要执行的系统命令(支持ssh和wmiexec)")
	flag.BoolVar(&SkipFingerprint, "skip", false, "跳过端口指纹识别")

	// 文件配置
	flag.StringVar(&HostsFile, "hf", "", "从文件中读取目标主机列表")
	flag.StringVar(&UsersFile, "userf", "", "从文件中读取用户名字典")
	flag.StringVar(&PasswordsFile, "pwdf", "", "从文件中读取密码字典")
	flag.StringVar(&HashFile, "hashf", "", "从文件中读取Hash字典")
	flag.StringVar(&PortsFile, "portf", "", "从文件中读取端口列表")

	// Web配置
	flag.StringVar(&TargetURL, "u", "", "指定目标URL")
	flag.StringVar(&URLsFile, "uf", "", "从文件中读取URL列表")
	flag.StringVar(&Cookie, "cookie", "", "设置HTTP请求Cookie")
	flag.Int64Var(&WebTimeout, "wt", 5, "设置Web请求超时时间(单位:秒)")
	flag.StringVar(&HttpProxy, "proxy", "", "设置HTTP代理服务器")
	flag.StringVar(&Socks5Proxy, "socks5", "", "设置Socks5代理(用于TCP连接,将影响超时设置)")

	// 本地扫描配置
	flag.BoolVar(&LocalMode, "local", false, "启用本地信息收集模式")

	// POC配置
	flag.StringVar(&PocPath, "pocpath", "", "指定自定义POC文件路径")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "指定要使用的POC名称,如: -pocname weblogic")
	flag.BoolVar(&PocFull, "full", false, "启用完整POC扫描(如测试shiro全部100个key)")
	flag.BoolVar(&DnsLog, "dns", false, "启用dnslog进行漏洞验证")
	flag.IntVar(&PocNum, "num", 20, "设置POC扫描并发数")

	// Redis利用配置
	flag.StringVar(&RedisFile, "rf", "", "指定Redis写入的SSH公钥文件")
	flag.StringVar(&RedisShell, "rs", "", "指定Redis写入的计划任务内容")
	flag.BoolVar(&DisableRedis, "noredis", false, "禁用Redis安全检测")

	// 暴力破解配置
	flag.BoolVar(&DisableBrute, "nobr", false, "禁用密码暴力破解")
	flag.IntVar(&MaxRetries, "retry", 3, "设置最大重试次数")

	// 其他配置
	flag.StringVar(&RemotePath, "path", "", "指定FCG/SMB远程文件路径")
	flag.StringVar(&HashValue, "hash", "", "指定要破解的Hash值")
	flag.StringVar(&Shellcode, "sc", "", "指定MS17漏洞利用的shellcode")
	flag.BoolVar(&EnableWmi, "wmi", false, "启用WMI协议扫描")

	// 输出配置
	flag.StringVar(&Outputfile, "o", "result.txt", "指定结果输出文件名")
	flag.BoolVar(&DisableSave, "no", false, "禁止保存扫描结果")
	flag.BoolVar(&Silent, "silent", false, "启用静默扫描模式(减少屏幕输出)")
	flag.BoolVar(&NoColor, "nocolor", false, "禁用彩色输出显示")
	flag.BoolVar(&JsonFormat, "json", false, "以JSON格式输出结果")
	flag.StringVar(&LogLevel, "log", LogLevelInfo, "日志输出级别(ALL/SUCCESS/ERROR/INFO/DEBUG)")
	flag.BoolVar(&NoProgress, "nopg", false, "禁用进度条显示")

	flag.Parse()
}
