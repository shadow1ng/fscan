package Common

import (
	"flag"
	"fmt"
	"github.com/fatih/color"
	"strings"
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

	// 创建边框
	topBorder := "┌" + strings.Repeat("─", maxLength+2) + "┐"
	bottomBorder := "└" + strings.Repeat("─", maxLength+2) + "┘"

	// 打印banner
	fmt.Println(topBorder)

	for lineNum, line := range lines {
		fmt.Print("│ ")
		// 使用对应的颜色打印每个字符
		c := color.New(colors[lineNum%2])
		c.Print(line)
		// 补齐空格
		padding := maxLength - len(line)
		fmt.Printf("%s │\n", strings.Repeat(" ", padding))
	}

	fmt.Println(bottomBorder)

	// 打印版本信息
	c := color.New(colors[1])
	c.Printf("      Fscan Version: %s\n\n", version)
}

func Flag(Info *HostInfo) {
	Banner()

	// 目标配置
	flag.StringVar(&Info.Host, "h", "", GetText("flag_host"))
	flag.StringVar(&ExcludeHosts, "eh", "", GetText("flag_exclude_hosts"))
	flag.StringVar(&Ports, "p", MainPorts, GetText("flag_ports"))

	// 认证配置
	flag.StringVar(&AddUsers, "usera", "", GetText("flag_add_users"))
	flag.StringVar(&AddPasswords, "pwda", "", GetText("flag_add_passwords"))
	flag.StringVar(&Username, "user", "", GetText("flag_username"))
	flag.StringVar(&Password, "pwd", "", GetText("flag_password"))
	flag.StringVar(&Domain, "domain", "", GetText("flag_domain"))
	flag.StringVar(&SshKeyPath, "sshkey", "", GetText("flag_ssh_key"))

	// 扫描配置
	flag.StringVar(&ScanMode, "m", "All", GetText("flag_scan_mode"))
	flag.IntVar(&ThreadNum, "t", 60, GetText("flag_thread_num"))
	flag.Int64Var(&Timeout, "time", 3, GetText("flag_timeout"))
	flag.IntVar(&LiveTop, "top", 10, GetText("flag_live_top"))
	flag.BoolVar(&DisablePing, "np", false, GetText("flag_disable_ping"))
	flag.BoolVar(&UsePing, "ping", false, GetText("flag_use_ping"))
	flag.StringVar(&Command, "c", "", GetText("flag_command"))
	flag.BoolVar(&SkipFingerprint, "skip", false, GetText("flag_skip_fingerprint"))

	// 文件配置
	flag.StringVar(&HostsFile, "hf", "", GetText("flag_hosts_file"))
	flag.StringVar(&UsersFile, "userf", "", GetText("flag_users_file"))
	flag.StringVar(&PasswordsFile, "pwdf", "", GetText("flag_passwords_file"))
	flag.StringVar(&HashFile, "hashf", "", GetText("flag_hash_file"))
	flag.StringVar(&PortsFile, "portf", "", GetText("flag_ports_file"))

	// Web配置
	flag.StringVar(&TargetURL, "u", "", GetText("flag_target_url"))
	flag.StringVar(&URLsFile, "uf", "", GetText("flag_urls_file"))
	flag.StringVar(&Cookie, "cookie", "", GetText("flag_cookie"))
	flag.Int64Var(&WebTimeout, "wt", 5, GetText("flag_web_timeout"))
	flag.StringVar(&HttpProxy, "proxy", "", GetText("flag_http_proxy"))
	flag.StringVar(&Socks5Proxy, "socks5", "", GetText("flag_socks5_proxy"))

	// 本地扫描配置
	flag.BoolVar(&LocalMode, "local", false, GetText("flag_local_mode"))

	// POC配置
	flag.StringVar(&PocPath, "pocpath", "", GetText("flag_poc_path"))
	flag.StringVar(&Pocinfo.PocName, "pocname", "", GetText("flag_poc_name"))
	flag.BoolVar(&PocFull, "full", false, GetText("flag_poc_full"))
	flag.BoolVar(&DnsLog, "dns", false, GetText("flag_dns_log"))
	flag.IntVar(&PocNum, "num", 20, GetText("flag_poc_num"))

	// Redis利用配置
	flag.StringVar(&RedisFile, "rf", "", GetText("flag_redis_file"))
	flag.StringVar(&RedisShell, "rs", "", GetText("flag_redis_shell"))
	flag.BoolVar(&DisableRedis, "noredis", false, GetText("flag_disable_redis"))

	// 暴力破解配置
	flag.BoolVar(&DisableBrute, "nobr", false, GetText("flag_disable_brute"))
	flag.IntVar(&MaxRetries, "retry", 3, GetText("flag_max_retries"))

	// 其他配置
	flag.StringVar(&RemotePath, "path", "", GetText("flag_remote_path"))
	flag.StringVar(&HashValue, "hash", "", GetText("flag_hash_value"))
	flag.StringVar(&Shellcode, "sc", "", GetText("flag_shellcode"))
	flag.BoolVar(&EnableWmi, "wmi", false, GetText("flag_enable_wmi"))

	// 输出配置
	flag.StringVar(&Outputfile, "o", "result.txt", GetText("flag_output_file"))
	flag.StringVar(&OutputFormat, "f", "txt", GetText("flag_output_format"))
	flag.BoolVar(&DisableSave, "no", false, GetText("flag_disable_save"))
	flag.BoolVar(&Silent, "silent", false, GetText("flag_silent_mode"))
	flag.BoolVar(&NoColor, "nocolor", false, GetText("flag_no_color"))
	flag.BoolVar(&JsonFormat, "json", false, GetText("flag_json_format"))
	flag.StringVar(&LogLevel, "log", LogLevelSuccess, GetText("flag_log_level"))
	flag.BoolVar(&ShowProgress, "pg", false, GetText("flag_show_progress"))

	flag.StringVar(&Language, "lang", "zh", GetText("flag_language"))

	flag.Parse()

	SetLanguage()
}
