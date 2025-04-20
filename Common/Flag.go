package Common

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
)

var flagInitOnce sync.Once

// defineFlags 用于本地 CLI 注册全局 flag.CommandLine 的 flag
func defineFlags(info *HostInfo) {
	flagInitOnce.Do(func() {
		defineFlagsForSet(flag.CommandLine, info)
	})
}

// 通用 flag 注册逻辑，支持 flag.CommandLine 和新建 FlagSet（用于远程）
func defineFlagsForSet(fs *flag.FlagSet, info *HostInfo) {
	// ═════════════════════════════════════════════════
	// 目标配置参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&info.Host, "h", "", GetText("flag_host"))
	flag.StringVar(&ExcludeHosts, "eh", "", GetText("flag_exclude_hosts"))
	flag.StringVar(&Ports, "p", MainPorts, GetText("flag_ports"))
	flag.StringVar(&HostsFile, "hf", "", GetText("flag_hosts_file"))
	flag.StringVar(&PortsFile, "pf", "", GetText("flag_ports_file"))

	// ═════════════════════════════════════════════════
	// 扫描控制参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&ScanMode, "m", "All", GetText("flag_scan_mode"))
	flag.IntVar(&ThreadNum, "t", 10, GetText("flag_thread_num"))
	flag.Int64Var(&Timeout, "time", 3, GetText("flag_timeout"))
	flag.IntVar(&ModuleThreadNum, "mt", 10, GetText("flag_module_thread_num"))
	flag.Int64Var(&GlobalTimeout, "gt", 180, GetText("flag_global_timeout"))
	flag.IntVar(&LiveTop, "top", 10, GetText("flag_live_top"))
	flag.BoolVar(&DisablePing, "np", false, GetText("flag_disable_ping"))
	flag.BoolVar(&UsePing, "ping", false, GetText("flag_use_ping"))
	flag.BoolVar(&EnableFingerprint, "fingerprint", false, GetText("flag_enable_fingerprint"))
	flag.BoolVar(&LocalMode, "local", false, GetText("flag_local_mode"))

	// ═════════════════════════════════════════════════
	// 认证与凭据参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Username, "user", "", GetText("flag_username"))
	flag.StringVar(&Password, "pwd", "", GetText("flag_password"))
	flag.StringVar(&AddUsers, "usera", "", GetText("flag_add_users"))
	flag.StringVar(&AddPasswords, "pwda", "", GetText("flag_add_passwords"))
	flag.StringVar(&UsersFile, "userf", "", GetText("flag_users_file"))
	flag.StringVar(&PasswordsFile, "pwdf", "", GetText("flag_passwords_file"))
	flag.StringVar(&HashFile, "hashf", "", GetText("flag_hash_file"))
	flag.StringVar(&HashValue, "hash", "", GetText("flag_hash_value"))
	flag.StringVar(&Domain, "domain", "", GetText("flag_domain"))      // SMB扫描用
	flag.StringVar(&SshKeyPath, "sshkey", "", GetText("flag_ssh_key")) // SSH扫描用

	// ═════════════════════════════════════════════════
	// Web扫描参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&TargetURL, "u", "", GetText("flag_target_url"))
	flag.StringVar(&URLsFile, "uf", "", GetText("flag_urls_file"))
	flag.StringVar(&Cookie, "cookie", "", GetText("flag_cookie"))
	flag.Int64Var(&WebTimeout, "wt", 5, GetText("flag_web_timeout"))
	flag.StringVar(&HttpProxy, "proxy", "", GetText("flag_http_proxy"))
	flag.StringVar(&Socks5Proxy, "socks5", "", GetText("flag_socks5_proxy"))

	// ═════════════════════════════════════════════════
	// POC测试参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&PocPath, "pocpath", "", GetText("flag_poc_path"))
	flag.StringVar(&Pocinfo.PocName, "pocname", "", GetText("flag_poc_name"))
	flag.BoolVar(&PocFull, "full", false, GetText("flag_poc_full"))
	flag.BoolVar(&DnsLog, "dns", false, GetText("flag_dns_log"))
	flag.IntVar(&PocNum, "num", 20, GetText("flag_poc_num"))
	flag.BoolVar(&DisablePocScan, "nopoc", false, GetText("flag_nopoc"))

	// ═════════════════════════════════════════════════
	// Redis利用参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&RedisFile, "rf", "", GetText("flag_redis_file"))
	flag.StringVar(&RedisShell, "rs", "", GetText("flag_redis_shell"))
	flag.BoolVar(&DisableRedis, "noredis", false, GetText("flag_disable_redis"))
	flag.StringVar(&RedisWritePath, "rwp", "", GetText("flag_redis_write_path"))
	flag.StringVar(&RedisWriteContent, "rwc", "", GetText("flag_redis_write_content"))
	flag.StringVar(&RedisWriteFile, "rwf", "", GetText("flag_redis_write_file"))

	// ═════════════════════════════════════════════════
	// 暴力破解控制参数
	// ═════════════════════════════════════════════════
	flag.BoolVar(&DisableBrute, "nobr", false, GetText("flag_disable_brute"))
	flag.IntVar(&MaxRetries, "retry", 3, GetText("flag_max_retries"))

	// ═════════════════════════════════════════════════
	// 输出与显示控制参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Outputfile, "o", "result.txt", GetText("flag_output_file"))
	flag.StringVar(&OutputFormat, "f", "txt", GetText("flag_output_format"))
	flag.BoolVar(&DisableSave, "no", false, GetText("flag_disable_save"))
	flag.BoolVar(&Silent, "silent", false, GetText("flag_silent_mode"))
	flag.BoolVar(&NoColor, "nocolor", false, GetText("flag_no_color"))
	flag.StringVar(&LogLevel, "log", LogLevelSuccess, GetText("flag_log_level"))
	flag.BoolVar(&ShowProgress, "pg", false, GetText("flag_show_progress"))
	flag.BoolVar(&ShowScanPlan, "sp", false, GetText("flag_show_scan_plan"))
	flag.BoolVar(&SlowLogOutput, "slow", false, GetText("flag_slow_log_output"))

	// ═════════════════════════════════════════════════
	// 其他参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Shellcode, "sc", "", GetText("flag_shellcode"))
	flag.StringVar(&Language, "lang", "zh", GetText("flag_language"))
	fs.StringVar(&ApiAddr, "api", "", GetText("flag_api"))
	fs.StringVar(&SecretKey, "secret", "", GetText("flag_api_key"))
}

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

func Flag(info *HostInfo) {
	Banner()

	// ═════════════════════════════════════════════════
	// 目标配置参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Info.Host, "h", "", GetText("flag_host"))
	flag.StringVar(&ExcludeHosts, "eh", "", GetText("flag_exclude_hosts"))
	flag.StringVar(&Ports, "p", MainPorts, GetText("flag_ports"))
	flag.StringVar(&ExcludePorts, "ep", "", GetText("flag_exclude_ports"))
	flag.StringVar(&HostsFile, "hf", "", GetText("flag_hosts_file"))
	flag.StringVar(&PortsFile, "pf", "", GetText("flag_ports_file"))

	// ═════════════════════════════════════════════════
	// 扫描控制参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&ScanMode, "m", "All", GetText("flag_scan_mode"))
	flag.IntVar(&ThreadNum, "t", 10, GetText("flag_thread_num"))
	flag.Int64Var(&Timeout, "time", 3, GetText("flag_timeout"))
	flag.IntVar(&ModuleThreadNum, "mt", 10, GetText("flag_module_thread_num"))
	flag.Int64Var(&GlobalTimeout, "gt", 180, GetText("flag_global_timeout"))
	flag.IntVar(&LiveTop, "top", 10, GetText("flag_live_top"))
	flag.BoolVar(&DisablePing, "np", false, GetText("flag_disable_ping"))
	flag.BoolVar(&UsePing, "ping", false, GetText("flag_use_ping"))
	flag.BoolVar(&EnableFingerprint, "fingerprint", false, GetText("flag_enable_fingerprint"))
	flag.BoolVar(&LocalMode, "local", false, GetText("flag_local_mode"))

	// ═════════════════════════════════════════════════
	// 认证与凭据参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Username, "user", "", GetText("flag_username"))
	flag.StringVar(&Password, "pwd", "", GetText("flag_password"))
	flag.StringVar(&AddUsers, "usera", "", GetText("flag_add_users"))
	flag.StringVar(&AddPasswords, "pwda", "", GetText("flag_add_passwords"))
	flag.StringVar(&UsersFile, "userf", "", GetText("flag_users_file"))
	flag.StringVar(&PasswordsFile, "pwdf", "", GetText("flag_passwords_file"))
	flag.StringVar(&HashFile, "hashf", "", GetText("flag_hash_file"))
	flag.StringVar(&HashValue, "hash", "", GetText("flag_hash_value"))
	flag.StringVar(&Domain, "domain", "", GetText("flag_domain"))      // SMB扫描用
	flag.StringVar(&SshKeyPath, "sshkey", "", GetText("flag_ssh_key")) // SSH扫描用

	// ═════════════════════════════════════════════════
	// Web扫描参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&TargetURL, "u", "", GetText("flag_target_url"))
	flag.StringVar(&URLsFile, "uf", "", GetText("flag_urls_file"))
	flag.StringVar(&Cookie, "cookie", "", GetText("flag_cookie"))
	flag.Int64Var(&WebTimeout, "wt", 5, GetText("flag_web_timeout"))
	flag.StringVar(&HttpProxy, "proxy", "", GetText("flag_http_proxy"))
	flag.StringVar(&Socks5Proxy, "socks5", "", GetText("flag_socks5_proxy"))

	// ═════════════════════════════════════════════════
	// POC测试参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&PocPath, "pocpath", "", GetText("flag_poc_path"))
	flag.StringVar(&Pocinfo.PocName, "pocname", "", GetText("flag_poc_name"))
	flag.BoolVar(&PocFull, "full", false, GetText("flag_poc_full"))
	flag.BoolVar(&DnsLog, "dns", false, GetText("flag_dns_log"))
	flag.IntVar(&PocNum, "num", 20, GetText("flag_poc_num"))
	flag.BoolVar(&DisablePocScan, "nopoc", false, GetText("flag_no_poc"))

	// ═════════════════════════════════════════════════
	// Redis利用参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&RedisFile, "rf", "", GetText("flag_redis_file"))
	flag.StringVar(&RedisShell, "rs", "", GetText("flag_redis_shell"))
	flag.BoolVar(&DisableRedis, "noredis", false, GetText("flag_disable_redis"))
	flag.StringVar(&RedisWritePath, "rwp", "", GetText("flag_redis_write_path"))
	flag.StringVar(&RedisWriteContent, "rwc", "", GetText("flag_redis_write_content"))
	flag.StringVar(&RedisWriteFile, "rwf", "", GetText("flag_redis_write_file"))

	// ═════════════════════════════════════════════════
	// 暴力破解控制参数
	// ═════════════════════════════════════════════════
	flag.BoolVar(&DisableBrute, "nobr", false, GetText("flag_disable_brute"))
	flag.IntVar(&MaxRetries, "retry", 3, GetText("flag_max_retries"))

	// ═════════════════════════════════════════════════
	// 输出与显示控制参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Outputfile, "o", "result.txt", GetText("flag_output_file"))
	flag.StringVar(&OutputFormat, "f", "txt", GetText("flag_output_format"))
	flag.BoolVar(&DisableSave, "no", false, GetText("flag_disable_save"))
	flag.BoolVar(&Silent, "silent", false, GetText("flag_silent_mode"))
	flag.BoolVar(&NoColor, "nocolor", false, GetText("flag_no_color"))
	flag.StringVar(&LogLevel, "log", LogLevelSuccess, GetText("flag_log_level"))
	flag.BoolVar(&ShowProgress, "pg", false, GetText("flag_show_progress"))
	flag.BoolVar(&ShowScanPlan, "sp", false, GetText("flag_show_scan_plan"))
	flag.BoolVar(&SlowLogOutput, "slow", false, GetText("flag_slow_log_output"))

	// ═════════════════════════════════════════════════
	// 其他参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Shellcode, "sc", "", GetText("flag_shellcode"))
	flag.StringVar(&Language, "lang", "zh", GetText("flag_language"))
	flag.StringVar(&ApiAddr, "api", "", GetText("flag_api"))
	flag.StringVar(&SecretKey, "secret", "", GetText("flag_api_key"))

	// 解析命令行参数
	parseCommandLineArgs()
	SetLanguage()
}

func FlagFromRemote(info *HostInfo, argString string) error {
	if strings.TrimSpace(argString) == "" {
		return fmt.Errorf("参数为空")
	}
	args, err := parseEnvironmentArgs(argString)
	if err != nil {
		return fmt.Errorf("远程参数解析失败: %v", err)
	}

	fs := flag.NewFlagSet("remote", flag.ContinueOnError)
	defineFlagsForSet(fs, info)

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("参数解析失败: %v", err)
	}
	return nil
}

func parseCommandLineArgs() {
	envArgsString := os.Getenv("FS_ARGS")
	if envArgsString != "" {
		envArgs, err := parseEnvironmentArgs(envArgsString)
		if err == nil && len(envArgs) > 0 {
			flag.CommandLine.Parse(envArgs)
			os.Unsetenv("FS_ARGS")
			return
		}
	}
	flag.Parse()
}

func parseEnvironmentArgs(argsString string) ([]string, error) {
	if strings.TrimSpace(argsString) == "" {
		return nil, fmt.Errorf("empty arguments string")
	}
	var args []string
	var currentArg strings.Builder
	inQuote := false
	quoteChar := ' '
	for _, char := range argsString {
		switch {
		case char == '"' || char == '\'':
			if inQuote && char == quoteChar {
				inQuote = false
			} else if !inQuote {
				inQuote = true
				quoteChar = char
			} else {
				currentArg.WriteRune(char)
			}
		case char == ' ' && !inQuote:
			if currentArg.Len() > 0 {
				args = append(args, currentArg.String())
				currentArg.Reset()
			}
		default:
			currentArg.WriteRune(char)
		}
	}
	if currentArg.Len() > 0 {
		args = append(args, currentArg.String())
	}
	return args, nil
}
