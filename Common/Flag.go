package Common

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

// ParseFlags 集成了所有命令行参数解析功能
// 支持本地命令行参数和远程参数字符串
func ParseFlags(Info *HostInfo, remoteArgs ...string) error {
	// 打印横幅
	printBanner()

	// 创建FlagSet，使用主命令行或者远程模式
	isRemote := len(remoteArgs) > 0 && remoteArgs[0] != ""
	fs := flag.CommandLine
	if isRemote {
		fs = flag.NewFlagSet("remote", flag.ContinueOnError)
	}

	// ═════════ 注册所有命令行参数 ═════════
	// 目标配置参数
	fs.StringVar(&Info.Host, "h", "", GetText("flag_host"))
	fs.StringVar(&ExcludeHosts, "eh", "", GetText("flag_exclude_hosts"))
	fs.StringVar(&Ports, "p", MainPorts, GetText("flag_ports"))
	fs.StringVar(&ExcludePorts, "ep", "", GetText("flag_exclude_ports"))
	fs.StringVar(&HostsFile, "hf", "", GetText("flag_hosts_file"))
	fs.StringVar(&PortsFile, "pf", "", GetText("flag_ports_file"))

	// 扫描控制参数
	fs.StringVar(&ScanMode, "m", "all", GetText("flag_scan_mode"))
	fs.IntVar(&ThreadNum, "t", 10, GetText("flag_thread_num"))
	fs.Int64Var(&Timeout, "time", 3, GetText("flag_timeout"))
	fs.IntVar(&ModuleThreadNum, "mt", 10, GetText("flag_module_thread_num"))
	fs.Int64Var(&GlobalTimeout, "gt", 180, GetText("flag_global_timeout"))
	fs.IntVar(&LiveTop, "top", 10, GetText("flag_live_top"))
	fs.BoolVar(&DisablePing, "np", false, GetText("flag_disable_ping"))
	fs.BoolVar(&UsePing, "ping", false, GetText("flag_use_ping"))
	fs.BoolVar(&EnableFingerprint, "fingerprint", false, GetText("flag_enable_fingerprint"))
	fs.BoolVar(&LocalMode, "local", false, GetText("flag_local_mode"))

	// 认证与凭据参数
	fs.StringVar(&Username, "user", "", GetText("flag_username"))
	fs.StringVar(&Password, "pwd", "", GetText("flag_password"))
	fs.StringVar(&AddUsers, "usera", "", GetText("flag_add_users"))
	fs.StringVar(&AddPasswords, "pwda", "", GetText("flag_add_passwords"))
	fs.StringVar(&UsersFile, "userf", "", GetText("flag_users_file"))
	fs.StringVar(&PasswordsFile, "pwdf", "", GetText("flag_passwords_file"))
	fs.StringVar(&HashFile, "hashf", "", GetText("flag_hash_file"))
	fs.StringVar(&HashValue, "hash", "", GetText("flag_hash_value"))
	fs.StringVar(&Domain, "domain", "", GetText("flag_domain"))
	fs.StringVar(&SshKeyPath, "sshkey", "", GetText("flag_ssh_key"))

	// Web扫描参数
	fs.StringVar(&TargetURL, "u", "", GetText("flag_target_url"))
	fs.StringVar(&URLsFile, "uf", "", GetText("flag_urls_file"))
	fs.StringVar(&Cookie, "cookie", "", GetText("flag_cookie"))
	fs.Int64Var(&WebTimeout, "wt", 5, GetText("flag_web_timeout"))
	fs.StringVar(&HttpProxy, "proxy", "", GetText("flag_http_proxy"))
	fs.StringVar(&Socks5Proxy, "socks5", "", GetText("flag_socks5_proxy"))

	// POC测试参数
	fs.StringVar(&PocPath, "pocpath", "", GetText("flag_poc_path"))
	fs.StringVar(&Pocinfo.PocName, "pocname", "", GetText("flag_poc_name"))
	fs.BoolVar(&PocFull, "full", false, GetText("flag_poc_full"))
	fs.BoolVar(&DnsLog, "dns", false, GetText("flag_dns_log"))
	fs.IntVar(&PocNum, "num", 20, GetText("flag_poc_num"))
	fs.BoolVar(&DisablePocScan, "nopoc", false, GetText("flag_no_poc"))

	// Redis利用参数
	fs.StringVar(&RedisFile, "rf", "", GetText("flag_redis_file"))
	fs.StringVar(&RedisShell, "rs", "", GetText("flag_redis_shell"))
	fs.BoolVar(&DisableRedis, "noredis", false, GetText("flag_disable_redis"))
	fs.StringVar(&RedisWritePath, "rwp", "", GetText("flag_redis_write_path"))
	fs.StringVar(&RedisWriteContent, "rwc", "", GetText("flag_redis_write_content"))
	fs.StringVar(&RedisWriteFile, "rwf", "", GetText("flag_redis_write_file"))

	// 暴力破解控制参数
	fs.BoolVar(&DisableBrute, "nobr", false, GetText("flag_disable_brute"))
	fs.IntVar(&MaxRetries, "retry", 3, GetText("flag_max_retries"))

	// 输出与显示控制参数
	fs.StringVar(&Outputfile, "o", "result.txt", GetText("flag_output_file"))
	fs.StringVar(&OutputFormat, "f", "txt", GetText("flag_output_format"))
	fs.BoolVar(&DisableSave, "no", false, GetText("flag_disable_save"))
	fs.BoolVar(&Silent, "silent", false, GetText("flag_silent_mode"))
	fs.BoolVar(&NoColor, "nocolor", false, GetText("flag_no_color"))
	fs.StringVar(&LogLevel, "log", LogLevelSuccess, GetText("flag_log_level"))
	fs.BoolVar(&ShowProgress, "pg", false, GetText("flag_show_progress"))
	fs.BoolVar(&ShowScanPlan, "sp", false, GetText("flag_show_scan_plan"))
	fs.BoolVar(&SlowLogOutput, "slow", false, GetText("flag_slow_log_output"))

	// 其他参数
	fs.StringVar(&Shellcode, "sc", "", GetText("flag_shellcode"))
	fs.StringVar(&Language, "lang", "zh", GetText("flag_language"))
	fs.StringVar(&ApiAddr, "api", "", GetText("flag_api"))
	fs.StringVar(&SecretKey, "secret", "", GetText("flag_api_key"))

	// 根据模式解析参数
	if isRemote {
		// 解析远程参数字符串
		args, err := parseArgs(remoteArgs[0])
		if err != nil {
			return fmt.Errorf("远程参数解析失败: %v", err)
		}
		return fs.Parse(args)
	} else {
		// 优先尝试从环境变量解析参数
		envArgs := os.Getenv("FS_ARGS")
		if envArgs != "" {
			if args, err := parseArgs(envArgs); err == nil && len(args) > 0 {
				fs.Parse(args)
				os.Unsetenv("FS_ARGS") // 使用后清除环境变量
				return nil
			}
		}
		// 解析命令行参数
		flag.Parse()
	}

	// 设置语言
	SetLanguage()
	return nil
}

// parseArgs 解析字符串形式的参数为参数切片
func parseArgs(argsString string) ([]string, error) {
	if strings.TrimSpace(argsString) == "" {
		return nil, fmt.Errorf("参数字符串为空")
	}

	var args []string
	var currentArg strings.Builder
	inQuote := false
	quoteChar := ' '

	// 安全解析带引号的参数
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

// printBanner 打印程序横幅
func printBanner() {
	// 定义颜色
	colors := []color.Attribute{color.FgGreen, color.FgHiGreen}

	// 横幅文本
	lines := []string{
		"   ___                              _    ",
		"  / _ \\     ___  ___ _ __ __ _  ___| | __ ",
		" / /_\\/____/ __|/ __| '__/ _` |/ __| |/ /",
		"/ /_\\\\_____\\__ \\ (__| | | (_| | (__|   <    ",
		"\\____/     |___/\\___|_|  \\__,_|\\___|_|\\_\\   ",
	}

	// 计算最长行长度和创建边框
	maxLength := 0
	for _, line := range lines {
		if len(line) > maxLength {
			maxLength = len(line)
		}
	}
	border := strings.Repeat("─", maxLength+2)

	// 打印带框架的横幅
	fmt.Printf("┌%s┐\n", border)
	for i, line := range lines {
		fmt.Print("│ ")
		color.New(colors[i%2]).Print(line)
		fmt.Printf("%s │\n", strings.Repeat(" ", maxLength-len(line)))
	}
	fmt.Printf("└%s┘\n", border)

	// 打印版本信息
	color.New(colors[1]).Printf("      Fscan Version: %s\n\n", version)
}
