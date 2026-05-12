package common

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/i18n"
)

// ErrShowHelp 表示用户请求显示帮助（正常退出）
var ErrShowHelp = errors.New("show help requested")

// Banner 显示程序横幅信息
func Banner() {
	// 静默模式下完全跳过Banner显示
	if flagVars.Silent {
		return
	}

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
		if flagVars.NoColor {
			// 无色彩模式下使用普通文本
			fmt.Print(line)
		} else {
			// 使用对应的颜色打印每个字符
			c := color.New(colors[lineNum%2])
			_, _ = c.Print(line)
		}
		// 补齐空格
		padding := maxLength - len(line)
		fmt.Printf("%s │\n", strings.Repeat(" ", padding))
	}

	fmt.Println(bottomBorder)

	// 打印版本信息
	versionStr := fmt.Sprintf("      Fscan %s (%s %s)", version, commit, date)
	if commit == "unknown" {
		versionStr = fmt.Sprintf("      Fscan %s", version)
	}
	if flagVars.NoColor {
		fmt.Printf("%s\n\n", versionStr)
	} else {
		c := color.New(colors[1])
		_, _ = c.Printf("%s\n\n", versionStr)
	}
}

// Flag 解析命令行参数并配置扫描选项
// 返回ErrShowHelp表示用户请求帮助（正常退出），其他error表示参数错误
func Flag(Info *HostInfo) error {
	// 预处理语言设置 - 在定义flag之前检查lang参数
	preProcessLanguage()

	fv := flagVars // 使用全局 FlagVars 实例

	// ═════════════════════════════════════════════════
	// 目标配置参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&Info.Host, "h", "", i18n.GetText("flag_host"))
	flag.StringVar(&fv.ExcludeHosts, "eh", "", i18n.GetText("flag_exclude_hosts"))
	flag.StringVar(&fv.ExcludeHostsFile, "ehf", "", i18n.GetText("flag_exclude_hosts_file"))
	flag.StringVar(&fv.Ports, "p", config.MainPorts, i18n.GetText("flag_ports"))
	flag.StringVar(&fv.ExcludePorts, "ep", "", i18n.GetText("flag_exclude_ports"))
	flag.StringVar(&fv.HostsFile, "hf", "", i18n.GetText("flag_hosts_file"))
	flag.StringVar(&fv.PortsFile, "pf", "", i18n.GetText("flag_ports_file"))

	// ═════════════════════════════════════════════════
	// 扫描控制参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&fv.ScanMode, "m", "all", i18n.GetText("flag_scan_mode"))
	flag.IntVar(&fv.ThreadNum, "t", 600, i18n.GetText("flag_thread_num"))
	flag.Int64Var(&fv.TimeoutSec, "time", 3, i18n.GetText("flag_timeout"))
	flag.IntVar(&fv.ModuleThreadNum, "mt", 20, i18n.GetText("flag_module_thread_num"))
	flag.Int64Var(&fv.GlobalTimeout, "gt", 180, i18n.GetText("flag_global_timeout"))
	flag.BoolVar(&fv.DisablePing, "np", false, i18n.GetText("flag_disable_ping"))
	flag.BoolVar(&fv.DisableTcpProbe, "ntp", false, i18n.GetText("flag_disable_tcp_probe"))
	flag.StringVar(&fv.LocalPlugin, "local", "", "指定本地插件名称 (如: cleaner, avdetect, keylogger 等)")
	flag.BoolVar(&fv.AliveOnly, "ao", false, i18n.GetText("flag_alive_only"))

	// ═════════════════════════════════════════════════
	// 认证与凭据参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&fv.Username, "user", "", i18n.GetText("flag_username"))
	flag.StringVar(&fv.Password, "pwd", "", i18n.GetText("flag_password"))
	flag.StringVar(&fv.AddUsers, "usera", "", i18n.GetText("flag_add_users"))
	flag.StringVar(&fv.AddPasswords, "pwda", "", i18n.GetText("flag_add_passwords"))
	flag.StringVar(&fv.UsersFile, "userf", "", i18n.GetText("flag_users_file"))
	flag.StringVar(&fv.PasswordsFile, "pwdf", "", i18n.GetText("flag_passwords_file"))
	flag.StringVar(&fv.UserPassFile, "upf", "", i18n.GetText("flag_userpass_file"))
	flag.StringVar(&fv.HashFile, "hashf", "", i18n.GetText("flag_hash_file"))
	flag.StringVar(&fv.HashValue, "hash", "", i18n.GetText("flag_hash_value"))
	flag.StringVar(&fv.Domain, "domain", "", i18n.GetText("flag_domain"))
	flag.StringVar(&fv.SSHKeyPath, "sshkey", "", i18n.GetText("flag_ssh_key"))

	// ═════════════════════════════════════════════════
	// Web扫描参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&fv.TargetURL, "u", "", i18n.GetText("flag_target_url"))
	flag.StringVar(&fv.URLsFile, "uf", "", i18n.GetText("flag_urls_file"))
	flag.StringVar(&fv.Cookie, "cookie", "", i18n.GetText("flag_cookie"))
	flag.Int64Var(&fv.WebTimeout, "wt", 5, i18n.GetText("flag_web_timeout"))
	flag.IntVar(&fv.MaxRedirects, "max-redirect", 10, i18n.GetText("flag_max_redirects"))
	flag.StringVar(&fv.HTTPProxy, "proxy", "", i18n.GetText("flag_http_proxy"))
	flag.StringVar(&fv.Socks5Proxy, "socks5", "", i18n.GetText("flag_socks5_proxy"))
	flag.StringVar(&fv.Iface, "iface", "", i18n.GetText("flag_iface"))

	// ═════════════════════════════════════════════════
	// POC测试参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&fv.PocPath, "pocpath", "", i18n.GetText("flag_poc_path"))
	flag.StringVar(&fv.PocName, "pocname", "", i18n.GetText("flag_poc_name"))
	flag.BoolVar(&fv.PocFull, "full", false, i18n.GetText("flag_poc_full"))
	flag.BoolVar(&fv.DNSLog, "dns", false, i18n.GetText("flag_dns_log"))
	flag.IntVar(&fv.PocNum, "num", 20, i18n.GetText("flag_poc_num"))
	flag.BoolVar(&fv.DisablePocScan, "nopoc", false, i18n.GetText("flag_no_poc"))

	// ═════════════════════════════════════════════════
	// Redis利用参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&fv.RedisFile, "rf", "", i18n.GetText("flag_redis_file"))
	flag.StringVar(&fv.RedisShell, "rs", "", i18n.GetText("flag_redis_shell"))
	flag.StringVar(&fv.RedisWritePath, "rwp", "", i18n.GetText("flag_redis_write_path"))
	flag.StringVar(&fv.RedisWriteContent, "rwc", "", i18n.GetText("flag_redis_write_content"))
	flag.StringVar(&fv.RedisWriteFile, "rwf", "", i18n.GetText("flag_redis_write_file"))
	flag.BoolVar(&fv.DisableRedis, "noredis", false, i18n.GetText("flag_disable_redis"))

	// ═════════════════════════════════════════════════
	// 暴力破解控制参数
	// ═════════════════════════════════════════════════
	flag.BoolVar(&fv.DisableBrute, "nobr", false, i18n.GetText("flag_disable_brute"))
	flag.IntVar(&fv.MaxRetries, "retry", 3, i18n.GetText("flag_max_retries"))

	// ═════════════════════════════════════════════════
	// 发包频率控制参数
	// ═════════════════════════════════════════════════
	flag.Int64Var(&fv.PacketRateLimit, "rate", 0, i18n.GetText("flag_packet_rate_limit"))
	flag.Int64Var(&fv.MaxPacketCount, "maxpkts", 0, i18n.GetText("flag_max_packet_count"))
	flag.Float64Var(&fv.ICMPRate, "icmp-rate", 0.1, i18n.GetText("flag_icmp_rate"))

	// ═════════════════════════════════════════════════
	// 输出与显示控制参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&fv.Outputfile, "o", "result.txt", i18n.GetText("flag_output_file"))
	flag.StringVar(&fv.OutputFormat, "f", "txt", i18n.GetText("flag_output_format"))
	flag.BoolVar(&fv.DisableSave, "no", false, i18n.GetText("flag_disable_save"))
	flag.BoolVar(&fv.Silent, "silent", false, i18n.GetText("flag_silent_mode"))
	flag.BoolVar(&fv.NoColor, "nocolor", false, i18n.GetText("flag_no_color"))
	flag.StringVar(&fv.LogLevel, "log", LogLevelBaseInfoSuccess, i18n.GetText("flag_log_level"))
	flag.BoolVar(&fv.Debug, "debug", false, i18n.GetText("flag_debug"))
	flag.BoolVar(&fv.DisableProgress, "nopg", false, i18n.GetText("flag_disable_progress"))
	flag.BoolVar(&fv.PerfStats, "perf", false, "输出性能统计JSON")

	// ═════════════════════════════════════════════════
	// 其他参数
	// ═════════════════════════════════════════════════
	flag.StringVar(&fv.Shellcode, "sc", "", i18n.GetText("flag_shellcode"))
	flag.StringVar(&fv.ReverseShellTarget, "rsh", "", i18n.GetText("flag_reverse_shell_target"))
	flag.IntVar(&fv.Socks5ProxyPort, "start-socks5", 0, i18n.GetText("flag_start_socks5_server"))
	flag.IntVar(&fv.ForwardShellPort, "fsh-port", 4444, i18n.GetText("flag_forward_shell_port"))
	flag.StringVar(&fv.PersistenceTargetFile, "persistence-file", "", i18n.GetText("flag_persistence_file"))
	flag.StringVar(&fv.WinPEFile, "win-pe", "", i18n.GetText("flag_win_pe_file"))
	flag.StringVar(&fv.KeyloggerOutputFile, "keylog-output", "keylog.txt", i18n.GetText("flag_keylogger_output"))

	// 文件下载插件参数
	flag.StringVar(&fv.DownloadURL, "download-url", "", i18n.GetText("flag_download_url"))
	flag.StringVar(&fv.DownloadSavePath, "download-path", "", i18n.GetText("flag_download_path"))
	flag.StringVar(&fv.Language, "lang", "zh", i18n.GetText("flag_language"))

	// 帮助参数
	flag.BoolVar(&fv.ShowHelp, "help", false, i18n.GetText("flag_help"))

	// 解析命令行参数
	if err := parseCommandLineArgs(); err != nil {
		return err
	}

	// 设置语言
	i18n.SetLanguage(fv.Language)

	// 如果显示帮助或者没有提供目标，显示帮助信息并退出
	if fv.ShowHelp || shouldShowHelp(Info, fv) {
		flag.Usage()
		return ErrShowHelp
	}

	return nil
}

// parseCommandLineArgs 解析命令行参数
func parseCommandLineArgs() error {
	flag.Parse()

	// 显示Banner
	Banner()

	// 检查参数冲突
	return checkParameterConflicts()
}

// preProcessLanguage 预处理语言参数，在定义flag之前设置语言
func preProcessLanguage() {
	// 遍历命令行参数查找-lang参数
	for i, arg := range os.Args {
		if arg == "-lang" && i+1 < len(os.Args) {
			lang := os.Args[i+1]
			if lang == "en" || lang == "zh" {
				flagVars.Language = lang
				i18n.SetLanguage(lang)
				return
			}
		} else if strings.HasPrefix(arg, "-lang=") {
			lang := strings.TrimPrefix(arg, "-lang=")
			if lang == "en" || lang == "zh" {
				flagVars.Language = lang
				i18n.SetLanguage(lang)
				return
			}
		}
	}

	// 检查环境变量
	envLang := os.Getenv("FS_LANG")
	if envLang == "en" || envLang == "zh" {
		flagVars.Language = envLang
		i18n.SetLanguage(envLang)
	}
}

// shouldShowHelp 检查是否应该显示帮助信息
func shouldShowHelp(Info *HostInfo, fv *FlagVars) bool {
	// Web模式不需要目标参数
	if WebMode {
		return false
	}

	// 检查是否提供了扫描目标
	hasTarget := Info.Host != "" || fv.TargetURL != "" || fv.HostsFile != "" || fv.URLsFile != ""

	// 本地模式需要指定插件才算有效目标
	if fv.LocalPlugin != "" {
		hasTarget = true
	}

	// 如果没有提供任何扫描目标，则显示帮助
	return !hasTarget
}

// checkParameterConflicts 检查参数冲突和兼容性
// 返回error而不是调用os.Exit，让调用者决定如何处理
func checkParameterConflicts() error {
	fv := flagVars

	// -debug 等价于 -log debug
	if fv.Debug {
		fv.LogLevel = LogLevelDebug
	}

	// 检查 -ao 和 -m icmp 同时指定的情况（向后兼容提示）
	if fv.AliveOnly && fv.ScanMode == "icmp" {
		LogInfo(i18n.GetText("param_conflict_ao_icmp_both"))
	}

	// 检查本地插件参数
	if fv.LocalPlugin != "" {
		// 检查是否包含分隔符（确保只能指定单个插件）
		invalidChars := []string{",", ";", " ", "|", "&"}
		for _, char := range invalidChars {
			if strings.Contains(fv.LocalPlugin, char) {
				return fmt.Errorf("本地插件只能指定单个插件，不支持使用 '%s' 分隔的多个插件", char)
			}
		}
	}

	return nil
}
