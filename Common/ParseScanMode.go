package Common

import "fmt"

// 扫描模式常量 - 使用大写开头表示这是一个预设的扫描模式
const (
	ModeAll      = "All"      // 全量扫描
	ModeBasic    = "Basic"    // 基础扫描
	ModeDatabase = "Database" // 数据库扫描
	ModeWeb      = "Web"      // Web扫描
	ModeService  = "Service"  // 服务扫描
	ModeVul      = "Vul"      // 漏洞扫描
	ModePort     = "Port"     // 端口扫描
	ModeICMP     = "ICMP"     // ICMP探测
	ModeLocal    = "Local"    // 本地信息收集
	ModeUDP      = "UDP"      //UDP扫描
)

// 插件分类映射表 - 所有插件名使用小写
var pluginGroups = map[string][]string{
	ModeAll: {
		"web", "fcgi", // web类
		"mysql", "mssql", "redis", "mongodb", "postgres", // 数据库类
		"oracle", "memcached", "elasticsearch", "rabbitmq", "kafka", "activemq", // 数据库类
		"ftp", "ssh", "telnet", "smb", "rdp", "vnc", "netbios", "ldap", "smtp", "imap", "pop3", "snmp", "zabbix", // 服务类
		"ms17010", "smbghost", "smb2", // 漏洞类
		"findnet", // 其他
	},
	ModeBasic: {
		"web", "ftp", "ssh", "smb", "findnet",
	},
	ModeDatabase: {
		"mysql", "mssql", "redis", "mongodb",
		"postgres", "oracle", "memcached", "elasticsearch", "rabbitmq", "kafka", "activemq",
	},
	ModeWeb: {
		"web", "fcgi",
	},
	ModeService: {
		"ftp", "ssh", "telnet", "smb", "rdp", "vnc", "netbios", "ldap", "smtp", "imap", "pop3", "zabbix",
	},
	ModeVul: {
		"ms17010", "smbghost", "smb2",
	},
	ModeLocal: {
		"localinfo",
	},
	ModeUDP: {
		"snmp",
	},
}

// ParseScanMode 解析扫描模式
func ParseScanMode(mode string) {
	fmt.Printf("[*] 解析扫描模式: %s\n", mode)

	// 检查是否是预设模式
	presetModes := []string{
		ModeAll, ModeBasic, ModeDatabase, ModeWeb,
		ModeService, ModeVul, ModePort, ModeICMP, ModeLocal,
	}

	for _, presetMode := range presetModes {
		if mode == presetMode {
			ScanMode = mode
			if plugins := GetPluginsForMode(mode); plugins != nil {
				fmt.Printf("[+] 使用预设模式: %s, 包含插件: %v\n", mode, plugins)
			} else {
				fmt.Printf("[+] 使用预设模式: %s\n", mode)
			}
			return
		}
	}

	// 检查是否是有效的插件名
	if _, exists := PluginManager[mode]; exists {
		ScanMode = mode
		fmt.Printf("[+] 使用单个插件: %s\n", mode)
		return
	}

	// 默认使用All模式
	ScanMode = ModeAll
	fmt.Printf("[*] 未识别的模式，使用默认模式: %s\n", ModeAll)
	fmt.Printf("[+] 包含插件: %v\n", pluginGroups[ModeAll])
}

// GetPluginsForMode 获取指定模式下的插件列表
func GetPluginsForMode(mode string) []string {
	plugins, exists := pluginGroups[mode]
	if exists {
		return plugins
	}
	return nil
}

// 辅助函数
func IsPortScan() bool    { return ScanMode == ModePort }
func IsICMPScan() bool    { return ScanMode == ModeICMP }
func IsWebScan() bool     { return ScanMode == ModeWeb }
func GetScanMode() string { return ScanMode }
