package Common

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
)

// 插件分类映射表 - 所有插件名使用小写
var PluginGroups = map[string][]string{
	ModeAll: {
		"webtitle", "webpoc", // web类
		"mysql", "mssql", "redis", "mongodb", "postgres", // 数据库类
		"oracle", "memcached", "elasticsearch", "rabbitmq", "kafka", "activemq", "cassandra", "neo4j", // 数据库类
		"ftp", "ssh", "telnet", "smb", "rdp", "vnc", "netbios", "ldap", "smtp", "imap", "pop3", "snmp", "modbus", "rsync", // 服务类
		"ms17010", "smbghost", "smb2", // 漏洞类
		"findnet", // 其他
	},
	ModeBasic: {
		"webtitle", "ftp", "ssh", "smb", "findnet",
	},
	ModeDatabase: {
		"mysql", "mssql", "redis", "mongodb",
		"postgres", "oracle", "memcached", "elasticsearch", "rabbitmq", "kafka", "activemq", "cassandra", "neo4j",
	},
	ModeWeb: {
		"webtitle", "webpoc",
	},
	ModeService: {
		"ftp", "ssh", "telnet", "smb", "rdp", "vnc", "netbios", "ldap", "smtp", "imap", "pop3", "modbus", "rsync",
	},
	ModeVul: {
		"ms17010", "smbghost", "smb2",
	},
	ModeLocal: {
		"localinfo", "minidump", "dcinfo",
	},
}

// ParseScanMode 解析扫描模式
func ParseScanMode(mode string) {
	LogInfo(GetText("parse_scan_mode", mode))

	// 检查是否是预设模式
	presetModes := []string{
		ModeAll, ModeBasic, ModeDatabase, ModeWeb,
		ModeService, ModeVul, ModePort, ModeICMP, ModeLocal,
	}

	for _, presetMode := range presetModes {
		if mode == presetMode {
			ScanMode = mode
			if plugins := GetPluginsForMode(mode); plugins != nil {
				LogInfo(GetText("using_preset_mode_plugins", mode, plugins))
			} else {
				LogInfo(GetText("using_preset_mode", mode))
			}
			return
		}
	}

	// 检查是否是有效的插件名
	if _, exists := PluginManager[mode]; exists {
		ScanMode = mode
		LogInfo(GetText("using_single_plugin", mode))
		return
	}

	// 默认使用All模式
	ScanMode = ModeAll
	LogInfo(GetText("using_default_mode", ModeAll))
	LogInfo(GetText("included_plugins", PluginGroups[ModeAll]))
}

// GetPluginsForMode 获取指定模式下的插件列表
func GetPluginsForMode(mode string) []string {
	plugins, exists := PluginGroups[mode]
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
