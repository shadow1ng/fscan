package Core

import (
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Plugins"
	"sort"
)

// init 初始化并注册所有扫描插件
// 包括标准端口服务扫描、特殊扫描类型和本地信息收集等
func init() {
	// 1. 标准网络服务扫描插件
	// 文件传输和远程访问服务
	Common.RegisterPlugin("ftp", Common.ScanPlugin{
		Name:     "FTP",
		Ports:    []int{21},
		ScanFunc: Plugins.FtpScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("ssh", Common.ScanPlugin{
		Name:     "SSH",
		Ports:    []int{22, 2222},
		ScanFunc: Plugins.SshScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("telnet", Common.ScanPlugin{
		Name:     "Telnet",
		Ports:    []int{23},
		ScanFunc: Plugins.TelnetScan,
		Types:    []string{Common.PluginTypeService},
	})

	// Windows网络服务
	Common.RegisterPlugin("findnet", Common.ScanPlugin{
		Name:     "FindNet",
		Ports:    []int{135},
		ScanFunc: Plugins.Findnet,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("netbios", Common.ScanPlugin{
		Name:     "NetBIOS",
		Ports:    []int{139},
		ScanFunc: Plugins.NetBIOS,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("smb", Common.ScanPlugin{
		Name:     "SMB",
		Ports:    []int{445},
		ScanFunc: Plugins.SmbScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 数据库服务
	Common.RegisterPlugin("mssql", Common.ScanPlugin{
		Name:     "MSSQL",
		Ports:    []int{1433, 1434},
		ScanFunc: Plugins.MssqlScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("oracle", Common.ScanPlugin{
		Name:     "Oracle",
		Ports:    []int{1521, 1522, 1526},
		ScanFunc: Plugins.OracleScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("mysql", Common.ScanPlugin{
		Name:     "MySQL",
		Ports:    []int{3306, 3307, 13306, 33306},
		ScanFunc: Plugins.MysqlScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 中间件和消息队列服务
	Common.RegisterPlugin("elasticsearch", Common.ScanPlugin{
		Name:     "Elasticsearch",
		Ports:    []int{9200, 9300},
		ScanFunc: Plugins.ElasticScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("rabbitmq", Common.ScanPlugin{
		Name:     "RabbitMQ",
		Ports:    []int{5672, 5671, 15672, 15671},
		ScanFunc: Plugins.RabbitMQScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("kafka", Common.ScanPlugin{
		Name:     "Kafka",
		Ports:    []int{9092, 9093},
		ScanFunc: Plugins.KafkaScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("activemq", Common.ScanPlugin{
		Name:     "ActiveMQ",
		Ports:    []int{61613},
		ScanFunc: Plugins.ActiveMQScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 目录和认证服务
	Common.RegisterPlugin("ldap", Common.ScanPlugin{
		Name:     "LDAP",
		Ports:    []int{389, 636},
		ScanFunc: Plugins.LDAPScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 邮件服务
	Common.RegisterPlugin("smtp", Common.ScanPlugin{
		Name:     "SMTP",
		Ports:    []int{25, 465, 587},
		ScanFunc: Plugins.SmtpScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("imap", Common.ScanPlugin{
		Name:     "IMAP",
		Ports:    []int{143, 993},
		ScanFunc: Plugins.IMAPScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("pop3", Common.ScanPlugin{
		Name:     "POP3",
		Ports:    []int{110, 995},
		ScanFunc: Plugins.POP3Scan,
		Types:    []string{Common.PluginTypeService},
	})

	// 网络管理和监控服务
	Common.RegisterPlugin("snmp", Common.ScanPlugin{
		Name:     "SNMP",
		Ports:    []int{161, 162},
		ScanFunc: Plugins.SNMPScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("modbus", Common.ScanPlugin{
		Name:     "Modbus",
		Ports:    []int{502, 5020},
		ScanFunc: Plugins.ModbusScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 数据同步和备份服务
	Common.RegisterPlugin("rsync", Common.ScanPlugin{
		Name:     "Rsync",
		Ports:    []int{873},
		ScanFunc: Plugins.RsyncScan,
		Types:    []string{Common.PluginTypeService},
	})

	// NoSQL数据库
	Common.RegisterPlugin("cassandra", Common.ScanPlugin{
		Name:     "Cassandra",
		Ports:    []int{9042},
		ScanFunc: Plugins.CassandraScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("neo4j", Common.ScanPlugin{
		Name:     "Neo4j",
		Ports:    []int{7687},
		ScanFunc: Plugins.Neo4jScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 远程桌面和显示服务
	Common.RegisterPlugin("rdp", Common.ScanPlugin{
		Name:     "RDP",
		Ports:    []int{3389, 13389, 33389},
		ScanFunc: Plugins.RdpScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("postgres", Common.ScanPlugin{
		Name:     "PostgreSQL",
		Ports:    []int{5432, 5433},
		ScanFunc: Plugins.PostgresScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("vnc", Common.ScanPlugin{
		Name:     "VNC",
		Ports:    []int{5900, 5901, 5902},
		ScanFunc: Plugins.VncScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 缓存和键值存储服务
	Common.RegisterPlugin("redis", Common.ScanPlugin{
		Name:     "Redis",
		Ports:    []int{6379, 6380, 16379},
		ScanFunc: Plugins.RedisScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("memcached", Common.ScanPlugin{
		Name:     "Memcached",
		Ports:    []int{11211},
		ScanFunc: Plugins.MemcachedScan,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("mongodb", Common.ScanPlugin{
		Name:     "MongoDB",
		Ports:    []int{27017, 27018},
		ScanFunc: Plugins.MongodbScan,
		Types:    []string{Common.PluginTypeService},
	})

	// 2. 特殊漏洞扫描插件
	Common.RegisterPlugin("ms17010", Common.ScanPlugin{
		Name:     "MS17010",
		Ports:    []int{445},
		ScanFunc: Plugins.MS17010,
		Types:    []string{Common.PluginTypeService},
	})

	Common.RegisterPlugin("smbghost", Common.ScanPlugin{
		Name:     "SMBGhost",
		Ports:    []int{445},
		ScanFunc: Plugins.SmbGhost,
		Types:    []string{Common.PluginTypeService},
	})

	// 3. Web应用扫描插件
	Common.RegisterPlugin("webtitle", Common.ScanPlugin{
		Name:     "WebTitle",
		Ports:    Common.ParsePortsFromString(Common.WebPorts),
		ScanFunc: Plugins.WebTitle,
		Types:    []string{Common.PluginTypeWeb},
	})

	Common.RegisterPlugin("webpoc", Common.ScanPlugin{
		Name:     "WebPoc",
		Ports:    Common.ParsePortsFromString(Common.WebPorts),
		ScanFunc: Plugins.WebPoc,
		Types:    []string{Common.PluginTypeWeb},
	})

	// 4. Windows系统专用插件
	Common.RegisterPlugin("smb2", Common.ScanPlugin{
		Name:     "SMBScan2",
		Ports:    []int{445},
		ScanFunc: Plugins.SmbScan2,
		Types:    []string{Common.PluginTypeService},
	})

	// 5. 本地信息收集插件
	Common.RegisterPlugin("localinfo", Common.ScanPlugin{
		Name:     "LocalInfo",
		Ports:    []int{},
		ScanFunc: Plugins.LocalInfoScan,
		Types:    []string{Common.PluginTypeLocal},
	})

	Common.RegisterPlugin("dcinfo", Common.ScanPlugin{
		Name:     "DCInfo",
		Ports:    []int{},
		ScanFunc: Plugins.DCInfoScan,
		Types:    []string{Common.PluginTypeLocal},
	})

	Common.RegisterPlugin("minidump", Common.ScanPlugin{
		Name:     "MiniDump",
		Ports:    []int{},
		ScanFunc: Plugins.MiniDump,
		Types:    []string{Common.PluginTypeLocal},
	})
}

// GetAllPlugins 返回所有已注册插件的名称列表
func GetAllPlugins() []string {
	pluginNames := make([]string, 0, len(Common.PluginManager))
	for name := range Common.PluginManager {
		pluginNames = append(pluginNames, name)
	}
	sort.Strings(pluginNames)
	return pluginNames
}
