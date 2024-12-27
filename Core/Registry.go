package Core

import (
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Plugins"
)

func init() {
	// 注册标准端口服务扫描
	Common.RegisterPlugin("ftp", Common.ScanPlugin{
		Name:     "FTP",
		Ports:    []int{21},
		ScanFunc: Plugins.FtpScan,
	})

	Common.RegisterPlugin("ssh", Common.ScanPlugin{
		Name:     "SSH",
		Ports:    []int{22, 2222},
		ScanFunc: Plugins.SshScan,
	})

	Common.RegisterPlugin("telnet", Common.ScanPlugin{
		Name:     "Telnet",
		Ports:    []int{23},
		ScanFunc: Plugins.TelnetScan,
	})

	Common.RegisterPlugin("findnet", Common.ScanPlugin{
		Name:     "FindNet",
		Ports:    []int{135},
		ScanFunc: Plugins.Findnet,
	})

	Common.RegisterPlugin("netbios", Common.ScanPlugin{
		Name:     "NetBIOS",
		Ports:    []int{139},
		ScanFunc: Plugins.NetBIOS,
	})

	Common.RegisterPlugin("smb", Common.ScanPlugin{
		Name:     "SMB",
		Ports:    []int{445},
		ScanFunc: Plugins.SmbScan,
	})

	Common.RegisterPlugin("mssql", Common.ScanPlugin{
		Name:     "MSSQL",
		Ports:    []int{1433, 1434}, // 支持多个端口
		ScanFunc: Plugins.MssqlScan,
	})

	Common.RegisterPlugin("oracle", Common.ScanPlugin{
		Name:     "Oracle",
		Ports:    []int{1521, 1522, 1526}, // Oracle 可能的多个端口
		ScanFunc: Plugins.OracleScan,
	})

	Common.RegisterPlugin("mysql", Common.ScanPlugin{
		Name:     "MySQL",
		Ports:    []int{3306, 3307, 13306, 33306}, // MySQL 可能的端口
		ScanFunc: Plugins.MysqlScan,
	})

	Common.RegisterPlugin("elasticsearch", Common.ScanPlugin{
		Name:     "Elasticsearch",
		Ports:    []int{9200, 9300}, // Elasticsearch 默认HTTP和Transport端口
		ScanFunc: Plugins.ElasticScan,
	})

	Common.RegisterPlugin("rabbitmq", Common.ScanPlugin{
		Name:     "RabbitMQ",
		Ports:    []int{5672, 5671, 15672, 15671}, // AMQP和管理端口
		ScanFunc: Plugins.RabbitMQScan,
	})

	Common.RegisterPlugin("kafka", Common.ScanPlugin{
		Name:     "Kafka",
		Ports:    []int{9092, 9093}, // Kafka默认端口和SSL端口
		ScanFunc: Plugins.KafkaScan,
	})

	Common.RegisterPlugin("activemq", Common.ScanPlugin{
		Name:     "ActiveMQ",
		Ports:    []int{61616, 61613},
		ScanFunc: Plugins.ActiveMQScan,
	})

	Common.RegisterPlugin("ldap", Common.ScanPlugin{
		Name:     "LDAP",
		Ports:    []int{389, 636}, // LDAP标准端口和LDAPS端口
		ScanFunc: Plugins.LDAPScan,
	})

	Common.RegisterPlugin("smtp", Common.ScanPlugin{
		Name:     "SMTP",
		Ports:    []int{25, 465, 587},
		ScanFunc: Plugins.SmtpScan,
	})

	Common.RegisterPlugin("imap", Common.ScanPlugin{
		Name:     "IMAP",
		Ports:    []int{143, 993}, // 143是标准端口，993是SSL端口
		ScanFunc: Plugins.IMAPScan,
	})

	Common.RegisterPlugin("pop3", Common.ScanPlugin{
		Name:     "POP3",
		Ports:    []int{110, 995}, // POP3和POP3S端口
		ScanFunc: Plugins.POP3Scan,
	})

	Common.RegisterPlugin("snmp", Common.ScanPlugin{
		Name:     "SNMP",
		Ports:    []int{161, 162}, // SNMP默认端口
		ScanFunc: Plugins.SNMPScan,
	})

	Common.RegisterPlugin("zabbix", Common.ScanPlugin{
		Name:     "Zabbix",
		Ports:    []int{80, 443, 8080, 8443, 10051}, // Zabbix常用端口
		ScanFunc: Plugins.ZabbixScan,
	})

	Common.RegisterPlugin("modbus", Common.ScanPlugin{
		Name:     "Modbus",
		Ports:    []int{502, 5020}, // Modbus 默认端口
		ScanFunc: Plugins.ModbusScan,
	})

	Common.RegisterPlugin("rsync", Common.ScanPlugin{
		Name:     "Rsync",
		Ports:    []int{873},
		ScanFunc: Plugins.RsyncScan,
	})

	Common.RegisterPlugin("cassandra", Common.ScanPlugin{
		Name:     "Cassandra",
		Ports:    []int{9042},
		ScanFunc: Plugins.CassandraScan,
	})

	Common.RegisterPlugin("neo4j", Common.ScanPlugin{
		Name:     "Neo4j",
		Ports:    []int{7687},
		ScanFunc: Plugins.Neo4jScan,
	})

	Common.RegisterPlugin("rdp", Common.ScanPlugin{
		Name:     "RDP",
		Ports:    []int{3389, 13389, 33389},
		ScanFunc: Plugins.RdpScan,
	})

	Common.RegisterPlugin("postgres", Common.ScanPlugin{
		Name:     "PostgreSQL",
		Ports:    []int{5432, 5433}, // PostgreSQL 可能的端口
		ScanFunc: Plugins.PostgresScan,
	})

	Common.RegisterPlugin("vnc", Common.ScanPlugin{
		Name:     "VNC",
		Ports:    []int{5900, 5901, 5902}, // VNC 可能的端口
		ScanFunc: Plugins.VncScan,
	})

	Common.RegisterPlugin("redis", Common.ScanPlugin{
		Name:     "Redis",
		Ports:    []int{6379, 6380, 16379}, // Redis 可能的端口
		ScanFunc: Plugins.RedisScan,
	})

	Common.RegisterPlugin("fcgi", Common.ScanPlugin{
		Name:     "FastCGI",
		Ports:    []int{9000},
		ScanFunc: Plugins.FcgiScan,
	})

	Common.RegisterPlugin("memcached", Common.ScanPlugin{
		Name:     "Memcached",
		Ports:    []int{11211},
		ScanFunc: Plugins.MemcachedScan,
	})

	Common.RegisterPlugin("mongodb", Common.ScanPlugin{
		Name:     "MongoDB",
		Ports:    []int{27017, 27018}, // MongoDB 可能的端口
		ScanFunc: Plugins.MongodbScan,
	})

	// 注册特殊扫描类型
	Common.RegisterPlugin("ms17010", Common.ScanPlugin{
		Name:     "MS17010",
		Ports:    []int{445},
		ScanFunc: Plugins.MS17010,
	})

	Common.RegisterPlugin("smbghost", Common.ScanPlugin{
		Name:     "SMBGhost",
		Ports:    []int{445},
		ScanFunc: Plugins.SmbGhost,
	})

	// web 相关插件添加 WebPorts 配置
	Common.RegisterPlugin("web", Common.ScanPlugin{
		Name:     "WebTitle",
		Ports:    Common.ParsePortsFromString(Common.WebPorts), // 将 WebPorts 字符串解析为端口数组
		ScanFunc: Plugins.WebTitle,
	})

	Common.RegisterPlugin("webpoc", Common.ScanPlugin{
		Name:     "WebPoc",
		Ports:    Common.ParsePortsFromString(Common.WebPorts), // 将 WebPorts 字符串解析为端口数组
		ScanFunc: Plugins.WebPoc,
	})

	Common.RegisterPlugin("smb2", Common.ScanPlugin{
		Name:     "SMBScan2",
		Ports:    []int{445},
		ScanFunc: Plugins.SmbScan2,
	})

	Common.RegisterPlugin("wmiexec", Common.ScanPlugin{
		Name:     "WMIExec",
		Ports:    []int{135},
		ScanFunc: Plugins.WmiExec,
	})

	Common.RegisterPlugin("localinfo", Common.ScanPlugin{
		Name:     "LocalInfo",
		Ports:    []int{}, // 本地信息收集不需要端口
		ScanFunc: Plugins.LocalInfoScan,
	})

	Common.RegisterPlugin("dcinfo", Common.ScanPlugin{
		Name:     "DCInfo",
		Ports:    []int{}, // 本地信息收集不需要端口
		ScanFunc: Plugins.DCInfoScan,
	})

	Common.RegisterPlugin("minidump", Common.ScanPlugin{
		Name:     "MiniDump",
		Ports:    []int{}, // 本地信息收集不需要端口
		ScanFunc: Plugins.MiniDump,
	})
}
