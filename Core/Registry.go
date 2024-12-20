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
		Name:     "TELNET",
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
		Ports:    []int{3306, 3307}, // MySQL 可能的端口
		ScanFunc: Plugins.MysqlScan,
	})

	Common.RegisterPlugin("rdp", Common.ScanPlugin{
		Name:     "RDP",
		Ports:    []int{3389},
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
		Ports:    []int{6379, 6380}, // Redis 可能的端口
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

	Common.RegisterPlugin("web", Common.ScanPlugin{
		Name:     "WebTitle",
		ScanFunc: Plugins.WebTitle,
	})

	Common.RegisterPlugin("webpoc", Common.ScanPlugin{
		Name:     "WebPoc",
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
}
