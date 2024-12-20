package Core

import (
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Plugins"
)

func init() {
	// 注册标准端口服务扫描
	Common.RegisterPlugin("ftp", Common.ScanPlugin{
		Name:     "FTP",
		Port:     21,
		ScanFunc: Plugins.FtpScan,
	})

	Common.RegisterPlugin("ssh", Common.ScanPlugin{
		Name:     "SSH",
		Port:     22,
		ScanFunc: Plugins.SshScan,
	})

	Common.RegisterPlugin("findnet", Common.ScanPlugin{
		Name:     "FindNet",
		Port:     135,
		ScanFunc: Plugins.Findnet,
	})

	Common.RegisterPlugin("netbios", Common.ScanPlugin{
		Name:     "NetBIOS",
		Port:     139,
		ScanFunc: Plugins.NetBIOS,
	})

	Common.RegisterPlugin("smb", Common.ScanPlugin{
		Name:     "SMB",
		Port:     445,
		ScanFunc: Plugins.SmbScan,
	})

	Common.RegisterPlugin("mssql", Common.ScanPlugin{
		Name:     "MSSQL",
		Port:     1433,
		ScanFunc: Plugins.MssqlScan,
	})

	Common.RegisterPlugin("oracle", Common.ScanPlugin{
		Name:     "Oracle",
		Port:     1521,
		ScanFunc: Plugins.OracleScan,
	})

	Common.RegisterPlugin("mysql", Common.ScanPlugin{
		Name:     "MySQL",
		Port:     3306,
		ScanFunc: Plugins.MysqlScan,
	})

	Common.RegisterPlugin("rdp", Common.ScanPlugin{
		Name:     "RDP",
		Port:     3389,
		ScanFunc: Plugins.RdpScan,
	})

	Common.RegisterPlugin("postgres", Common.ScanPlugin{
		Name:     "PostgreSQL",
		Port:     5432,
		ScanFunc: Plugins.PostgresScan,
	})

	Common.RegisterPlugin("vnc", Common.ScanPlugin{
		Name:     "VNC",
		Port:     5900,
		ScanFunc: Plugins.VncScan,
	})

	Common.RegisterPlugin("redis", Common.ScanPlugin{
		Name:     "Redis",
		Port:     6379,
		ScanFunc: Plugins.RedisScan,
	})

	Common.RegisterPlugin("fcgi", Common.ScanPlugin{
		Name:     "FastCGI",
		Port:     9000,
		ScanFunc: Plugins.FcgiScan,
	})

	Common.RegisterPlugin("memcached", Common.ScanPlugin{
		Name:     "Memcached",
		Port:     11211,
		ScanFunc: Plugins.MemcachedScan,
	})

	Common.RegisterPlugin("mongodb", Common.ScanPlugin{
		Name:     "MongoDB",
		Port:     27017,
		ScanFunc: Plugins.MongodbScan,
	})

	// 注册特殊扫描类型
	Common.RegisterPlugin("ms17010", Common.ScanPlugin{
		Name:     "MS17010",
		Port:     445,
		ScanFunc: Plugins.MS17010,
	})

	Common.RegisterPlugin("smbghost", Common.ScanPlugin{
		Name:     "SMBGhost",
		Port:     445,
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
		Port:     445,
		ScanFunc: Plugins.SmbScan2,
	})

	Common.RegisterPlugin("wmiexec", Common.ScanPlugin{
		Name:     "WMIExec",
		Port:     135,
		ScanFunc: Plugins.WmiExec,
	})

	Common.RegisterPlugin("localinfo", Common.ScanPlugin{
		Name:     "LocalInfo",
		ScanFunc: Plugins.LocalInfoScan,
	})
}
