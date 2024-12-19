package Core

import (
	"github.com/shadow1ng/fscan/Config"
	"github.com/shadow1ng/fscan/Plugins"
)

func init() {
	// 注册标准端口服务扫描
	Config.RegisterPlugin("ftp", Config.ScanPlugin{
		Name:     "FTP",
		Port:     21,
		ScanFunc: Plugins.FtpScan,
	})

	Config.RegisterPlugin("ssh", Config.ScanPlugin{
		Name:     "SSH",
		Port:     22,
		ScanFunc: Plugins.SshScan,
	})

	Config.RegisterPlugin("findnet", Config.ScanPlugin{
		Name:     "FindNet",
		Port:     135,
		ScanFunc: Plugins.Findnet,
	})

	Config.RegisterPlugin("netbios", Config.ScanPlugin{
		Name:     "NetBIOS",
		Port:     139,
		ScanFunc: Plugins.NetBIOS,
	})

	Config.RegisterPlugin("smb", Config.ScanPlugin{
		Name:     "SMB",
		Port:     445,
		ScanFunc: Plugins.SmbScan,
	})

	Config.RegisterPlugin("mssql", Config.ScanPlugin{
		Name:     "MSSQL",
		Port:     1433,
		ScanFunc: Plugins.MssqlScan,
	})

	Config.RegisterPlugin("oracle", Config.ScanPlugin{
		Name:     "Oracle",
		Port:     1521,
		ScanFunc: Plugins.OracleScan,
	})

	Config.RegisterPlugin("mysql", Config.ScanPlugin{
		Name:     "MySQL",
		Port:     3306,
		ScanFunc: Plugins.MysqlScan,
	})

	Config.RegisterPlugin("rdp", Config.ScanPlugin{
		Name:     "RDP",
		Port:     3389,
		ScanFunc: Plugins.RdpScan,
	})

	Config.RegisterPlugin("postgres", Config.ScanPlugin{
		Name:     "PostgreSQL",
		Port:     5432,
		ScanFunc: Plugins.PostgresScan,
	})

	Config.RegisterPlugin("redis", Config.ScanPlugin{
		Name:     "Redis",
		Port:     6379,
		ScanFunc: Plugins.RedisScan,
	})

	Config.RegisterPlugin("fcgi", Config.ScanPlugin{
		Name:     "FastCGI",
		Port:     9000,
		ScanFunc: Plugins.FcgiScan,
	})

	Config.RegisterPlugin("memcached", Config.ScanPlugin{
		Name:     "Memcached",
		Port:     11211,
		ScanFunc: Plugins.MemcachedScan,
	})

	Config.RegisterPlugin("mongodb", Config.ScanPlugin{
		Name:     "MongoDB",
		Port:     27017,
		ScanFunc: Plugins.MongodbScan,
	})

	// 注册特殊扫描类型
	Config.RegisterPlugin("ms17010", Config.ScanPlugin{
		Name:     "MS17010",
		Port:     445,
		ScanFunc: Plugins.MS17010,
	})

	Config.RegisterPlugin("smbghost", Config.ScanPlugin{
		Name:     "SMBGhost",
		Port:     445,
		ScanFunc: Plugins.SmbGhost,
	})

	Config.RegisterPlugin("web", Config.ScanPlugin{
		Name:     "WebTitle",
		Port:     0,
		ScanFunc: Plugins.WebTitle,
	})

	Config.RegisterPlugin("smb2", Config.ScanPlugin{
		Name:     "SMBScan2",
		Port:     445,
		ScanFunc: Plugins.SmbScan2,
	})

	Config.RegisterPlugin("wmiexec", Config.ScanPlugin{
		Name:     "WMIExec",
		Port:     135,
		ScanFunc: Plugins.WmiExec,
	})

	Config.RegisterPlugin("localinfo", Config.ScanPlugin{
		Name:     "LocalInfo",
		Port:     0,
		ScanFunc: Plugins.LocalInfoScan,
	})
}
