package Core

import (
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Plugins"
)

func init() {
	// 注册标准端口服务扫描
	Common.RegisterPlugin("ftp", Common.ScanPlugin{
		Name:     "FTP",
		ScanFunc: Plugins.FtpScan,
	})

	Common.RegisterPlugin("ssh", Common.ScanPlugin{
		Name:     "SSH",
		ScanFunc: Plugins.SshScan,
	})

	Common.RegisterPlugin("findnet", Common.ScanPlugin{
		Name:     "FindNet",
		ScanFunc: Plugins.Findnet,
	})

	Common.RegisterPlugin("netbios", Common.ScanPlugin{
		Name:     "NetBIOS",
		ScanFunc: Plugins.NetBIOS,
	})

	Common.RegisterPlugin("smb", Common.ScanPlugin{
		Name:     "SMB",
		ScanFunc: Plugins.SmbScan,
	})

	Common.RegisterPlugin("mssql", Common.ScanPlugin{
		Name:     "MSSQL",
		ScanFunc: Plugins.MssqlScan,
	})

	Common.RegisterPlugin("oracle", Common.ScanPlugin{
		Name:     "Oracle",
		ScanFunc: Plugins.OracleScan,
	})

	Common.RegisterPlugin("mysql", Common.ScanPlugin{
		Name:     "MySQL",
		ScanFunc: Plugins.MysqlScan,
	})

	Common.RegisterPlugin("rdp", Common.ScanPlugin{
		Name:     "RDP",
		ScanFunc: Plugins.RdpScan,
	})

	Common.RegisterPlugin("postgres", Common.ScanPlugin{
		Name:     "PostgreSQL",
		ScanFunc: Plugins.PostgresScan,
	})

	Common.RegisterPlugin("vnc", Common.ScanPlugin{
		Name:     "VNC",
		ScanFunc: Plugins.VncScan,
	})

	Common.RegisterPlugin("redis", Common.ScanPlugin{
		Name:     "Redis",
		ScanFunc: Plugins.RedisScan,
	})

	Common.RegisterPlugin("fcgi", Common.ScanPlugin{
		Name:     "FastCGI",
		ScanFunc: Plugins.FcgiScan,
	})

	Common.RegisterPlugin("memcached", Common.ScanPlugin{
		Name:     "Memcached",
		ScanFunc: Plugins.MemcachedScan,
	})

	Common.RegisterPlugin("mongodb", Common.ScanPlugin{
		Name:     "MongoDB",
		ScanFunc: Plugins.MongodbScan,
	})

	// 注册特殊扫描类型
	Common.RegisterPlugin("ms17010", Common.ScanPlugin{
		Name:     "MS17010",
		ScanFunc: Plugins.MS17010,
	})

	Common.RegisterPlugin("smbghost", Common.ScanPlugin{
		Name:     "SMBGhost",
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
		ScanFunc: Plugins.SmbScan2,
	})

	Common.RegisterPlugin("wmiexec", Common.ScanPlugin{
		Name:     "WMIExec",
		ScanFunc: Plugins.WmiExec,
	})

	Common.RegisterPlugin("localinfo", Common.ScanPlugin{
		Name:     "LocalInfo",
		ScanFunc: Plugins.LocalInfoScan,
	})
}
