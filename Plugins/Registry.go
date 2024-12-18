package Plugins

import "github.com/shadow1ng/fscan/Config"

func init() {
	// 注册标准端口服务扫描
	Config.RegisterPlugin("ftp", Config.ScanPlugin{
		Name:     "FTP",
		Port:     21,
		ScanFunc: FtpScan,
	})

	Config.RegisterPlugin("ssh", Config.ScanPlugin{
		Name:     "SSH",
		Port:     22,
		ScanFunc: SshScan,
	})

	Config.RegisterPlugin("findnet", Config.ScanPlugin{
		Name:     "FindNet",
		Port:     135,
		ScanFunc: Findnet,
	})

	Config.RegisterPlugin("netbios", Config.ScanPlugin{
		Name:     "NetBIOS",
		Port:     139,
		ScanFunc: NetBIOS,
	})

	Config.RegisterPlugin("smb", Config.ScanPlugin{
		Name:     "SMB",
		Port:     445,
		ScanFunc: SmbScan,
	})

	Config.RegisterPlugin("mssql", Config.ScanPlugin{
		Name:     "MSSQL",
		Port:     1433,
		ScanFunc: MssqlScan,
	})

	Config.RegisterPlugin("oracle", Config.ScanPlugin{
		Name:     "Oracle",
		Port:     1521,
		ScanFunc: OracleScan,
	})

	Config.RegisterPlugin("mysql", Config.ScanPlugin{
		Name:     "MySQL",
		Port:     3306,
		ScanFunc: MysqlScan,
	})

	Config.RegisterPlugin("rdp", Config.ScanPlugin{
		Name:     "RDP",
		Port:     3389,
		ScanFunc: RdpScan,
	})

	Config.RegisterPlugin("postgres", Config.ScanPlugin{
		Name:     "PostgreSQL",
		Port:     5432,
		ScanFunc: PostgresScan,
	})

	Config.RegisterPlugin("redis", Config.ScanPlugin{
		Name:     "Redis",
		Port:     6379,
		ScanFunc: RedisScan,
	})

	Config.RegisterPlugin("fcgi", Config.ScanPlugin{
		Name:     "FastCGI",
		Port:     9000,
		ScanFunc: FcgiScan,
	})

	Config.RegisterPlugin("memcached", Config.ScanPlugin{
		Name:     "Memcached",
		Port:     11211,
		ScanFunc: MemcachedScan,
	})

	Config.RegisterPlugin("mongodb", Config.ScanPlugin{
		Name:     "MongoDB",
		Port:     27017,
		ScanFunc: MongodbScan,
	})

	// 注册特殊扫描类型
	Config.RegisterPlugin("ms17010", Config.ScanPlugin{
		Name:     "MS17010",
		Port:     445,
		ScanFunc: MS17010,
	})

	Config.RegisterPlugin("smbghost", Config.ScanPlugin{
		Name:     "SMBGhost",
		Port:     445,
		ScanFunc: SmbGhost,
	})

	Config.RegisterPlugin("web", Config.ScanPlugin{
		Name:     "WebTitle",
		Port:     0,
		ScanFunc: WebTitle,
	})

	Config.RegisterPlugin("smb2", Config.ScanPlugin{
		Name:     "SMBScan2",
		Port:     445,
		ScanFunc: SmbScan2,
	})

	Config.RegisterPlugin("wmiexec", Config.ScanPlugin{
		Name:     "WMIExec",
		Port:     135,
		ScanFunc: WmiExec,
	})

	Config.RegisterPlugin("localinfo", Config.ScanPlugin{
		Name:     "LocalInfo",
		Port:     0,
		ScanFunc: LocalInfoScan,
	})
}
