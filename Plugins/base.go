package Plugins

var PluginList = map[string]interface{}{
	"21": FtpScan,
	"22": SshScan,
	"135": Findnet,
	"445": SmbScan,
	"1433":MssqlScan,
	"3306": MysqlScan,
	"5432": PostgresScan,
	"6379": RedisScan,
	"9200":elasticsearchScan,
	"11211":MemcachedScan,
	"27017":MongodbScan,
	"1000001": MS17010,
	"1000002": SmbGhost,
	//"WebTitle":WebTitle,
}

//var Passwords = []string{"admin123A","123456","admin","root","password","123123","123","1","{user}","{user}{user}","{user}1","{user}123","{user}2016","{user}2015","{user}!","","P@ssw0rd!!","qwa123","12345678","test","123qwe!@#","123456789","123321","1314520","666666","woaini","fuckyou","000000","1234567890","8888888","qwerty","1qaz2wsx","abc123","abc123456","1q2w3e4r","123qwe","p@ssw0rd","p@55w0rd","password!","p@ssw0rd!","password1","r00t","tomcat","apache","system","huawei","admin123","zte"}
//const Username = "admin"
//const Password = "123456"
//const Timeout = 3 * time.Second
//const FTPPORT = 21
//const SSHPORT = 22
//const MEMCACHEDPORT = 11211
//const MONGODBPORT  = 27017
//const MSSQLPORT = 1433
//const OraclePORT = 1433
//const PSQLPORT = 5432
//const REDISPORT = 6379
//const MYSQLPORT  = 3306
//const SMBPORT = 445
//const POSTGRESPORT = 5432


//var PluginList = map[string]interface{}{
//	"ftp": FtpScan,
//	"mysql": MysqlScan,
//	//"mongodb":MgoConn,
//	"mssql":MssqlScan,
//	"redis": RedisScan,
//	//"smb": SmbScan,
//	"ssh": SshScan,
//	//"portscan": PortConn,
//	//"icmp": IcmpConn,
//	"postgresql": PostgresScan,
//	//"urlscan":UrlConn,
//	//"auth":ApacheConn,
//	//"subdomain":SDConn,
//	//"memcached":MemConn,
//}