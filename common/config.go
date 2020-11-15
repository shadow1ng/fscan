package common

var Userdict = map[string][]string{
	"ftp":  {"www","admin","root","db","wwwroot","data","web","ftp"},
	"mysql": {"root"},
	"mssql": {"root","sa"},
	"smb": {"administrator","guest"},
	"postgresql": {"postgres","admin"},
	"ssh": {"root","admin"},
	"mongodb": {"root","admin"},
	//"telnet": []string{"administrator","admin","root","cisco","huawei","zte"},
}

var Passwords = []string{"admin123A","admin123","123456","admin","root","password","123123","654321","123","1","admin@123","Admin@123","{user}","{user}123","","P@ssw0rd!","qwa123","12345678","test","123qwe!@#","123456789","123321","666666","fuckyou","000000","1234567890","8888888","qwerty","1qaz2wsx","abc123","abc123456","1qaz@WSX","Aa123456","sysadmin","system","huawei"}

var PORTList = map[string]int{
	"ftp": 21,
	"ssh": 22,
	"mem": 11211,
	"mgo": 27017,
	"mssql": 1433,
	"psql": 5432,
	"redis": 6379,
	"mysql": 3306,
	"smb": 445,
	"ms17010": 1000001,
	"cve20200796":1000002,
	"elastic": 9200,
	"findnet": 135,
	"all":0,
	//"wenscan": 17010,
}

var Outputfile = "result.txt"
var IsSave = true

var DefaultPorts = "21,22,23,80,135,443,445,1433,1521,3306,5432,6379,7001,8080,8089,9000,9200,11211,27017"


type HostInfo struct {
	Host string
	HostFile string
	Ports string
	Url string
	Timeout int64
	Scantype string
	Isping bool
	Threads int
	Command string
	Username string
	Password string
	Userfile string
	Passfile string
	Usernames []string
	Passwords []string
	Outputfile string
	IsSave bool
	RedisFile string
	RedisShell string
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

//var Userdict = map[string][]string{
//	"ftp":  []string{"www","admin","root","db","wwwroot","data","web","ftp"},
//	"mysql": []string{"root"},
//	"mssql": []string{"root","sa"},
//	"smb": []string{"administrator","guest"},
//	"postgresql": []string{"postgres","admin"},
//	"ssh": []string{"root","admin"},
//	"mongodb": []string{"root","admin"},
//	//"telnet": []string{"administrator","admin","root","cisco","huawei","zte"},
//}

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