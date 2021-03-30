package common

var Userdict = map[string][]string{
	"ftp":        {"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"},
	"mysql":      {"root", "mysql"},
	"mssql":      {"sa", "root"},
	"smb":        {"administrator", "guest"},
	"postgresql": {"postgres", "admin"},
	"ssh":        {"root", "admin"},
	"mongodb":    {"root", "admin"},
}

var Passwords = []string{"123456", "admin", "admin123", "root", "", "password", "123123", "654321", "123", "1", "admin@123", "Admin@123", "{user}", "{user}123", "P@ssw0rd!", "qwa123", "12345678", "test", "123qwe!@#", "123456789", "123321", "666666", "fuckyou", "000000", "1234567890", "8888888", "qwerty", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "Aa123456", "sysadmin", "system", "huawei"}

var PORTList = map[string]int{
	"ftp":         21,
	"ssh":         22,
	"mem":         11211,
	"mgo":         27017,
	"mssql":       1433,
	"psql":        5432,
	"redis":       6379,
	"mysql":       3306,
	"smb":         445,
	"ms17010":     1000001,
	"cve20200796": 1000002,
	"webtitle":    1000003,
	"elastic":     9200,
	"findnet":     135,
	"all":         0,
	"portscan":    0,
	"icmp":        0,
}

var PortlistBack = map[string]int{
	"ftp":         21,
	"ssh":         22,
	"mem":         11211,
	"mgo":         27017,
	"mssql":       1433,
	"psql":        5432,
	"redis":       6379,
	"mysql":       3306,
	"smb":         445,
	"ms17010":     1000001,
	"cve20200796": 1000002,
	"webtitle":    1000003,
	"elastic":     9200,
	"findnet":     135,
	"all":         0,
	"portscan":    0,
	"icmp":        0,
}

var Outputfile = getpath() + "result.txt"
var IsSave = true
var Webport = "9098,9448,8888,82,8858,1081,8879,21502,9097,8088,8090,8200,91,1080,889,8834,8011,9986,9043,9988,7080,10000,9089,8028,9999,8001,89,8086,8244,9000,2008,8080,7000,8030,8983,8096,8288,18080,8020,8848,808,8099,6868,18088,10004,8443,8042,7008,8161,7001,1082,8095,8087,8880,9096,7074,8044,8048,9087,10008,2020,8003,8069,20000,7688,1010,8092,8484,6648,9100,21501,8009,8360,9060,85,99,8000,9085,9998,8172,8899,9084,9010,9082,10010,7005,12018,87,7004,18004,8098,18098,8002,3505,8018,3000,9094,83,8108,1118,8016,20720,90,8046,9443,8091,7002,8868,8010,18082,8222,7088,8448,18090,3008,12443,9001,9093,7003,8101,14000,7687,8094,9002,8082,9081,8300,9086,8081,8089,8006,443,7007,7777,1888,9090,9095,81,1000,18002,8800,84,9088,7071,7070,8038,9091,8258,9008,9083,16080,88,8085,801,5555,7680,800,8180,9800,10002,18000,18008,98,28018,86,9092,8881,8100,8012,8084,8989,6080,7078,18001,8093,8053,8070,8280,880,92,9099,8181,9981,8060,8004,8083,10001,8097,21000,80,7200,888,7890,3128,8838,8008,8118,9080,2100,7180,9200"
var DefaultPorts = "21,22,80,81,135,443,445,1433,3306,5432,6379,7001,8000,8080,8089,9200,11211,27017"

type HostInfo struct {
	Host      string
	Ports     string
	Domain    string
	Url       string
	Timeout   int64
	Scantype  string
	Command   string
	Username  string
	Password  string
	Usernames []string
	Passwords []string
}

type PocInfo struct {
	Num        int
	Rate       int
	Timeout    int64
	Proxy      string
	PocName    string
	PocDir     string
	Target     string
	TargetFile string
	RawFile    string
	Cookie     string
	ForceSSL   bool
	ApiKey     string
	CeyeDomain string
}

var TmpOutputfile string
var TmpSave bool
var IsPing bool
var Ping bool
var Pocinfo PocInfo
var IsWebCan bool
var RedisFile string
var RedisShell string
var Userfile string
var Passfile string
var HostFile string
var Threads int
var URL string
var UrlFile string
var Urls []string
