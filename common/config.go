package common

//fscan version 1.3
var Userdict = map[string][]string{
	"ftp":        {"www", "admin", "root", "db", "wwwroot", "data", "web", "ftp"},
	"mysql":      {"root"},
	"mssql":      {"root", "sa"},
	"smb":        {"administrator", "guest"},
	"postgresql": {"postgres", "admin"},
	"ssh":        {"root", "admin"},
	"mongodb":    {"root", "admin"},
	//"telnet": []string{"administrator","admin","root","cisco","huawei","zte"},
}

var Passwords = []string{"admin123A", "admin123", "123456", "admin", "root", "password", "123123", "654321", "123", "1", "admin@123", "Admin@123", "{user}", "{user}123", "", "P@ssw0rd!", "qwa123", "12345678", "test", "123qwe!@#", "123456789", "123321", "666666", "fuckyou", "000000", "1234567890", "8888888", "qwerty", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "Aa123456", "sysadmin", "system", "huawei"}

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
}

var PORTList_bak = map[string]int{
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
}

var Outputfile = "result.txt"
var IsSave = true

var DefaultPorts = "21,22,23,80,135,443,445,1433,1521,3306,5432,6379,7001,8080,8089,9000,9200,11211,27017"

type HostInfo struct {
	Host        string
	HostFile    string
	Ports       string
	Url         string
	Timeout     int64
	WebTimeout  int64
	Scantype    string
	Ping        bool
	Isping      bool
	Threads     int
	IcmpThreads int
	Command     string
	Username    string
	Password    string
	Userfile    string
	Passfile    string
	Usernames   []string
	Passwords   []string
	Outputfile  string
	IsSave      bool
	RedisFile   string
	RedisShell  string
}
