package Common

var version = "2.0.0"
var Userdict = map[string][]string{
	"ftp":        {"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"},
	"mysql":      {"root", "mysql"},
	"mssql":      {"sa", "sql"},
	"smb":        {"administrator", "admin", "guest"},
	"rdp":        {"administrator", "admin", "guest"},
	"postgresql": {"postgres", "admin"},
	"ssh":        {"root", "admin"},
	"mongodb":    {"root", "admin"},
	"oracle":     {"sys", "system", "admin", "test", "web", "orcl"},
	"telnet":     {"root", "admin", "test"},
	"elastic":    {"elastic", "admin", "kibana"},
	"rabbitmq":   {"guest", "admin", "administrator", "rabbit", "rabbitmq", "root"},
}

var Passwords = []string{"123456", "admin", "admin123", "root", "", "pass123", "pass@123", "password", "P@ssword123", "123123", "654321", "111111", "123", "1", "admin@123", "Admin@123", "admin123!@#", "{user}", "{user}1", "{user}111", "{user}123", "{user}@123", "{user}_123", "{user}#123", "{user}@111", "{user}@2019", "{user}@123#4", "P@ssw0rd!", "P@ssw0rd", "Passw0rd", "qwe123", "12345678", "test", "test123", "123qwe", "123qwe!@#", "123456789", "123321", "666666", "a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888", "!QAZ2wsx", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "a11111", "a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123", "Aa123123", "Aa123456", "Aa12345.", "sysadmin", "system", "1qaz!QAZ", "2wsx@WSX", "qwe123!@#", "Aa123456!", "A123456s!", "sa123456", "1q2w3e", "Charge123", "Aa123456789", "elastic123"}

var Outputfile = "result.txt"
var IsSave = true

type PocInfo struct {
	Target  string
	PocName string
}

var (
	// 目标配置
	Ports        string
	ExcludePorts string // 原NoPorts
	ExcludeHosts string
	AddPorts     string // 原PortAdd

	// 认证配置
	Username     string
	Password     string
	Domain       string
	SshKeyPath   string // 原SshKey
	AddUsers     string // 原UserAdd
	AddPasswords string // 原PassAdd

	// 扫描配置
	ScanMode    string // 原Scantype
	ThreadNum   int    // 原Threads
	Timeout     int64  = 3
	LiveTop     int
	DisablePing bool // 原NoPing
	UsePing     bool // 原Ping
	Command     string

	// 本地扫描配置
	LocalScan bool

	// 文件配置
	HostsFile     string // 原HostFile
	UsersFile     string // 原Userfile
	PasswordsFile string // 原Passfile
	HashFile      string // 原Hashfile
	PortsFile     string // 原PortFile

	// Web配置
	TargetURL   string   // 原URL
	URLsFile    string   // 原UrlFile
	URLs        []string // 原Urls
	WebTimeout  int64    = 5
	HttpProxy   string   // 原Proxy
	Socks5Proxy string

	// POC配置
	PocPath    string
	Pocinfo    PocInfo
	DisablePoc bool // 原NoPoc

	// Redis配置
	RedisFile    string
	RedisShell   string
	DisableRedis bool // 原Noredistest

	// 爆破配置
	DisableBrute bool // 原IsBrute
	BruteThreads int  // 原BruteThread

	// 其他配置
	RemotePath string   // 原Path
	HashValue  string   // 原Hash
	HashValues []string // 原Hashs
	HashBytes  [][]byte
	HostPort   []string
	Shellcode  string // 原SC
	EnableWmi  bool   // 原IsWmi

	// 输出配置
	DisableSave bool // 原TmpSave
)

var (
	UserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
	Accept     = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
	DnsLog     bool
	PocNum     int
	PocFull    bool
	CeyeDomain string
	ApiKey     string
	Cookie     string
)
