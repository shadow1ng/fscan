package config

// PocInfo POC详细信息结构 - 保留给webscan使用
type PocInfo struct {
	Target  string `json:"target"`
	PocName string `json:"poc_name"`
}

// CredentialPair 精确的用户名密码对
type CredentialPair struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// =============================================================================
// 端口组常量 - 从common/constants.go迁移
// =============================================================================

// 预定义端口组 - 字符串格式，用于命令行参数默认值
var (
	// 注意：9100 已移除，该端口为打印机 RAW 端口，发送数据会触发打印 (Issue #517)
	WebPorts = "80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8005,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10051,10250,12018,12443,14000,15672,15671,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,20880,21000,21501,21502,28018"

	// MainPorts 主要扫描端口 (约150个)
	// 包含: 基础服务、远程管理、数据库、消息队列、Web中间件、容器云、监控、安全设备等
	MainPorts = "" +
		// 基础服务 (21-995)
		"21,22,23,25,53,80,81,88,110,111,135,139,143,161,389,443,445,465,502,512,513,514,515,548,554,587,623,636,873,902,993,995," +
		// 代理/隧道 (1080-1883)
		"1080,1099,1194,1433,1434,1521,1522,1525,1723,1883," +
		// 远程/数据库 (2049-3690)
		"2049,2121,2181,2200,2222,2375,2376,2379,2380,3000,3128,3268,3269,3306,3389,3690," +
		// Java/中间件 (4369-5986)
		"4369,4444,4848,5000,5005,5044,5060,5432,5601,5631,5632,5671,5672,5900,5984,5985,5986," +
		// 缓存/数据库 (6000-6667)
		"6000,6379,6380,6443,6666,6667," +
		// Web/中间件 (7001-9999)
		// 注意：9100 已移除，该端口为打印机 RAW 端口，发送数据会触发打印
		"7001,7002,7474,7687,8000,8005,8008,8009,8080,8081,8086,8088,8089,8090,8161,8180,8443,8500,8834,8848,8880,8883,8888,9000,9001,9042,9080,9090,9092,9093,9160,9200,9300,9418,9443,9999," +
		// 管理/监控 (10000-11211)
		"10000,10051,10250,10255,11211," +
		// 消息队列/集群 (15672-27018)
		"15672,22222,26379,27017,27018," +
		// Hadoop/大数据 (50000-61616)
		"50000,50070,50075,61613,61614,61616"

	// DbPorts 数据库端口
	DbPorts = "1433,1521,3306,5432,5672,5984,6379,7687,8086,9042,9093,9160,9200,11211,26379,27017,27018,61616"

	// ServicePorts 服务端口
	ServicePorts = "21,22,23,25,53,110,111,135,139,143,161,389,445,465,502,512,513,514,587,623,636,873,993,995,1433,1521,1883,2049,2181,2222,3306,3389,5432,5672,5671,5900,5985,5986,6379,8161,8443,8883,9000,9092,9093,9200,10051,11211,15672,15671,27017,61616,61613"

	// CommonPorts 常用端口
	CommonPorts = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3389,5060,5985,5986"

	// AllPorts 全端口
	AllPorts = "1-65535"
)

// GetPortGroups 获取端口组映射 - 用于解析器
func GetPortGroups() map[string]string {
	return map[string]string{
		"web":     WebPorts,
		"main":    MainPorts,
		"db":      DbPorts,
		"service": ServicePorts,
		"common":  CommonPorts,
		"all":     AllPorts,
	}
}

// =============================================================================
// 服务探测配置
// =============================================================================

// DefaultProbeMap 默认探测器列表
var DefaultProbeMap = []string{
	"GenericLines",
	"GetRequest",
	"TLSSessionReq",
	"SSLSessionReq",
	"ms-sql-s",
	"JavaRMI",
	"LDAPSearchReq",
	"LDAPBindReq",
	"oracle-tns",
	"Socks5",
}

// DefaultPortMap 默认端口映射关系
var DefaultPortMap = map[int][]string{
	1:     {"GetRequest", "Help"},
	7:     {"Help"},
	21:    {"GenericLines", "Help"},
	23:    {"GenericLines", "tn3270"},
	25:    {"Hello", "Help"},
	35:    {"GenericLines"},
	42:    {"SMBProgNeg"},
	43:    {"GenericLines"},
	53:    {"DNSVersionBindReqTCP", "DNSStatusRequestTCP"},
	70:    {"GetRequest"},
	79:    {"GenericLines", "GetRequest", "Help"},
	80:    {"GetRequest", "HTTPOptions", "RTSPRequest", "X11Probe", "FourOhFourRequest"},
	81:    {"GetRequest", "HTTPOptions", "RPCCheck", "FourOhFourRequest"},
	82:    {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	83:    {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	84:    {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	85:    {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	88:    {"GetRequest", "Kerberos", "SMBProgNeg", "FourOhFourRequest"},
	98:    {"GenericLines"},
	110:   {"GenericLines"},
	111:   {"RPCCheck"},
	113:   {"GenericLines", "GetRequest", "Help"},
	119:   {"GenericLines", "Help"},
	130:   {"NotesRPC"},
	135:   {"DNSVersionBindReqTCP", "SMBProgNeg"},
	139:   {"GetRequest", "SMBProgNeg"},
	143:   {"GetRequest"},
	175:   {"NJE"},
	199:   {"GenericLines", "RPCCheck", "Socks5", "Socks4"},
	214:   {"GenericLines"},
	264:   {"GenericLines"},
	311:   {"LDAPSearchReq"},
	340:   {"GenericLines"},
	389:   {"LDAPSearchReq", "LDAPBindReq"},
	443:   {"TLSSessionReq", "SSLSessionReq", "GetRequest", "HTTPOptions", "TerminalServerCookie"},
	444:   {"TLSSessionReq", "SSLSessionReq", "GetRequest", "HTTPOptions", "TerminalServerCookie"},
	445:   {"SMBProgNeg"},
	465:   {"SSLSessionReq", "TLSSessionReq", "Hello", "Help", "GetRequest", "HTTPOptions", "TerminalServerCookie"},
	502:   {"GenericLines"},
	503:   {"GenericLines"},
	513:   {"GenericLines"},
	514:   {"GenericLines"},
	515:   {"LPDString"},
	544:   {"GenericLines"},
	548:   {"afp"},
	554:   {"GetRequest"},
	563:   {"GenericLines"},
	587:   {"Hello", "Help"},
	631:   {"GetRequest", "HTTPOptions"},
	636:   {"LDAPSearchReq", "LDAPBindReq", "SSLSessionReq"},
	646:   {"LDAPSearchReq", "RPCCheck"},
	691:   {"GenericLines"},
	873:   {"GenericLines"},
	898:   {"GetRequest"},
	993:   {"GenericLines", "SSLSessionReq", "TerminalServerCookie", "TLSSessionReq"},
	995:   {"GenericLines", "SSLSessionReq", "TerminalServerCookie", "TLSSessionReq"},
	1080:  {"GenericLines", "Socks5", "Socks4"},
	1099:  {"JavaRMI"},
	1234:  {"SqueezeCenter_CLI"},
	1311:  {"GenericLines"},
	1352:  {"oracle-tns"},
	1414:  {"ibm-mqseries"},
	1433:  {"ms-sql-s"},
	1521:  {"oracle-tns"},
	1723:  {"GenericLines"},
	1883:  {"mqtt"},
	1911:  {"oracle-tns"},
	2000:  {"GenericLines", "oracle-tns"},
	2049:  {"RPCCheck"},
	2121:  {"GenericLines", "Help"},
	2181:  {"GenericLines"},
	2222:  {"GetRequest", "GenericLines", "HTTPOptions", "Help", "SSH", "TerminalServerCookie"},
	2375:  {"docker", "GetRequest", "HTTPOptions"},
	2376:  {"TLSSessionReq", "SSLSessionReq", "docker", "GetRequest", "HTTPOptions"},
	2484:  {"oracle-tns"},
	2628:  {"dominoconsole"},
	3000:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	3268:  {"LDAPSearchReq", "LDAPBindReq"},
	3269:  {"LDAPSearchReq", "LDAPBindReq", "SSLSessionReq"},
	3306:  {"GenericLines", "GetRequest", "HTTPOptions"},
	3389:  {"TerminalServerCookie", "TerminalServer"},
	3690:  {"GenericLines"},
	4000:  {"GenericLines"},
	4369:  {"epmd"},
	4444:  {"GenericLines"},
	4840:  {"GenericLines"},
	5000:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	5050:  {"GenericLines"},
	5060:  {"SIPOptions"},
	5222:  {"GenericLines"},
	5432:  {"GenericLines"},
	5555:  {"GenericLines"},
	5560:  {"GenericLines", "oracle-tns"},
	5631:  {"GenericLines", "PCWorkstation"},
	5672:  {"GenericLines"},
	5984:  {"GetRequest", "HTTPOptions"},
	6000:  {"X11Probe"},
	6379:  {"redis-server"},
	6432:  {"GenericLines"},
	6667:  {"GenericLines"},
	7000:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "JavaRMI"},
	7001:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "JavaRMI"},
	7002:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "JavaRMI"},
	7070:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	7443:  {"TLSSessionReq", "SSLSessionReq", "GetRequest", "HTTPOptions"},
	7777:  {"GenericLines", "oracle-tns"},
	8000:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "iperf3"},
	8005:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	8008:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	8009:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "ajp"},
	8080:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	8081:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	8089:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	8090:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	8443:  {"TLSSessionReq", "SSLSessionReq", "GetRequest", "HTTPOptions"},
	8888:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	9000:  {"GetRequest", "HTTPOptions", "FourOhFourRequest"},
	9042:  {"GenericLines"},
	9092:  {"GenericLines", "kafka"},
	9200:  {"GetRequest", "HTTPOptions", "elasticsearch"},
	9300:  {"GenericLines"},
	9999:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "adbConnect"},
	10000: {"GetRequest", "HTTPOptions", "FourOhFourRequest", "JavaRMI"},
	10051: {"GenericLines"},
	11211: {"Memcache"},
	15672: {"GetRequest", "HTTPOptions"},
	27017: {"mongodb"},
	27018: {"mongodb"},
	50070: {"GetRequest", "HTTPOptions"},
	61616: {"GenericLines"},
}

// DefaultUserDict 默认服务用户字典
var DefaultUserDict = map[string][]string{
	"ftp":        {"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"},
	"mysql":      {"root", "mysql"},
	"mssql":      {"sa", "sql"},
	"smb":        {"administrator", "admin", "guest"},
	"rdp":        {"administrator", "admin", "guest"},
	"postgresql": {"postgres", "admin"},
	"ssh":        {"root", "admin"},
	"mongodb":    {"root", "admin"},
	"redis":      {""},
	"oracle":     {"sys", "system", "admin", "test", "web", "orcl"},
	"telnet":     {"root", "admin", "test"},
	"elastic":    {"elastic", "admin", "kibana"},
	"rabbitmq":   {"guest", "admin", "administrator", "rabbit", "rabbitmq", "root"},
	"kafka":      {"admin", "kafka", "root", "test"},
	"activemq":   {"admin", "root", "activemq", "system", "user"},
	"ldap":       {"admin", "administrator", "root", "cn=admin", "cn=administrator", "cn=manager"},
	"smtp":       {"admin", "root", "postmaster", "mail", "smtp", "administrator"},
	"imap":       {"admin", "mail", "postmaster", "root", "user", "test"},
	"pop3":       {"admin", "root", "mail", "user", "test", "postmaster"},
	"zabbix":     {"Admin", "admin", "guest", "user"},
	"rsync":      {"root", "admin", "backup"},
	"cassandra":  {"cassandra", "admin", "root", "system"},
	"neo4j":      {"neo4j", "admin", "root", "test"},
}

// DefaultPasswords 默认密码字典
var DefaultPasswords = []string{
	"123456", "admin", "admin123", "root", "", "pass123", "pass@123",
	"password", "Password", "P@ssword123", "123123", "654321", "111111",
	"123", "1", "admin@123", "Admin@123", "admin123!@#", "{user}",
	"{user}1", "{user}111", "{user}123", "{user}@123", "{user}_123",
	"{user}#123", "{user}@111", "{user}@2019", "{user}@123#4",
	"P@ssw0rd!", "P@ssw0rd", "Passw0rd", "qwe123", "12345678", "test",
	"test123", "123qwe", "123qwe!@#", "123456789", "123321", "666666",
	"a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888",
	"!QAZ2wsx", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "a11111",
	"a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123",
	"Aa123123", "Aa123456", "Aa12345.", "sysadmin", "system", "1qaz!QAZ",
	"2wsx@WSX", "qwe123!@#", "Aa123456!", "A123456s!", "sa123456",
	"1q2w3e", "Charge123", "Aa123456789", "redis", "elastic123",
}
