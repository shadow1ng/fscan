package Plugins

var PluginList = map[string]interface{}{
	"21":       FtpScan,
	"22":       SshScan,
	"135":      Findnet,
	"139":      NetBIOS,
	"445":      SmbScan,
	"1433":     MssqlScan,
	"1521":     OracleScan,
	"3306":     MysqlScan,
	"3389":     RdpScan,
	"5432":     PostgresScan,
	"6379":     RedisScan,
	"9000":     FcgiScan,
	"11211":    MemcachedScan,
	"27017":    MongodbScan,
	"1000001":  MS17010,
	"1000002":  SmbGhost,
	"1000003":  WebTitle,
	"10000031": WebTitle,
}
