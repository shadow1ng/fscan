package Common

import (
	"github.com/schollz/progressbar/v3"
	"sync"
)

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
	"kafka":      {"admin", "kafka", "root", "test"},
	"activemq":   {"admin", "root", "activemq", "system", "user"},
	"ldap":       {"admin", "administrator", "root", "cn=admin", "cn=administrator", "cn=manager"},
	"smtp":       {"admin", "root", "postmaster", "mail", "smtp", "administrator"},
	"imap":       {"admin", "mail", "postmaster", "root", "user", "test"},
	"pop3":       {"admin", "root", "mail", "user", "test", "postmaster"},
	"zabbix":     {"Admin", "admin", "guest", "user"},
	"rsync":      {"rsync", "root", "admin", "backup"},
	"cassandra":  {"cassandra", "admin", "root", "system"},
	"neo4j":      {"neo4j", "admin", "root", "test"},
}

var DefaultMap = []string{
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

var PortMap = map[int][]string{
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
	256:   {"LDAPSearchReq", "LDAPBindReq"},
	257:   {"LDAPSearchReq", "LDAPBindReq"},
	261:   {"SSLSessionReq"},
	264:   {"GenericLines"},
	271:   {"SSLSessionReq"},
	280:   {"GetRequest"},
	322:   {"RTSPRequest", "SSLSessionReq"},
	324:   {"SSLSessionReq"},
	389:   {"LDAPSearchReq", "LDAPBindReq"},
	390:   {"LDAPSearchReq", "LDAPBindReq"},
	406:   {"SIPOptions"},
	427:   {"NotesRPC"},
	443:   {"TLSSessionReq", "GetRequest", "HTTPOptions", "SSLSessionReq", "SSLv23SessionReq", "X11Probe", "FourOhFourRequest", "tor-versions", "OpenVPN"},
	444:   {"TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	445:   {"SMBProgNeg"},
	448:   {"SSLSessionReq"},
	449:   {"GenericLines"},
	465:   {"Hello", "Help", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	497:   {"GetRequest", "X11Probe"},
	500:   {"OpenVPN"},
	505:   {"GenericLines", "GetRequest"},
	510:   {"GenericLines"},
	512:   {"DNSVersionBindReqTCP"},
	513:   {"DNSVersionBindReqTCP", "DNSStatusRequestTCP"},
	514:   {"GetRequest", "RPCCheck", "DNSVersionBindReqTCP", "DNSStatusRequestTCP"},
	515:   {"GetRequest", "Help", "LPDString", "TerminalServer"},
	523:   {"ibm-db2-das", "ibm-db2"},
	524:   {"NCP"},
	540:   {"GenericLines", "GetRequest"},
	543:   {"DNSVersionBindReqTCP"},
	544:   {"RPCCheck", "DNSVersionBindReqTCP"},
	548:   {"SSLSessionReq", "SSLv23SessionReq", "afp"},
	554:   {"GetRequest", "RTSPRequest"},
	563:   {"SSLSessionReq"},
	585:   {"SSLSessionReq"},
	587:   {"GenericLines", "Hello", "Help"},
	591:   {"GetRequest"},
	616:   {"GenericLines"},
	620:   {"GetRequest"},
	623:   {"tn3270"},
	628:   {"GenericLines", "DNSVersionBindReqTCP"},
	631:   {"GetRequest", "HTTPOptions"},
	636:   {"TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq", "LDAPSearchReq", "LDAPBindReq"},
	637:   {"LDAPSearchReq", "LDAPBindReq"},
	641:   {"HTTPOptions"},
	660:   {"SMBProgNeg"},
	666:   {"GenericLines", "beast2"},
	684:   {"SSLSessionReq"},
	706:   {"JavaRMI", "mydoom", "WWWOFFLEctrlstat"},
	710:   {"RPCCheck"},
	711:   {"RPCCheck"},
	731:   {"GenericLines"},
	771:   {"GenericLines"},
	782:   {"GenericLines"},
	783:   {"GetRequest"},
	853:   {"DNSVersionBindReqTCP", "DNSStatusRequestTCP", "SSLSessionReq"},
	888:   {"GetRequest"},
	898:   {"GetRequest"},
	900:   {"GetRequest"},
	901:   {"GetRequest"},
	989:   {"GenericLines", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	990:   {"GenericLines", "Help", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	992:   {"GenericLines", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq", "tn3270"},
	993:   {"GetRequest", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	994:   {"TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	995:   {"GenericLines", "GetRequest", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	999:   {"JavaRMI"},
	1000:  {"GenericLines"},
	1010:  {"GenericLines"},
	1025:  {"SMBProgNeg"},
	1026:  {"GetRequest"},
	1027:  {"SMBProgNeg"},
	1028:  {"TerminalServer"},
	1029:  {"DNSVersionBindReqTCP"},
	1030:  {"JavaRMI"},
	1031:  {"SMBProgNeg"},
	1035:  {"JavaRMI", "oracle-tns"},
	1040:  {"GenericLines"},
	1041:  {"GenericLines"},
	1042:  {"GenericLines", "GetRequest"},
	1043:  {"GenericLines"},
	1068:  {"TerminalServer"},
	1080:  {"GenericLines", "GetRequest", "Socks5", "Socks4"},
	1090:  {"JavaRMI", "Socks5", "Socks4"},
	1095:  {"Socks5", "Socks4"},
	1098:  {"JavaRMI"},
	1099:  {"JavaRMI"},
	1100:  {"JavaRMI", "Socks5", "Socks4"},
	1101:  {"JavaRMI"},
	1102:  {"JavaRMI"},
	1103:  {"JavaRMI"},
	1105:  {"Socks5", "Socks4"},
	1109:  {"Socks5", "Socks4"},
	1111:  {"Help"},
	1112:  {"SMBProgNeg"},
	1129:  {"JavaRMI"},
	1194:  {"OpenVPN"},
	1199:  {"JavaRMI"},
	1200:  {"NCP"},
	1212:  {"GenericLines"},
	1214:  {"GetRequest"},
	1217:  {"NCP"},
	1220:  {"GenericLines", "GetRequest"},
	1234:  {"GetRequest", "JavaRMI"},
	1241:  {"TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq", "NessusTPv12", "NessusTPv12", "NessusTPv11", "NessusTPv11", "NessusTPv10", "NessusTPv10"},
	1248:  {"GenericLines"},
	1302:  {"GenericLines"},
	1311:  {"GetRequest", "Help", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	1314:  {"GetRequest"},
	1344:  {"GetRequest"},
	1352:  {"NotesRPC"},
	1400:  {"GenericLines"},
	1414:  {"ibm-mqseries"},
	1415:  {"ibm-mqseries"},
	1416:  {"ibm-mqseries"},
	1417:  {"ibm-mqseries"},
	1418:  {"ibm-mqseries"},
	1419:  {"ibm-mqseries"},
	1420:  {"ibm-mqseries"},
	1432:  {"GenericLines"},
	1433:  {"ms-sql-s", "RPCCheck"},
	1440:  {"JavaRMI"},
	1443:  {"GetRequest", "SSLSessionReq"},
	1467:  {"GenericLines"},
	1500:  {"Verifier"},
	1501:  {"GenericLines", "VerifierAdvanced"},
	1503:  {"GetRequest", "TerminalServer"},
	1505:  {"GenericLines"},
	1521:  {"oracle-tns"},
	1522:  {"oracle-tns"},
	1525:  {"oracle-tns"},
	1526:  {"oracle-tns", "informix", "drda"},
	1527:  {"drda"},
	1549:  {"WMSRequest"},
	1550:  {"X11Probe"},
	1574:  {"oracle-tns"},
	1583:  {"pervasive-relational", "pervasive-btrieve"},
	1599:  {"LibreOfficeImpressSCPair"},
	1610:  {"GetRequest"},
	1611:  {"GetRequest"},
	1666:  {"GenericLines"},
	1687:  {"GenericLines"},
	1688:  {"GenericLines"},
	1702:  {"LDAPSearchReq", "LDAPBindReq"},
	1720:  {"TerminalServer"},
	1748:  {"oracle-tns"},
	1754:  {"oracle-tns"},
	1755:  {"WMSRequest"},
	1761:  {"LANDesk-RC"},
	1762:  {"LANDesk-RC"},
	1763:  {"LANDesk-RC"},
	1830:  {"GetRequest"},
	1883:  {"mqtt"},
	1900:  {"GetRequest"},
	1911:  {"niagara-fox"},
	1935:  {"TerminalServer"},
	1962:  {"pcworx"},
	1972:  {"NotesRPC"},
	1981:  {"JavaRMI"},
	2000:  {"SSLSessionReq", "SSLv23SessionReq", "NCP"},
	2001:  {"GetRequest"},
	2002:  {"GetRequest", "X11Probe"},
	2010:  {"GenericLines"},
	2023:  {"tn3270"},
	2024:  {"GenericLines"},
	2030:  {"GetRequest"},
	2040:  {"TerminalServer"},
	2049:  {"RPCCheck"},
	2050:  {"dominoconsole"},
	2064:  {"GetRequest"},
	2068:  {"DNSVersionBindReqTCP"},
	2100:  {"FourOhFourRequest"},
	2105:  {"DNSVersionBindReqTCP"},
	2160:  {"GetRequest"},
	2181:  {"Memcache"},
	2199:  {"JavaRMI"},
	2221:  {"SSLSessionReq"},
	2252:  {"TLSSessionReq", "SSLSessionReq", "NJE"},
	2301:  {"HTTPOptions"},
	2306:  {"GetRequest"},
	2323:  {"tn3270"},
	2375:  {"docker"},
	2376:  {"SSLSessionReq", "docker"},
	2379:  {"docker"},
	2380:  {"docker"},
	2396:  {"GetRequest"},
	2401:  {"Help"},
	2443:  {"SSLSessionReq"},
	2481:  {"giop"},
	2482:  {"giop"},
	2525:  {"GetRequest"},
	2600:  {"GenericLines"},
	2627:  {"Help"},
	2701:  {"LANDesk-RC"},
	2715:  {"GetRequest"},
	2809:  {"JavaRMI"},
	2869:  {"GetRequest"},
	2947:  {"LPDString"},
	2967:  {"DNSVersionBindReqTCP"},
	3000:  {"GenericLines", "GetRequest", "Help", "NCP"},
	3001:  {"NCP"},
	3002:  {"GetRequest", "NCP"},
	3003:  {"NCP"},
	3004:  {"NCP"},
	3005:  {"GenericLines", "NCP"},
	3006:  {"SMBProgNeg", "NCP"},
	3025:  {"Hello"},
	3031:  {"NCP"},
	3050:  {"firebird"},
	3052:  {"GetRequest", "RTSPRequest"},
	3127:  {"mydoom"},
	3128:  {"GenericLines", "GetRequest", "HTTPOptions", "mydoom", "Socks5", "Socks4"},
	3129:  {"mydoom"},
	3130:  {"mydoom"},
	3131:  {"mydoom"},
	3132:  {"mydoom"},
	3133:  {"mydoom"},
	3134:  {"mydoom"},
	3135:  {"mydoom"},
	3136:  {"mydoom"},
	3137:  {"mydoom"},
	3138:  {"mydoom"},
	3139:  {"mydoom"},
	3140:  {"mydoom"},
	3141:  {"mydoom"},
	3142:  {"mydoom"},
	3143:  {"mydoom"},
	3144:  {"mydoom"},
	3145:  {"mydoom"},
	3146:  {"mydoom"},
	3147:  {"mydoom"},
	3148:  {"mydoom"},
	3149:  {"mydoom"},
	3150:  {"mydoom"},
	3151:  {"mydoom"},
	3152:  {"mydoom"},
	3153:  {"mydoom"},
	3154:  {"mydoom"},
	3155:  {"mydoom"},
	3156:  {"mydoom"},
	3157:  {"mydoom"},
	3158:  {"mydoom"},
	3159:  {"mydoom"},
	3160:  {"mydoom"},
	3161:  {"mydoom"},
	3162:  {"mydoom"},
	3163:  {"mydoom"},
	3164:  {"mydoom"},
	3165:  {"mydoom"},
	3166:  {"mydoom"},
	3167:  {"mydoom"},
	3168:  {"mydoom"},
	3169:  {"mydoom"},
	3170:  {"mydoom"},
	3171:  {"mydoom"},
	3172:  {"mydoom"},
	3173:  {"mydoom"},
	3174:  {"mydoom"},
	3175:  {"mydoom"},
	3176:  {"mydoom"},
	3177:  {"mydoom"},
	3178:  {"mydoom"},
	3179:  {"mydoom"},
	3180:  {"mydoom"},
	3181:  {"mydoom"},
	3182:  {"mydoom"},
	3183:  {"mydoom"},
	3184:  {"mydoom"},
	3185:  {"mydoom"},
	3186:  {"mydoom"},
	3187:  {"mydoom"},
	3188:  {"mydoom"},
	3189:  {"mydoom"},
	3190:  {"mydoom"},
	3191:  {"mydoom"},
	3192:  {"mydoom"},
	3193:  {"mydoom"},
	3194:  {"mydoom"},
	3195:  {"mydoom"},
	3196:  {"mydoom"},
	3197:  {"mydoom"},
	3198:  {"mydoom"},
	3268:  {"LDAPSearchReq", "LDAPBindReq"},
	3269:  {"LDAPSearchReq", "LDAPBindReq"},
	3273:  {"JavaRMI"},
	3280:  {"GetRequest"},
	3310:  {"GenericLines", "VersionRequest"},
	3333:  {"GenericLines", "LPDString", "JavaRMI", "kumo-server"},
	3351:  {"pervasive-relational", "pervasive-btrieve"},
	3372:  {"GetRequest", "RTSPRequest"},
	3388:  {"TLSSessionReq", "TerminalServerCookie", "TerminalServer"},
	3389:  {"TerminalServerCookie", "TerminalServer", "TLSSessionReq"},
	3443:  {"GetRequest", "SSLSessionReq"},
	3493:  {"Help"},
	3531:  {"GetRequest"},
	3632:  {"DistCCD"},
	3689:  {"GetRequest"},
	3790:  {"metasploit-msgrpc"},
	3872:  {"GetRequest"},
	3892:  {"LDAPSearchReq", "LDAPBindReq"},
	3900:  {"SMBProgNeg", "JavaRMI"},
	3940:  {"GenericLines"},
	4000:  {"GetRequest", "NoMachine"},
	4035:  {"LDAPBindReq", "LDAPBindReq"},
	4045:  {"RPCCheck"},
	4155:  {"GenericLines"},
	4369:  {"epmd"},
	4433:  {"TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	4443:  {"GetRequest", "HTTPOptions", "SSLSessionReq", "FourOhFourRequest"},
	4444:  {"GetRequest", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq"},
	4533:  {"rotctl"},
	4567:  {"GetRequest"},
	4660:  {"GetRequest"},
	4711:  {"GetRequest", "piholeVersion"},
	4899:  {"Radmin"},
	4911:  {"SSLSessionReq", "niagara-fox"},
	4999:  {"RPCCheck"},
	5000:  {"GenericLines", "GetRequest", "RTSPRequest", "DNSVersionBindReqTCP", "SMBProgNeg", "ZendJavaBridge"},
	5001:  {"WMSRequest", "ZendJavaBridge"},
	5002:  {"ZendJavaBridge"},
	5009:  {"SMBProgNeg"},
	5060:  {"GetRequest", "SIPOptions"},
	5061:  {"GetRequest", "TLSSessionReq", "SSLSessionReq", "SIPOptions"},
	5201:  {"iperf3"},
	5222:  {"GetRequest"},
	5232:  {"HTTPOptions"},
	5269:  {"GetRequest"},
	5280:  {"GetRequest"},
	5302:  {"X11Probe"},
	5323:  {"DNSVersionBindReqTCP"},
	5400:  {"GenericLines"},
	5427:  {"GetRequest"},
	5432:  {"GenericLines", "GetRequest", "SMBProgNeg"},
	5443:  {"SSLSessionReq"},
	5520:  {"DNSVersionBindReqTCP", "JavaRMI"},
	5521:  {"JavaRMI"},
	5530:  {"DNSVersionBindReqTCP"},
	5550:  {"SSLSessionReq", "SSLv23SessionReq"},
	5555:  {"GenericLines", "DNSVersionBindReqTCP", "SMBProgNeg", "adbConnect"},
	5556:  {"DNSVersionBindReqTCP"},
	5570:  {"GenericLines"},
	5580:  {"JavaRMI"},
	5600:  {"SMBProgNeg"},
	5701:  {"hazelcast-http"},
	5702:  {"hazelcast-http"},
	5703:  {"hazelcast-http"},
	5704:  {"hazelcast-http"},
	5705:  {"hazelcast-http"},
	5706:  {"hazelcast-http"},
	5707:  {"hazelcast-http"},
	5708:  {"hazelcast-http"},
	5709:  {"LANDesk-RC", "hazelcast-http"},
	5800:  {"GetRequest"},
	5801:  {"GetRequest"},
	5802:  {"GetRequest"},
	5803:  {"GetRequest"},
	5868:  {"SSLSessionReq"},
	5900:  {"GetRequest"},
	5985:  {"GetRequest"},
	5986:  {"GetRequest", "SSLSessionReq"},
	5999:  {"JavaRMI"},
	6000:  {"HTTPOptions", "X11Probe"},
	6001:  {"X11Probe"},
	6002:  {"X11Probe"},
	6003:  {"X11Probe"},
	6004:  {"X11Probe"},
	6005:  {"X11Probe"},
	6006:  {"X11Probe"},
	6007:  {"X11Probe"},
	6008:  {"X11Probe"},
	6009:  {"X11Probe"},
	6010:  {"X11Probe"},
	6011:  {"X11Probe"},
	6012:  {"X11Probe"},
	6013:  {"X11Probe"},
	6014:  {"X11Probe"},
	6015:  {"X11Probe"},
	6016:  {"X11Probe"},
	6017:  {"X11Probe"},
	6018:  {"X11Probe"},
	6019:  {"X11Probe"},
	6020:  {"X11Probe"},
	6050:  {"DNSStatusRequestTCP"},
	6060:  {"JavaRMI"},
	6103:  {"GetRequest"},
	6112:  {"GenericLines"},
	6163:  {"HELP4STOMP"},
	6251:  {"SSLSessionReq"},
	6346:  {"GetRequest"},
	6379:  {"redis-server"},
	6432:  {"GenericLines"},
	6443:  {"SSLSessionReq"},
	6543:  {"DNSVersionBindReqTCP"},
	6544:  {"GetRequest"},
	6560:  {"Help"},
	6588:  {"Socks5", "Socks4"},
	6600:  {"GetRequest"},
	6660:  {"Socks5", "Socks4"},
	6661:  {"Socks5", "Socks4"},
	6662:  {"Socks5", "Socks4"},
	6663:  {"Socks5", "Socks4"},
	6664:  {"Socks5", "Socks4"},
	6665:  {"Socks5", "Socks4"},
	6666:  {"Help", "Socks5", "Socks4", "beast2", "vp3"},
	6667:  {"GenericLines", "Help", "Socks5", "Socks4"},
	6668:  {"GenericLines", "Help", "Socks5", "Socks4"},
	6669:  {"GenericLines", "Help", "Socks5", "Socks4"},
	6670:  {"GenericLines", "Help"},
	6679:  {"TLSSessionReq", "SSLSessionReq"},
	6697:  {"TLSSessionReq", "SSLSessionReq"},
	6699:  {"GetRequest"},
	6715:  {"JMON", "JMON"},
	6789:  {"JavaRMI"},
	6802:  {"NCP"},
	6969:  {"GetRequest"},
	6996:  {"JavaRMI"},
	7000:  {"RPCCheck", "DNSVersionBindReqTCP", "SSLSessionReq", "X11Probe"},
	7002:  {"GetRequest"},
	7007:  {"GetRequest"},
	7008:  {"DNSVersionBindReqTCP"},
	7070:  {"GetRequest", "RTSPRequest"},
	7100:  {"GetRequest", "X11Probe"},
	7101:  {"X11Probe"},
	7144:  {"GenericLines"},
	7145:  {"GenericLines"},
	7171:  {"NotesRPC"},
	7200:  {"GenericLines"},
	7210:  {"SSLSessionReq", "SSLv23SessionReq"},
	7272:  {"SSLSessionReq", "SSLv23SessionReq"},
	7402:  {"GetRequest"},
	7443:  {"GetRequest", "SSLSessionReq"},
	7461:  {"SMBProgNeg"},
	7700:  {"JavaRMI"},
	7776:  {"GetRequest"},
	7777:  {"X11Probe", "Socks5", "Arucer"},
	7780:  {"GenericLines"},
	7800:  {"JavaRMI"},
	7801:  {"JavaRMI"},
	7878:  {"JavaRMI"},
	7887:  {"xmlsysd"},
	7890:  {"JavaRMI"},
	8000:  {"GenericLines", "GetRequest", "X11Probe", "FourOhFourRequest", "Socks5", "Socks4"},
	8001:  {"GetRequest", "FourOhFourRequest"},
	8002:  {"GetRequest", "FourOhFourRequest"},
	8003:  {"GetRequest", "FourOhFourRequest"},
	8004:  {"GetRequest", "FourOhFourRequest"},
	8005:  {"GetRequest", "FourOhFourRequest"},
	8006:  {"GetRequest", "FourOhFourRequest"},
	8007:  {"GetRequest", "FourOhFourRequest"},
	8008:  {"GetRequest", "FourOhFourRequest", "Socks5", "Socks4", "ajp"},
	8009:  {"GetRequest", "SSLSessionReq", "SSLv23SessionReq", "FourOhFourRequest", "ajp"},
	8010:  {"GetRequest", "FourOhFourRequest", "Socks5"},
	8050:  {"JavaRMI"},
	8051:  {"JavaRMI"},
	8080:  {"GetRequest", "HTTPOptions", "RTSPRequest", "FourOhFourRequest", "Socks5", "Socks4"},
	8081:  {"GetRequest", "FourOhFourRequest", "SIPOptions", "WWWOFFLEctrlstat"},
	8082:  {"GetRequest", "FourOhFourRequest"},
	8083:  {"GetRequest", "FourOhFourRequest"},
	8084:  {"GetRequest", "FourOhFourRequest"},
	8085:  {"GetRequest", "FourOhFourRequest", "JavaRMI"},
	8087:  {"riak-pbc"},
	8088:  {"GetRequest", "Socks5", "Socks4"},
	8091:  {"JavaRMI"},
	8118:  {"GetRequest"},
	8138:  {"GenericLines"},
	8181:  {"GetRequest", "SSLSessionReq"},
	8194:  {"SSLSessionReq", "SSLv23SessionReq"},
	8205:  {"JavaRMI"},
	8303:  {"JavaRMI"},
	8307:  {"RPCCheck"},
	8333:  {"RPCCheck"},
	8443:  {"GetRequest", "HTTPOptions", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq", "FourOhFourRequest"},
	8530:  {"GetRequest"},
	8531:  {"GetRequest", "SSLSessionReq"},
	8642:  {"JavaRMI"},
	8686:  {"JavaRMI"},
	8701:  {"JavaRMI"},
	8728:  {"NotesRPC"},
	8770:  {"apple-iphoto"},
	8880:  {"GetRequest", "FourOhFourRequest"},
	8881:  {"GetRequest", "FourOhFourRequest"},
	8882:  {"GetRequest", "FourOhFourRequest"},
	8883:  {"GetRequest", "TLSSessionReq", "SSLSessionReq", "FourOhFourRequest", "mqtt"},
	8884:  {"GetRequest", "FourOhFourRequest"},
	8885:  {"GetRequest", "FourOhFourRequest"},
	8886:  {"GetRequest", "FourOhFourRequest"},
	8887:  {"GetRequest", "FourOhFourRequest"},
	8888:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "JavaRMI", "LSCP"},
	8889:  {"JavaRMI"},
	8890:  {"JavaRMI"},
	8901:  {"JavaRMI"},
	8902:  {"JavaRMI"},
	8903:  {"JavaRMI"},
	8999:  {"JavaRMI"},
	9000:  {"GenericLines", "GetRequest"},
	9001:  {"GenericLines", "GetRequest", "TLSSessionReq", "SSLSessionReq", "SSLv23SessionReq", "JavaRMI", "Radmin", "mongodb", "tarantool", "tor-versions"},
	9002:  {"GenericLines", "tor-versions"},
	9003:  {"GenericLines", "JavaRMI"},
	9004:  {"JavaRMI"},
	9005:  {"JavaRMI"},
	9030:  {"GetRequest"},
	9050:  {"GetRequest", "JavaRMI"},
	9080:  {"GetRequest"},
	9088:  {"informix", "drda"},
	9089:  {"informix", "drda"},
	9090:  {"GetRequest", "JavaRMI", "WMSRequest", "ibm-db2-das", "SqueezeCenter_CLI", "informix", "drda"},
	9091:  {"informix", "drda"},
	9092:  {"informix", "drda"},
	9093:  {"informix", "drda"},
	9094:  {"informix", "drda"},
	9095:  {"informix", "drda"},
	9096:  {"informix", "drda"},
	9097:  {"informix", "drda"},
	9098:  {"informix", "drda"},
	9099:  {"JavaRMI", "informix", "drda"},
	9100:  {"hp-pjl", "informix", "drda"},
	9101:  {"hp-pjl"},
	9102:  {"SMBProgNeg", "hp-pjl"},
	9103:  {"SMBProgNeg", "hp-pjl"},
	9104:  {"hp-pjl"},
	9105:  {"hp-pjl"},
	9106:  {"hp-pjl"},
	9107:  {"hp-pjl"},
	9300:  {"JavaRMI"},
	9390:  {"metasploit-xmlrpc"},
	9443:  {"GetRequest", "SSLSessionReq"},
	9481:  {"Socks5"},
	9500:  {"JavaRMI"},
	9711:  {"JavaRMI"},
	9761:  {"insteonPLM"},
	9801:  {"GenericLines"},
	9809:  {"JavaRMI"},
	9810:  {"JavaRMI"},
	9811:  {"JavaRMI"},
	9812:  {"JavaRMI"},
	9813:  {"JavaRMI"},
	9814:  {"JavaRMI"},
	9815:  {"JavaRMI"},
	9875:  {"JavaRMI"},
	9910:  {"JavaRMI"},
	9930:  {"ibm-db2-das"},
	9931:  {"ibm-db2-das"},
	9932:  {"ibm-db2-das"},
	9933:  {"ibm-db2-das"},
	9934:  {"ibm-db2-das"},
	9991:  {"JavaRMI"},
	9998:  {"teamspeak-tcpquery-ver"},
	9999:  {"GetRequest", "HTTPOptions", "FourOhFourRequest", "JavaRMI"},
	10000: {"GetRequest", "HTTPOptions", "RTSPRequest"},
	10001: {"GetRequest", "JavaRMI", "ZendJavaBridge"},
	10002: {"ZendJavaBridge", "SharpTV"},
	10003: {"ZendJavaBridge"},
	10005: {"GetRequest"},
	10031: {"HTTPOptions"},
	10098: {"JavaRMI"},
	10099: {"JavaRMI"},
	10162: {"JavaRMI"},
	10333: {"teamtalk-login"},
	10443: {"GetRequest", "SSLSessionReq"},
	10990: {"JavaRMI"},
	11001: {"JavaRMI"},
	11099: {"JavaRMI"},
	11210: {"couchbase-data"},
	11211: {"Memcache"},
	11333: {"JavaRMI"},
	11371: {"GenericLines", "GetRequest"},
	11711: {"LDAPSearchReq"},
	11712: {"LDAPSearchReq"},
	11965: {"GenericLines"},
	12000: {"JavaRMI"},
	12345: {"Help", "OfficeScan"},
	13013: {"GetRequest", "JavaRMI"},
	13666: {"GetRequest"},
	13720: {"GenericLines"},
	13722: {"GetRequest"},
	13783: {"DNSVersionBindReqTCP"},
	14000: {"JavaRMI"},
	14238: {"oracle-tns"},
	14443: {"GetRequest", "SSLSessionReq"},
	14534: {"GetRequest"},
	14690: {"Help"},
	15000: {"GenericLines", "GetRequest", "JavaRMI"},
	15001: {"GenericLines", "JavaRMI"},
	15002: {"GenericLines", "SSLSessionReq"},
	15200: {"JavaRMI"},
	16000: {"JavaRMI"},
	17007: {"RPCCheck"},
	17200: {"JavaRMI"},
	17988: {"GetRequest"},
	18086: {"GenericLines"},
	18182: {"SMBProgNeg"},
	18264: {"GetRequest"},
	18980: {"JavaRMI"},
	19150: {"GenericLines", "gkrellm"},
	19350: {"LPDString"},
	19700: {"kumo-server"},
	19800: {"kumo-server"},
	20000: {"JavaRMI", "oracle-tns"},
	20547: {"proconos"},
	22001: {"NotesRPC"},
	22490: {"Help"},
	23791: {"JavaRMI"},
	25565: {"minecraft-ping"},
	26214: {"GenericLines"},
	26256: {"JavaRMI"},
	26470: {"GenericLines"},
	27000: {"SMBProgNeg"},
	27001: {"SMBProgNeg"},
	27002: {"SMBProgNeg"},
	27003: {"SMBProgNeg"},
	27004: {"SMBProgNeg"},
	27005: {"SMBProgNeg"},
	27006: {"SMBProgNeg"},
	27007: {"SMBProgNeg"},
	27008: {"SMBProgNeg"},
	27009: {"SMBProgNeg"},
	27010: {"SMBProgNeg"},
	27017: {"mongodb"},
	27036: {"TLS-PSK"},
	30444: {"GenericLines"},
	31099: {"JavaRMI"},
	31337: {"GetRequest", "SIPOptions"},
	31416: {"GenericLines"},
	32211: {"LPDString"},
	32750: {"RPCCheck"},
	32751: {"RPCCheck"},
	32752: {"RPCCheck"},
	32753: {"RPCCheck"},
	32754: {"RPCCheck"},
	32755: {"RPCCheck"},
	32756: {"RPCCheck"},
	32757: {"RPCCheck"},
	32758: {"RPCCheck"},
	32759: {"RPCCheck"},
	32760: {"RPCCheck"},
	32761: {"RPCCheck"},
	32762: {"RPCCheck"},
	32763: {"RPCCheck"},
	32764: {"RPCCheck"},
	32765: {"RPCCheck"},
	32766: {"RPCCheck"},
	32767: {"RPCCheck"},
	32768: {"RPCCheck"},
	32769: {"RPCCheck"},
	32770: {"RPCCheck"},
	32771: {"RPCCheck"},
	32772: {"RPCCheck"},
	32773: {"RPCCheck"},
	32774: {"RPCCheck"},
	32775: {"RPCCheck"},
	32776: {"RPCCheck"},
	32777: {"RPCCheck"},
	32778: {"RPCCheck"},
	32779: {"RPCCheck"},
	32780: {"RPCCheck"},
	32781: {"RPCCheck"},
	32782: {"RPCCheck"},
	32783: {"RPCCheck"},
	32784: {"RPCCheck"},
	32785: {"RPCCheck"},
	32786: {"RPCCheck"},
	32787: {"RPCCheck"},
	32788: {"RPCCheck"},
	32789: {"RPCCheck"},
	32790: {"RPCCheck"},
	32791: {"RPCCheck"},
	32792: {"RPCCheck"},
	32793: {"RPCCheck"},
	32794: {"RPCCheck"},
	32795: {"RPCCheck"},
	32796: {"RPCCheck"},
	32797: {"RPCCheck"},
	32798: {"RPCCheck"},
	32799: {"RPCCheck"},
	32800: {"RPCCheck"},
	32801: {"RPCCheck"},
	32802: {"RPCCheck"},
	32803: {"RPCCheck"},
	32804: {"RPCCheck"},
	32805: {"RPCCheck"},
	32806: {"RPCCheck"},
	32807: {"RPCCheck"},
	32808: {"RPCCheck"},
	32809: {"RPCCheck"},
	32810: {"RPCCheck"},
	32913: {"JavaRMI"},
	33000: {"JavaRMI"},
	33015: {"tarantool"},
	34012: {"GenericLines"},
	37435: {"HTTPOptions"},
	37718: {"JavaRMI"},
	38978: {"RPCCheck"},
	40193: {"GetRequest"},
	41523: {"DNSStatusRequestTCP"},
	44443: {"GetRequest", "SSLSessionReq"},
	45230: {"JavaRMI"},
	47001: {"JavaRMI"},
	47002: {"JavaRMI"},
	49152: {"FourOhFourRequest"},
	49153: {"mongodb"},
	49400: {"HTTPOptions"},
	50000: {"GetRequest", "ibm-db2-das", "ibm-db2", "drda"},
	50001: {"ibm-db2"},
	50002: {"ibm-db2"},
	50003: {"ibm-db2"},
	50004: {"ibm-db2"},
	50005: {"ibm-db2"},
	50006: {"ibm-db2"},
	50007: {"ibm-db2"},
	50008: {"ibm-db2"},
	50009: {"ibm-db2"},
	50010: {"ibm-db2"},
	50011: {"ibm-db2"},
	50012: {"ibm-db2"},
	50013: {"ibm-db2"},
	50014: {"ibm-db2"},
	50015: {"ibm-db2"},
	50016: {"ibm-db2"},
	50017: {"ibm-db2"},
	50018: {"ibm-db2"},
	50019: {"ibm-db2"},
	50020: {"ibm-db2"},
	50021: {"ibm-db2"},
	50022: {"ibm-db2"},
	50023: {"ibm-db2"},
	50024: {"ibm-db2"},
	50025: {"ibm-db2"},
	50050: {"JavaRMI"},
	50500: {"JavaRMI"},
	50501: {"JavaRMI"},
	50502: {"JavaRMI"},
	50503: {"JavaRMI"},
	50504: {"JavaRMI"},
	50505: {"metasploit-msgrpc"},
	51234: {"teamspeak-tcpquery-ver"},
	55552: {"metasploit-msgrpc"},
	55553: {"metasploit-xmlrpc", "metasploit-xmlrpc"},
	55555: {"GetRequest"},
	56667: {"GenericLines"},
	59100: {"kumo-server"},
	60000: {"ibm-db2", "drda"},
	60001: {"ibm-db2"},
	60002: {"ibm-db2"},
	60003: {"ibm-db2"},
	60004: {"ibm-db2"},
	60005: {"ibm-db2"},
	60006: {"ibm-db2"},
	60007: {"ibm-db2"},
	60008: {"ibm-db2"},
	60009: {"ibm-db2"},
	60010: {"ibm-db2"},
	60011: {"ibm-db2"},
	60012: {"ibm-db2"},
	60013: {"ibm-db2"},
	60014: {"ibm-db2"},
	60015: {"ibm-db2"},
	60016: {"ibm-db2"},
	60017: {"ibm-db2"},
	60018: {"ibm-db2"},
	60019: {"ibm-db2"},
	60020: {"ibm-db2"},
	60021: {"ibm-db2"},
	60022: {"ibm-db2"},
	60023: {"ibm-db2"},
	60024: {"ibm-db2"},
	60025: {"ibm-db2"},
	60443: {"GetRequest", "SSLSessionReq"},
	61613: {"HELP4STOMP"},
}

var Passwords = []string{"123456", "admin", "admin123", "root", "", "pass123", "pass@123", "password", "Password", "P@ssword123", "123123", "654321", "111111", "123", "1", "admin@123", "Admin@123", "admin123!@#", "{user}", "{user}1", "{user}111", "{user}123", "{user}@123", "{user}_123", "{user}#123", "{user}@111", "{user}@2019", "{user}@123#4", "P@ssw0rd!", "P@ssw0rd", "Passw0rd", "qwe123", "12345678", "test", "test123", "123qwe", "123qwe!@#", "123456789", "123321", "666666", "a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888", "!QAZ2wsx", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "a11111", "a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123", "Aa123123", "Aa123456", "Aa12345.", "sysadmin", "system", "1qaz!QAZ", "2wsx@WSX", "qwe123!@#", "Aa123456!", "A123456s!", "sa123456", "1q2w3e", "Charge123", "Aa123456789", "elastic123"}

var (
	Outputfile   string // 输出文件路径
	OutputFormat string // 输出格式
)

// 添加一个全局的进度条变量
var ProgressBar *progressbar.ProgressBar

// 添加一个全局互斥锁来控制输出
var OutputMutex sync.Mutex

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
	ScanMode  string // 原Scantype
	ThreadNum int    // 原Threads
	//UseSynScan      bool
	Timeout         int64 = 3
	LiveTop         int
	DisablePing     bool // 原NoPing
	UsePing         bool // 原Ping
	Command         string
	SkipFingerprint bool

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

	LocalMode bool // -local 本地模式

	// POC配置
	PocPath string
	Pocinfo PocInfo

	// Redis配置
	RedisFile    string
	RedisShell   string
	DisableRedis bool // 原Noredistest

	// 爆破配置
	DisableBrute bool // 原IsBrute
	//BruteThreads int  // 原BruteThread
	MaxRetries int // 最大重试次数

	// 其他配置
	RemotePath string   // 原Path
	HashValue  string   // 原Hash
	HashValues []string // 原Hashs
	HashBytes  [][]byte
	HostPort   []string
	Shellcode  string // 原SC
	EnableWmi  bool   // 原IsWmi

	// 输出配置
	DisableSave  bool   // 禁止保存结果
	Silent       bool   // 静默模式
	NoColor      bool   // 禁用彩色输出
	JsonFormat   bool   // JSON格式输出
	LogLevel     string // 日志输出级别
	ShowProgress bool   // 是否显示进度条

	Language string // 语言
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
