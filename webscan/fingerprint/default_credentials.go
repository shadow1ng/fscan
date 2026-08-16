package fingerprint

import (
	"sort"
	"strings"
	"unicode"
)

// defaultCredentialEntry links exact technology aliases to passive credential
// candidates. These values are hints only: detecting a technology does not
// prove that any credential is valid on the target.
type defaultCredentialEntry struct {
	Aliases     []string
	Credentials []string
}

// Keep this database deliberately focused on common intranet middleware and
// management consoles. Empty passwords are rendered as <empty> so they cannot
// be confused with a truncated output value.
var defaultCredentialEntries = []defaultCredentialEntry{
	{[]string{"Apache ActiveMQ", "ActiveMQ"}, []string{"admin/admin", "user/user", "guest/guest"}},
	{[]string{"Apache Tomcat", "Tomcat"}, []string{"tomcat/tomcat", "admin/admin", "manager/manager"}},
	{[]string{"Apache Axis2", "Axis2"}, []string{"admin/axis2"}},
	{[]string{"Oracle WebLogic Server", "WebLogic", "WebLogic Server"}, []string{"weblogic/weblogic1", "weblogic/welcome1", "system/password"}},
	{[]string{"JBoss Application Server", "JBoss AS", "JBoss"}, []string{"admin/admin", "jboss/jboss"}},
	{[]string{"WildFly"}, []string{"admin/admin"}},
	{[]string{"GlassFish", "Oracle GlassFish Server"}, []string{"admin/adminadmin"}},
	{[]string{"RabbitMQ", "RabbitMQ Management"}, []string{"guest/guest"}},
	{[]string{"EMQX", "EMQ X", "EMQX Dashboard"}, []string{"admin/public"}},
	{[]string{"Grafana"}, []string{"admin/admin"}},
	{[]string{"Jenkins"}, []string{"admin/admin"}},
	{[]string{"SonarQube"}, []string{"admin/admin"}},
	{[]string{"Nexus Repository Manager", "Sonatype Nexus Repository", "Nexus"}, []string{"admin/admin123"}},
	{[]string{"Nacos"}, []string{"nacos/nacos"}},
	{[]string{"XXL-JOB", "XXL Job", "XXL-JOB Admin"}, []string{"admin/123456"}},
	{[]string{"Alibaba Druid", "Druid Monitor", "Druid"}, []string{"admin/admin"}},
	{[]string{"Dubbo Admin", "Apache Dubbo Admin"}, []string{"root/root", "guest/guest"}},
	{[]string{"MinIO", "MinIO Console"}, []string{"minioadmin/minioadmin"}},
	{[]string{"Harbor"}, []string{"admin/Harbor12345"}},
	{[]string{"Zabbix"}, []string{"Admin/zabbix"}},
	{[]string{"GitLab"}, []string{"root/5iveL!fe"}},
	{[]string{"Apache Airflow", "Airflow"}, []string{"admin/admin"}},
	{[]string{"Apache Superset", "Superset"}, []string{"admin/admin"}},
	{[]string{"phpMyAdmin"}, []string{"root/<empty>", "root/root"}},
	{[]string{"MySQL"}, []string{"root/<empty>", "root/root", "root/mysql"}},
	{[]string{"PostgreSQL"}, []string{"postgres/postgres"}},
	{[]string{"Microsoft SQL Server", "MSSQL"}, []string{"sa/sa"}},
	{[]string{"Oracle Database", "Oracle DB"}, []string{"scott/tiger", "system/manager"}},
	{[]string{"Mongo Express"}, []string{"admin/pass"}},
	{[]string{"InfluxDB"}, []string{"admin/admin"}},
}

var defaultCredentialAliasIndex = buildDefaultCredentialAliasIndex()

func buildDefaultCredentialAliasIndex() map[string][]string {
	index := make(map[string][]string)
	for _, entry := range defaultCredentialEntries {
		for _, alias := range entry.Aliases {
			key := normalizeCredentialTechnology(alias)
			if key != "" {
				index[key] = appendUniqueStrings(index[key], entry.Credentials...)
			}
		}
	}
	return index
}

// MatchDefaultCredentialHints returns deterministic, de-duplicated candidates
// for the detected technologies. Matching is exact after case, punctuation and
// version normalization; substring matching is intentionally avoided.
func MatchDefaultCredentialHints(fingerprints []string) []string {
	matched := make(map[string]struct{})
	for _, technology := range fingerprints {
		for _, credential := range defaultCredentialAliasIndex[normalizeCredentialTechnology(technology)] {
			matched[credential] = struct{}{}
		}
	}
	if len(matched) == 0 {
		return nil
	}
	result := make([]string, 0, len(matched))
	for credential := range matched {
		result = append(result, credential)
	}
	sort.Strings(result)
	return result
}

func normalizeCredentialTechnology(value string) string {
	value = strings.TrimSpace(value)
	for _, separator := range []byte{':', '/'} {
		if index := strings.LastIndexByte(value, separator); index > 0 && versionSuffix(value[index+1:]) {
			value = value[:index]
			break
		}
	}
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
		} else if b.Len() > 0 && !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

func versionSuffix(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value[0] >= '0' && value[0] <= '9'
}

func appendUniqueStrings(destination []string, values ...string) []string {
	seen := make(map[string]struct{}, len(destination)+len(values))
	for _, value := range destination {
		seen[value] = struct{}{}
	}
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		destination = append(destination, value)
	}
	return destination
}
