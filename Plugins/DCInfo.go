//go:build windows

package Plugins

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/shadow1ng/fscan/Common"
	"os/exec"
	"strconv"
	"strings"
)

type DomainInfo struct {
	conn   *ldap.Conn
	baseDN string
}

func (d *DomainInfo) Close() {
	if d.conn != nil {
		d.conn.Close()
	}
}

func (d *DomainInfo) GetCAComputers() ([]string, error) {
	Common.LogDebug("开始查询域内CA服务器...")

	searchRequest := ldap.NewSearchRequest(
		"CN=Configuration,"+d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=pKIEnrollmentService))",
		[]string{"cn", "dNSHostName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询CA服务器失败: %v", err))
		return nil, err
	}

	var caComputers []string
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			caComputers = append(caComputers, cn)
			Common.LogDebug(fmt.Sprintf("发现CA服务器: %s", cn))
		}
	}

	if len(caComputers) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个CA服务器", len(caComputers)))
	} else {
		Common.LogDebug("未发现CA服务器")
	}

	return caComputers, nil
}

func (d *DomainInfo) GetExchangeServers() ([]string, error) {
	Common.LogDebug("开始查询Exchange服务器...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=group)(cn=Exchange Servers))",
		[]string{"member"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询Exchange服务器失败: %v", err))
		return nil, err
	}

	var exchangeServers []string
	for _, entry := range sr.Entries {
		for _, member := range entry.GetAttributeValues("member") {
			if member != "" {
				exchangeServers = append(exchangeServers, member)
				Common.LogDebug(fmt.Sprintf("发现Exchange服务器成员: %s", member))
			}
		}
	}

	// 移除第一个条目（如果存在）
	if len(exchangeServers) > 1 {
		exchangeServers = exchangeServers[1:]
		Common.LogDebug("移除第一个条目")
	}

	if len(exchangeServers) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个Exchange服务器", len(exchangeServers)))
	} else {
		Common.LogDebug("未发现Exchange服务器")
	}

	return exchangeServers, nil
}

func (d *DomainInfo) GetMsSqlServers() ([]string, error) {
	Common.LogDebug("开始查询SQL Server服务器...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer)(servicePrincipalName=MSSQLSvc*))",
		[]string{"name"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询SQL Server失败: %v", err))
		return nil, err
	}

	var sqlServers []string
	for _, entry := range sr.Entries {
		name := entry.GetAttributeValue("name")
		if name != "" {
			sqlServers = append(sqlServers, name)
			Common.LogDebug(fmt.Sprintf("发现SQL Server: %s", name))
		}
	}

	if len(sqlServers) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个SQL Server", len(sqlServers)))
	} else {
		Common.LogDebug("未发现SQL Server")
	}

	return sqlServers, nil
}

func (d *DomainInfo) GetSpecialComputers() (map[string][]string, error) {
	Common.LogDebug("开始查询特殊计算机...")
	results := make(map[string][]string)

	// 获取SQL Server
	Common.LogDebug("正在查询SQL Server...")
	sqlServers, err := d.GetMsSqlServers()
	if err == nil && len(sqlServers) > 0 {
		results["SQL服务器"] = sqlServers
	} else if err != nil {
		Common.LogError(fmt.Sprintf("查询SQL Server时出错: %v", err))
	}

	// 获取CA服务器
	Common.LogDebug("正在查询CA服务器...")
	caComputers, err := d.GetCAComputers()
	if err == nil && len(caComputers) > 0 {
		results["CA服务器"] = caComputers
	} else if err != nil {
		Common.LogError(fmt.Sprintf("查询CA服务器时出错: %v", err))
	}

	// 获取域控制器
	Common.LogDebug("正在查询域控制器...")
	dcQuery := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"cn"},
		nil,
	)

	if sr, err := d.conn.SearchWithPaging(dcQuery, 10000); err == nil {
		var dcs []string
		for _, entry := range sr.Entries {
			name := entry.GetAttributeValue("cn")
			if name != "" {
				dcs = append(dcs, name)
				Common.LogDebug(fmt.Sprintf("发现域控制器: %s", name))
			}
		}
		if len(dcs) > 0 {
			results["域控制器"] = dcs
			Common.LogSuccess(fmt.Sprintf("共发现 %d 个域控制器", len(dcs)))
		} else {
			Common.LogDebug("未发现域控制器")
		}
	} else {
		Common.LogError(fmt.Sprintf("查询域控制器时出错: %v", err))
	}

	// 获取Exchange服务器
	Common.LogDebug("正在查询Exchange服务器...")
	exchangeServers, err := d.GetExchangeServers()
	if err == nil && len(exchangeServers) > 0 {
		results["Exchange服务器"] = exchangeServers
	} else if err != nil {
		Common.LogError(fmt.Sprintf("查询Exchange服务器时出错: %v", err))
	}

	if len(results) > 0 {
		Common.LogSuccess(fmt.Sprintf("特殊计算机查询完成，共发现 %d 类服务器", len(results)))
		for serverType, servers := range results {
			Common.LogDebug(fmt.Sprintf("%s: %d 台", serverType, len(servers)))
		}
	} else {
		Common.LogDebug("未发现任何特殊计算机")
	}

	return results, nil
}

func (d *DomainInfo) GetDomainUsers() ([]string, error) {
	Common.LogDebug("开始查询域用户...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询域用户失败: %v", err))
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		username := entry.GetAttributeValue("sAMAccountName")
		if username != "" {
			users = append(users, username)
			Common.LogDebug(fmt.Sprintf("发现用户: %s", username))
		}
	}

	if len(users) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个域用户", len(users)))
	} else {
		Common.LogDebug("未发现域用户")
	}

	return users, nil
}

func (d *DomainInfo) GetDomainAdmins() ([]string, error) {
	Common.LogDebug("开始查询域管理员...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=group)(cn=Domain Admins))",
		[]string{"member", "sAMAccountName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询Domain Admins组失败: %v", err))
		return nil, err
	}

	var admins []string
	if len(sr.Entries) > 0 {
		members := sr.Entries[0].GetAttributeValues("member")
		Common.LogDebug(fmt.Sprintf("发现 %d 个Domain Admins组成员", len(members)))

		for _, memberDN := range members {
			memberSearch := ldap.NewSearchRequest(
				memberDN,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"sAMAccountName"},
				nil,
			)

			memberResult, err := d.conn.Search(memberSearch)
			if err != nil {
				Common.LogError(fmt.Sprintf("查询成员 %s 失败: %v", memberDN, err))
				continue
			}

			if len(memberResult.Entries) > 0 {
				samAccountName := memberResult.Entries[0].GetAttributeValue("sAMAccountName")
				if samAccountName != "" {
					admins = append(admins, samAccountName)
					Common.LogDebug(fmt.Sprintf("发现域管理员: %s", samAccountName))
				}
			}
		}
	}

	if len(admins) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个域管理员", len(admins)))
	} else {
		Common.LogDebug("未发现域管理员")
	}

	return admins, nil
}

func (d *DomainInfo) GetOUs() ([]string, error) {
	Common.LogDebug("开始查询组织单位(OU)...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=organizationalUnit)",
		[]string{"ou"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询OU失败: %v", err))
		return nil, err
	}

	var ous []string
	for _, entry := range sr.Entries {
		ou := entry.GetAttributeValue("ou")
		if ou != "" {
			ous = append(ous, ou)
			Common.LogDebug(fmt.Sprintf("发现OU: %s", ou))
		}
	}

	if len(ous) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个组织单位", len(ous)))
	} else {
		Common.LogDebug("未发现组织单位")
	}

	return ous, nil
}

func (d *DomainInfo) GetComputers() ([]Computer, error) {
	Common.LogDebug("开始查询域内计算机...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer))",
		[]string{"cn", "operatingSystem", "dNSHostName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询计算机失败: %v", err))
		return nil, err
	}

	var computers []Computer
	for _, entry := range sr.Entries {
		computer := Computer{
			Name:            entry.GetAttributeValue("cn"),
			OperatingSystem: entry.GetAttributeValue("operatingSystem"),
			DNSHostName:     entry.GetAttributeValue("dNSHostName"),
		}
		computers = append(computers, computer)
		Common.LogDebug(fmt.Sprintf("发现计算机: %s (OS: %s, DNS: %s)",
			computer.Name,
			computer.OperatingSystem,
			computer.DNSHostName))
	}

	if len(computers) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 台计算机", len(computers)))

		// 统计操作系统分布
		osCount := make(map[string]int)
		for _, computer := range computers {
			if computer.OperatingSystem != "" {
				osCount[computer.OperatingSystem]++
			}
		}

		for os, count := range osCount {
			Common.LogDebug(fmt.Sprintf("操作系统 %s: %d 台", os, count))
		}
	} else {
		Common.LogDebug("未发现计算机")
	}

	return computers, nil
}

// 定义计算机结构体
type Computer struct {
	Name            string
	OperatingSystem string
	DNSHostName     string
}

func (d *DomainInfo) GetTrustDomains() ([]string, error) {
	Common.LogDebug("开始查询域信任关系...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=trustedDomain))",
		[]string{"cn", "trustDirection", "trustType"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询信任域失败: %v", err))
		return nil, err
	}

	var trustInfo []string
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			trustInfo = append(trustInfo, cn)
			Common.LogDebug(fmt.Sprintf("发现信任域: %s", cn))
		}
	}

	if len(trustInfo) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个信任域", len(trustInfo)))
	} else {
		Common.LogDebug("未发现信任域关系")
	}

	return trustInfo, nil
}

func (d *DomainInfo) GetAdminGroups() (map[string][]string, error) {
	Common.LogDebug("开始查询管理员组信息...")

	adminGroups := map[string]string{
		"Domain Admins":     "(&(objectClass=group)(cn=Domain Admins))",
		"Enterprise Admins": "(&(objectClass=group)(cn=Enterprise Admins))",
		"Administrators":    "(&(objectClass=group)(cn=Administrators))",
	}

	results := make(map[string][]string)

	for groupName, filter := range adminGroups {
		Common.LogDebug(fmt.Sprintf("正在查询 %s 组...", groupName))

		searchRequest := ldap.NewSearchRequest(
			d.baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"member"},
			nil,
		)

		sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
		if err != nil {
			Common.LogError(fmt.Sprintf("查询 %s 组失败: %v", groupName, err))
			continue
		}

		if len(sr.Entries) > 0 {
			members := sr.Entries[0].GetAttributeValues("member")
			if len(members) > 0 {
				results[groupName] = members
				Common.LogDebug(fmt.Sprintf("%s 组成员数量: %d", groupName, len(members)))
				for _, member := range members {
					Common.LogDebug(fmt.Sprintf("- %s: %s", groupName, member))
				}
			} else {
				Common.LogDebug(fmt.Sprintf("%s 组未发现成员", groupName))
			}
		}
	}

	if len(results) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个管理员组", len(results)))
	} else {
		Common.LogDebug("未发现管理员组信息")
	}

	return results, nil
}

func (d *DomainInfo) GetDelegation() (map[string][]string, error) {
	Common.LogDebug("开始查询委派信息...")

	delegationQueries := map[string]string{
		"非约束委派":     "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
		"约束委派":      "(msDS-AllowedToDelegateTo=*)",
		"基于资源的约束委派": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
	}

	results := make(map[string][]string)

	for delegationType, query := range delegationQueries {
		Common.LogDebug(fmt.Sprintf("正在查询%s...", delegationType))

		searchRequest := ldap.NewSearchRequest(
			d.baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			query,
			[]string{"cn", "distinguishedName"},
			nil,
		)

		sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
		if err != nil {
			Common.LogError(fmt.Sprintf("查询%s失败: %v", delegationType, err))
			continue
		}

		var entries []string
		for _, entry := range sr.Entries {
			cn := entry.GetAttributeValue("cn")
			if cn != "" {
				entries = append(entries, cn)
				Common.LogDebug(fmt.Sprintf("发现%s: %s", delegationType, cn))
			}
		}

		if len(entries) > 0 {
			results[delegationType] = entries
			Common.LogSuccess(fmt.Sprintf("%s: 发现 %d 条记录", delegationType, len(entries)))
		} else {
			Common.LogDebug(fmt.Sprintf("未发现%s记录", delegationType))
		}
	}

	if len(results) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 类委派配置", len(results)))
	} else {
		Common.LogDebug("未发现任何委派配置")
	}

	return results, nil
}

// 获取AS-REP Roasting漏洞用户
func (d *DomainInfo) GetAsrepRoastUsers() ([]string, error) {
	Common.LogDebug("开始查询AS-REP Roasting漏洞用户...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询AS-REP Roasting漏洞用户失败: %v", err))
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		if name != "" {
			users = append(users, name)
			Common.LogDebug(fmt.Sprintf("发现存在AS-REP Roasting漏洞的用户: %s", name))
		}
	}

	if len(users) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个存在AS-REP Roasting漏洞的用户", len(users)))
	} else {
		Common.LogDebug("未发现存在AS-REP Roasting漏洞的用户")
	}

	return users, nil
}

func (d *DomainInfo) GetPasswordPolicy() (map[string]string, error) {
	Common.LogDebug("开始查询域密码策略...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{
			"maxPwdAge",
			"minPwdAge",
			"minPwdLength",
			"pwdHistoryLength",
			"pwdProperties",
			"lockoutThreshold",
			"lockoutDuration",
		},
		nil,
	)

	sr, err := d.conn.Search(searchRequest)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询密码策略失败: %v", err))
		return nil, err
	}

	if len(sr.Entries) == 0 {
		Common.LogError("未找到密码策略信息")
		return nil, fmt.Errorf("未找到密码策略信息")
	}

	policy := make(map[string]string)
	entry := sr.Entries[0]

	// 转换最大密码期限
	if maxAge := entry.GetAttributeValue("maxPwdAge"); maxAge != "" {
		maxAgeInt, _ := strconv.ParseInt(maxAge, 10, 64)
		if maxAgeInt != 0 {
			days := float64(maxAgeInt) * -1 / float64(864000000000)
			policy["最大密码期限"] = fmt.Sprintf("%.0f天", days)
			Common.LogDebug(fmt.Sprintf("最大密码期限: %.0f天", days))
		}
	}

	if minLength := entry.GetAttributeValue("minPwdLength"); minLength != "" {
		policy["最小密码长度"] = minLength + "个字符"
		Common.LogDebug(fmt.Sprintf("最小密码长度: %s个字符", minLength))
	}

	if historyLength := entry.GetAttributeValue("pwdHistoryLength"); historyLength != "" {
		policy["密码历史长度"] = historyLength + "个"
		Common.LogDebug(fmt.Sprintf("密码历史长度: %s个", historyLength))
	}

	if lockoutThreshold := entry.GetAttributeValue("lockoutThreshold"); lockoutThreshold != "" {
		policy["账户锁定阈值"] = lockoutThreshold + "次"
		Common.LogDebug(fmt.Sprintf("账户锁定阈值: %s次", lockoutThreshold))
	}

	if len(policy) > 0 {
		Common.LogSuccess(fmt.Sprintf("成功获取域密码策略，共 %d 项配置", len(policy)))

		// 安全性评估
		minLengthInt, _ := strconv.Atoi(strings.TrimSuffix(policy["最小密码长度"], "个字符"))
		if minLengthInt < 8 {
			Common.LogDebug("警告：密码最小长度小于8个字符，存在安全风险")
		}

		lockoutThresholdInt, _ := strconv.Atoi(strings.TrimSuffix(policy["账户锁定阈值"], "次"))
		if lockoutThresholdInt == 0 {
			Common.LogDebug("警告：未启用账户锁定策略，存在暴力破解风险")
		}
	} else {
		Common.LogDebug("未获取到任何密码策略配置")
	}

	return policy, nil
}

func (d *DomainInfo) GetSPNs() (map[string][]string, error) {
	Common.LogDebug("开始查询SPN信息...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(servicePrincipalName=*)",
		[]string{"distinguishedName", "servicePrincipalName", "cn"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("查询SPN失败: %v", err))
		return nil, err
	}

	spns := make(map[string][]string)
	for _, entry := range sr.Entries {
		dn := entry.GetAttributeValue("distinguishedName")
		cn := entry.GetAttributeValue("cn")
		spnList := entry.GetAttributeValues("servicePrincipalName")

		if len(spnList) > 0 {
			key := fmt.Sprintf("SPN：%s", dn)
			spns[key] = spnList
			Common.LogDebug(fmt.Sprintf("发现SPN - CN: %s", cn))
			for _, spn := range spnList {
				Common.LogDebug(fmt.Sprintf("  - %s", spn))
			}
		}
	}

	if len(spns) > 0 {
		Common.LogSuccess(fmt.Sprintf("共发现 %d 个SPN配置", len(spns)))
	} else {
		Common.LogDebug("未发现SPN配置")
	}

	return spns, nil
}

func getDomainController() (string, error) {
	Common.LogDebug("开始查询域控制器地址...")

	// 尝试使用wmic获取当前域名
	Common.LogDebug("正在使用wmic获取域名...")
	cmd := exec.Command("wmic", "computersystem", "get", "domain")
	output, err := cmd.Output()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取域名失败: %v", err))
		return "", fmt.Errorf("获取域名失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		Common.LogError("wmic输出格式异常，未找到域名")
		return "", fmt.Errorf("未找到域名")
	}

	domain := strings.TrimSpace(lines[1])
	if domain == "" {
		Common.LogError("获取到的域名为空")
		return "", fmt.Errorf("域名为空")
	}
	Common.LogDebug(fmt.Sprintf("获取到域名: %s", domain))

	// 使用nslookup查询域控制器
	Common.LogDebug(fmt.Sprintf("正在使用nslookup查询域控制器 (_ldap._tcp.dc._msdcs.%s)...", domain))
	cmd = exec.Command("nslookup", "-type=SRV", fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domain))
	output, err = cmd.Output()
	if err != nil {
		Common.LogError(fmt.Sprintf("nslookup查询失败: %v", err))
		return "", fmt.Errorf("查询域控制器失败: %v", err)
	}

	// 解析nslookup输出
	lines = strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "svr hostname") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				dcHost := strings.TrimSpace(parts[1])
				dcHost = strings.TrimSuffix(dcHost, ".")
				Common.LogSuccess(fmt.Sprintf("找到域控制器: %s", dcHost))
				return dcHost, nil
			}
		}
	}

	// 尝试使用域名前缀加DC后缀
	Common.LogDebug("未从nslookup获取到域控制器，尝试使用域名前缀...")
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 0 {
		dcHost := fmt.Sprintf("dc.%s", domain)
		Common.LogDebug(fmt.Sprintf("使用备选域控制器地址: %s", dcHost))
		return dcHost, nil
	}

	Common.LogError("无法获取域控制器地址")
	return "", fmt.Errorf("无法获取域控制器地址")
}

func NewDomainInfo() (*DomainInfo, error) {
	Common.LogDebug("开始初始化域信息...")

	// 获取域控制器地址
	Common.LogDebug("正在获取域控制器地址...")
	dcHost, err := getDomainController()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取域控制器失败: %v", err))
		return nil, fmt.Errorf("获取域控制器失败: %v", err)
	}
	Common.LogDebug(fmt.Sprintf("成功获取域控制器地址: %s", dcHost))

	// 创建SSPI客户端
	Common.LogDebug("正在创建SSPI客户端...")
	ldapClient, err := gssapi.NewSSPIClient()
	if err != nil {
		Common.LogError(fmt.Sprintf("创建SSPI客户端失败: %v", err))
		return nil, fmt.Errorf("创建SSPI客户端失败: %v", err)
	}
	defer ldapClient.Close()
	Common.LogDebug("SSPI客户端创建成功")

	// 创建LDAP连接
	Common.LogDebug(fmt.Sprintf("正在连接LDAP服务器 ldap://%s:389", dcHost))
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcHost))
	if err != nil {
		Common.LogError(fmt.Sprintf("LDAP连接失败: %v", err))
		return nil, fmt.Errorf("LDAP连接失败: %v", err)
	}
	Common.LogDebug("LDAP连接建立成功")

	// 使用GSSAPI进行绑定
	Common.LogDebug(fmt.Sprintf("正在进行GSSAPI绑定 (ldap/%s)...", dcHost))
	err = conn.GSSAPIBind(ldapClient, fmt.Sprintf("ldap/%s", dcHost), "")
	if err != nil {
		conn.Close()
		Common.LogError(fmt.Sprintf("GSSAPI绑定失败: %v", err))
		return nil, fmt.Errorf("GSSAPI绑定失败: %v", err)
	}
	Common.LogDebug("GSSAPI绑定成功")

	// 获取defaultNamingContext
	Common.LogDebug("正在查询defaultNamingContext...")
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		conn.Close()
		Common.LogError(fmt.Sprintf("获取defaultNamingContext失败: %v", err))
		return nil, fmt.Errorf("获取defaultNamingContext失败: %v", err)
	}

	if len(result.Entries) == 0 {
		conn.Close()
		Common.LogError("未找到defaultNamingContext")
		return nil, fmt.Errorf("未找到defaultNamingContext")
	}

	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		Common.LogDebug("defaultNamingContext为空，使用备选方法获取BaseDN")
		baseDN = getDomainDN(dcHost) // 使用备选方法
	}

	Common.LogSuccess(fmt.Sprintf("初始化完成，使用BaseDN: %s", baseDN))

	return &DomainInfo{
		conn:   conn,
		baseDN: baseDN,
	}, nil
}

func DCInfoScan(info *Common.HostInfo) (err error) {

	// 创建DomainInfo实例
	Common.LogDebug("正在初始化域信息...")
	di, err := NewDomainInfo()
	if err != nil {
		Common.LogError(fmt.Sprintf("初始化域信息失败: %v", err))
		return err
	}
	defer di.Close()

	// 获取特殊计算机列表
	specialComputers, err := di.GetSpecialComputers()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取特殊计算机失败: %v", err))
	} else {
		categories := []string{
			"SQL服务器",
			"CA服务器",
			"域控制器",
			"Exchange服务器",
		}

		Common.LogSuccess("[*] 特殊计算机信息:")
		for _, category := range categories {
			if computers, ok := specialComputers[category]; ok {
				Common.LogSuccess(fmt.Sprintf("[+] %s:", category))
				for _, computer := range computers {
					Common.LogSuccess(fmt.Sprintf("    %s", computer))
				}
			}
		}
	}

	// 获取域用户
	users, err := di.GetDomainUsers()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取域用户失败: %v", err))
	} else {
		Common.LogSuccess("[*] 域用户列表:")
		for _, user := range users {
			Common.LogSuccess(fmt.Sprintf("    %s", user))
		}
	}

	// 获取域管理员
	admins, err := di.GetDomainAdmins()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取域管理员失败: %v", err))
	} else {
		Common.LogSuccess("[*] 域管理员列表:")
		for _, admin := range admins {
			Common.LogSuccess(fmt.Sprintf("    %s", admin))
		}
	}

	// 获取组织单位
	ous, err := di.GetOUs()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取组织单位失败: %v", err))
	} else {
		Common.LogSuccess("[*] 组织单位:")
		for _, ou := range ous {
			Common.LogSuccess(fmt.Sprintf("    %s", ou))
		}
	}

	// 获取域计算机
	computers, err := di.GetComputers()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取域计算机失败: %v", err))
	} else {
		Common.LogSuccess("[*] 域计算机:")
		for _, computer := range computers {
			if computer.OperatingSystem != "" {
				Common.LogSuccess(fmt.Sprintf("    %s --> %s", computer.Name, computer.OperatingSystem))
			} else {
				Common.LogSuccess(fmt.Sprintf("    %s", computer.Name))
			}
		}
	}

	// 获取信任域关系
	trustDomains, err := di.GetTrustDomains()
	if err == nil && len(trustDomains) > 0 {
		Common.LogSuccess("[*] 信任域关系:")
		for _, domain := range trustDomains {
			Common.LogSuccess(fmt.Sprintf("    %s", domain))
		}
	}

	// 获取域管理员组信息
	adminGroups, err := di.GetAdminGroups()
	if err == nil && len(adminGroups) > 0 {
		Common.LogSuccess("[*] 管理员组信息:")
		for groupName, members := range adminGroups {
			Common.LogSuccess(fmt.Sprintf("[+] %s成员:", groupName))
			for _, member := range members {
				Common.LogSuccess(fmt.Sprintf("    %s", member))
			}
		}
	}

	// 获取委派信息
	delegations, err := di.GetDelegation()
	if err == nil && len(delegations) > 0 {
		Common.LogSuccess("[*] 委派信息:")
		for delegationType, entries := range delegations {
			Common.LogSuccess(fmt.Sprintf("[+] %s:", delegationType))
			for _, entry := range entries {
				Common.LogSuccess(fmt.Sprintf("    %s", entry))
			}
		}
	}

	// 获取AS-REP Roasting漏洞用户
	asrepUsers, err := di.GetAsrepRoastUsers()
	if err == nil && len(asrepUsers) > 0 {
		Common.LogSuccess("[*] AS-REP弱口令账户:")
		for _, user := range asrepUsers {
			Common.LogSuccess(fmt.Sprintf("    %s", user))
		}
	}

	// 获取域密码策略
	passwordPolicy, err := di.GetPasswordPolicy()
	if err == nil && len(passwordPolicy) > 0 {
		Common.LogSuccess("[*] 域密码策略:")
		for key, value := range passwordPolicy {
			Common.LogSuccess(fmt.Sprintf("    %s: %s", key, value))
		}
	}

	// 获取SPN信息
	spns, err := di.GetSPNs()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取SPN信息失败: %v", err))
	} else if len(spns) > 0 {
		Common.LogSuccess("[*] SPN信息:")
		for dn, spnList := range spns {
			Common.LogSuccess(fmt.Sprintf("[+] %s", dn))
			for _, spn := range spnList {
				Common.LogSuccess(fmt.Sprintf("    %s", spn))
			}
		}
	}

	return nil
}

// 辅助函数：从服务器地址获取域DN
func getDomainDN(server string) string {
	parts := strings.Split(server, ".")
	var dn []string
	for _, part := range parts {
		dn = append(dn, fmt.Sprintf("DC=%s", part))
	}
	return strings.Join(dn, ",")
}
