//go:build windows

package Plugins

import (
	"fmt"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/shadow1ng/fscan/Common"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/go-ldap/ldap/v3"
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
	// 在Configuration容器中查找CA服务器
	searchRequest := ldap.NewSearchRequest(
		"CN=Configuration,"+d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=pKIEnrollmentService))", // CA服务器的查询条件
		[]string{"cn", "dNSHostName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		return nil, err
	}

	var caComputers []string
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			caComputers = append(caComputers, cn)
		}
	}
	return caComputers, nil
}

func (d *DomainInfo) GetExchangeServers() ([]string, error) {
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
		return nil, err
	}

	var exchangeServers []string
	for _, entry := range sr.Entries {
		for _, member := range entry.GetAttributeValues("member") {
			if member != "" {
				exchangeServers = append(exchangeServers, member)
			}
		}
	}

	// 移除第一个条目（如果存在）
	if len(exchangeServers) > 1 {
		exchangeServers = exchangeServers[1:]
	}

	return exchangeServers, nil
}

func (d *DomainInfo) GetMsSqlServers() ([]string, error) {
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
		return nil, err
	}

	var sqlServers []string
	for _, entry := range sr.Entries {
		name := entry.GetAttributeValue("name")
		if name != "" {
			sqlServers = append(sqlServers, name)
		}
	}

	return sqlServers, nil
}

func (d *DomainInfo) GetSpecialComputers() (map[string][]string, error) {
	results := make(map[string][]string)

	// 获取SQL Server
	sqlServers, err := d.GetMsSqlServers()
	if err == nil && len(sqlServers) > 0 {
		results["SQL服务器"] = sqlServers
	}

	// 获取CA服务器
	caComputers, err := d.GetCAComputers()
	if err == nil && len(caComputers) > 0 {
		results["CA服务器"] = caComputers
	}

	// 获取域控制器
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
			}
		}
		if len(dcs) > 0 {
			results["域控制器"] = dcs
		}
	}

	// 获取Exchange服务器
	exchangeServers, err := d.GetExchangeServers()
	if err == nil && len(exchangeServers) > 0 {
		results["Exchange服务器"] = exchangeServers
	}

	return results, nil
}

// 获取域用户
func (d *DomainInfo) GetDomainUsers() ([]string, error) {

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
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		users = append(users, entry.GetAttributeValue("sAMAccountName"))
	}

	return users, nil
}

// 获取域管理员
func (d *DomainInfo) GetDomainAdmins() ([]string, error) {
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
		return nil, err
	}

	var admins []string
	if len(sr.Entries) > 0 {
		// 获取组成员
		members := sr.Entries[0].GetAttributeValues("member")

		// 对每个成员DN执行查询以获取其sAMAccountName
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
				continue // 跳过出错的成员
			}

			if len(memberResult.Entries) > 0 {
				samAccountName := memberResult.Entries[0].GetAttributeValue("sAMAccountName")
				if samAccountName != "" {
					admins = append(admins, samAccountName)
				}
			}
		}
	}

	return admins, nil
}

// 获取组织单位(OU)
func (d *DomainInfo) GetOUs() ([]string, error) {
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
		return nil, err
	}

	var ous []string
	for _, entry := range sr.Entries {
		ou := entry.GetAttributeValue("ou")
		if ou != "" {
			ous = append(ous, ou)
		}
	}
	return ous, nil
}

func (d *DomainInfo) GetComputers() ([]Computer, error) {
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
	}
	return computers, nil
}

// 定义计算机结构体
type Computer struct {
	Name            string
	OperatingSystem string
	DNSHostName     string
}

// 获取信任域关系
func (d *DomainInfo) GetTrustDomains() ([]string, error) {
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
		return nil, err
	}

	var trustInfo []string
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			trustInfo = append(trustInfo, cn)
		}
	}
	return trustInfo, nil
}

// 获取域管理员组成员
func (d *DomainInfo) GetAdminGroups() (map[string][]string, error) {
	adminGroups := map[string]string{
		"Domain Admins":     "(&(objectClass=group)(cn=Domain Admins))",
		"Enterprise Admins": "(&(objectClass=group)(cn=Enterprise Admins))",
		"Administrators":    "(&(objectClass=group)(cn=Administrators))",
	}

	results := make(map[string][]string)

	for groupName, filter := range adminGroups {
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
			continue
		}

		if len(sr.Entries) > 0 {
			members := sr.Entries[0].GetAttributeValues("member")
			if len(members) > 0 {
				results[groupName] = members
			}
		}
	}
	return results, nil
}

// 获取委派信息
func (d *DomainInfo) GetDelegation() (map[string][]string, error) {
	delegationQueries := map[string]string{
		"非约束委派":     "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
		"约束委派":      "(msDS-AllowedToDelegateTo=*)",
		"基于资源的约束委派": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
	}

	results := make(map[string][]string)

	for delegationType, query := range delegationQueries {
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
			continue
		}

		var entries []string
		for _, entry := range sr.Entries {
			cn := entry.GetAttributeValue("cn")
			if cn != "" {
				entries = append(entries, cn)
			}
		}

		if len(entries) > 0 {
			results[delegationType] = entries
		}
	}
	return results, nil
}

// 获取AS-REP Roasting漏洞用户
func (d *DomainInfo) GetAsrepRoastUsers() ([]string, error) {
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
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		if name != "" {
			users = append(users, name)
		}
	}
	return users, nil
}

// 获取域密码策略
func (d *DomainInfo) GetPasswordPolicy() (map[string]string, error) {
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
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("未找到密码策略信息")
	}

	policy := make(map[string]string)
	entry := sr.Entries[0]

	// 转换最大密码期限（负值，以100纳秒为单位）
	if maxAge := entry.GetAttributeValue("maxPwdAge"); maxAge != "" {
		maxAgeInt, _ := strconv.ParseInt(maxAge, 10, 64)
		if maxAgeInt != 0 {
			days := float64(maxAgeInt) * -1 / float64(864000000000)
			policy["最大密码期限"] = fmt.Sprintf("%.0f天", days)
		}
	}

	if minLength := entry.GetAttributeValue("minPwdLength"); minLength != "" {
		policy["最小密码长度"] = minLength + "个字符"
	}

	if historyLength := entry.GetAttributeValue("pwdHistoryLength"); historyLength != "" {
		policy["密码历史长度"] = historyLength + "个"
	}

	if lockoutThreshold := entry.GetAttributeValue("lockoutThreshold"); lockoutThreshold != "" {
		policy["账户锁定阈值"] = lockoutThreshold + "次"
	}

	return policy, nil
}

// 获取SPN信息
func (d *DomainInfo) GetSPNs() (map[string][]string, error) {
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
		return nil, err
	}

	spns := make(map[string][]string)
	for _, entry := range sr.Entries {
		dn := entry.GetAttributeValue("distinguishedName")
		_ = entry.GetAttributeValue("cn")
		spnList := entry.GetAttributeValues("servicePrincipalName")
		if len(spnList) > 0 {
			key := fmt.Sprintf("[*] SPN：%s", dn)
			spns[key] = spnList
		}
	}
	return spns, nil
}

// 获取域控制器地址
func getDomainController() (string, error) {
	// 先尝试使用 wmic 获取当前域名
	cmd := exec.Command("wmic", "computersystem", "get", "domain")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("获取域名失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("未找到域名")
	}

	domain := strings.TrimSpace(lines[1])
	if domain == "" {
		return "", fmt.Errorf("域名为空")
	}

	// 使用 nslookup 查询域控制器
	cmd = exec.Command("nslookup", "-type=SRV", fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domain))
	output, err = cmd.Output()
	if err != nil {
		return "", fmt.Errorf("查询域控制器失败: %v", err)
	}

	// 解析 nslookup 输出
	lines = strings.Split(string(output), "\n")
	for _, line := range lines {
		// 查找包含域控制器主机名的行
		if strings.Contains(line, "svr hostname") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				dcHost := strings.TrimSpace(parts[1])
				// 移除末尾的点号（如果存在）
				dcHost = strings.TrimSuffix(dcHost, ".")
				return dcHost, nil
			}
		}
	}

	// 如果上述方法失败，尝试直接使用域名前缀加上 DC 后缀
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 0 {
		return fmt.Sprintf("dc.%s", domain), nil
	}

	return "", fmt.Errorf("无法获取域控制器地址")
}

func NewDomainInfo() (*DomainInfo, error) {
	// 获取域控制器地址
	dcHost, err := getDomainController()
	if err != nil {
		return nil, fmt.Errorf("获取域控制器失败: %v", err)
	}

	// 创建SSPI客户端
	ldapClient, err := gssapi.NewSSPIClient()
	if err != nil {
		return nil, fmt.Errorf("创建SSPI客户端失败: %v", err)
	}
	defer ldapClient.Close()

	// 创建LDAP连接
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcHost))
	if err != nil {
		return nil, fmt.Errorf("LDAP连接失败: %v", err)
	}

	// 使用GSSAPI进行绑定
	err = conn.GSSAPIBind(ldapClient, fmt.Sprintf("ldap/%s", dcHost), "")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("GSSAPI绑定失败: %v", err)
	}

	// 先执行一个根搜索来获取defaultNamingContext
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
		return nil, fmt.Errorf("获取defaultNamingContext失败: %v", err)
	}

	if len(result.Entries) == 0 {
		conn.Close()
		return nil, fmt.Errorf("未找到defaultNamingContext")
	}

	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		baseDN = getDomainDN(dcHost) // 使用备选方法
	}

	fmt.Printf("Using BaseDN: %s\n", baseDN) // 添加调试输出

	return &DomainInfo{
		conn:   conn,
		baseDN: baseDN,
	}, nil
}

// 检查是否在域环境中
func IsInDomain() bool {
	// 获取计算机域成员身份信息
	var joinStatus uint32
	var buffer uint32

	ret, _, _ := syscall.NewLazyDLL("netapi32.dll").NewProc("NetGetJoinInformation").Call(
		0,
		uintptr(unsafe.Pointer(&joinStatus)),
		uintptr(unsafe.Pointer(&buffer)),
	)

	if ret == 0 {
		// 清理资源
		syscall.NewLazyDLL("netapi32.dll").NewProc("NetApiBufferFree").Call(uintptr(buffer))
		// 检查是否为域成员
		return joinStatus == 3 // 3 = NetSetupDomainName 表示是域成员
	}
	return false
}

func DCInfoScan(info *Common.HostInfo) (err error) {
	if !IsInDomain() {
		return fmt.Errorf("当前系统不在域环境中")
	}

	// 创建DomainInfo实例，使用当前用户凭据
	di, err := NewDomainInfo()
	if err != nil {
		log.Fatal(err)
	}
	defer di.Close()

	// 首先获取特殊计算机列表
	specialComputers, err := di.GetSpecialComputers()
	if err != nil {
		log.Printf("获取特殊计算机失败: %v", err)
	} else {
		// 按固定顺序显示结果
		categories := []string{
			"SQL服务器",
			"CA服务器",
			"域控制器",
			"Exchange服务器",
		}

		for _, category := range categories {
			if computers, ok := specialComputers[category]; ok {
				fmt.Printf("[*] %s:\n", category)
				for _, computer := range computers {
					fmt.Printf("\t%s\n", computer)
				}
			}
		}
		fmt.Println()
	}

	users, err := di.GetDomainUsers()
	if err != nil {
		log.Printf("获取域用户失败: %v", err)
		return
	}

	// 打印用户信息
	fmt.Println("[*] 域用户:")
	for _, user := range users {
		fmt.Println("\t" + user)
	}

	// 获取域管理员
	admins, err := di.GetDomainAdmins()
	if err != nil {
		log.Printf("获取域管理员失败: %v", err)
		return
	}

	// 打印域管理员信息
	fmt.Println("[*] 域管理员:")
	for _, admin := range admins {
		fmt.Println("\t" + admin)
	}

	// 获取组织单位
	ous, err := di.GetOUs()
	if err != nil {
		log.Printf("获取组织单位失败: %v", err)
		return
	}

	// 打印组织单位信息
	fmt.Println("[*] 组织单位:")
	for _, ou := range ous {
		fmt.Println("\t" + ou)
	}

	// 获取域计算机
	computers, err := di.GetComputers()
	if err != nil {
		log.Printf("获取域计算机失败: %v", err)
		return
	}

	// 打印域计算机信息
	fmt.Println("[*] 域计算机:")
	for _, computer := range computers {
		fmt.Printf("\t%s", computer.Name)
		if computer.OperatingSystem != "" {
			fmt.Printf(" --> %s", computer.OperatingSystem)
		}
		fmt.Println()
	}

	// 获取并显示信任域关系
	trustDomains, err := di.GetTrustDomains()
	if err == nil {
		fmt.Println("[*] 信任域关系:")
		for _, domain := range trustDomains {
			fmt.Printf("\t%s\n", domain)
		}
		fmt.Println()
	}

	// 获取并显示域管理员组信息
	adminGroups, err := di.GetAdminGroups()
	if err == nil {
		for groupName, members := range adminGroups {
			fmt.Printf("[*] %s成员:\n", groupName)
			for _, member := range members {
				fmt.Printf("\t%s\n", member)
			}
			fmt.Println()
		}
	}

	// 获取并显示委派信息
	delegations, err := di.GetDelegation()
	if err == nil {
		for delegationType, entries := range delegations {
			fmt.Printf("[*] %s:\n", delegationType)
			for _, entry := range entries {
				fmt.Printf("\t%s\n", entry)
			}
			fmt.Println()
		}
	}

	// 获取并显示AS-REP Roasting漏洞用户
	asrepUsers, err := di.GetAsrepRoastUsers()
	if err == nil {
		fmt.Println("[*] AS-REP弱口令账户:")
		for _, user := range asrepUsers {
			fmt.Printf("\t%s\n", user)
		}
		fmt.Println()
	}

	// 获取并显示域密码策略
	passwordPolicy, err := di.GetPasswordPolicy()
	if err == nil {
		fmt.Println("[*] 域密码策略:")
		for key, value := range passwordPolicy {
			fmt.Printf("\t%s: %s\n", key, value)
		}
		fmt.Println()
	}

	// 获取SPN信息
	spns, err := di.GetSPNs()
	if err != nil {
		log.Printf("获取SPN信息失败: %v", err)
		return
	}

	// 打印SPN信息
	if len(spns) > 0 {
		for dn, spnList := range spns {
			fmt.Println(dn)
			for _, spn := range spnList {
				fmt.Printf("\t%s\n", spn)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("[*] 未发现SPN信息\n")
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
