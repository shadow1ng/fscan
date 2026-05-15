//go:build (plugin_dcinfo || !plugin_selective) && windows && !no_local

package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// DCInfoPlugin 域控信息收集插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现域信息收集功能
// - 保持原有功能逻辑
type DCInfoPlugin struct {
	plugins.BasePlugin
}

// DomainInfo 域信息结构
type DomainInfo struct {
	Domain   string
	BaseDN   string
	LDAPConn *ldap.Conn
}

// NewDCInfoPlugin 创建域控信息收集插件
func NewDCInfoPlugin() *DCInfoPlugin {
	return &DCInfoPlugin{
		BasePlugin: plugins.NewBasePlugin("dcinfo"),
	}
}

// Scan 执行域控信息收集 - 直接实现
func (p *DCInfoPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	_ = session.Config
	_ = session.State
	var output strings.Builder

	output.WriteString("=== 域控制器信息收集 ===\n")

	// 建立域控连接
	domainConn, err := p.connectToDomain()
	if err != nil {
		if common.ContainsAny(err.Error(), "未加入域", "WORKGROUP") {
			msg := i18n.GetText("dcinfo_not_joined")
			output.WriteString(msg + "，无法执行域信息收集\n")
			common.LogError(msg)
			return &plugins.Result{
				Success: false,
				Output:  output.String(),
				Error:   errors.New(msg),
			}
		}
		output.WriteString(fmt.Sprintf("域控连接失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("域控连接失败: %w", err),
		}
	}
	defer func() {
		if domainConn.LDAPConn != nil {
			_ = domainConn.LDAPConn.Close()
		}
	}()

	output.WriteString(fmt.Sprintf("成功连接到域: %s\n", domainConn.Domain))
	output.WriteString(fmt.Sprintf("Base DN: %s\n\n", domainConn.BaseDN))

	var successCount int

	// 收集域基本信息
	if domainInfo, err := p.getDomainInfo(domainConn); err == nil {
		output.WriteString("✓ 域基本信息:\n")
		p.logDomainInfoToOutput(&output, domainInfo)
		successCount++
	} else {
		output.WriteString(fmt.Sprintf("✗ 获取域基本信息失败: %v\n", err))
	}

	// 获取域控制器信息
	if domainControllers, err := p.getDomainControllers(domainConn); err == nil {
		output.WriteString("✓ 域控制器信息:\n")
		p.logDomainControllersToOutput(&output, domainControllers)
		successCount++
	} else {
		output.WriteString(fmt.Sprintf("✗ 获取域控制器信息失败: %v\n", err))
	}

	// 获取域用户信息
	if users, err := p.getDomainUsersDetailed(domainConn); err == nil {
		output.WriteString("✓ 域用户信息:\n")
		p.logDomainUsersToOutput(&output, users)
		successCount++
	} else {
		output.WriteString(fmt.Sprintf("✗ 获取域用户失败: %v\n", err))
	}

	// 获取域管理员信息
	if admins, err := p.getDomainAdminsDetailed(domainConn); err == nil {
		output.WriteString("✓ 域管理员信息:\n")
		p.logDomainAdminsToOutput(&output, admins)
		successCount++
	} else {
		output.WriteString(fmt.Sprintf("✗ 获取域管理员失败: %v\n", err))
	}

	// 获取域计算机信息
	if computers, err := p.getComputersDetailed(domainConn); err == nil {
		output.WriteString("✓ 域计算机信息:\n")
		p.logComputersToOutput(&output, computers)
		successCount++
	} else {
		output.WriteString(fmt.Sprintf("✗ 获取域计算机失败: %v\n", err))
	}

	// 获取组策略信息
	if gpos, err := p.getGroupPolicies(domainConn); err == nil {
		output.WriteString("✓ 组策略信息:\n")
		p.logGroupPoliciesToOutput(&output, gpos)
		successCount++
	} else {
		output.WriteString(fmt.Sprintf("✗ 获取组策略失败: %v\n", err))
	}

	// 获取组织单位信息
	if ous, err := p.getOrganizationalUnits(domainConn); err == nil {
		output.WriteString("✓ 组织单位信息:\n")
		p.logOrganizationalUnitsToOutput(&output, ous)
		successCount++
	} else {
		output.WriteString(fmt.Sprintf("✗ 获取组织单位失败: %v\n", err))
	}

	// 输出统计
	output.WriteString(fmt.Sprintf("\n域信息收集完成: 成功(%d) 总计(%d)\n", successCount, 7))

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("dcinfo_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// connectToDomain 连接到域控制器
func (p *DCInfoPlugin) connectToDomain() (*DomainInfo, error) {
	// 获取域控制器地址
	dcHost, domain, err := p.getDomainController()
	if err != nil {
		return nil, fmt.Errorf("获取域控制器失败: %w", err)
	}

	// 建立LDAP连接
	ldapConn, baseDN, err := p.connectToLDAP(dcHost, domain)
	if err != nil {
		return nil, fmt.Errorf("LDAP连接失败: %w", err)
	}

	return &DomainInfo{
		Domain:   domain,
		BaseDN:   baseDN,
		LDAPConn: ldapConn,
	}, nil
}

// getDomainController 获取域控制器地址
func (p *DCInfoPlugin) getDomainController() (string, string, error) {
	// 尝试使用PowerShell获取域名
	domain, err := p.getDomainNamePowerShell()
	if err != nil {
		// 尝试使用wmic
		domain, err = p.getDomainNameWmic()
		if err != nil {
			// 尝试使用环境变量
			domain, err = p.getDomainNameFromEnv()
			if err != nil {
				return "", "", fmt.Errorf("获取域名失败: %w", err)
			}
		}
	}

	if domain == "" || domain == "WORKGROUP" {
		return "", "", fmt.Errorf("当前机器未加入域")
	}

	// 查询域控制器
	dcHost, err := p.findDomainController(domain)
	if err != nil {
		// 备选方案：使用域名直接构造
		dcHost = fmt.Sprintf("dc.%s", domain)
	}

	return dcHost, domain, nil
}

// getDomainNamePowerShell 使用PowerShell获取域名
func (p *DCInfoPlugin) getDomainNamePowerShell() (string, error) {
	cmd := exec.Command("powershell", "-Command", "(Get-WmiObject Win32_ComputerSystem).Domain")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	domain := strings.TrimSpace(string(output))
	if domain == "" || domain == "WORKGROUP" {
		return "", fmt.Errorf("未加入域")
	}

	return domain, nil
}

// getDomainNameWmic 使用wmic获取域名
func (p *DCInfoPlugin) getDomainNameWmic() (string, error) {
	cmd := exec.Command("wmic", "computersystem", "get", "domain", "/value")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Domain=") {
			domain := strings.TrimSpace(strings.TrimPrefix(line, "Domain="))
			if domain != "" && domain != "WORKGROUP" {
				return domain, nil
			}
		}
	}

	return "", fmt.Errorf("未找到域名")
}

// getDomainNameFromEnv 从环境变量获取域名
func (p *DCInfoPlugin) getDomainNameFromEnv() (string, error) {
	cmd := exec.Command("cmd", "/c", "echo %USERDOMAIN%")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	userDomain := strings.ToLower(strings.TrimSpace(string(output)))
	if userDomain != "" && userDomain != "workgroup" && userDomain != "%userdomain%" {
		return userDomain, nil
	}

	return "", fmt.Errorf("从环境变量获取域名失败")
}

// findDomainController 查找域控制器
func (p *DCInfoPlugin) findDomainController(domain string) (string, error) {
	// 使用nslookup查询SRV记录
	cmd := exec.Command("nslookup", "-type=SRV", fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domain))
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if common.ContainsAny(line, "svr hostname", "service") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					dcHost := strings.TrimSpace(parts[len(parts)-1])
					dcHost = strings.TrimSuffix(dcHost, ".")
					if dcHost != "" {
						return dcHost, nil
					}
				}
			}
		}
	}

	// 尝试直接ping域名
	cmd = exec.Command("ping", "-n", "1", domain)
	if err := cmd.Run(); err == nil {
		return domain, nil
	}

	return "", fmt.Errorf("无法找到域控制器")
}

// connectToLDAP 连接到LDAP服务器
func (p *DCInfoPlugin) connectToLDAP(dcHost, domain string) (*ldap.Conn, string, error) {
	// 创建SSPI客户端
	ldapClient, err := gssapi.NewSSPIClient()
	if err != nil {
		return nil, "", fmt.Errorf("创建SSPI客户端失败: %w", err)
	}
	defer func() { _ = ldapClient.Close() }()

	// 尝试连接
	var conn *ldap.Conn
	var lastError error

	// 直接连接
	conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcHost))
	if err != nil {
		lastError = err
		// 尝试使用IPv4地址
		ipv4, resolveErr := p.resolveIPv4(dcHost)
		if resolveErr == nil {
			conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", ipv4))
			if err != nil {
				lastError = err
			}
		} else {
			lastError = resolveErr
		}
	}

	if conn == nil {
		return nil, "", fmt.Errorf("LDAP连接失败: %w", lastError)
	}

	// 使用GSSAPI进行绑定
	err = conn.GSSAPIBind(ldapClient, fmt.Sprintf("ldap/%s", dcHost), "")
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("GSSAPI绑定失败: %w", err)
	}

	// 获取BaseDN
	baseDN, err := p.getBaseDN(conn, domain)
	if err != nil {
		_ = conn.Close()
		return nil, "", err
	}

	return conn, baseDN, nil
}

// getBaseDN 获取BaseDN
func (p *DCInfoPlugin) getBaseDN(conn *ldap.Conn, domain string) (string, error) {
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
		return "", fmt.Errorf("获取defaultNamingContext失败: %w", err)
	}

	if len(result.Entries) == 0 {
		// 备选方案：从域名构造BaseDN
		parts := strings.Split(domain, ".")
		var dn []string
		for _, part := range parts {
			dn = append(dn, fmt.Sprintf("DC=%s", part))
		}
		return strings.Join(dn, ","), nil
	}

	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		return "", fmt.Errorf("获取BaseDN失败")
	}

	return baseDN, nil
}

// resolveIPv4 解析主机名为IPv4地址
func (p *DCInfoPlugin) resolveIPv4(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("未找到IPv4地址")
}

// getDomainInfo 获取域基本信息
func (p *DCInfoPlugin) getDomainInfo(conn *DomainInfo) (map[string]interface{}, error) {
	searchRequest := ldap.NewSearchRequest(
		conn.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"whenCreated", "whenChanged", "objectSid", "msDS-Behavior-Version", "dnsRoot"},
		nil,
	)

	sr, err := conn.LDAPConn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	domainInfo := make(map[string]interface{})
	domainInfo["domain"] = conn.Domain
	domainInfo["base_dn"] = conn.BaseDN

	if len(sr.Entries) > 0 {
		entry := sr.Entries[0]
		domainInfo["created"] = entry.GetAttributeValue("whenCreated")
		domainInfo["modified"] = entry.GetAttributeValue("whenChanged")
		domainInfo["object_sid"] = entry.GetAttributeValue("objectSid")
		domainInfo["functional_level"] = entry.GetAttributeValue("msDS-Behavior-Version")
		domainInfo["dns_root"] = entry.GetAttributeValue("dnsRoot")
	}

	return domainInfo, nil
}

// getDomainControllers 获取域控制器信息
func (p *DCInfoPlugin) getDomainControllers(conn *DomainInfo) ([]map[string]interface{}, error) {
	dcQuery := ldap.NewSearchRequest(
		conn.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack", "whenCreated", "lastLogonTimestamp"},
		nil,
	)

	sr, err := conn.LDAPConn.SearchWithPaging(dcQuery, 10000)
	if err != nil {
		return nil, err
	}

	var dcs []map[string]interface{}
	for _, entry := range sr.Entries {
		dc := make(map[string]interface{})
		dc["name"] = entry.GetAttributeValue("cn")
		dc["dns_name"] = entry.GetAttributeValue("dNSHostName")
		dc["os"] = entry.GetAttributeValue("operatingSystem")
		dc["os_version"] = entry.GetAttributeValue("operatingSystemVersion")
		dc["os_service_pack"] = entry.GetAttributeValue("operatingSystemServicePack")
		dc["created"] = entry.GetAttributeValue("whenCreated")
		dc["last_logon"] = entry.GetAttributeValue("lastLogonTimestamp")
		dcs = append(dcs, dc)
	}

	return dcs, nil
}

// getDomainUsersDetailed 获取域用户信息
func (p *DCInfoPlugin) getDomainUsersDetailed(conn *DomainInfo) ([]map[string]interface{}, error) {
	searchRequest := ldap.NewSearchRequest(
		conn.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "displayName", "mail", "userAccountControl", "whenCreated", "lastLogonTimestamp", "badPwdCount", "pwdLastSet"},
		nil,
	)

	sr, err := conn.LDAPConn.SearchWithPaging(searchRequest, 0)
	if err != nil {
		return nil, err
	}

	var users []map[string]interface{}
	for _, entry := range sr.Entries {
		user := make(map[string]interface{})
		user["username"] = entry.GetAttributeValue("sAMAccountName")
		user["display_name"] = entry.GetAttributeValue("displayName")
		user["email"] = entry.GetAttributeValue("mail")
		user["account_control"] = entry.GetAttributeValue("userAccountControl")
		user["created"] = entry.GetAttributeValue("whenCreated")
		user["last_logon"] = entry.GetAttributeValue("lastLogonTimestamp")
		user["bad_pwd_count"] = entry.GetAttributeValue("badPwdCount")
		user["pwd_last_set"] = entry.GetAttributeValue("pwdLastSet")
		users = append(users, user)
	}

	return users, nil
}

// getDomainAdminsDetailed 获取域管理员信息
func (p *DCInfoPlugin) getDomainAdminsDetailed(conn *DomainInfo) ([]map[string]interface{}, error) {
	// 获取Domain Admins组
	searchRequest := ldap.NewSearchRequest(
		conn.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=group)(cn=Domain Admins))",
		[]string{"member"},
		nil,
	)

	sr, err := conn.LDAPConn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		return nil, err
	}

	var admins []map[string]interface{}
	if len(sr.Entries) > 0 {
		members := sr.Entries[0].GetAttributeValues("member")
		for _, memberDN := range members {
			adminInfo, err := p.getUserInfoByDN(conn, memberDN)
			if err == nil {
				admins = append(admins, adminInfo)
			}
		}
	}

	return admins, nil
}

// getComputersDetailed 获取域计算机信息
func (p *DCInfoPlugin) getComputersDetailed(conn *DomainInfo) ([]map[string]interface{}, error) {
	searchRequest := ldap.NewSearchRequest(
		conn.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"cn", "operatingSystem", "operatingSystemVersion", "dNSHostName", "whenCreated", "lastLogonTimestamp", "userAccountControl"},
		nil,
	)

	sr, err := conn.LDAPConn.SearchWithPaging(searchRequest, 0)
	if err != nil {
		return nil, err
	}

	var computers []map[string]interface{}
	for _, entry := range sr.Entries {
		computer := make(map[string]interface{})
		computer["name"] = entry.GetAttributeValue("cn")
		computer["os"] = entry.GetAttributeValue("operatingSystem")
		computer["os_version"] = entry.GetAttributeValue("operatingSystemVersion")
		computer["dns_name"] = entry.GetAttributeValue("dNSHostName")
		computer["created"] = entry.GetAttributeValue("whenCreated")
		computer["last_logon"] = entry.GetAttributeValue("lastLogonTimestamp")
		computer["account_control"] = entry.GetAttributeValue("userAccountControl")
		computers = append(computers, computer)
	}

	return computers, nil
}

// getUserInfoByDN 根据DN获取用户信息
func (p *DCInfoPlugin) getUserInfoByDN(conn *DomainInfo, userDN string) (map[string]interface{}, error) {
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"sAMAccountName", "displayName", "mail", "whenCreated", "lastLogonTimestamp", "userAccountControl"},
		nil,
	)

	sr, err := conn.LDAPConn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("用户不存在")
	}

	entry := sr.Entries[0]
	userInfo := make(map[string]interface{})
	userInfo["dn"] = userDN
	userInfo["username"] = entry.GetAttributeValue("sAMAccountName")
	userInfo["display_name"] = entry.GetAttributeValue("displayName")
	userInfo["email"] = entry.GetAttributeValue("mail")
	userInfo["created"] = entry.GetAttributeValue("whenCreated")
	userInfo["last_logon"] = entry.GetAttributeValue("lastLogonTimestamp")
	userInfo["group_type"] = "Domain Admins"

	return userInfo, nil
}

// getGroupPolicies 获取组策略信息
func (p *DCInfoPlugin) getGroupPolicies(conn *DomainInfo) ([]map[string]interface{}, error) {
	searchRequest := ldap.NewSearchRequest(
		conn.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=groupPolicyContainer)",
		[]string{"cn", "displayName", "objectClass", "distinguishedName", "whenCreated", "whenChanged", "gPCFileSysPath"},
		nil,
	)

	sr, err := conn.LDAPConn.Search(searchRequest)
	if err != nil {
		sr, err = conn.LDAPConn.SearchWithPaging(searchRequest, 1000)
		if err != nil {
			return nil, err
		}
	}

	var gpos []map[string]interface{}
	for _, entry := range sr.Entries {
		gpo := make(map[string]interface{})
		gpo["guid"] = entry.GetAttributeValue("cn")
		gpo["display_name"] = entry.GetAttributeValue("displayName")
		gpo["created"] = entry.GetAttributeValue("whenCreated")
		gpo["modified"] = entry.GetAttributeValue("whenChanged")
		gpo["file_sys_path"] = entry.GetAttributeValue("gPCFileSysPath")
		gpo["dn"] = entry.GetAttributeValue("distinguishedName")
		gpos = append(gpos, gpo)
	}

	return gpos, nil
}

// getOrganizationalUnits 获取组织单位信息
func (p *DCInfoPlugin) getOrganizationalUnits(conn *DomainInfo) ([]map[string]interface{}, error) {
	searchRequest := ldap.NewSearchRequest(
		conn.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"ou", "cn", "name", "description", "objectClass", "distinguishedName", "whenCreated", "gPLink"},
		nil,
	)

	sr, err := conn.LDAPConn.SearchWithPaging(searchRequest, 100)
	if err != nil {
		return nil, err
	}

	var ous []map[string]interface{}
	for _, entry := range sr.Entries {
		objectClasses := entry.GetAttributeValues("objectClass")
		dn := entry.GetAttributeValue("distinguishedName")

		isOU := false
		isContainer := false
		for _, class := range objectClasses {
			switch class {
			case "organizationalUnit":
				isOU = true
			case "container":
				isContainer = true
			}
		}

		if !isOU && !isContainer {
			continue
		}

		// 获取名称
		name := entry.GetAttributeValue("ou")
		if name == "" {
			name = entry.GetAttributeValue("cn")
		}
		if name == "" {
			name = entry.GetAttributeValue("name")
		}

		// 跳过系统容器
		if strings.Contains(dn, "CN=LostAndFound") ||
			strings.Contains(dn, "CN=Configuration") ||
			strings.Contains(dn, "CN=Schema") ||
			strings.Contains(dn, "CN=System") ||
			strings.Contains(dn, "CN=Program Data") ||
			strings.Contains(dn, "CN=Microsoft") ||
			(strings.HasPrefix(dn, "CN=") && len(name) == 36 && strings.Count(name, "-") == 4) {
			continue
		}

		if name != "" {
			ou := make(map[string]interface{})
			ou["name"] = name
			ou["description"] = entry.GetAttributeValue("description")
			ou["created"] = entry.GetAttributeValue("whenCreated")
			ou["gp_link"] = entry.GetAttributeValue("gPLink")
			ou["dn"] = dn
			ou["is_ou"] = isOU
			ous = append(ous, ou)
		}
	}

	return ous, nil
}

// 输出日志函数
func (p *DCInfoPlugin) logDomainInfoToOutput(output *strings.Builder, domainInfo map[string]interface{}) {
	if domain, ok := domainInfo["domain"]; ok {
		_, _ = fmt.Fprintf(output, "  域名: %v\n", domain)
	}
	if created, ok := domainInfo["created"]; ok && created != "" {
		_, _ = fmt.Fprintf(output, "  创建时间: %v\n", created)
	}
	output.WriteString("\n")
}

func (p *DCInfoPlugin) logDomainControllersToOutput(output *strings.Builder, dcs []map[string]interface{}) {
	_, _ = fmt.Fprintf(output, "  发现 %d 个域控制器\n", len(dcs))
	for _, dc := range dcs {
		if name, ok := dc["name"]; ok {
			_, _ = fmt.Fprintf(output, "  - %v (%v)\n", name, dc["dns_name"])
			if os, ok := dc["os"]; ok && os != "" {
				_, _ = fmt.Fprintf(output, "    操作系统: %v\n", os)
			}
		}
	}
	output.WriteString("\n")
}

func (p *DCInfoPlugin) logDomainUsersToOutput(output *strings.Builder, users []map[string]interface{}) {
	_, _ = fmt.Fprintf(output, "  发现 %d 个域用户\n", len(users))
	count := 0
	for _, user := range users {
		if count >= 10 { // 限制显示数量
			output.WriteString("  ...(更多用户已省略)\n")
			break
		}
		if username, ok := user["username"]; ok && username != "" {
			displayInfo := fmt.Sprintf("  - %v", username)
			if displayName, ok := user["display_name"]; ok && displayName != "" {
				displayInfo += fmt.Sprintf(" (%v)", displayName)
			}
			if email, ok := user["email"]; ok && email != "" {
				displayInfo += fmt.Sprintf(" [%v]", email)
			}
			output.WriteString(displayInfo + "\n")
			count++
		}
	}
	output.WriteString("\n")
}

func (p *DCInfoPlugin) logDomainAdminsToOutput(output *strings.Builder, admins []map[string]interface{}) {
	_, _ = fmt.Fprintf(output, "  发现 %d 个域管理员\n", len(admins))
	for _, admin := range admins {
		if username, ok := admin["username"]; ok && username != "" {
			adminInfo := fmt.Sprintf("  - %v", username)
			if displayName, ok := admin["display_name"]; ok && displayName != "" {
				adminInfo += fmt.Sprintf(" (%v)", displayName)
			}
			if email, ok := admin["email"]; ok && email != "" {
				adminInfo += fmt.Sprintf(" [%v]", email)
			}
			output.WriteString(adminInfo + "\n")
		}
	}
	output.WriteString("\n")
}

func (p *DCInfoPlugin) logComputersToOutput(output *strings.Builder, computers []map[string]interface{}) {
	_, _ = fmt.Fprintf(output, "  发现 %d 台域计算机\n", len(computers))
	count := 0
	for _, computer := range computers {
		if count >= 10 { // 限制显示数量
			output.WriteString("  ...(更多计算机已省略)\n")
			break
		}
		if name, ok := computer["name"]; ok && name != "" {
			computerInfo := fmt.Sprintf("  - %v", name)
			if os, ok := computer["os"]; ok && os != "" {
				computerInfo += fmt.Sprintf(" (%v)", os)
			}
			if dnsName, ok := computer["dns_name"]; ok && dnsName != "" {
				computerInfo += fmt.Sprintf(" [%v]", dnsName)
			}
			output.WriteString(computerInfo + "\n")
			count++
		}
	}
	output.WriteString("\n")
}

func (p *DCInfoPlugin) logGroupPoliciesToOutput(output *strings.Builder, gpos []map[string]interface{}) {
	_, _ = fmt.Fprintf(output, "  发现 %d 个组策略对象\n", len(gpos))
	for _, gpo := range gpos {
		if displayName, ok := gpo["display_name"]; ok && displayName != "" {
			gpoInfo := fmt.Sprintf("  - %v", displayName)
			if guid, ok := gpo["guid"]; ok {
				gpoInfo += fmt.Sprintf(" [%v]", guid)
			}
			output.WriteString(gpoInfo + "\n")
		}
	}
	output.WriteString("\n")
}

func (p *DCInfoPlugin) logOrganizationalUnitsToOutput(output *strings.Builder, ous []map[string]interface{}) {
	_, _ = fmt.Fprintf(output, "  发现 %d 个组织单位和容器\n", len(ous))
	for _, ou := range ous {
		if name, ok := ou["name"]; ok && name != "" {
			ouInfo := fmt.Sprintf("  - %v", name)
			if isOU, ok := ou["is_ou"]; ok {
				if isOUBool, ok := isOU.(bool); ok && isOUBool {
					ouInfo += " [OU]"
				} else {
					ouInfo += " [Container]"
				}
			} else {
				ouInfo += " [Container]"
			}
			if desc, ok := ou["description"]; ok && desc != "" {
				ouInfo += fmt.Sprintf(" 描述: %v", desc)
			}
			output.WriteString(ouInfo + "\n")
		}
	}
	output.WriteString("\n")
}

// 注册插件
func init() {
	RegisterLocalPlugin("dcinfo", func() Plugin {
		return NewDCInfoPlugin()
	})
}
