//go:build (plugin_systeminfo || !plugin_selective) && windows && !no_local

package local

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/shadow1ng/fscan/common"
)

type domainInfo struct {
	Domain   string
	BaseDN   string
	LDAPConn *ldap.Conn
}

func (p *SystemInfoPlugin) collectDomainInfo() {
	domain := p.detectDomain()
	if domain == "" {
		return
	}

	p.logSuccess("systeminfo_dc_detected", domain)

	conn, err := p.connectToDomain(domain)
	if err != nil {
		p.log("systeminfo_dc_connect_failed", err.Error())
		return
	}
	defer func() {
		if conn.LDAPConn != nil {
			_ = conn.LDAPConn.Close()
		}
	}()

	p.log("systeminfo_dc_basedn", conn.BaseDN)

	p.queryDomainBasicInfo(conn)
	p.queryDomainControllers(conn)
	p.queryDomainAdmins(conn)
	p.queryDomainUsers(conn)
	p.queryDomainComputers(conn)
	p.queryGroupPolicies(conn)
}

func (p *SystemInfoPlugin) detectDomain() string {
	// PowerShell
	if out, err := exec.Command("powershell", "-Command", "(Get-WmiObject Win32_ComputerSystem).Domain").Output(); err == nil {
		domain := strings.TrimSpace(string(out))
		if domain != "" && !strings.EqualFold(domain, "WORKGROUP") {
			return domain
		}
	}
	// wmic
	if out, err := exec.Command("wmic", "computersystem", "get", "domain", "/value").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Domain=") {
				domain := strings.TrimSpace(strings.TrimPrefix(line, "Domain="))
				if domain != "" && !strings.EqualFold(domain, "WORKGROUP") {
					return domain
				}
			}
		}
	}
	return ""
}

func (p *SystemInfoPlugin) connectToDomain(domain string) (*domainInfo, error) {
	dcHost, err := p.findDC(domain)
	if err != nil {
		return nil, err
	}

	client, err := gssapi.NewSSPIClient()
	if err != nil {
		return nil, fmt.Errorf("SSPI: %w", err)
	}
	defer func() { _ = client.Close() }()

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcHost))
	if err != nil {
		if ipv4, resolveErr := resolveIPv4(dcHost); resolveErr == nil {
			conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", ipv4))
		}
		if err != nil {
			return nil, fmt.Errorf("LDAP dial: %w", err)
		}
	}

	if err := conn.GSSAPIBind(client, fmt.Sprintf("ldap/%s", dcHost), ""); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("GSSAPI bind: %w", err)
	}

	baseDN, err := p.getBaseDN(conn, domain)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &domainInfo{Domain: domain, BaseDN: baseDN, LDAPConn: conn}, nil
}

func (p *SystemInfoPlugin) findDC(domain string) (string, error) {
	if out, err := exec.Command("nslookup", "-type=SRV", fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domain)).Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if common.ContainsAny(line, "svr hostname", "service") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					host := strings.TrimSpace(parts[len(parts)-1])
					host = strings.TrimSuffix(host, ".")
					if host != "" {
						return host, nil
					}
				}
			}
		}
	}
	if err := exec.Command("ping", "-n", "1", domain).Run(); err == nil {
		return domain, nil
	}
	return "", fmt.Errorf("cannot find DC for %s", domain)
}

func (p *SystemInfoPlugin) getBaseDN(conn *ldap.Conn, domain string) (string, error) {
	sr, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if err == nil && len(sr.Entries) > 0 {
		if dn := sr.Entries[0].GetAttributeValue("defaultNamingContext"); dn != "" {
			return dn, nil
		}
	}
	var parts []string
	for _, p := range strings.Split(domain, ".") {
		parts = append(parts, fmt.Sprintf("DC=%s", p))
	}
	return strings.Join(parts, ","), nil
}

func (p *SystemInfoPlugin) queryDomainBasicInfo(conn *domainInfo) {
	sr, err := conn.LDAPConn.Search(ldap.NewSearchRequest(conn.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"whenCreated", "whenChanged", "msDS-Behavior-Version"}, nil))
	if err != nil {
		return
	}
	if len(sr.Entries) > 0 {
		e := sr.Entries[0]
		if v := e.GetAttributeValue("whenCreated"); v != "" {
			p.log("systeminfo_dc_created", v)
		}
		if v := e.GetAttributeValue("msDS-Behavior-Version"); v != "" {
			p.log("systeminfo_dc_func_level", v)
		}
	}
}

func (p *SystemInfoPlugin) queryDomainControllers(conn *domainInfo) {
	sr, err := conn.LDAPConn.SearchWithPaging(ldap.NewSearchRequest(conn.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", []string{"cn", "dNSHostName", "operatingSystem"}, nil), 1000)
	if err != nil {
		return
	}
	p.logSuccess("systeminfo_dc_controllers", len(sr.Entries))
	for _, e := range sr.Entries {
		p.log("systeminfo_dc_controller_detail", e.GetAttributeValue("cn"), e.GetAttributeValue("dNSHostName"), e.GetAttributeValue("operatingSystem"))
	}
}

func (p *SystemInfoPlugin) queryDomainAdmins(conn *domainInfo) {
	sr, err := conn.LDAPConn.SearchWithPaging(ldap.NewSearchRequest(conn.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectCategory=group)(cn=Domain Admins))", []string{"member"}, nil), 1000)
	if err != nil || len(sr.Entries) == 0 {
		return
	}
	members := sr.Entries[0].GetAttributeValues("member")
	p.logSuccess("systeminfo_dc_admins", len(members))
	for _, dn := range members {
		userSr, err := conn.LDAPConn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"sAMAccountName", "displayName"}, nil))
		if err == nil && len(userSr.Entries) > 0 {
			p.log("systeminfo_dc_admin_detail", userSr.Entries[0].GetAttributeValue("sAMAccountName"), userSr.Entries[0].GetAttributeValue("displayName"))
		}
	}
}

func (p *SystemInfoPlugin) queryDomainUsers(conn *domainInfo) {
	sr, err := conn.LDAPConn.SearchWithPaging(ldap.NewSearchRequest(conn.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectCategory=person)(objectClass=user))", []string{"sAMAccountName"}, nil), 0)
	if err != nil {
		return
	}
	p.log("systeminfo_dc_users", len(sr.Entries))
}

func (p *SystemInfoPlugin) queryDomainComputers(conn *domainInfo) {
	sr, err := conn.LDAPConn.SearchWithPaging(ldap.NewSearchRequest(conn.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=8192))", []string{"cn", "operatingSystem"}, nil), 0)
	if err != nil {
		return
	}
	p.log("systeminfo_dc_computers", len(sr.Entries))
	for _, e := range sr.Entries {
		os := e.GetAttributeValue("operatingSystem")
		if os != "" {
			p.log("systeminfo_dc_computer_detail", e.GetAttributeValue("cn"), os)
		}
	}
}

func (p *SystemInfoPlugin) queryGroupPolicies(conn *domainInfo) {
	sr, err := conn.LDAPConn.SearchWithPaging(ldap.NewSearchRequest(conn.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=groupPolicyContainer)", []string{"displayName", "cn"}, nil), 1000)
	if err != nil {
		return
	}
	p.log("systeminfo_dc_gpos", len(sr.Entries))
	for _, e := range sr.Entries {
		if name := e.GetAttributeValue("displayName"); name != "" {
			p.log("systeminfo_dc_gpo_detail", name, e.GetAttributeValue("cn"))
		}
	}
}

func resolveIPv4(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 found")
}
