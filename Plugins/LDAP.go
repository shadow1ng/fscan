package Plugins

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

func LDAPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug("Attempting anonymous access...")

	// First try anonymous access
	flag, err := LDAPConn(info, "", "")
	if flag && err == nil {
		// Record successful anonymous access
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":    info.Ports,
				"service": "ldap",
				"type":    "anonymous-access",
			},
		}
		Common.SaveResult(result)
		Common.LogSuccess(fmt.Sprintf("LDAP service %s anonymous access successful", target))
		return err
	}

	totalUsers := len(Common.Userdict["ldap"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate over all username and password combinations
	for _, user := range Common.Userdict["ldap"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			// Retry loop
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retry %d: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := LDAPConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						// Record successful brute force credentials
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "ldap",
								"username": user,
								"password": pass,
								"type":     "weak-password",
							},
						}
						Common.SaveResult(vulnResult)
						Common.LogSuccess(fmt.Sprintf("LDAP service %s brute force successful Username: %v Password: %v", target, user, pass))
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("connection timeout")
				}

				if err != nil {
					errlog := fmt.Sprintf("LDAP service %s attempt failed Username: %v Password: %v Error: %v", target, user, pass, err)
					Common.LogError(errlog)

					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue
					}
				}
				break
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("Scan complete, tried %d combinations", tried))
	return tmperr
}

func LDAPConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	address := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	timeout := time.Duration(Common.Timeout) * time.Second

	// Configure LDAP connection
	l, err := ldap.Dial("tcp", address)
	if err != nil {
		return false, err
	}
	defer l.Close()

	// Set timeout
	l.SetTimeout(timeout)

	// Attempt to bind
	if user != "" {
		bindDN := fmt.Sprintf("cn=%s,dc=example,dc=com", user)
		err = l.Bind(bindDN, pass)
	} else {
		err = l.UnauthenticatedBind("")
	}

	if err != nil {
		return false, err
	}

	// Attempt a simple search to verify permissions
	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = l.Search(searchRequest)
	if err != nil {
		return false, err
	}

	return true, nil
}
