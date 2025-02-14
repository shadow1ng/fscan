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

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
	Common.LogDebug("尝试匿名访问...")

	// 首先尝试匿名访问
	flag, err := LDAPConn(info, "", "")
	if flag && err == nil {
		// 记录匿名访问成功
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
		Common.LogSuccess(fmt.Sprintf("LDAP服务 %s 匿名访问成功", target))
		return err
	}

	totalUsers := len(Common.Userdict["ldap"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["ldap"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
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
						// 记录成功爆破的凭据
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
						Common.LogSuccess(fmt.Sprintf("LDAP服务 %s 爆破成功 用户名: %v 密码: %v", target, user, pass))
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("LDAP服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v", target, user, pass, err)
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

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", tried))
	return tmperr
}

func LDAPConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	address := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	timeout := time.Duration(Common.Timeout) * time.Second

	// 配置LDAP连接
	l, err := ldap.Dial("tcp", address)
	if err != nil {
		return false, err
	}
	defer l.Close()

	// 设置超时
	l.SetTimeout(timeout)

	// 尝试绑定
	if user != "" {
		bindDN := fmt.Sprintf("cn=%s,dc=example,dc=com", user)
		err = l.Bind(bindDN, pass)
	} else {
		err = l.UnauthenticatedBind("")
	}

	if err != nil {
		return false, err
	}

	// 尝试简单搜索以验证权限
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
