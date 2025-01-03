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

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	Common.LogDebug("尝试匿名访问...")

	// 首先尝试匿名访问
	flag, err := LDAPConn(info, "", "")
	if flag && err == nil {
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

				// 执行LDAP连接
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

				// 等待结果或超时
				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				// 处理错误情况
				if err != nil {
					errlog := fmt.Sprintf("LDAP服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					// 检查是否需要重试
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue // 继续重试
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
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second
	address := fmt.Sprintf("%s:%s", host, port)

	Common.LogDebug(fmt.Sprintf("尝试连接: %s", address))

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
		// 构造DN
		bindDN := fmt.Sprintf("cn=%s,dc=example,dc=com", user)
		err = l.Bind(bindDN, pass)
	} else {
		// 匿名绑定
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

	// 记录成功结果
	result := fmt.Sprintf("LDAP服务 %v:%v ", host, port)
	if user != "" {
		result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
	} else {
		result += "匿名访问成功"
	}
	Common.LogSuccess(result)

	return true, nil
}
