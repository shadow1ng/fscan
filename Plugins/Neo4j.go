package Plugins

import (
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

func Neo4jScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 首先测试无认证访问和默认凭证
	initialChecks := []struct {
		user string
		pass string
	}{
		{"", ""},           // 无认证
		{"neo4j", "neo4j"}, // 默认凭证
	}

	Common.LogDebug("尝试默认凭证...")
	for _, check := range initialChecks {
		Common.LogDebug(fmt.Sprintf("尝试: %s:%s", check.user, check.pass))
		flag, err := Neo4jConn(info, check.user, check.pass)
		if flag && err == nil {
			var msg string
			if check.user == "" {
				msg = fmt.Sprintf("Neo4j服务 %s 无需认证即可访问", target)
				Common.LogSuccess(msg)

				// 保存结果 - 无认证访问
				result := &Common.ScanResult{
					Time:   time.Now(),
					Type:   Common.VULN,
					Target: info.Host,
					Status: "vulnerable",
					Details: map[string]interface{}{
						"port":    info.Ports,
						"service": "neo4j",
						"type":    "unauthorized-access",
					},
				}
				Common.SaveResult(result)
			} else {
				msg = fmt.Sprintf("Neo4j服务 %s 默认凭证可用 用户名: %s 密码: %s", target, check.user, check.pass)
				Common.LogSuccess(msg)

				// 保存结果 - 默认凭证
				result := &Common.ScanResult{
					Time:   time.Now(),
					Type:   Common.VULN,
					Target: info.Host,
					Status: "vulnerable",
					Details: map[string]interface{}{
						"port":     info.Ports,
						"service":  "neo4j",
						"type":     "default-credentials",
						"username": check.user,
						"password": check.pass,
					},
				}
				Common.SaveResult(result)
			}
			return err
		}
	}

	totalUsers := len(Common.Userdict["neo4j"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["neo4j"] {
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
					flag, err := Neo4jConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						msg := fmt.Sprintf("Neo4j服务 %s 爆破成功 用户名: %s 密码: %s", target, user, pass)
						Common.LogSuccess(msg)

						// 保存结果 - 成功爆破
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "neo4j",
								"type":     "weak-password",
								"username": user,
								"password": pass,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("Neo4j服务 %s 尝试失败 用户名: %s 密码: %s 错误: %v", target, user, pass, err)
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

// Neo4jConn 尝试 Neo4j 连接
func Neo4jConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造Neo4j URL
	uri := fmt.Sprintf("bolt://%s:%s", host, port)

	// 配置驱动选项
	config := func(c *neo4j.Config) {
		c.SocketConnectTimeout = timeout
	}

	var driver neo4j.Driver
	var err error

	// 尝试建立连接
	if user != "" || pass != "" {
		// 有认证信息时使用认证
		driver, err = neo4j.NewDriver(uri, neo4j.BasicAuth(user, pass, ""), config)
	} else {
		// 无认证时使用NoAuth
		driver, err = neo4j.NewDriver(uri, neo4j.NoAuth(), config)
	}

	if err != nil {
		return false, err
	}
	defer driver.Close()

	// 测试连接
	err = driver.VerifyConnectivity()
	if err != nil {
		return false, err
	}

	return true, nil
}
