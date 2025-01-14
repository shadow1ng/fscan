package Plugins

import (
	"fmt"
	"github.com/gocql/gocql"
	"github.com/shadow1ng/fscan/Common"
	"strconv"
	"strings"
	"time"
)

func CassandraScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
	Common.LogDebug("尝试无认证访问...")

	// 首先测试无认证访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("第%d次重试无认证访问", retryCount+1))
		}

		flag, err := CassandraConn(info, "", "")
		if flag && err == nil {
			successMsg := fmt.Sprintf("Cassandra服务 %s 无认证访问成功", target)
			Common.LogSuccess(successMsg)

			// 保存无认证访问结果
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":        info.Ports,
					"service":     "cassandra",
					"auth_type":   "anonymous",
					"type":        "unauthorized-access",
					"description": "数据库允许无认证访问",
				},
			}
			Common.SaveResult(result)
			return err
		}
		if err != nil && Common.CheckErrs(err) != nil {
			if retryCount == maxRetries-1 {
				return err
			}
			continue
		}
		break
	}

	totalUsers := len(Common.Userdict["cassandra"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["cassandra"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := CassandraConn(info, user, pass)
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
						successMsg := fmt.Sprintf("Cassandra服务 %s 爆破成功 用户名: %v 密码: %v", target, user, pass)
						Common.LogSuccess(successMsg)

						// 保存爆破成功结果
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "cassandra",
								"username": user,
								"password": pass,
								"type":     "weak-password",
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("Cassandra服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v", target, user, pass, err)
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

// CassandraConn 清理后的连接测试函数
func CassandraConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	cluster := gocql.NewCluster(host)
	cluster.Port, _ = strconv.Atoi(port)
	cluster.Timeout = timeout
	cluster.ProtoVersion = 4
	cluster.Consistency = gocql.One

	if user != "" || pass != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: user,
			Password: pass,
		}
	}

	cluster.RetryPolicy = &gocql.SimpleRetryPolicy{NumRetries: 3}

	session, err := cluster.CreateSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	var version string
	if err := session.Query("SELECT peer FROM system.peers").Scan(&version); err != nil {
		if err := session.Query("SELECT now() FROM system.local").Scan(&version); err != nil {
			return false, err
		}
	}

	return true, nil
}
