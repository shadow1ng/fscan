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

	maxRetries := Common.MaxRetries
	starttime := time.Now().Unix()

	// 首先测试无认证访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := CassandraConn(info, "", "")
		if flag && err == nil {
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

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["cassandra"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 检查是否超时
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("扫描超时")
			}

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// 执行连接
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					success, err := CassandraConn(info, user, pass)
					done <- struct {
						success bool
						err     error
					}{success, err}
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
					errlog := fmt.Sprintf("Cassandra服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					// 检查是否需要重试
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							return err
						}
						continue // 继续重试
					}
				}

				break // 如果不需要重试，跳出重试循环
			}
		}
	}

	return tmperr
}

func CassandraConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	cluster := gocql.NewCluster(host)
	cluster.Port, _ = strconv.Atoi(port)
	cluster.Timeout = timeout
	cluster.ProtoVersion = 4 // 指定协议版本
	cluster.Consistency = gocql.One

	if user != "" || pass != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: user,
			Password: pass,
		}
	}

	// 增加重试机制
	cluster.RetryPolicy = &gocql.SimpleRetryPolicy{NumRetries: 3}

	session, err := cluster.CreateSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	// 使用更简单的查询测试连接
	var version string
	if err := session.Query("SELECT peer FROM system.peers").Scan(&version); err != nil {
		if err := session.Query("SELECT now() FROM system.local").Scan(&version); err != nil {
			return false, err
		}
	}

	result := fmt.Sprintf("Cassandra服务 %v:%v ", host, port)
	if user != "" {
		result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
	} else {
		result += "无需认证即可访问"
	}
	Common.LogSuccess(result)

	return true, nil
}
