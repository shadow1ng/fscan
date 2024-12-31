package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// PostgresScan 执行PostgreSQL服务扫描
func PostgresScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	starttime := time.Now().Unix()

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["postgresql"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 检查是否超时
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("扫描超时")
			}

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// 执行PostgreSQL连接
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					success, err := PostgresConn(info, user, pass)
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
					errlog := fmt.Sprintf("PostgreSQL %v:%v %v %v %v",
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

// PostgresConn 尝试PostgreSQL连接
func PostgresConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf(
		"postgres://%v:%v@%v:%v/postgres?sslmode=disable",
		username, password, host, port,
	)

	// 建立数据库连接
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// 设置连接参数
	db.SetConnMaxLifetime(timeout)

	// 测试连接
	if err = db.Ping(); err != nil {
		return false, err
	}

	// 连接成功
	result := fmt.Sprintf("PostgreSQL %v:%v:%v %v", host, port, username, password)
	Common.LogSuccess(result)
	return true, nil
}
