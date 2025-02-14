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

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
	totalUsers := len(Common.Userdict["postgresql"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	for _, user := range Common.Userdict["postgresql"] {
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
					success, err := PostgresConn(info, user, pass)
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
						successMsg := fmt.Sprintf("PostgreSQL服务 %s 成功爆破 用户名: %v 密码: %v", target, user, pass)
						Common.LogSuccess(successMsg)

						// 保存结果
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "postgresql",
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
					errMsg := fmt.Sprintf("PostgreSQL服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v", target, user, pass, err)
					Common.LogError(errMsg)

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

// PostgresConn 尝试PostgreSQL连接
func PostgresConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf(
		"postgres://%v:%v@%v:%v/postgres?sslmode=disable",
		user, pass, info.Host, info.Ports,
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

	return true, nil
}
