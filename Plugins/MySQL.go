package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// MysqlScan 执行MySQL服务扫描
func MysqlScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	totalUsers := len(Common.Userdict["mysql"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["mysql"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				// 执行MySQL连接
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := MysqlConn(info, user, pass)
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
						successLog := fmt.Sprintf("MySQL %v:%v %v %v",
							info.Host, info.Ports, user, pass)
						Common.LogSuccess(successLog)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				// 处理错误情况
				if err != nil {
					errlog := fmt.Sprintf("MySQL %v:%v %v %v %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					// 特殊处理认证失败的情况
					if strings.Contains(err.Error(), "Access denied") {
						break // 跳出重试循环，继续下一个密码
					}

					// 检查是否需要重试
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							tmperr = err
							if !strings.Contains(err.Error(), "Access denied") {
								continue
							}
						}
						continue // 继续重试
					}
					break // 如果不需要重试，跳出重试循环
				}
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", tried))
	return tmperr
}

// MysqlConn 尝试MySQL连接
func MysqlConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf(
		"%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v",
		username, password, host, port, timeout,
	)

	// 建立数据库连接
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// 设置连接参数
	db.SetConnMaxLifetime(timeout)
	db.SetConnMaxIdleTime(timeout)
	db.SetMaxIdleConns(0)

	// 测试连接
	if err = db.Ping(); err != nil {
		return false, err
	}

	// 连接成功，只返回结果，不打印日志
	return true, nil
}
