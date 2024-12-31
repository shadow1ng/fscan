package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// MysqlScan 执行MySQL服务扫描
func MysqlScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 添加成功标志通道
	successChan := make(chan struct{}, 1)
	defer close(successChan)

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["mysql"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["mysql"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			taskChan <- struct {
				user string
				pass string
			}{user, pass}
		}
	}
	close(taskChan)

	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			starttime := time.Now().Unix()

			for task := range taskChan {
				// 检查是否已经成功
				select {
				case <-successChan:
					resultChan <- nil
					return
				default:
				}

				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					if time.Now().Unix()-starttime > int64(Common.Timeout) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

					// 执行MySQL连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := MysqlConn(info, user, pass)
						done <- struct {
							success bool
							err     error
						}{success, err}
					}(task.user, task.pass)

					// 等待结果或超时
					var err error
					select {
					case result := <-done:
						err = result.err
						if result.success && err == nil {
							// 连接成功
							select {
							case successChan <- struct{}{}: // 标记成功
								successLog := fmt.Sprintf("[+] MySQL %v:%v %v %v",
									info.Host, info.Ports, task.user, task.pass)
								Common.LogSuccess(successLog)
							default:
							}
							resultChan <- nil
							return
						}
					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						err = fmt.Errorf("连接超时")
					}

					// 处理错误情况
					if err != nil {
						errlog := fmt.Sprintf("[-] MySQL %v:%v %v %v %v",
							info.Host, info.Ports, task.user, task.pass, err)
						Common.LogError(errlog)

						// 特殊处理认证失败的情况
						if strings.Contains(err.Error(), "Access denied") {
							break // 跳出重试循环，继续下一个密码
						}

						// 检查是否需要重试
						if retryErr := Common.CheckErrs(err); retryErr != nil {
							if retryCount == maxRetries-1 {
								resultChan <- err
								return
							}
							continue // 继续重试
						}
						break // 如果不需要重试，跳出重试循环
					}
				}
			}
			resultChan <- nil
		}()
	}

	// 等待所有线程完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 检查结果
	for err := range resultChan {
		if err != nil {
			tmperr = err
			if !strings.Contains(err.Error(), "Access denied") {
				if retryErr := Common.CheckErrs(err); retryErr != nil {
					return err
				}
			}
		}
	}

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
