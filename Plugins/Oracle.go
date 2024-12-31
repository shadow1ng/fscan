package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	_ "github.com/sijms/go-ora/v2"
	"strings"
	"sync"
	"time"
)

// OracleScan 执行Oracle服务扫描
func OracleScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["oracle"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["oracle"] {
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
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					if time.Now().Unix()-starttime > int64(Common.Timeout) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

					// 执行Oracle连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := OracleConn(info, user, pass)
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
							resultChan <- nil
							return
						}
					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						err = fmt.Errorf("连接超时")
					}

					// 处理错误情况
					if err != nil {
						errlog := fmt.Sprintf("[-] Oracle %v:%v %v %v %v",
							info.Host, info.Ports, task.user, task.pass, err)
						Common.LogError(errlog)

						// 检查是否需要重试
						if retryErr := Common.CheckErrs(err); retryErr != nil {
							if retryCount == maxRetries-1 {
								resultChan <- err
								return
							}
							continue // 继续重试
						}
					}

					break // 如果不需要重试，跳出重试循环
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
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				return err
			}
		}
	}

	return tmperr
}

// OracleConn 尝试Oracle连接
func OracleConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl",
		username, password, host, port)

	// 建立数据库连接
	db, err := sql.Open("oracle", connStr)
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

	// 连接成功
	result := fmt.Sprintf("[+] Oracle %v:%v:%v %v", host, port, username, password)
	Common.LogSuccess(result)
	return true, nil
}
