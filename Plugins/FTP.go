package Plugins

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// FtpScan 执行FTP服务扫描
func FtpScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 先尝试匿名登录
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := FtpConn(info, "anonymous", "")
		if flag && err == nil {
			return nil
		}
		errlog := fmt.Sprintf("[-] ftp %v:%v %v %v", info.Host, info.Ports, "anonymous", err)
		Common.LogError(errlog)

		if retryErr := Common.CheckErrs(err); retryErr != nil {
			if retryCount == maxRetries-1 {
				return err
			}
			continue
		}
		break
	}

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["ftp"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["ftp"] {
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

					// 执行FTP连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := FtpConn(info, user, pass)
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
						errlog := fmt.Sprintf("[-] ftp %v:%v %v %v %v",
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

// FtpConn 建立FTP连接并尝试登录
func FtpConn(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	Host, Port, Username, Password := info.Host, info.Ports, user, pass

	// 建立FTP连接
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, err
	}

	// 尝试登录
	if err = conn.Login(Username, Password); err != nil {
		return false, err
	}

	// 登录成功,获取目录信息
	result := fmt.Sprintf("[+] ftp %v:%v:%v %v", Host, Port, Username, Password)
	dirs, err := conn.List("")
	if err == nil && len(dirs) > 0 {
		// 最多显示前6个目录
		for i := 0; i < len(dirs) && i < 6; i++ {
			name := dirs[i].Name
			if len(name) > 50 {
				name = name[:50]
			}
			result += "\n   [->]" + name
		}
	}

	Common.LogSuccess(result)
	return true, nil
}
