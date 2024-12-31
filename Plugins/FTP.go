package Plugins

import (
	"context"
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

	// 创建带取消功能的context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 先尝试匿名登录
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := FtpConn(info, "anonymous", "")
		if flag && err == nil {
			return nil
		}
		errlog := fmt.Sprintf("ftp %v:%v %v %v", info.Host, info.Ports, "anonymous", err)
		Common.LogError(errlog)

		if err != nil && !strings.Contains(err.Error(), "Login incorrect") {
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["ftp"])*len(Common.Passwords))

	// 任务分发goroutine
	go func() {
		defer close(taskChan)
		for _, user := range Common.Userdict["ftp"] {
			for _, pass := range Common.Passwords {
				select {
				case <-ctx.Done():
					return
				default:
					pass = strings.Replace(pass, "{user}", user, -1)
					taskChan <- struct {
						user string
						pass string
					}{user, pass}
				}
			}
		}
	}()

	var wg sync.WaitGroup
	resultChan := make(chan error, threads)

	// 启动工作线程
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- nil
					return
				default:
				}

				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					done := make(chan struct {
						success bool
						err     error
					}, 1)

					connCtx, connCancel := context.WithTimeout(ctx, time.Duration(Common.Timeout)*time.Second)

					go func(user, pass string) {
						success, err := FtpConn(info, user, pass)
						select {
						case <-connCtx.Done():
						case done <- struct {
							success bool
							err     error
						}{success, err}:
						}
					}(task.user, task.pass)

					var err error
					select {
					case <-ctx.Done():
						connCancel()
						resultChan <- nil
						return
					case result := <-done:
						err = result.err
						if result.success && err == nil {
							successLog := fmt.Sprintf("FTP %v:%v %v %v",
								info.Host, info.Ports, task.user, task.pass)
							Common.LogSuccess(successLog)
							time.Sleep(100 * time.Millisecond)
							cancel() // 取消所有操作
							resultChan <- nil
							return
						}
					case <-connCtx.Done():
						err = fmt.Errorf("连接超时")
					}

					connCancel()

					if err != nil {
						select {
						case <-ctx.Done():
							resultChan <- nil
							return
						default:
						}

						errlog := fmt.Sprintf("ftp %v:%v %v %v %v",
							info.Host, info.Ports, task.user, task.pass, err)
						Common.LogError(errlog)

						if strings.Contains(err.Error(), "Login incorrect") {
							break
						}

						if strings.Contains(err.Error(), "too many connections") {
							time.Sleep(5 * time.Second)
							if retryCount < maxRetries-1 {
								continue
							}
						}

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
			resultChan <- nil
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for err := range resultChan {
		if err != nil {
			tmperr = err
			if !strings.Contains(err.Error(), "扫描超时") {
				if retryErr := Common.CheckErrs(err); retryErr != nil {
					continue
				}
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
	// 确保连接被关闭
	defer func() {
		if conn != nil {
			conn.Quit() // 发送QUIT命令关闭连接
		}
	}()

	// 尝试登录
	if err = conn.Login(Username, Password); err != nil {
		return false, err
	}

	// 登录成功,获取目录信息
	result := fmt.Sprintf("ftp %v:%v:%v %v", Host, Port, Username, Password)
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

	return true, nil
}
