package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"sync"
	"time"
)

// SmbScan 执行SMB服务的认证扫描
func SmbScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["smb"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["smb"] {
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
			startTime := time.Now().Unix()

			for task := range taskChan {
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					if time.Now().Unix()-startTime > int64(Common.Timeout) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

					// 执行SMB认证
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := doWithTimeOut(info, user, pass)
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
							// 认证成功
							var successLog string
							if Common.Domain != "" {
								successLog = fmt.Sprintf("[✓] SMB认证成功 %v:%v Domain:%v\\%v Pass:%v",
									info.Host, info.Ports, Common.Domain, task.user, task.pass)
							} else {
								successLog = fmt.Sprintf("[✓] SMB认证成功 %v:%v User:%v Pass:%v",
									info.Host, info.Ports, task.user, task.pass)
							}
							Common.LogSuccess(successLog)
							resultChan <- nil
							return
						}
					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						err = fmt.Errorf("连接超时")
					}

					// 处理错误情况
					if err != nil {
						errlog := fmt.Sprintf("[x] SMB认证失败 %v:%v User:%v Pass:%v Err:%v",
							info.Host, info.Ports, task.user, task.pass,
							strings.ReplaceAll(err.Error(), "\n", ""))
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

// SmblConn 尝试建立SMB连接并进行认证
func SmblConn(info *Common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false

	// 配置SMB连接选项
	options := smb.Options{
		Host:        info.Host,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      Common.Domain,
		Workstation: "",
	}

	// 尝试建立SMB会话
	session, err := smb.NewSession(options, false)
	if err == nil {
		defer session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}

	// 发送完成信号
	signal <- struct{}{}
	return flag, err
}

// doWithTimeOut 执行带超时的SMB连接认证
func doWithTimeOut(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})

	// 在goroutine中执行SMB连接
	go func() {
		flag, err = SmblConn(info, user, pass, signal)
	}()

	// 等待连接结果或超时
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(Common.Timeout) * time.Second):
		return false, errors.New("[-] SMB连接超时")
	}
}
