package Plugins

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TomcatScan 执行 Tomcat Manager 服务扫描
func TomcatScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["tomcat"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["tomcat"] {
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

					// 执行Tomcat连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := TomcatConn(info, user, pass)
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
						errlog := fmt.Sprintf("[-] Tomcat Manager %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
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

// TomcatConn 尝试 Tomcat Manager 连接
func TomcatConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 尝试不同的管理路径
	paths := []string{
		"/manager/html",
		"/manager/status",
		"/manager/text",
		"/host-manager/html",
	}

	for _, path := range paths {
		baseURL := fmt.Sprintf("http://%s:%s%s", host, port, path)

		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			continue
		}

		// 添加Basic认证
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Add("Authorization", "Basic "+auth)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// 检查响应状态
		if resp.StatusCode == 200 {
			result := fmt.Sprintf("[+] Tomcat Manager %v:%v %s 爆破成功 用户名: %v 密码: %v",
				host, port, path, user, pass)
			Common.LogSuccess(result)
			return true, nil
		}
	}

	return false, fmt.Errorf("认证失败")
}
