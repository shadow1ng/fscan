package Plugins

import (
	"encoding/json"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

// ZabbixScan 执行 Zabbix 服务扫描
func ZabbixScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 先测试默认账号
	defaultDone := make(chan struct {
		success bool
		err     error
	})

	go func() {
		success, err := ZabbixConn(info, "Admin", "zabbix")
		defaultDone <- struct {
			success bool
			err     error
		}{success, err}
	}()

	select {
	case result := <-defaultDone:
		if result.success && result.err == nil {
			return result.err
		}
	case <-time.After(time.Duration(Common.Timeout) * time.Second):
		Common.LogError(fmt.Sprintf("[-] Zabbix默认账号连接超时 %v:%v", info.Host, info.Ports))
	}

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["zabbix"])*len(Common.Passwords))
	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["zabbix"] {
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

					// 执行Zabbix连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := ZabbixConn(info, user, pass)
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
						errlog := fmt.Sprintf("[-] Zabbix服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
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

// ZabbixConn 尝试 Zabbix API 连接
func ZabbixConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造 API URL
	apiURL := fmt.Sprintf("http://%s:%s/api_jsonrpc.php", host, port)

	// 构造认证请求
	authRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "user.login",
		"params": map[string]string{
			"user":     user,
			"password": pass,
		},
		"id": 1,
	}

	// 创建HTTP客户端
	client := resty.New()
	client.SetTimeout(timeout)

	// 发送认证请求
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(authRequest).
		Post(apiURL)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, fmt.Errorf("连接超时")
		}
		return false, err
	}

	// 解析响应
	var result struct {
		Result string `json:"result"`
		Error  struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return false, fmt.Errorf("响应解析失败")
	}

	// 检查是否认证成功
	if result.Result != "" {
		success := fmt.Sprintf("[+] Zabbix服务 %v:%v 爆破成功 用户名: %v 密码: %v", host, port, user, pass)
		Common.LogSuccess(success)
		return true, nil
	}

	return false, fmt.Errorf("认证失败: %v", result.Error.Message)
}
