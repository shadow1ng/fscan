package Plugins

import (
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// Neo4jScan 执行 Neo4j 服务扫描
func Neo4jScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 首先测试无认证访问和默认凭证
	initialChecks := []struct {
		user string
		pass string
	}{
		{"", ""},           // 无认证
		{"neo4j", "neo4j"}, // 默认凭证
	}

	for _, check := range initialChecks {
		flag, err := Neo4jConn(info, check.user, check.pass)
		if flag && err == nil {
			return err
		}
	}

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["neo4j"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["neo4j"] {
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

					// 执行Neo4j连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						flag, err := Neo4jConn(info, user, pass)
						done <- struct {
							success bool
							err     error
						}{flag, err}
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
						errlog := fmt.Sprintf("Neo4j服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
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

// Neo4jConn 尝试 Neo4j 连接
func Neo4jConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造Neo4j URL
	uri := fmt.Sprintf("bolt://%s:%s", host, port)

	// 配置驱动选项
	config := func(c *neo4j.Config) {
		c.SocketConnectTimeout = timeout
	}

	var driver neo4j.Driver
	var err error

	// 尝试建立连接
	if user != "" || pass != "" {
		// 有认证信息时使用认证
		driver, err = neo4j.NewDriver(uri, neo4j.BasicAuth(user, pass, ""), config)
	} else {
		// 无认证时使用NoAuth
		driver, err = neo4j.NewDriver(uri, neo4j.NoAuth(), config)
	}

	if err != nil {
		return false, err
	}
	defer driver.Close()

	// 测试连接
	err = driver.VerifyConnectivity()
	if err != nil {
		return false, err
	}

	// 连接成功
	result := fmt.Sprintf("Neo4j服务 %v:%v ", host, port)
	if user != "" {
		result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
	} else {
		result += "无需认证即可访问"
	}
	Common.LogSuccess(result)
	return true, nil
}
