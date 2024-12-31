package Plugins

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// LDAPScan 执行LDAP服务扫描
func LDAPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 首先尝试匿名访问
	flag, err := LDAPConn(info, "", "")
	if flag && err == nil {
		return err
	}

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["ldap"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["ldap"] {
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

					// 执行LDAP连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := LDAPConn(info, user, pass)
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
						errlog := fmt.Sprintf("LDAP服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
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

// LDAPConn 尝试LDAP连接
func LDAPConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造LDAP连接地址
	address := fmt.Sprintf("%s:%s", host, port)

	// 配置LDAP连接
	l, err := ldap.Dial("tcp", address)
	if err != nil {
		return false, err
	}
	defer l.Close()

	// 设置超时
	l.SetTimeout(timeout)

	// 尝试绑定
	if user != "" {
		// 构造DN
		bindDN := fmt.Sprintf("cn=%s,dc=example,dc=com", user)
		err = l.Bind(bindDN, pass)
	} else {
		// 匿名绑定
		err = l.UnauthenticatedBind("")
	}

	if err != nil {
		return false, err
	}

	// 尝试简单搜索以验证权限
	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = l.Search(searchRequest)
	if err != nil {
		return false, err
	}

	// 记录成功结果
	result := fmt.Sprintf("LDAP服务 %v:%v ", host, port)
	if user != "" {
		result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
	} else {
		result += "匿名访问成功"
	}
	Common.LogSuccess(result)

	return true, nil
}
