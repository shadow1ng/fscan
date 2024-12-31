package Plugins

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net/http"
	"strings"
	"time"
)

// ElasticScan 执行 Elasticsearch 服务扫描
func ElasticScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	// 首先测试无认证访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := ElasticConn(info, "", "")
		if flag && err == nil {
			return err
		}
		if err != nil && Common.CheckErrs(err) != nil {
			if retryCount == maxRetries-1 {
				return err
			}
			continue
		}
		break
	}

	starttime := time.Now().Unix()

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["elastic"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 检查是否超时
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("扫描超时")
			}

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// 执行连接尝试
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					flag, err := ElasticConn(info, user, pass)
					done <- struct {
						success bool
						err     error
					}{flag, err}
				}(user, pass)

				// 等待结果或超时
				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				// 处理错误情况
				if err != nil {
					errlog := fmt.Sprintf("Elasticsearch服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					// 检查是否需要重试
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							return err
						}
						continue // 继续重试
					}
				}

				break // 如果不需要重试，跳出重试循环
			}
		}
	}

	return tmperr
}

// ElasticConn 尝试 Elasticsearch 连接
func ElasticConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造请求客户端
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 构造基础URL
	baseURL := fmt.Sprintf("http://%s:%s", host, port)

	// 创建请求
	req, err := http.NewRequest("GET", baseURL+"/_cat/indices", nil)
	if err != nil {
		return false, err
	}

	// 如果提供了认证信息,添加Basic认证头
	if user != "" || pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Add("Authorization", "Basic "+auth)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode == 200 {
		result := fmt.Sprintf("Elasticsearch服务 %v:%v ", host, port)
		if user != "" {
			result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
		} else {
			result += "无需认证即可访问"
		}
		Common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
