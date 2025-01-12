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

func ElasticScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	Common.LogDebug("尝试无认证访问...")

	// 首先测试无认证访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("第%d次重试无认证访问", retryCount+1))
		}
		flag, err := ElasticConn(info, "", "")
		if flag && err == nil {
			Common.LogSuccess(fmt.Sprintf("Elasticsearch服务 %v:%v 无需认证",
				info.Host, info.Ports))
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

	totalUsers := len(Common.Userdict["elastic"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)",
		totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["elastic"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				// 执行连接尝试
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := ElasticConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag, err}:
					default:
					}
				}(user, pass)

				// 等待结果或超时
				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						Common.LogSuccess(fmt.Sprintf("Elasticsearch服务 %v:%v 爆破成功 用户名: %v 密码: %v",
							info.Host, info.Ports, user, pass))
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
							continue
						}
						continue // 继续重试
					}
				}

				break // 如果不需要重试，跳出重试循环
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", tried))
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
