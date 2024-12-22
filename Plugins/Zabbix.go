package Plugins

import (
	"encoding/json"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

// ZabbixScan 执行 Zabbix 服务扫描
func ZabbixScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	starttime := time.Now().Unix()

	// 首先测试默认账户
	flag, err := ZabbixConn(info, "Admin", "zabbix")
	if flag && err == nil {
		return err
	}

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["zabbix"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := ZabbixConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			errlog := fmt.Sprintf("[-] Zabbix服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["zabbix"])*len(Common.Passwords)) * Common.Timeout) {
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
