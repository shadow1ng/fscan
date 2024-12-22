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

// TomcatScan 执行 Tomcat Manager 服务扫描
func TomcatScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	starttime := time.Now().Unix()

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["tomcat"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := TomcatConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			errlog := fmt.Sprintf("[-] Tomcat Manager %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["tomcat"])*len(Common.Passwords)) * Common.Timeout) {
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
