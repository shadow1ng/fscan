package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

// RsyncScan 执行 Rsync 服务扫描
func RsyncScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	starttime := time.Now().Unix()

	// 首先测试匿名访问
	flag, err := RsyncConn(info, "", "")
	if flag && err == nil {
		return err
	}

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["rsync"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := RsyncConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			errlog := fmt.Sprintf("[-] Rsync服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
				info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["rsync"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	return tmperr
}

func RsyncConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 建立连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	buffer := make([]byte, 1024)

	// 1. 读取服务器初始greeting
	n, err := conn.Read(buffer)
	if err != nil {
		return false, err
	}

	greeting := string(buffer[:n])
	if !strings.HasPrefix(greeting, "@RSYNCD:") {
		return false, fmt.Errorf("不是Rsync服务")
	}

	// 获取服务器版本号
	version := strings.TrimSpace(strings.TrimPrefix(greeting, "@RSYNCD:"))

	// 2. 回应相同的版本号
	_, err = conn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
	if err != nil {
		return false, err
	}

	// 3. 选择模块 - 先列出可用模块
	_, err = conn.Write([]byte("#list\n"))
	if err != nil {
		return false, err
	}

	// 4. 读取模块列表
	var moduleList strings.Builder
	for {
		n, err = conn.Read(buffer)
		if err != nil {
			break
		}
		chunk := string(buffer[:n])
		moduleList.WriteString(chunk)
		if strings.Contains(chunk, "@RSYNCD: EXIT") {
			break
		}
	}

	modules := strings.Split(moduleList.String(), "\n")
	for _, module := range modules {
		if strings.HasPrefix(module, "@RSYNCD") || module == "" {
			continue
		}

		// 获取模块名
		moduleName := strings.Fields(module)[0]

		// 5. 为每个模块创建新连接尝试认证
		authConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
		if err != nil {
			continue
		}
		defer authConn.Close()

		// 重复初始握手
		_, err = authConn.Read(buffer)
		if err != nil {
			authConn.Close()
			continue
		}

		_, err = authConn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
		if err != nil {
			authConn.Close()
			continue
		}

		// 6. 选择模块
		_, err = authConn.Write([]byte(moduleName + "\n"))
		if err != nil {
			authConn.Close()
			continue
		}

		// 7. 等待认证挑战
		n, err = authConn.Read(buffer)
		if err != nil {
			authConn.Close()
			continue
		}

		authResponse := string(buffer[:n])
		if strings.Contains(authResponse, "@RSYNCD: OK") {
			// 模块不需要认证
			if user == "" && pass == "" {
				result := fmt.Sprintf("[+] Rsync服务 %v:%v 模块:%v 无需认证", host, port, moduleName)
				Common.LogSuccess(result)
				return true, nil
			}
		} else if strings.Contains(authResponse, "@RSYNCD: AUTHREQD") {
			if user != "" && pass != "" {
				// 8. 发送认证信息
				authString := fmt.Sprintf("%s %s\n", user, pass)
				_, err = authConn.Write([]byte(authString))
				if err != nil {
					authConn.Close()
					continue
				}

				// 9. 读取认证结果
				n, err = authConn.Read(buffer)
				if err != nil {
					authConn.Close()
					continue
				}

				if !strings.Contains(string(buffer[:n]), "@ERROR") {
					result := fmt.Sprintf("[+] Rsync服务 %v:%v 模块:%v 认证成功 用户名: %v 密码: %v",
						host, port, moduleName, user, pass)
					Common.LogSuccess(result)
					return true, nil
				}
			}
		}
		authConn.Close()
	}

	return false, fmt.Errorf("认证失败或无可用模块")
}
