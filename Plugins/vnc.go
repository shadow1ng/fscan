package Plugins

import (
	"fmt"
	"github.com/Run0nceEx/go-vnc"
	"github.com/shadow1ng/fscan/common"
	"net"
	"time"
)

// VncScan 扫描 VNC 服务
func VncScan(info *common.HostInfo) (flag bool, err error) {
	if common.IsBrute {
		return false, nil
	}

	flag = false
	Host, Port := info.Host, info.Ports
	addr := fmt.Sprintf("%s:%s", Host, Port)

	// 建立 TCP 连接
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	//设置连接超时防止过长等待
	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return false, fmt.Errorf("无法连接到 %v: %v", addr, err)
	}
	defer conn.Close()

	// 无认证测试
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			new(vnc.ClientAuthNone),
		},
	}

	client, err := vnc.Client(conn, config)

	if err == nil {
		// 无需认证即可访问
		result := fmt.Sprintf("[+] VNC unauthenticated access successful: %v:%v", Host, Port)
		common.LogSuccess(result)
		defer client.Close()
		return true, nil
	}

	// 如果无认证失败，进行密码爆破
	for _, pass := range common.Passwords {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			continue // 如果无法重连，跳过此密码
		}
		defer conn.Close()

		config := &vnc.ClientConfig{
			Auth: []vnc.ClientAuth{
				&vnc.PasswordAuth{
					Password: pass,
				},
			},
		}

		client, err := vnc.Client(conn, config)

		if err == nil {
			// 密码验证成功
			result := fmt.Sprintf("[+] VNC password verification successful: %v:%v, password: %v", Host, Port, pass)
			common.LogSuccess(result)
			err := client.Close()
			if err != nil {
				return false, err
			}
			return true, nil
		} else {
			if "security handshake failed: Either the username was not recognised, or the password was incorrect" != err.Error() {
				err := client.Close()
				if err != nil {
					return false, err
				}
			}
		}
	}

	// 如果无认证和密码爆破都失败
	return false, nil
}
