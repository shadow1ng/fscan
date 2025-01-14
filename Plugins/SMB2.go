package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// SmbScan2 执行SMB2服务的认证扫描，支持密码和哈希两种认证方式
func SmbScan2(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	// 使用哈希认证模式
	if len(Common.HashBytes) > 0 {
		return smbHashScan(info)
	}

	// 使用密码认证模式
	return smbPasswordScan(info)
}

func smbPasswordScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	hasprint := false

	// 遍历每个用户
	for _, user := range Common.Userdict["smb"] {
		accountLocked := false // 添加账户锁定标志

		// 遍历该用户的所有密码
		for _, pass := range Common.Passwords {
			if accountLocked { // 如果账户被锁定，跳过剩余密码
				break
			}

			pass = strings.ReplaceAll(pass, "{user}", user)

			// 重试循环
			for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
				success, err, printed := Smb2Con(info, user, pass, []byte{}, hasprint)

				if printed {
					hasprint = true
				}

				if success {
					logSuccessfulAuth(info, user, pass, []byte{})
					return nil
				}

				if err != nil {
					logFailedAuth(info, user, pass, []byte{}, err)

					// 检查是否账户锁定
					if strings.Contains(err.Error(), "account has been automatically locked") ||
						strings.Contains(err.Error(), "account has been locked") {
						accountLocked = true // 设置锁定标志
						break
					}

					// 其他登录失败情况
					if strings.Contains(err.Error(), "LOGIN_FAILED") ||
						strings.Contains(err.Error(), "Authentication failed") ||
						strings.Contains(err.Error(), "attempted logon is invalid") ||
						strings.Contains(err.Error(), "bad username or authentication") {
						break
					}

					if retryCount < Common.MaxRetries-1 {
						time.Sleep(time.Second * time.Duration(retryCount+2))
						continue
					}
				}
				break
			}
		}
	}

	return nil
}

func smbHashScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	hasprint := false

	// 遍历每个用户
	for _, user := range Common.Userdict["smb"] {
		// 遍历该用户的所有hash
		for _, hash := range Common.HashBytes {
			// 重试循环
			for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
				success, err, printed := Smb2Con(info, user, "", hash, hasprint)

				if printed {
					hasprint = true
				}

				if success {
					logSuccessfulAuth(info, user, "", hash)
					return nil
				}

				if err != nil {
					logFailedAuth(info, user, "", hash, err)

					// 检查是否账户锁定
					if strings.Contains(err.Error(), "user account has been automatically locked") {
						// 账户锁定，跳过该用户的剩余hash
						break
					}

					// 其他登录失败情况
					if strings.Contains(err.Error(), "LOGIN_FAILED") ||
						strings.Contains(err.Error(), "Authentication failed") ||
						strings.Contains(err.Error(), "attempted logon is invalid") ||
						strings.Contains(err.Error(), "bad username or authentication") {
						break
					}

					if retryCount < Common.MaxRetries-1 {
						time.Sleep(time.Second * time.Duration(retryCount+1))
						continue
					}
				}
				break
			}
		}
	}

	return nil
}

// logSuccessfulAuth 记录成功的认证
func logSuccessfulAuth(info *Common.HostInfo, user, pass string, hash []byte) {
	credential := pass
	if len(hash) > 0 {
		credential = Common.HashValue
	}

	// 保存认证成功结果
	result := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "success",
		Details: map[string]interface{}{
			"port":       info.Ports,
			"service":    "smb2",
			"username":   user,
			"domain":     Common.Domain,
			"type":       "weak-auth",
			"credential": credential,
			"auth_type":  map[bool]string{true: "hash", false: "password"}[len(hash) > 0],
		},
	}
	Common.SaveResult(result)

	// 控制台输出
	var msg string
	if Common.Domain != "" {
		msg = fmt.Sprintf("SMB2认证成功 %s:%s %s\\%s", info.Host, info.Ports, Common.Domain, user)
	} else {
		msg = fmt.Sprintf("SMB2认证成功 %s:%s %s", info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		msg += fmt.Sprintf(" Hash:%s", Common.HashValue)
	} else {
		msg += fmt.Sprintf(" Pass:%s", pass)
	}
	Common.LogSuccess(msg)
}

// logFailedAuth 记录失败的认证
func logFailedAuth(info *Common.HostInfo, user, pass string, hash []byte, err error) {
	var errlog string
	if len(hash) > 0 {
		errlog = fmt.Sprintf("SMB2认证失败 %s:%s %s Hash:%s %v",
			info.Host, info.Ports, user, Common.HashValue, err)
	} else {
		errlog = fmt.Sprintf("SMB2认证失败 %s:%s %s:%s %v",
			info.Host, info.Ports, user, pass, err)
	}
	errlog = strings.ReplaceAll(errlog, "\n", " ")
	Common.LogError(errlog)
}

// Smb2Con 尝试SMB2连接并进行认证，检查共享访问权限
func Smb2Con(info *Common.HostInfo, user string, pass string, hash []byte, hasprint bool) (flag bool, err error, flag2 bool) {
	// 建立TCP连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", info.Host),
		time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, fmt.Errorf("连接失败: %v", err), false
	}
	defer conn.Close()

	// 配置NTLM认证
	initiator := smb2.NTLMInitiator{
		User:   user,
		Domain: Common.Domain,
	}

	// 设置认证方式(哈希或密码)
	if len(hash) > 0 {
		initiator.Hash = hash
	} else {
		initiator.Password = pass
	}

	// 创建SMB2会话
	d := &smb2.Dialer{
		Initiator: &initiator,
	}
	session, err := d.Dial(conn)
	if err != nil {
		return false, fmt.Errorf("SMB2会话建立失败: %v", err), false
	}
	defer session.Logoff()

	// 获取共享列表
	shares, err := session.ListSharenames()
	if err != nil {
		return false, fmt.Errorf("获取共享列表失败: %v", err), false
	}

	// 打印共享信息(如果未打印过)
	if !hasprint {
		logShareInfo(info, user, pass, hash, shares)
		flag2 = true
	}

	// 尝试访问C$共享以验证管理员权限
	fs, err := session.Mount("C$")
	if err != nil {
		return false, fmt.Errorf("挂载C$失败: %v", err), flag2
	}
	defer fs.Umount()

	// 尝试读取系统文件以验证权限
	path := `Windows\win.ini`
	f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return false, fmt.Errorf("访问系统文件失败: %v", err), flag2
	}
	defer f.Close()

	return true, nil, flag2
}

// logShareInfo 记录SMB共享信息
func logShareInfo(info *Common.HostInfo, user string, pass string, hash []byte, shares []string) {
	credential := pass
	if len(hash) > 0 {
		credential = Common.HashValue
	}

	// 保存共享信息结果
	result := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "shares-found",
		Details: map[string]interface{}{
			"port":       info.Ports,
			"service":    "smb2",
			"username":   user,
			"domain":     Common.Domain,
			"shares":     shares,
			"credential": credential,
			"auth_type":  map[bool]string{true: "hash", false: "password"}[len(hash) > 0],
		},
	}
	Common.SaveResult(result)

	// 控制台输出
	var msg string
	if Common.Domain != "" {
		msg = fmt.Sprintf("SMB2共享信息 %s:%s %s\\%s", info.Host, info.Ports, Common.Domain, user)
	} else {
		msg = fmt.Sprintf("SMB2共享信息 %s:%s %s", info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		msg += fmt.Sprintf(" Hash:%s", Common.HashValue)
	} else {
		msg += fmt.Sprintf(" Pass:%s", pass)
	}
	msg += fmt.Sprintf(" 共享:%v", shares)
	Common.LogInfo(msg)
}
