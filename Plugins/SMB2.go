package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"os"
	"strings"
	"sync"
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

// smbPasswordScan 使用密码进行认证扫描
func smbPasswordScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	threads := Common.BruteThreads

	var wg sync.WaitGroup
	successChan := make(chan struct{}, 1)
	hasprint := false
	var hasPrintMutex sync.Mutex

	// 改成按用户分组处理
	for _, user := range Common.Userdict["smb"] {
		// 为每个用户创建密码任务通道
		taskChan := make(chan string, len(Common.Passwords))

		// 生成该用户的所有密码任务
		for _, pass := range Common.Passwords {
			pass = strings.ReplaceAll(pass, "{user}", user)
			taskChan <- pass
		}
		close(taskChan)

		// 启动工作线程
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func(username string) {
				defer wg.Done()

				for pass := range taskChan {
					select {
					case <-successChan:
						return
					default:
						time.Sleep(100 * time.Millisecond)
					}

					// 重试循环
					for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
						hasPrintMutex.Lock()
						currentHasPrint := hasprint
						hasPrintMutex.Unlock()

						success, err, printed := Smb2Con(info, username, pass, []byte{}, currentHasPrint)

						if printed {
							hasPrintMutex.Lock()
							hasprint = true
							hasPrintMutex.Unlock()
							time.Sleep(100 * time.Millisecond)
						}

						if success {
							logSuccessfulAuth(info, username, pass, []byte{})
							time.Sleep(100 * time.Millisecond)
							successChan <- struct{}{}
							return
						}

						if err != nil {
							logFailedAuth(info, username, pass, []byte{}, err)
							time.Sleep(100 * time.Millisecond)

							// 检查是否账户锁定
							if strings.Contains(err.Error(), "user account has been automatically locked") {
								// 发现账户锁定，清空任务通道并返回
								for range taskChan {
									// 清空通道
								}
								return
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
			}(user)
		}

		wg.Wait() // 等待当前用户的所有密码尝试完成

		// 检查是否已经找到正确密码
		select {
		case <-successChan:
			return nil
		default:
		}
	}

	time.Sleep(200 * time.Millisecond)
	return nil
}

func smbHashScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	threads := Common.BruteThreads
	var wg sync.WaitGroup
	successChan := make(chan struct{}, 1)
	hasprint := false
	var hasPrintMutex sync.Mutex

	// 按用户分组处理
	for _, user := range Common.Userdict["smb"] {
		// 为每个用户创建hash任务通道
		taskChan := make(chan []byte, len(Common.HashBytes))

		// 生成该用户的所有hash任务
		for _, hash := range Common.HashBytes {
			taskChan <- hash
		}
		close(taskChan)

		// 启动工作线程
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func(username string) {
				defer wg.Done()

				for hash := range taskChan {
					select {
					case <-successChan:
						return
					default:
					}

					// 重试循环
					for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
						hasPrintMutex.Lock()
						currentHasPrint := hasprint
						hasPrintMutex.Unlock()

						success, err, printed := Smb2Con(info, username, "", hash, currentHasPrint)

						if printed {
							hasPrintMutex.Lock()
							hasprint = true
							hasPrintMutex.Unlock()
						}

						if success {
							logSuccessfulAuth(info, username, "", hash)
							successChan <- struct{}{}
							return
						}

						if err != nil {
							logFailedAuth(info, username, "", hash, err)

							// 检查是否账户锁定
							if strings.Contains(err.Error(), "user account has been automatically locked") {
								// 发现账户锁定，清空任务通道并返回
								for range taskChan {
									// 清空通道
								}
								return
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
			}(user)
		}

		wg.Wait() // 等待当前用户的所有hash尝试完成

		// 检查是否已经找到正确凭据
		select {
		case <-successChan:
			return nil
		default:
		}
	}

	return nil
}

// logSuccessfulAuth 记录成功的认证
func logSuccessfulAuth(info *Common.HostInfo, user, pass string, hash []byte) {
	var result string
	if Common.Domain != "" {
		result = fmt.Sprintf("SMB2认证成功 %s:%s %s\\%s",
			info.Host, info.Ports, Common.Domain, user)
	} else {
		result = fmt.Sprintf("SMB2认证成功 %s:%s %s",
			info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		result += fmt.Sprintf(" Hash:%s", Common.HashValue)
	} else {
		result += fmt.Sprintf(" Pass:%s", pass)
	}
	Common.LogSuccess(result)
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
	var result string
	if Common.Domain != "" {
		result = fmt.Sprintf("SMB2共享信息 %s:%s %s\\%s",
			info.Host, info.Ports, Common.Domain, user)
	} else {
		result = fmt.Sprintf("SMB2共享信息 %s:%s %s",
			info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		result += fmt.Sprintf(" Hash:%s", Common.HashValue)
	} else {
		result += fmt.Sprintf(" Pass:%s", pass)
	}

	result += fmt.Sprintf(" 共享:%v", shares)
	Common.LogInfo(result)
}
