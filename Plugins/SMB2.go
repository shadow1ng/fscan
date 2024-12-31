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

// smbHashScan 使用哈希进行认证扫描
func smbHashScan(info *Common.HostInfo) error {
	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads
	hasprint := false

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		hash []byte
	}, len(Common.Userdict["smb"])*len(Common.HashBytes))

	resultChan := make(chan error, threads)

	// 生成所有用户名和哈希组合任务
	for _, user := range Common.Userdict["smb"] {
		for _, hash := range Common.HashBytes {
			taskChan <- struct {
				user string
				hash []byte
			}{user, hash}
		}
	}
	close(taskChan)

	// 启动工作线程
	var wg sync.WaitGroup
	var hasPrintMutex sync.Mutex

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startTime := time.Now().Unix()

			for task := range taskChan {
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					if time.Now().Unix()-startTime > int64(Common.Timeout) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

					// 执行SMB2认证
					done := make(chan struct {
						success bool
						err     error
						printed bool
					})

					go func(user string, hash []byte) {
						hasPrintMutex.Lock()
						currentHasPrint := hasprint
						hasPrintMutex.Unlock()

						success, err, printed := Smb2Con(info, user, "", hash, currentHasPrint)

						if printed {
							hasPrintMutex.Lock()
							hasprint = true
							hasPrintMutex.Unlock()
						}

						done <- struct {
							success bool
							err     error
							printed bool
						}{success, err, printed}
					}(task.user, task.hash)

					// 等待结果或超时
					select {
					case result := <-done:
						if result.success {
							logSuccessfulAuth(info, task.user, "", task.hash)
							resultChan <- nil
							return
						}

						if result.err != nil {
							logFailedAuth(info, task.user, "", task.hash, result.err)

							// 检查是否需要重试
							if retryErr := Common.CheckErrs(result.err); retryErr != nil {
								if retryCount == maxRetries-1 {
									resultChan <- result.err
									return
								}
								continue // 继续重试
							}
						}

					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						logFailedAuth(info, task.user, "", task.hash, fmt.Errorf("连接超时"))
					}

					break // 如果不需要重试，跳出重试循环
				}

				if len(Common.HashValue) > 0 {
					break
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
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				return err
			}
		}
	}

	return nil
}

// smbPasswordScan 使用密码进行认证扫描
func smbPasswordScan(info *Common.HostInfo) error {
	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads
	hasprint := false

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["smb"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["smb"] {
		for _, pass := range Common.Passwords {
			pass = strings.ReplaceAll(pass, "{user}", user)
			taskChan <- struct {
				user string
				pass string
			}{user, pass}
		}
	}
	close(taskChan)

	// 启动工作线程
	var wg sync.WaitGroup
	var hasPrintMutex sync.Mutex

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startTime := time.Now().Unix()

			for task := range taskChan {
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					if time.Now().Unix()-startTime > int64(Common.Timeout) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

					// 执行SMB2认证
					done := make(chan struct {
						success bool
						err     error
						printed bool
					})

					go func(user, pass string) {
						hasPrintMutex.Lock()
						currentHasPrint := hasprint
						hasPrintMutex.Unlock()

						success, err, printed := Smb2Con(info, user, pass, []byte{}, currentHasPrint)

						if printed {
							hasPrintMutex.Lock()
							hasprint = true
							hasPrintMutex.Unlock()
						}

						done <- struct {
							success bool
							err     error
							printed bool
						}{success, err, printed}
					}(task.user, task.pass)

					// 等待结果或超时
					select {
					case result := <-done:
						if result.success {
							logSuccessfulAuth(info, task.user, task.pass, []byte{})
							resultChan <- nil
							return
						}

						if result.err != nil {
							logFailedAuth(info, task.user, task.pass, []byte{}, result.err)

							// 检查是否需要重试
							if retryErr := Common.CheckErrs(result.err); retryErr != nil {
								if retryCount == maxRetries-1 {
									resultChan <- result.err
									return
								}
								continue // 继续重试
							}
						}

					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						logFailedAuth(info, task.user, task.pass, []byte{}, fmt.Errorf("连接超时"))
					}

					break // 如果不需要重试，跳出重试循环
				}

				if len(Common.HashValue) > 0 {
					break
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
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				return err
			}
		}
	}

	return nil
}

// logSuccessfulAuth 记录成功的认证
func logSuccessfulAuth(info *Common.HostInfo, user, pass string, hash []byte) {
	var result string
	if Common.Domain != "" {
		result = fmt.Sprintf("[+] SMB2认证成功 %v:%v Domain:%v\\%v ",
			info.Host, info.Ports, Common.Domain, user)
	} else {
		result = fmt.Sprintf("[+] SMB2认证成功 %v:%v User:%v ",
			info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		result += fmt.Sprintf("HashValue:%v", Common.HashValue)
	} else {
		result += fmt.Sprintf("Pass:%v", pass)
	}
	Common.LogSuccess(result)
}

// logFailedAuth 记录失败的认证
func logFailedAuth(info *Common.HostInfo, user, pass string, hash []byte, err error) {
	var errlog string
	if len(hash) > 0 {
		errlog = fmt.Sprintf("[-] SMB2认证失败 %v:%v User:%v HashValue:%v Err:%v",
			info.Host, info.Ports, user, Common.HashValue, err)
	} else {
		errlog = fmt.Sprintf("[-] SMB2认证失败 %v:%v User:%v Pass:%v Err:%v",
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

	// 构建基础信息
	if Common.Domain != "" {
		result = fmt.Sprintf("[*] SMB2共享信息 %v:%v Domain:%v\\%v ",
			info.Host, info.Ports, Common.Domain, user)
	} else {
		result = fmt.Sprintf("[*] SMB2共享信息 %v:%v User:%v ",
			info.Host, info.Ports, user)
	}

	// 添加认证信息
	if len(hash) > 0 {
		result += fmt.Sprintf("HashValue:%v ", Common.HashValue)
	} else {
		result += fmt.Sprintf("Pass:%v ", pass)
	}

	// 添加共享列表
	result += fmt.Sprintf("可用共享: %v", shares)
	Common.LogSuccess(result)
}
