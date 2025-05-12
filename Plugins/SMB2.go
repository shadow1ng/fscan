package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// Smb2Credential 表示一个SMB2凭据
type Smb2Credential struct {
	Username string
	Password string
	Hash     []byte
	IsHash   bool
}

// Smb2ScanResult 表示SMB2扫描结果
type Smb2ScanResult struct {
	Success    bool
	Error      error
	Credential Smb2Credential
	Shares     []string
}

// SmbScan2 执行SMB2服务的认证扫描，支持密码和哈希两种认证方式
func SmbScan2(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始SMB2扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 根据是否提供哈希选择认证模式
	if len(Common.HashBytes) > 0 {
		return smbHashScan(ctx, info)
	}

	return smbPasswordScan(ctx, info)
}

// smbPasswordScan 使用密码进行SMB2认证扫描
func smbPasswordScan(ctx context.Context, info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	// 构建凭据列表
	var credentials []Smb2Credential
	for _, user := range Common.Userdict["smb"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.ReplaceAll(pass, "{user}", user)
			credentials = append(credentials, Smb2Credential{
				Username: user,
				Password: actualPass,
				Hash:     []byte{},
				IsHash:   false,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始SMB2密码认证扫描 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["smb"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	return concurrentSmb2Scan(ctx, info, credentials)
}

// smbHashScan 使用哈希进行SMB2认证扫描
func smbHashScan(ctx context.Context, info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	// 构建凭据列表
	var credentials []Smb2Credential
	for _, user := range Common.Userdict["smb"] {
		for _, hash := range Common.HashBytes {
			credentials = append(credentials, Smb2Credential{
				Username: user,
				Password: "",
				Hash:     hash,
				IsHash:   true,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始SMB2哈希认证扫描 (总用户数: %d, 总哈希数: %d, 总组合数: %d)",
		len(Common.Userdict["smb"]), len(Common.HashBytes), len(credentials)))

	// 使用工作池并发扫描
	return concurrentSmb2Scan(ctx, info, credentials)
}

// concurrentSmb2Scan 并发扫描SMB2服务
func concurrentSmb2Scan(ctx context.Context, info *Common.HostInfo, credentials []Smb2Credential) error {
	// 使用ModuleThreadNum控制并发数
	maxConcurrent := Common.ModuleThreadNum
	if maxConcurrent <= 0 {
		maxConcurrent = 10 // 默认值
	}
	if maxConcurrent > len(credentials) {
		maxConcurrent = len(credentials)
	}

	// 创建工作池
	var wg sync.WaitGroup
	resultChan := make(chan *Smb2ScanResult, 1)
	workChan := make(chan Smb2Credential, maxConcurrent)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	// 记录共享信息是否已打印和锁定的用户
	var (
		sharesPrinted bool
		lockedUsers   = make(map[string]bool)
		mutex         sync.Mutex
	)

	// 启动工作协程
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for credential := range workChan {
				select {
				case <-scanCtx.Done():
					return
				default:
					// 检查用户是否已锁定
					mutex.Lock()
					locked := lockedUsers[credential.Username]
					currentSharesPrinted := sharesPrinted
					mutex.Unlock()

					if locked {
						Common.LogDebug(fmt.Sprintf("跳过已锁定用户: %s", credential.Username))
						continue
					}

					// 尝试凭据
					result := trySmb2Credential(scanCtx, info, credential, currentSharesPrinted)

					// 更新共享信息打印状态
					if result.Shares != nil && len(result.Shares) > 0 && !currentSharesPrinted {
						mutex.Lock()
						sharesPrinted = true
						mutex.Unlock()

						// 打印共享信息
						logShareInfo(info, credential.Username, credential.Password, credential.Hash, result.Shares)
					}

					// 检查认证成功
					if result.Success {
						select {
						case resultChan <- result:
							scanCancel() // 找到有效凭据，取消其他工作
						default:
						}
						return
					}

					// 检查账户锁定
					if result.Error != nil {
						errMsg := result.Error.Error()
						if strings.Contains(errMsg, "account has been automatically locked") ||
							strings.Contains(errMsg, "account has been locked") ||
							strings.Contains(errMsg, "user account has been automatically locked") {

							mutex.Lock()
							lockedUsers[credential.Username] = true
							mutex.Unlock()

							Common.LogError(fmt.Sprintf("用户 %s 已被锁定", credential.Username))
						}
					}
				}
			}
		}()
	}

	// 发送工作
	go func() {
		for i, cred := range credentials {
			select {
			case <-scanCtx.Done():
				break
			default:
				// 检查用户是否已锁定
				mutex.Lock()
				locked := lockedUsers[cred.Username]
				mutex.Unlock()

				if locked {
					continue // 跳过已锁定用户
				}

				if cred.IsHash {
					Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s Hash:%s",
						i+1, len(credentials), cred.Username, Common.HashValue))
				} else {
					Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s",
						i+1, len(credentials), cred.Username, cred.Password))
				}

				workChan <- cred
			}
		}
		close(workChan)
	}()

	// 等待结果或完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 获取结果，考虑全局超时
	select {
	case result, ok := <-resultChan:
		if ok && result != nil && result.Success {
			// 记录成功结果
			logSuccessfulAuth(info, result.Credential.Username,
				result.Credential.Password, result.Credential.Hash)
			return nil
		}
		return nil
	case <-ctx.Done():
		Common.LogDebug("SMB2扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return fmt.Errorf("全局超时")
	}
}

// trySmb2Credential 尝试单个SMB2凭据
func trySmb2Credential(ctx context.Context, info *Common.HostInfo, credential Smb2Credential, hasprint bool) *Smb2ScanResult {
	// 创建单个连接超时上下文
	connCtx, cancel := context.WithTimeout(ctx, time.Duration(Common.Timeout)*time.Second)
	defer cancel()

	// 在协程中尝试连接
	resultChan := make(chan struct {
		success bool
		shares  []string
		err     error
	}, 1)

	go func() {
		success, err, shares := Smb2Con(connCtx, info, credential.Username,
			credential.Password, credential.Hash, hasprint)

		select {
		case <-connCtx.Done():
		case resultChan <- struct {
			success bool
			shares  []string
			err     error
		}{success, shares, err}:
		}
	}()

	// 等待结果或超时
	select {
	case result := <-resultChan:
		if result.success {
			return &Smb2ScanResult{
				Success:    true,
				Credential: credential,
				Shares:     result.shares,
			}
		}

		// 失败时记录错误
		if result.err != nil {
			logFailedAuth(info, credential.Username, credential.Password, credential.Hash, result.err)
		}

		return &Smb2ScanResult{
			Success:    false,
			Error:      result.err,
			Credential: credential,
			Shares:     result.shares,
		}

	case <-connCtx.Done():
		if ctx.Err() != nil {
			// 全局超时
			return &Smb2ScanResult{
				Success:    false,
				Error:      ctx.Err(),
				Credential: credential,
			}
		}
		// 单个连接超时
		err := fmt.Errorf("连接超时")
		logFailedAuth(info, credential.Username, credential.Password, credential.Hash, err)
		return &Smb2ScanResult{
			Success:    false,
			Error:      err,
			Credential: credential,
		}
	}
}

// Smb2Con 尝试SMB2连接并进行认证，检查共享访问权限
func Smb2Con(ctx context.Context, info *Common.HostInfo, user string, pass string, hash []byte, hasprint bool) (flag bool, err error, shares []string) {
	// 建立TCP连接，使用上下文提供的超时控制
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:445", info.Host))
	if err != nil {
		return false, fmt.Errorf("连接失败: %v", err), nil
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
	dialer := &smb2.Dialer{
		Initiator: &initiator,
	}

	// 使用context设置超时
	session, err := dialer.Dial(conn)
	if err != nil {
		return false, fmt.Errorf("SMB2会话建立失败: %v", err), nil
	}
	defer session.Logoff()

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return false, ctx.Err(), nil
	default:
	}

	// 获取共享列表
	sharesList, err := session.ListSharenames()
	if err != nil {
		return false, fmt.Errorf("获取共享列表失败: %v", err), nil
	}

	// 再次检查上下文是否已取消
	select {
	case <-ctx.Done():
		return false, ctx.Err(), sharesList
	default:
	}

	// 尝试访问C$共享以验证管理员权限
	fs, err := session.Mount("C$")
	if err != nil {
		return false, fmt.Errorf("挂载C$失败: %v", err), sharesList
	}
	defer fs.Umount()

	// 最后检查上下文是否已取消
	select {
	case <-ctx.Done():
		return false, ctx.Err(), sharesList
	default:
	}

	// 尝试读取系统文件以验证权限
	path := `Windows\win.ini`
	f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return false, fmt.Errorf("访问系统文件失败: %v", err), sharesList
	}
	defer f.Close()

	return true, nil, sharesList
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
	Common.LogBase(msg)
}
