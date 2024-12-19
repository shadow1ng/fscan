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

	// 如果未启用暴力破解则直接返回
	if Common.IsBrute {
		return nil
	}
	fmt.Println("[+] Smb2扫描模块开始...")

	hasprint := false
	startTime := time.Now().Unix()

	// 使用哈希认证模式
	if len(Common.HashBytes) > 0 {
		return smbHashScan(info, hasprint, startTime)
	}

	// 使用密码认证模式
	return smbPasswordScan(info, hasprint, startTime)
}

// smbHashScan 使用哈希进行认证扫描
func smbHashScan(info *Common.HostInfo, hasprint bool, startTime int64) error {
	for _, user := range Common.Userdict["smb"] {
		for _, hash := range Common.HashBytes {
			success, err, printed := Smb2Con(info, user, "", hash, hasprint)
			if printed {
				hasprint = true
			}

			if success {
				logSuccessfulAuth(info, user, "", hash)
				return err
			}

			logFailedAuth(info, user, "", hash, err)

			if shouldStopScan(err, startTime, len(Common.Userdict["smb"])*len(Common.HashBytes)) {
				return err
			}

			if len(Common.Hash) > 0 {
				break
			}
		}
	}
	fmt.Println("[+] Smb2扫描模块结束...")
	return nil
}

// smbPasswordScan 使用密码进行认证扫描
func smbPasswordScan(info *Common.HostInfo, hasprint bool, startTime int64) error {
	for _, user := range Common.Userdict["smb"] {
		for _, pass := range Common.Passwords {
			pass = strings.ReplaceAll(pass, "{user}", user)
			success, err, printed := Smb2Con(info, user, pass, []byte{}, hasprint)
			if printed {
				hasprint = true
			}

			if success {
				logSuccessfulAuth(info, user, pass, []byte{})
				return err
			}

			logFailedAuth(info, user, pass, []byte{}, err)

			if shouldStopScan(err, startTime, len(Common.Userdict["smb"])*len(Common.Passwords)) {
				return err
			}

			if len(Common.Hash) > 0 {
				break
			}
		}
	}
	fmt.Println("[+] Smb2扫描模块结束...")
	return nil
}

// logSuccessfulAuth 记录成功的认证
func logSuccessfulAuth(info *Common.HostInfo, user, pass string, hash []byte) {
	var result string
	if Common.Domain != "" {
		result = fmt.Sprintf("[✓] SMB2认证成功 %v:%v Domain:%v\\%v ",
			info.Host, info.Ports, Common.Domain, user)
	} else {
		result = fmt.Sprintf("[✓] SMB2认证成功 %v:%v User:%v ",
			info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		result += fmt.Sprintf("Hash:%v", Common.Hash)
	} else {
		result += fmt.Sprintf("Pass:%v", pass)
	}
	Common.LogSuccess(result)
}

// logFailedAuth 记录失败的认证
func logFailedAuth(info *Common.HostInfo, user, pass string, hash []byte, err error) {
	var errlog string
	if len(hash) > 0 {
		errlog = fmt.Sprintf("[x] SMB2认证失败 %v:%v User:%v Hash:%v Err:%v",
			info.Host, info.Ports, user, Common.Hash, err)
	} else {
		errlog = fmt.Sprintf("[x] SMB2认证失败 %v:%v User:%v Pass:%v Err:%v",
			info.Host, info.Ports, user, pass, err)
	}
	errlog = strings.ReplaceAll(errlog, "\n", " ")
	Common.LogError(errlog)
}

// shouldStopScan 检查是否应该停止扫描
func shouldStopScan(err error, startTime int64, totalAttempts int) bool {
	if Common.CheckErrs(err) {
		return true
	}

	if time.Now().Unix()-startTime > (int64(totalAttempts) * Common.Timeout) {
		return true
	}

	return false
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
		result += fmt.Sprintf("Hash:%v ", Common.Hash)
	} else {
		result += fmt.Sprintf("Pass:%v ", pass)
	}

	// 添加共享列表
	result += fmt.Sprintf("可用共享: %v", shares)
	Common.LogSuccess(result)
}
