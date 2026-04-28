//go:build plugin_smb || !plugin_selective

package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	iofs "io/fs"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/shadow1ng/fscan/common"
	"github.com/stacktitan/smb/smb"
)

// SMBProtocol SMB协议版本
type SMBProtocol int

const (
	SMBProtocolUnknown SMBProtocol = iota
	SMBProtocol1
	SMBProtocol2
)

func (p SMBProtocol) String() string {
	switch p {
	case SMBProtocol1:
		return "SMBv1"
	case SMBProtocol2:
		return "SMBv2"
	default:
		return "Unknown"
	}
}

// SMBTarget 目标信息（一次探测，到处使用）
type SMBTarget struct {
	Protocol     SMBProtocol
	ComputerName string
	DomainName   string
	OSVersion    string
	NativeOS     string
	NativeLM     string
	NTLMFlags    []string
	Vulnerable   *SMBVuln
}

// SMBVuln 漏洞信息
type SMBVuln struct {
	CVE20200796 bool // SMB Ghost
}

// Summary 返回SMB信息摘要
func (t *SMBTarget) Summary() string {
	var parts []string
	parts = append(parts, t.Protocol.String())

	if t.OSVersion != "" {
		parts = append(parts, t.OSVersion)
	}

	if t.ComputerName != "" {
		parts = append(parts, t.ComputerName)
	}

	return strings.Join(parts, " ")
}

// SMB协议数据包定义
var (
	smbv1NegotiatePacket = []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
		0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
		0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
		0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
		0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
		0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}

	smbv1SessionSetupPacket = []byte{
		0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
		0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
		0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
		0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
		0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
		0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
		0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
		0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
		0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
		0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	smbv2NegotiatePacket = []byte{
		0x00, 0x00, 0x00, 0x45, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
		0x00, 0x00, 0x00, 0x18, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
		0xAC, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02,
		0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32,
		0x00, 0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x30, 0x30,
		0x32, 0x00, 0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x3F,
		0x3F, 0x3F, 0x00,
	}

	smbv2SessionSetupPacket = []byte{
		0x00, 0x00, 0x00, 0x68, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
		0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02,
	}

	// SMB Ghost (CVE-2020-0796) 检测数据包
	smbGhostPacket = "\x00" +
		"\x00\x00\xc0" +
		"\xfeSMB@\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x1f\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"$\x00" +
		"\x08\x00" +
		"\x01\x00" +
		"\x00\x00" +
		"\x7f\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"x\x00" +
		"\x00\x00" +
		"\x02\x00" +
		"\x00\x00" +
		"\x02\x02" +
		"\x10\x02" +
		"\x22\x02" +
		"$\x02" +
		"\x00\x03" +
		"\x02\x03" +
		"\x10\x03" +
		"\x11\x03" +
		"\x00\x00\x00\x00" +
		"\x01\x00" +
		"&\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" +
		"\x20\x00" +
		"\x01\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00" +
		"\x03\x00" +
		"\x0e\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" +
		"\x00\x00" +
		"\x01\x00\x00\x00" +
		"\x01\x00" +
		"\x00\x00" +
		"\x00\x00\x00\x00"
)

// probeTarget 探测目标SMB信息（协议版本、系统信息）
func probeTarget(ctx context.Context, host string, port int, timeout time.Duration, session *common.ScanSession) (*SMBTarget, error) {
	target := fmt.Sprintf("%s:%d", host, port)

	conn, err := session.DialTCP(ctx, "tcp", target, timeout)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 首先尝试SMBv1协商
	_, err = conn.Write(smbv1NegotiatePacket)
	if err != nil {
		return nil, fmt.Errorf("发送SMBv1协商包失败: %w", err)
	}

	// 读取SMBv1协商响应
	r1, err := readSMBMessage(conn)
	if err != nil {
		common.LogDebug(fmt.Sprintf("读取SMBv1协商响应失败: %v", err))
	}

	// 检查是否支持SMBv1
	if len(r1) > 0 {
		return probeSMBv1(conn, target, timeout)
	}

	// SMBv2路径
	return probeSMBv2(ctx, target, timeout, session)
}

// probeSMBv1 处理SMBv1协议信息收集
func probeSMBv1(conn net.Conn, target string, timeout time.Duration) (*SMBTarget, error) {
	// 发送Session Setup请求
	_, err := conn.Write(smbv1SessionSetupPacket)
	if err != nil {
		return nil, fmt.Errorf("发送SMBv1 Session Setup失败: %w", err)
	}

	ret, err := readSMBMessage(conn)
	if err != nil || len(ret) < 47 {
		return nil, fmt.Errorf("读取SMBv1 Session Setup响应失败: %w", err)
	}

	info := &SMBTarget{
		Protocol: SMBProtocol1,
	}

	// 解析blob信息
	blobLength := int(bytesToUint16(ret[43:45]))
	blobCount := int(bytesToUint16(ret[45:47]))

	gssNative := ret[47:]
	gssLen := len(gssNative)

	// 校验远端返回的偏移量
	if blobLength > gssLen || blobCount > gssLen || blobLength > blobCount {
		return info, nil
	}

	offNTLM := bytes.Index(gssNative, []byte("NTLMSSP"))
	if offNTLM == -1 {
		return info, nil
	}

	// 提取native OS和LM信息
	native := gssNative[blobLength:blobCount]
	ss := strings.Split(string(native), "\x00\x00")

	if len(ss) > 0 {
		info.NativeOS = trimSMBString(ss[0])
	}
	if len(ss) > 1 {
		info.NativeLM = trimSMBString(ss[1])
	}

	// 解析NTLM信息
	if offNTLM <= blobLength {
		bs := gssNative[offNTLM:blobLength]
		parseNTLMChallenge(bs, info)
	}

	return info, nil
}

// probeSMBv2 处理SMBv2协议信息收集
func probeSMBv2(ctx context.Context, target string, timeout time.Duration, session *common.ScanSession) (*SMBTarget, error) {
	conn2, err := session.DialTCP(ctx, "tcp", target, timeout)
	if err != nil {
		return nil, fmt.Errorf("SMBv2连接失败: %w", err)
	}
	defer func() { _ = conn2.Close() }()

	_ = conn2.SetDeadline(time.Now().Add(timeout))

	// 发送SMBv2协商包
	_, err = conn2.Write(smbv2NegotiatePacket)
	if err != nil {
		return nil, fmt.Errorf("发送SMBv2协商包失败: %w", err)
	}

	r2, err := readSMBMessage(conn2)
	if err != nil {
		return nil, fmt.Errorf("读取SMBv2协商响应失败: %w", err)
	}

	// 构建NTLM数据包
	var ntlmData []byte
	if len(r2) > 70 && hex.EncodeToString(r2[70:71]) == "03" {
		flags := []byte{0x15, 0x82, 0x08, 0xa0}
		ntlmData = buildNTLMSSPData(flags)
	} else {
		flags := []byte{0x05, 0x80, 0x08, 0xa0}
		ntlmData = buildNTLMSSPData(flags)
	}

	// 发送Session Setup
	_, err = conn2.Write(smbv2SessionSetupPacket)
	if err != nil {
		return nil, fmt.Errorf("发送SMBv2 Session Setup失败: %w", err)
	}

	_, err = readSMBMessage(conn2)
	if err != nil {
		return nil, fmt.Errorf("读取SMBv2 Session Setup响应失败: %w", err)
	}

	// 发送NTLM协商包
	_, err = conn2.Write(ntlmData)
	if err != nil {
		return nil, fmt.Errorf("发送SMBv2 NTLM包失败: %w", err)
	}

	ret, err := readSMBMessage(conn2)
	if err != nil {
		return nil, fmt.Errorf("读取SMBv2 NTLM响应失败: %w", err)
	}

	ntlmOff := bytes.Index(ret, []byte("NTLMSSP"))
	if ntlmOff == -1 {
		return &SMBTarget{Protocol: SMBProtocol2}, nil
	}

	info := &SMBTarget{
		Protocol: SMBProtocol2,
	}

	parseNTLMChallenge(ret[ntlmOff:], info)
	return info, nil
}

// checkSMBGhost 检测CVE-2020-0796漏洞
func checkSMBGhost(ctx context.Context, host string, timeout time.Duration, session *common.ScanSession) bool {
	addr := fmt.Sprintf("%s:445", host)

	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	if _, err = conn.Write([]byte(smbGhostPacket)); err != nil {
		return false
	}

	buff := make([]byte, 1024)
	n, err := conn.Read(buff)
	if err != nil || n == 0 {
		return false
	}

	// 检测CVE-2020-0796特征
	if bytes.Contains(buff[:n], []byte("Public")) &&
		len(buff[:n]) >= 76 &&
		bytes.Equal(buff[72:74], []byte{0x11, 0x03}) &&
		bytes.Equal(buff[74:76], []byte{0x02, 0x00}) {
		return true
	}

	return false
}

// SMBAuthenticator 统一认证接口
type SMBAuthenticator interface {
	Authenticate(ctx context.Context, host string, port int, cred Credential, domain string, timeout time.Duration, session *common.ScanSession) (*AuthResult, error)
	ListShares(ctx context.Context, host string, port int, cred Credential, domain string, timeout time.Duration, session *common.ScanSession) ([]string, error)
}

// SMB1Authenticator SMB1认证器
type SMB1Authenticator struct{}

// Authenticate 执行SMB1认证
func (a *SMB1Authenticator) Authenticate(ctx context.Context, host string, port int, cred Credential, domain string, timeout time.Duration, session *common.ScanSession) (*AuthResult, error) {
	options := smb.Options{
		Host:        host,
		Port:        port,
		User:        cred.Username,
		Password:    cred.Password,
		Domain:      domain,
		Workstation: "",
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resultChan := make(chan *AuthResult, 1)

	go func() {
		session, err := smb.NewSession(options, false)
		if err != nil {
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifySMBError(err),
				Error:     err,
			}
			return
		}

		if session.IsAuthenticated {
			resultChan <- &AuthResult{
				Success:   true,
				Conn:      &smb1SessionWrapper{session},
				ErrorType: ErrorTypeUnknown,
				Error:     nil,
			}
		} else {
			session.Close()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeAuth,
				Error:     fmt.Errorf("认证失败：用户名或密码错误"),
			}
		}
	}()

	select {
	case result := <-resultChan:
		return result, nil
	case <-timeoutCtx.Done():
		go func() {
			result := <-resultChan
			if result != nil && result.Conn != nil {
				_ = result.Conn.Close()
			}
		}()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     fmt.Errorf("连接超时"),
		}, nil
	case <-ctx.Done():
		go func() {
			result := <-resultChan
			if result != nil && result.Conn != nil {
				_ = result.Conn.Close()
			}
		}()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     ctx.Err(),
		}, nil
	}
}

// ListShares 列举SMB共享（SMB1使用SMB2库列举）
func (a *SMB1Authenticator) ListShares(ctx context.Context, host string, port int, cred Credential, domain string, timeout time.Duration, session *common.ScanSession) ([]string, error) {
	return listSMBSharesInternal(ctx, host, port, cred, domain, timeout, session)
}

// SMB2Authenticator SMB2认证器
type SMB2Authenticator struct{}

// Authenticate 执行SMB2认证
func (a *SMB2Authenticator) Authenticate(ctx context.Context, host string, port int, cred Credential, domain string, timeout time.Duration, session *common.ScanSession) (*AuthResult, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := session.DialTCP(ctx, "tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return &AuthResult{
			Success:   false,
			ErrorType: classifySMBError(err),
			Error:     err,
		}, nil
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cred.Username,
			Password: cred.Password,
			Domain:   domain,
		},
	}

	s, err := d.DialContext(timeoutCtx, conn)
	if err != nil {
		_ = conn.Close()
		return &AuthResult{
			Success:   false,
			ErrorType: classifySMBError(err),
			Error:     fmt.Errorf("SMB2认证失败: %w", err),
		}, nil
	}

	// 尝试列举共享来验证认证成功
	_, _ = s.ListSharenames()

	return &AuthResult{
		Success:   true,
		Conn:      &smb2SessionWrapper{s, conn},
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}, nil
}

// ListShares 列举SMB2共享
func (a *SMB2Authenticator) ListShares(ctx context.Context, host string, port int, cred Credential, domain string, timeout time.Duration, session *common.ScanSession) ([]string, error) {
	return listSMBSharesInternal(ctx, host, port, cred, domain, timeout, session)
}

// listSMBSharesInternal 内部共享列举实现
func listSMBSharesInternal(ctx context.Context, host string, port int, cred Credential, domain string, timeout time.Duration, session *common.ScanSession) ([]string, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := session.DialTCP(ctx, "tcp", target, timeout*2)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cred.Username,
			Password: cred.Password,
			Domain:   domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Logoff() }()

	shares, err := s.ListSharenames()
	if err != nil {
		return nil, err
	}

	var shareInfo []string
	systemShares := map[string]bool{
		"ADMIN$": true,
		"C$":     true,
		"IPC$":   true,
	}

	for _, shareName := range shares {
		if systemShares[shareName] {
			continue
		}

		fs, err := s.Mount(shareName)
		if err != nil {
			continue
		}

		fileCount := 0
		maxFiles := 10
		_ = iofs.WalkDir(fs.DirFS("."), ".", func(path string, d iofs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if path != "." && fileCount < maxFiles {
				shareInfo = append(shareInfo, fmt.Sprintf("   [->] [%s] %s", shareName, path))
				fileCount++
			}

			if fileCount >= maxFiles {
				return iofs.SkipDir
			}

			return nil
		})

		_ = fs.Umount()
	}

	return shareInfo, nil
}

// smb1SessionWrapper 包装SMB1会话以实现io.Closer
type smb1SessionWrapper struct {
	session *smb.Session
}

func (w *smb1SessionWrapper) Close() error {
	w.session.Close()
	return nil
}

// smb2SessionWrapper 包装SMB2会话以实现io.Closer
type smb2SessionWrapper struct {
	session *smb2.Session
	conn    io.Closer
}

func (w *smb2SessionWrapper) Close() error {
	_ = w.session.Logoff()
	return w.conn.Close()
}

// classifySMBError 统一SMB错误分类
func classifySMBError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	smbAuthErrors := []string{
		// 通用认证错误
		"invalid username",
		"invalid password",
		"authentication failed",
		"logon failed",
		"logon failure",
		"access denied",
		"permission denied",
		"unauthorized",
		"login failed",
		"bad username",
		"bad password",
		"wrong password",
		"incorrect password",
		"invalid credentials",
		"bad credentials",
		"authentication error",
		"auth failed",
		"login denied",
		"credential",
		"user not found",
		"invalid account",
		"account locked",
		"account disabled",
		"password expired",
		// SMB特定错误
		"smb: authentication failed",
		"smb: invalid user",
		"smb: invalid password",
		"smb: access denied",
		"smb: logon failure",
		"smb: bad password",
		"smb: user unknown",
		"smb: wrong password",
		"smb: login failed",
		"smb: unauthorized",
		"smb2认证失败",
		"ntlm authentication failed",
		"ntlm auth failed",
		// NT Status codes
		"nt_status_logon_failure",
		"nt_status_wrong_password",
		"nt_status_no_such_user",
		"nt_status_access_denied",
		"nt_status_account_disabled",
		"nt_status_account_locked_out",
		"nt_status_password_expired",
		"status_logon_failure",
		"status_wrong_password",
		"status_access_denied",
		"status_invalid_parameter",
		"status_no_such_user",
		"status_account_locked_out",
		"status_password_expired",
		"status_account_disabled",
		// 十六进制状态码
		"0xc000006d",
		"0xc0000022",
		"0xc000006a",
		"0xc0000064",
		"0xc0000234",
	}

	return ClassifyError(err, smbAuthErrors, CommonNetworkErrors)
}

// readSMBMessage 从连接读取NetBIOS消息
func readSMBMessage(conn net.Conn) ([]byte, error) {
	headerBuf := make([]byte, 4)
	n, err := conn.Read(headerBuf)
	if err != nil {
		return nil, err
	}
	if n != 4 {
		return nil, fmt.Errorf("NetBIOS头部长度不足: %d", n)
	}

	messageLength := int(headerBuf[0])<<24 | int(headerBuf[1])<<16 | int(headerBuf[2])<<8 | int(headerBuf[3])

	if messageLength > 1024*1024 {
		return nil, fmt.Errorf("消息长度过大: %d", messageLength)
	}

	if messageLength == 0 {
		return headerBuf, nil
	}

	messageBuf := make([]byte, messageLength)
	totalRead := 0
	for totalRead < messageLength {
		n, err := conn.Read(messageBuf[totalRead:])
		if err != nil {
			return nil, err
		}
		totalRead += n
	}

	result := make([]byte, 0, 4+messageLength)
	result = append(result, headerBuf...)
	result = append(result, messageBuf...)

	return result, nil
}

// parseNTLMChallenge 解析NTLM Challenge消息
func parseNTLMChallenge(data []byte, info *SMBTarget) {
	if len(data) < 32 {
		return
	}

	if !bytes.Equal(data[0:8], []byte("NTLMSSP\x00")) {
		return
	}

	if len(data) < 12 {
		return
	}
	messageType := bytesToUint32(data[8:12])
	if messageType != 2 {
		return
	}

	// 解析Target Name
	if len(data) >= 20 {
		targetLength := bytesToUint16(data[12:14])
		targetOffset := bytesToUint32(data[16:20])

		if targetLength > 0 && int(targetOffset) < len(data) && int(targetOffset+uint32(targetLength)) <= len(data) {
			targetName := parseUnicodeString(data[targetOffset : targetOffset+uint32(targetLength)])
			if targetName != "" {
				info.DomainName = targetName
			}
		}
	}

	// 解析Flags
	if len(data) >= 24 {
		flags := bytesToUint32(data[20:24])
		info.NTLMFlags = parseNTLMFlags(flags)
	}

	// 解析Target Info (AV_PAIR结构)
	if len(data) >= 52 {
		targetInfoLength := bytesToUint16(data[40:42])
		targetInfoOffset := bytesToUint32(data[44:48])

		if targetInfoLength > 0 && int(targetInfoOffset) < len(data) &&
			int(targetInfoOffset+uint32(targetInfoLength)) <= len(data) {
			targetInfoData := data[targetInfoOffset : targetInfoOffset+uint32(targetInfoLength)]
			parseTargetInfo(targetInfoData, info)
		}
	}

	// 解析OS版本信息
	if len(data) >= 56 {
		flags := bytesToUint32(data[20:24])
		if flags&0x02000000 != 0 && len(data) >= 56 {
			parseOSVersion(data[48:56], info)
		}
	}
}

// parseTargetInfo 解析Target Information
func parseTargetInfo(data []byte, info *SMBTarget) {
	offset := 0

	for offset+4 <= len(data) {
		avId := bytesToUint16(data[offset : offset+2])
		avLen := bytesToUint16(data[offset+2 : offset+4])

		if avId == 0x0000 {
			break
		}

		if offset+4+int(avLen) > len(data) {
			break
		}

		value := data[offset+4 : offset+4+int(avLen)]

		switch avId {
		case 0x0001: // MsvAvNbComputerName
			computerName := parseUnicodeString(value)
			if computerName != "" {
				info.ComputerName = computerName
			}
		case 0x0002: // MsvAvNbDomainName
			if info.DomainName == "" {
				domainName := parseUnicodeString(value)
				if domainName != "" {
					info.DomainName = domainName
				}
			}
		case 0x0003: // MsvAvDnsComputerName
			if info.ComputerName == "" {
				dnsComputerName := parseUnicodeString(value)
				if dnsComputerName != "" {
					info.ComputerName = dnsComputerName
				}
			}
		}

		offset += 4 + int(avLen)
	}
}

// parseOSVersion 解析操作系统版本
func parseOSVersion(data []byte, info *SMBTarget) {
	if len(data) < 8 {
		return
	}

	majorVersion := data[0]
	minorVersion := data[1]
	buildNumber := bytesToUint16(data[2:4])

	var osName string
	switch {
	case majorVersion == 10 && minorVersion == 0:
		if buildNumber >= 22000 {
			osName = "Windows 11"
		} else {
			osName = "Windows 10"
		}
	case majorVersion == 6 && minorVersion == 3:
		osName = "Windows 8.1/Server 2012 R2"
	case majorVersion == 6 && minorVersion == 2:
		osName = "Windows 8/Server 2012"
	case majorVersion == 6 && minorVersion == 1:
		osName = "Windows 7/Server 2008 R2"
	case majorVersion == 6 && minorVersion == 0:
		osName = "Windows Vista/Server 2008"
	case majorVersion == 5 && minorVersion == 2:
		osName = "Windows XP x64/Server 2003"
	case majorVersion == 5 && minorVersion == 1:
		osName = "Windows XP"
	case majorVersion == 5 && minorVersion == 0:
		osName = "Windows 2000"
	default:
		osName = fmt.Sprintf("Windows %d.%d", majorVersion, minorVersion)
	}

	info.OSVersion = fmt.Sprintf("%s (Build %d)", osName, buildNumber)
}

// 辅助函数
func bytesToUint16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return uint16(b[0]) | uint16(b[1])<<8
}

func bytesToUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func trimSMBString(s string) string {
	return strings.Trim(strings.TrimSpace(s), "\x00")
}

func parseUnicodeString(data []byte) string {
	if len(data)%2 != 0 {
		return ""
	}

	var runes []rune
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			break
		}
		r := uint16(data[i]) | uint16(data[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, rune(r))
	}
	return string(runes)
}

func parseNTLMFlags(flags uint32) []string {
	flagNames := map[uint32]string{
		0x00000001: "NEGOTIATE_UNICODE",
		0x00000002: "NEGOTIATE_OEM",
		0x00000004: "REQUEST_TARGET",
		0x00000010: "NEGOTIATE_SIGN",
		0x00000020: "NEGOTIATE_SEAL",
		0x00000200: "NEGOTIATE_NTLM",
		0x00080000: "NEGOTIATE_EXTENDED_SESSIONSECURITY",
		0x02000000: "NEGOTIATE_VERSION",
		0x20000000: "NEGOTIATE_128",
		0x80000000: "NEGOTIATE_56",
	}

	var activeFlags []string
	for flag, name := range flagNames {
		if flags&flag != 0 {
			activeFlags = append(activeFlags, name)
		}
	}

	return activeFlags
}

func buildNTLMSSPData(flags []byte) []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x9A, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x58, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x60, 0x40, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
		0x05, 0x02, 0xA0, 0x36, 0x30, 0x34, 0xA0, 0x0E, 0x30, 0x0C,
		0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
		0x02, 0x0A, 0xA2, 0x22, 0x04, 0x20, 0x4E, 0x54, 0x4C, 0x4D,
		0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
		flags[0], flags[1], flags[2], flags[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}
