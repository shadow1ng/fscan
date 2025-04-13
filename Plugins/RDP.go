package Plugins

import (
	"context"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/rfb"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RDPCredential 表示一个RDP凭据
type RDPCredential struct {
	Username string
	Password string
	Domain   string
}

// RDPScanResult 表示RDP扫描结果
type RDPScanResult struct {
	Success    bool
	Error      error
	Credential RDPCredential
}

// RdpScan 执行RDP服务扫描
func RdpScan(info *Common.HostInfo) error {
	defer func() {
		if r := recover(); r != nil {
			Common.LogError(fmt.Sprintf("RDP扫描panic: %v", r))
		}
	}()

	if Common.DisableBrute {
		return nil
	}

	port, _ := strconv.Atoi(info.Ports)
	target := fmt.Sprintf("%v:%v", info.Host, port)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []RDPCredential
	for _, user := range Common.Userdict["rdp"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, RDPCredential{
				Username: user,
				Password: actualPass,
				Domain:   Common.Domain,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["rdp"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentRdpScan(ctx, info, credentials, port, Common.Timeout)
	if result != nil {
		// 记录成功结果
		saveRdpResult(info, target, port, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("RDP扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentRdpScan 并发扫描RDP服务
func concurrentRdpScan(ctx context.Context, info *Common.HostInfo, credentials []RDPCredential, port int, timeoutSeconds int64) *RDPScanResult {
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
	resultChan := make(chan *RDPScanResult, 1)
	workChan := make(chan RDPCredential, maxConcurrent)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

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
					result := tryRdpCredential(scanCtx, info.Host, credential, port, timeoutSeconds)
					if result.Success {
						select {
						case resultChan <- result:
							scanCancel() // 找到有效凭据，取消其他工作
						default:
						}
						return
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
				Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", i+1, len(credentials), cred.Username, cred.Password))
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
			return result
		}
		return nil
	case <-ctx.Done():
		Common.LogDebug("RDP并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryRdpCredential 尝试单个RDP凭据
func tryRdpCredential(ctx context.Context, host string, credential RDPCredential, port int, timeoutSeconds int64) *RDPScanResult {
	// 创建结果通道
	resultChan := make(chan *RDPScanResult, 1)

	// 在协程中进行连接尝试
	go func() {
		success, err := RdpConn(host, credential.Domain, credential.Username, credential.Password, port, timeoutSeconds)

		select {
		case <-ctx.Done():
			// 上下文已取消，不返回结果
		case resultChan <- &RDPScanResult{
			Success:    success,
			Error:      err,
			Credential: credential,
		}:
			// 成功发送结果
		}
	}()

	// 等待结果或上下文取消
	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return &RDPScanResult{
			Success:    false,
			Error:      ctx.Err(),
			Credential: credential,
		}
	case <-time.After(time.Duration(timeoutSeconds) * time.Second):
		// 单个连接超时
		return &RDPScanResult{
			Success:    false,
			Error:      fmt.Errorf("连接超时"),
			Credential: credential,
		}
	}
}

// RdpConn 尝试RDP连接
func RdpConn(ip, domain, user, password string, port int, timeout int64) (bool, error) {
	defer func() {
		if r := recover(); r != nil {
			glog.Error("RDP连接panic:", r)
		}
	}()

	target := fmt.Sprintf("%s:%d", ip, port)

	// 创建RDP客户端
	client := NewClient(target, glog.NONE)
	if err := client.Login(domain, user, password, timeout); err != nil {
		return false, err
	}

	return true, nil
}

// saveRdpResult 保存RDP扫描结果
func saveRdpResult(info *Common.HostInfo, target string, port int, credential RDPCredential) {
	var successMsg string

	if credential.Domain != "" {
		successMsg = fmt.Sprintf("RDP %v Domain: %v\\%v Password: %v",
			target, credential.Domain, credential.Username, credential.Password)
	} else {
		successMsg = fmt.Sprintf("RDP %v Username: %v Password: %v",
			target, credential.Username, credential.Password)
	}

	Common.LogSuccess(successMsg)

	// 保存结果
	details := map[string]interface{}{
		"port":     port,
		"service":  "rdp",
		"username": credential.Username,
		"password": credential.Password,
		"type":     "weak-password",
	}

	if credential.Domain != "" {
		details["domain"] = credential.Domain
	}

	vulnResult := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.VULN,
		Target:  info.Host,
		Status:  "vulnerable",
		Details: details,
	}
	Common.SaveResult(vulnResult)
}

// Client RDP客户端结构
type Client struct {
	Host string          // 服务地址(ip:port)
	tpkt *tpkt.TPKT      // TPKT协议层
	x224 *x224.X224      // X224协议层
	mcs  *t125.MCSClient // MCS协议层
	sec  *sec.Client     // 安全层
	pdu  *pdu.Client     // PDU协议层
	vnc  *rfb.RFB        // VNC协议(可选)
}

// NewClient 创建新的RDP客户端
func NewClient(host string, logLevel glog.LEVEL) *Client {
	// 配置日志
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)

	return &Client{
		Host: host,
	}
}

// Login 执行RDP登录
func (g *Client) Login(domain, user, pwd string, timeout int64) error {
	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("[连接错误] %v", err)
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	// 初始化协议栈
	g.initProtocolStack(conn, domain, user, pwd)

	// 建立X224连接
	if err = g.x224.Connect(); err != nil {
		return fmt.Errorf("[X224连接错误] %v", err)
	}
	glog.Info("等待连接建立...")

	// 等待连接完成
	wg := &sync.WaitGroup{}
	breakFlag := false
	wg.Add(1)

	// 设置事件处理器
	g.setupEventHandlers(wg, &breakFlag, &err)

	// 添加额外的超时保护
	connectionDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(connectionDone)
	}()

	select {
	case <-connectionDone:
		// 连接过程正常完成
		return err
	case <-time.After(time.Duration(timeout) * time.Second):
		// 超时
		if !breakFlag {
			breakFlag = true
			wg.Done()
		}
		return fmt.Errorf("连接超时")
	}
}

// initProtocolStack 初始化RDP协议栈
func (g *Client) initProtocolStack(conn net.Conn, domain, user, pwd string) {
	// 创建协议层实例
	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	// 设置认证信息
	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)

	// 配置协议层关联
	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)
}

// setupEventHandlers 设置PDU事件处理器
func (g *Client) setupEventHandlers(wg *sync.WaitGroup, breakFlag *bool, err *error) {
	// 错误处理
	g.pdu.On("error", func(e error) {
		*err = e
		glog.Error("错误:", e)
		g.pdu.Emit("done")
	})

	// 连接关闭
	g.pdu.On("close", func() {
		*err = errors.New("连接关闭")
		glog.Info("连接已关闭")
		g.pdu.Emit("done")
	})

	// 连接成功
	g.pdu.On("success", func() {
		*err = nil
		glog.Info("连接成功")
		g.pdu.Emit("done")
	})

	// 连接就绪
	g.pdu.On("ready", func() {
		glog.Info("连接就绪")
		g.pdu.Emit("done")
	})

	// 屏幕更新
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("屏幕更新:", rectangles)
	})

	// 完成处理
	g.pdu.On("done", func() {
		if !*breakFlag {
			*breakFlag = true
			wg.Done()
		}
	})
}
