package Plugins

import (
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

// Brutelist 表示暴力破解的用户名密码组合
type Brutelist struct {
	user string
	pass string
}

// RdpScan 执行RDP服务扫描
func RdpScan(info *Common.HostInfo) (tmperr error) {
	defer func() {
		recover()
	}()
	if Common.DisableBrute {
		return
	}

	port, _ := strconv.Atoi(info.Ports)
	total := len(Common.Userdict["rdp"]) * len(Common.Passwords)
	num := 0
	target := fmt.Sprintf("%v:%v", info.Host, port)

	// 遍历用户名密码组合
	for _, user := range Common.Userdict["rdp"] {
		for _, pass := range Common.Passwords {
			num++
			pass = strings.Replace(pass, "{user}", user, -1)

			// 尝试连接
			flag, err := RdpConn(info.Host, Common.Domain, user, pass, port, Common.Timeout)

			if flag && err == nil {
				// 连接成功
				var result string
				if Common.Domain != "" {
					result = fmt.Sprintf("RDP %v Domain: %v\\%v Password: %v", target, Common.Domain, user, pass)
				} else {
					result = fmt.Sprintf("RDP %v Username: %v Password: %v", target, user, pass)
				}
				Common.LogSuccess(result)

				// 保存结果
				details := map[string]interface{}{
					"port":     port,
					"service":  "rdp",
					"username": user,
					"password": pass,
					"type":     "weak-password",
				}
				if Common.Domain != "" {
					details["domain"] = Common.Domain
				}

				vulnResult := &Common.ScanResult{
					Time:    time.Now(),
					Type:    Common.VULN,
					Target:  info.Host,
					Status:  "vulnerable",
					Details: details,
				}
				Common.SaveResult(vulnResult)

				return nil
			}

			// 连接失败
			errlog := fmt.Sprintf("(%v/%v) RDP %v Username: %v Password: %v Error: %v",
				num, total, target, user, pass, err)
			Common.LogError(errlog)
		}
	}

	return tmperr
}

// RdpConn 尝试RDP连接
func RdpConn(ip, domain, user, password string, port int, timeout int64) (bool, error) {
	defer func() {
		recover()
	}()
	target := fmt.Sprintf("%s:%d", ip, port)

	// 创建RDP客户端
	client := NewClient(target, glog.NONE)
	if err := client.Login(domain, user, password, timeout); err != nil {
		return false, err
	}

	return true, nil
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

	wg.Wait()
	return err
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
