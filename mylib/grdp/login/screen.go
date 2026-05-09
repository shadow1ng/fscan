package login

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/mylib/grdp/core"
	"github.com/shadow1ng/fscan/mylib/grdp/glog"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/nla"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/pdu"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/sec"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/t125"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/tpkt"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/x224"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	Socks5Proxy string     = ""
	LogLever    glog.LEVEL = glog.NONE
	OutputDir   string
)

// NlaAuth 仅进行NLA认证验证，不建立RDP会话，不会挤掉已登录用户
// 返回: (认证成功, 错误信息)
func NlaAuth(host, domain, user, password string, timeout int64) (bool, error) {
	g := NewClient(host, LogLever)
	return g.NlaAuthOnly(domain, user, password, timeout)
}

type Client struct {
	Host string // ip:port
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
}

func NewClient(host string, logLevel glog.LEVEL) *Client {
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)
	return &Client{
		Host: host,
	}
}

func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	local_ip := "0.0.0.0"
	net_ip := net.ParseIP(local_ip)
	if net_ip == nil {
		net_ip = net.ParseIP("0.0.0.0")
	}
	local_addr := &net.TCPAddr{
		IP: net_ip,
	}
	d := &net.Dialer{Timeout: timeout, LocalAddr: local_addr}
	return WrapperTCP(network, address, d)
}

func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	var conn net.Conn
	if Socks5Proxy == "" {
		var err error
		conn, err = forward.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		dailer, err := Socks5Dailer(forward)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}

	timeout := forward.Timeout
	if err := conn.SetWriteDeadline(time.Now().Add(timeout * 6)); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout * 6)); err != nil {
		return nil, err
	}

	return conn, nil
}

func Socks5Dailer(forward *net.Dialer) (proxy.Dialer, error) {
	u, err := url.Parse(Socks5Proxy)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("Only support socks5")
	}
	address := u.Host
	var auth proxy.Auth
	var dailer proxy.Dialer
	if u.User.String() != "" {
		auth = proxy.Auth{}
		auth.User = u.User.Username()
		password, _ := u.User.Password()
		auth.Password = password
		dailer, err = proxy.SOCKS5("tcp", address, &auth, forward)
	} else {
		dailer, err = proxy.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}

// NlaAuthOnly 仅进行NLA认证验证凭据，不建立RDP会话
// 这样不会挤掉已登录的用户
func (g *Client) NlaAuthOnly(domain, user, pwd string, timeout int64) (bool, error) {
	conn, err := WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return false, fmt.Errorf("[dial err] %v", err)
	}
	defer conn.Close()

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)

	// 设置NLA仅验证模式
	g.tpkt.SetNLAAuthOnly(true)

	// 使用 PROTOCOL_HYBRID (NLA) 协议
	g.x224.SetRequestedProtocol(x224.PROTOCOL_HYBRID)

	// 用于接收结果的通道
	resultChan := make(chan error, 1)

	// 监听错误事件（包括 ErrNLAAuthSuccess）
	g.x224.On("error", func(err error) {
		resultChan <- err
	})

	// 监听连接事件（不应该发生在 auth-only 模式）
	g.x224.On("connect", func(protocol uint32) {
		resultChan <- fmt.Errorf("unexpected connect in auth-only mode")
	})

	// 发起连接
	err = g.x224.Connect()
	if err != nil {
		return false, err
	}

	// 等待结果或超时
	select {
	case err := <-resultChan:
		if err == tpkt.ErrNLAAuthSuccess {
			return true, nil
		}
		return false, err
	case <-time.After(time.Duration(timeout*3) * time.Second):
		return false, fmt.Errorf("NLA auth timeout")
	}
}

func (g *Client) ProbeOSInfo(host, domain, user, pwd string, timeout int64, rdpProtocol uint32) (info map[string]any) {
	start := time.Now()
	exitFlag := make(chan bool, 1)
	info = make(map[string]any)

	targetSlice := strings.Split(g.Host, ":")
	ip := targetSlice[0]
	conn, err := WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)
	g.sec.SetChannelSender(g.mcs)

	g.sec.On("error", func(e error) {
		err = e
		glog.Error("sec error", e)
		g.pdu.Emit("done")
	})

	g.tpkt.On("os_info", func(infoMap map[string]any) {
		glog.Debug("[+] callback, get os info ........................")
		for k, v := range infoMap {
			glog.Debugf("%s: %s\n", k, v)
		}
		info = infoMap
		g.pdu.Emit("done")
	})

	g.x224.SetRequestedProtocol(rdpProtocol)
	g.x224.On("reconnect", func(protocol uint32) {
		info["reconn"] = protocol
		g.pdu.Emit("close")
		exitFlag <- true
	})

	err = g.x224.Connect()
	if err != nil {
		info["err"] = err.Error()
		return
	}
	glog.Info("wait connect ok")

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		glog.Debugf("===============login success %s===============", ip)
		err = nil
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		err = nil
		glog.Debug("on ready")
	})
	g.pdu.On("bitmap", func(rectangles []pdu.BitmapData) {
	})
	g.pdu.On("done", func() {
		glog.Debug("done信号触发")
		exitFlag <- true
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*3)*time.Second)
	defer cancel()

loop:
	for {
		select {
		case <-time.After(time.Second * time.Duration(timeout)):
			break loop
		case <-exitFlag:
			break loop
		case <-ctx.Done():
			glog.Debug("总超时已达到，退出")
			break loop
		}
	}
	glog.Debug("循环结束，总时间过去了：", time.Since(start))
	return info
}
