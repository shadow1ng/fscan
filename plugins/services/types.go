package services

import (
	"context"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

// 插件接口定义 - 统一命名风格
type Plugin interface {
	Name() string
	Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult
}

type ScanResult = plugins.Result
type ExploitResult = plugins.ExploitResult
type Exploiter = plugins.Exploiter
type Credential = plugins.Credential

// RegisterPluginWithPorts 高效注册：直接传递端口信息，避免实例创建
func RegisterPluginWithPorts(name string, factory func() Plugin, ports []int) {
	plugins.RegisterWithPorts(name, func() plugins.Plugin {
		return factory()
	}, ports)
}

// RegisterUDPPluginWithPorts 注册UDP协议插件
func RegisterUDPPluginWithPorts(name string, factory func() Plugin, ports []int) {
	plugins.RegisterUDPWithPorts(name, func() plugins.Plugin {
		return factory()
	}, ports)
}

var GenerateCredentials = plugins.GenerateCredentials

// udpProbe 执行带超时保护的 UDP 探测（防止 Write/Read 在某些内核下永久阻塞）
// 返回读到的数据和长度，超时/错误返回 nil
func udpProbe(ctx context.Context, session *common.ScanSession, target string, timeout time.Duration, pkt []byte, bufSize int) ([]byte, int) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := session.DialUDP(probeCtx, target, timeout)
	if err != nil {
		return nil, 0
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	type result struct {
		data []byte
		n    int
	}
	ch := make(chan *result, 1)
	go func() {
		if _, err := conn.Write(pkt); err != nil {
			ch <- nil
			return
		}
		buf := make([]byte, bufSize)
		n, err := conn.Read(buf)
		if err != nil {
			ch <- nil
			return
		}
		ch <- &result{data: buf[:n], n: n}
	}()

	select {
	case <-probeCtx.Done():
		_ = conn.Close()
		return nil, 0
	case r := <-ch:
		if r == nil {
			return nil, 0
		}
		return r.data, r.n
	}
}
