package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"time"
)

// tlsDialerWrapper TLS拨号器包装器
type tlsDialerWrapper struct {
	dialer Dialer
	config *ProxyConfig
	stats  *ProxyStats
}

func (t *tlsDialerWrapper) Dial(network, address string) (net.Conn, error) {
	return t.dialer.Dial(network, address)
}

func (t *tlsDialerWrapper) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.dialer.DialContext(ctx, network, address)
}

func (t *tlsDialerWrapper) DialTLS(network, address string, config *tls.Config) (net.Conn, error) {
	return t.DialTLSContext(context.Background(), network, address, config)
}

func (t *tlsDialerWrapper) DialTLSContext(ctx context.Context, network, address string, tlsConfig *tls.Config) (net.Conn, error) {
	start := time.Now()

	// 首先建立TCP连接
	tcpConn, err := t.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, NewProxyError(ErrTypeConnection, ErrMsgTLSTCPConnFailed, ErrCodeTLSTCPConnFailed, err)
	}

	// 创建TLS连接
	tlsConn := tls.Client(tcpConn, tlsConfig)

	// 设置TLS握手超时
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(t.config.Timeout))
	}

	// 进行TLS握手
	if err := tlsConn.Handshake(); err != nil {
		_ = tcpConn.Close() // TLS握手失败，Close错误可忽略
		atomic.AddInt64(&t.stats.FailedConnections, 1)
		t.stats.mu.Lock()
		t.stats.LastError = err.Error()
		t.stats.mu.Unlock()
		return nil, NewProxyError(ErrTypeConnection, ErrMsgTLSHandshakeFailed, ErrCodeTLSHandshakeFailed, err)
	}

	// 清除deadline，让上层代码管理超时
	_ = tlsConn.SetDeadline(time.Time{})

	duration := time.Since(start)
	t.updateAverageConnectTime(duration)

	return &trackedTLSConn{
		trackedConn: &trackedConn{
			Conn:  tlsConn,
			stats: t.stats,
		},
		isTLS: true,
	}, nil
}

// updateAverageConnectTime 更新平均连接时间
func (t *tlsDialerWrapper) updateAverageConnectTime(duration time.Duration) {
	t.stats.mu.Lock()
	defer t.stats.mu.Unlock()
	if t.stats.AverageConnectTime == 0 {
		t.stats.AverageConnectTime = duration
	} else {
		t.stats.AverageConnectTime = (t.stats.AverageConnectTime + duration) / 2
	}
}

// trackedConn 带统计的连接
type trackedConn struct {
	net.Conn
	stats     *ProxyStats
	bytesSent int64
	bytesRecv int64
}

func (tc *trackedConn) Read(b []byte) (n int, err error) {
	n, err = tc.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&tc.bytesRecv, int64(n))
	}
	return n, err
}

func (tc *trackedConn) Write(b []byte) (n int, err error) {
	n, err = tc.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&tc.bytesSent, int64(n))
	}
	return n, err
}

func (tc *trackedConn) Close() error {
	atomic.AddInt64(&tc.stats.ActiveConnections, -1)
	return tc.Conn.Close()
}

// trackedTLSConn 带统计的TLS连接
type trackedTLSConn struct {
	*trackedConn
	isTLS bool
}

func (ttc *trackedTLSConn) ConnectionState() tls.ConnectionState {
	if tlsConn, ok := ttc.Conn.(*tls.Conn); ok {
		return tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (ttc *trackedTLSConn) Handshake() error {
	if tlsConn, ok := ttc.Conn.(*tls.Conn); ok {
		return tlsConn.Handshake()
	}
	return nil
}

func (ttc *trackedTLSConn) OCSPResponse() []byte {
	if tlsConn, ok := ttc.Conn.(*tls.Conn); ok {
		return tlsConn.OCSPResponse()
	}
	return nil
}

func (ttc *trackedTLSConn) PeerCertificates() []*tls.Certificate {
	if tlsConn, ok := ttc.Conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		var certs []*tls.Certificate
		for _, cert := range state.PeerCertificates {
			certs = append(certs, &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
			})
		}
		return certs
	}
	return nil
}

func (ttc *trackedTLSConn) VerifyHostname(host string) error {
	if tlsConn, ok := ttc.Conn.(*tls.Conn); ok {
		return tlsConn.VerifyHostname(host)
	}
	return nil
}
