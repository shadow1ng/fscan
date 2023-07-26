package common

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type Socks5 struct {
	Address string
}

func WrapperTcpWithTimeout(network, address string, socks5Proxy Socks5, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return WrapperTCP(network, address, socks5Proxy, d)
}

func WrapperTCP(network, address string, socks5Proxy Socks5, forward *net.Dialer) (net.Conn, error) {
	//get conn
	var conn net.Conn
	if socks5Proxy.Address == "" {
		var err error
		conn, err = forward.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		dailer, err := Socks5Dailer(forward, socks5Proxy)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func Socks5Dailer(forward *net.Dialer, socks5Proxy Socks5) (proxy.Dialer, error) {
	u, err := url.Parse(socks5Proxy.Address)
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
