package common

import (
	"net"
	"sync"
)

// DNSCache 并发安全的 DNS 解析缓存
// 对纯 IP 输入零开销（直接返回），对域名避免重复系统调用
var DNSCache = &dnsCache{}

type dnsCache struct {
	m sync.Map // host -> *net.IPAddr
}

// ResolveIP 解析 host 为 *net.IPAddr，结果缓存
func (c *dnsCache) ResolveIP(host string) (*net.IPAddr, error) {
	if v, ok := c.m.Load(host); ok {
		addr, _ := v.(*net.IPAddr)
		return addr, nil
	}
	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}
	c.m.Store(host, addr)
	return addr, nil
}
