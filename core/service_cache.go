package core

import (
	"net"
	"strconv"
	"strings"
	"sync"
)

// 服务识别缓存：host:port → 服务名称
// 端口扫描阶段写入，插件匹配阶段读取
// 解决非标准端口上的服务无法匹配对应插件的问题
var (
	serviceNameCache = make(map[string]string)
	serviceCacheMu   sync.RWMutex
)

// MarkServiceName 记录端口上识别到的服务名称
func MarkServiceName(host string, port int, serviceName string) {
	if serviceName == "" || serviceName == "unknown" {
		return
	}
	key := net.JoinHostPort(host, strconv.Itoa(port))
	serviceCacheMu.Lock()
	serviceNameCache[key] = strings.ToLower(serviceName)
	serviceCacheMu.Unlock()
}

// GetServiceName 查询端口上的服务名称
func GetServiceName(host string, port int) (string, bool) {
	key := net.JoinHostPort(host, strconv.Itoa(port))
	serviceCacheMu.RLock()
	name, ok := serviceNameCache[key]
	serviceCacheMu.RUnlock()
	return name, ok
}
