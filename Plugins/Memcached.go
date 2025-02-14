package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// MemcachedScan 检测Memcached未授权访问
func MemcachedScan(info *Common.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	timeout := time.Duration(Common.Timeout) * time.Second

	// 建立TCP连接
	client, err := Common.WrapperTcpWithTimeout("tcp", realhost, timeout)
	if err != nil {
		return err
	}
	defer client.Close()

	// 设置超时时间
	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	// 发送stats命令
	if _, err := client.Write([]byte("stats\n")); err != nil {
		return err
	}

	// 读取响应
	rev := make([]byte, 1024)
	n, err := client.Read(rev)
	if err != nil {
		Common.LogError(fmt.Sprintf("Memcached %v:%v %v", info.Host, info.Ports, err))
		return err
	}

	// 检查响应内容
	if strings.Contains(string(rev[:n]), "STAT") {
		// 保存结果
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":        info.Ports,
				"service":     "memcached",
				"type":        "unauthorized-access",
				"description": "Memcached unauthorized access",
			},
		}
		Common.SaveResult(result)
		Common.LogSuccess(fmt.Sprintf("Memcached %s 未授权访问", realhost))
	}

	return nil
}
