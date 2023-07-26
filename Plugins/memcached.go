package Plugins

import (
	"fmt"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
)

func MemcachedScan(info common.HostInfo, flags common.Flags) (err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	client, err := common.WrapperTcpWithTimeout("tcp", realhost, common.Socks5{Address: flags.Socks5Proxy}, time.Duration(flags.Timeout)*time.Second)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(flags.Timeout) * time.Second))
		if err == nil {
			_, err = client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
			if err == nil {
				rev := make([]byte, 1024)
				n, err := client.Read(rev)
				if err == nil {
					if strings.Contains(string(rev[:n]), "STAT") {
						result := fmt.Sprintf("[+] Memcached %s unauthorized", realhost)
						common.LogSuccess(result)
					}
				} else {
					errlog := fmt.Sprintf("[-] Memcached %v:%v %v", info.Host, info.Ports, err)
					common.LogError(errlog)
				}
			}
		}
	}
	return err
}
