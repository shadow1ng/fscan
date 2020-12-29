package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"strings"
	"time"
)

func MemcachedScan(info *common.HostInfo) (err error, result string) {
	realhost := fmt.Sprintf("%s:%d", info.Host, common.PORTList["mem"])
	client, err := net.DialTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	if err == nil {
		client.SetDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
		client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
		rev := make([]byte, 1024)
		n, err := client.Read(rev)
		if err == nil {
			if strings.Contains(string(rev[:n]), "STAT") {
				defer client.Close()
				result = fmt.Sprintf("Memcached:%s unauthorized", realhost)
				common.LogSuccess(result)
			}
		}
	}
	return err, result
}
