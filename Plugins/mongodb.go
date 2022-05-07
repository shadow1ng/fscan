package Plugins

import (
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"time"
)

func MongodbScan(info *common.HostInfo) error {
	if common.IsBrute {
		return nil
	}

	_, err := MongodbUnauth(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] Mongodb %v:%v %v", info.Host, info.Ports, err)
		common.LogError(errlog)
	}
	return err
}

func MongodbUnauth(info *common.HostInfo) (flag bool, err error) {
	flag = false
	senddata := []byte{72, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 1, 0, 0, 0, 33, 0, 0, 0, 2, 103, 101, 116, 76, 111, 103, 0, 16, 0, 0, 0, 115, 116, 97, 114, 116, 117, 112, 87, 97, 114, 110, 105, 110, 103, 115, 0, 0}
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return flag, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write(senddata)
	if err != nil {
		return flag, err
	}
	buf := make([]byte, 1024)
	count, err := conn.Read(buf)
	if err != nil {
		return flag, err
	}
	text := string(buf[0:count])
	if strings.Contains(text, "totalLinesWritten") {
		flag = true
		result := fmt.Sprintf("[+] Mongodb:%v unauthorized", realhost)
		common.LogSuccess(result)
	}
	return flag, err
}
