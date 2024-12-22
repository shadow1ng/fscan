package Plugins

import (
	"fmt"
	"github.com/gosnmp/gosnmp"
	"github.com/shadow1ng/fscan/Common"
	"strconv"
	"strings"
	"time"
)

// SNMPScan 执行SNMP服务扫描
// SNMPScan 执行SNMP服务扫描
func SNMPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	starttime := time.Now().Unix()
	portNum, _ := strconv.Atoi(info.Ports) // 添加端口转换

	// 首先尝试默认community strings
	defaultCommunities := []string{"public", "private", "cisco", "community"}

	for _, community := range defaultCommunities {
		flag, err := SNMPConnect(info, community, portNum) // 传入转换后的端口
		if flag && err == nil {
			return err
		}

		if Common.CheckErrs(err) {
			return err
		}

		errlog := fmt.Sprintf("[-] SNMP服务 %v:%v 尝试失败 community: %v 错误: %v",
			info.Host, info.Ports, community, err)
		Common.LogError(errlog)
		tmperr = err

		// 修正超时计算
		timeout := time.Duration(Common.Timeout) * time.Second
		if time.Now().Unix()-starttime > int64(timeout.Seconds())*int64(len(defaultCommunities)) {
			return err
		}
	}

	return tmperr
}

// SNMPConnect 尝试SNMP连接
func SNMPConnect(info *Common.HostInfo, community string, portNum int) (bool, error) {
	host := info.Host
	timeout := time.Duration(Common.Timeout) * time.Second

	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(portNum),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}

	err := snmp.Connect()
	if err != nil {
		return false, err
	}
	defer snmp.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	result, err := snmp.Get(oids)
	if err != nil {
		return false, err
	}

	if len(result.Variables) > 0 {
		success := fmt.Sprintf("[+] SNMP服务 %v:%v community: %v",
			host, portNum, community) // 使用portNum替换port

		if result.Variables[0].Type != gosnmp.NoSuchObject {
			sysDesc := strings.TrimSpace(string(result.Variables[0].Value.([]byte)))
			success += fmt.Sprintf(" System: %v", sysDesc)
		}

		Common.LogSuccess(success)
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
