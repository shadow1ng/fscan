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
func SNMPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	portNum, _ := strconv.Atoi(info.Ports)
	defaultCommunities := []string{"public", "private", "cisco", "community"}
	timeout := time.Duration(Common.Timeout) * time.Second
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
	Common.LogDebug(fmt.Sprintf("尝试默认 community 列表 (总数: %d)", len(defaultCommunities)))

	tried := 0
	total := len(defaultCommunities)

	for _, community := range defaultCommunities {
		tried++
		Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试 community: %s", tried, total, community))

		for retryCount := 0; retryCount < maxRetries; retryCount++ {
			if retryCount > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: community: %s", retryCount+1, community))
			}

			done := make(chan struct {
				success bool
				sysDesc string
				err     error
			}, 1)

			go func(community string) {
				success, sysDesc, err := SNMPConnect(info, community, portNum)
				select {
				case done <- struct {
					success bool
					sysDesc string
					err     error
				}{success, sysDesc, err}:
				default:
				}
			}(community)

			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success && err == nil {
					successMsg := fmt.Sprintf("SNMP服务 %s community: %v 连接成功", target, community)
					if result.sysDesc != "" {
						successMsg += fmt.Sprintf(" System: %v", result.sysDesc)
					}
					Common.LogSuccess(successMsg)

					// 保存结果
					vulnResult := &Common.ScanResult{
						Time:   time.Now(),
						Type:   Common.VULN,
						Target: info.Host,
						Status: "vulnerable",
						Details: map[string]interface{}{
							"port":      info.Ports,
							"service":   "snmp",
							"community": community,
							"type":      "weak-community",
							"system":    result.sysDesc,
						},
					}
					Common.SaveResult(vulnResult)
					return nil
				}
			case <-time.After(timeout):
				err = fmt.Errorf("连接超时")
			}

			if err != nil {
				errlog := fmt.Sprintf("SNMP服务 %s 尝试失败 community: %v 错误: %v",
					target, community, err)
				Common.LogError(errlog)

				if retryErr := Common.CheckErrs(err); retryErr != nil {
					if retryCount == maxRetries-1 {
						continue
					}
					continue
				}
			}
			break
		}
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个 community", tried))
	return tmperr
}

// SNMPConnect 尝试SNMP连接
func SNMPConnect(info *Common.HostInfo, community string, portNum int) (bool, string, error) {
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
		return false, "", err
	}
	defer snmp.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	result, err := snmp.Get(oids)
	if err != nil {
		return false, "", err
	}

	if len(result.Variables) > 0 {
		var sysDesc string
		if result.Variables[0].Type != gosnmp.NoSuchObject {
			sysDesc = strings.TrimSpace(string(result.Variables[0].Value.([]byte)))
		}
		return true, sysDesc, nil
	}

	return false, "", fmt.Errorf("认证失败")
}
