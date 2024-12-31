package Plugins

import (
	"fmt"
	"github.com/gosnmp/gosnmp"
	"github.com/shadow1ng/fscan/Common"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SNMPScan 执行SNMP服务扫描
func SNMPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	portNum, _ := strconv.Atoi(info.Ports)
	defaultCommunities := []string{"public", "private", "cisco", "community"}

	// 创建任务通道
	taskChan := make(chan string, len(defaultCommunities))
	resultChan := make(chan error, threads)

	// 生成所有community任务
	for _, community := range defaultCommunities {
		taskChan <- community
	}
	close(taskChan)

	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			starttime := time.Now().Unix()

			for community := range taskChan {
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					timeout := time.Duration(Common.Timeout) * time.Second
					if time.Now().Unix()-starttime > int64(timeout.Seconds()) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

					// 执行SNMP连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(community string) {
						success, err := SNMPConnect(info, community, portNum)
						done <- struct {
							success bool
							err     error
						}{success, err}
					}(community)

					// 等待结果或超时
					var err error
					select {
					case result := <-done:
						err = result.err
						if result.success && err == nil {
							// 连接成功
							successLog := fmt.Sprintf("[+] SNMP服务 %v:%v community: %v 连接成功",
								info.Host, info.Ports, community)
							Common.LogSuccess(successLog)
							resultChan <- nil
							return
						}
					case <-time.After(timeout):
						err = fmt.Errorf("连接超时")
					}

					// 处理错误情况
					if err != nil {
						errlog := fmt.Sprintf("[-] SNMP服务 %v:%v 尝试失败 community: %v 错误: %v",
							info.Host, info.Ports, community, err)
						Common.LogError(errlog)

						// 检查是否需要重试
						if retryErr := Common.CheckErrs(err); retryErr != nil {
							if retryCount == maxRetries-1 {
								resultChan <- err
								return
							}
							continue // 继续重试
						}
					}

					break // 如果不需要重试，跳出重试循环
				}
			}
			resultChan <- nil
		}()
	}

	// 等待所有线程完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 检查结果
	for err := range resultChan {
		if err != nil {
			tmperr = err
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				return err
			}
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
