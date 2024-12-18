package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

func Scan(info common.HostInfo) {
	fmt.Println("[*] 开始信息扫描...")

	// 本地信息收集模块
	if common.Scantype == "localinfo" {
		ch := make(chan struct{}, common.Threads)
		wg := sync.WaitGroup{}
		AddScan("1000006", info, &ch, &wg)
		wg.Wait()
		common.LogWG.Wait()
		close(common.Results)
		fmt.Printf("[✓] 扫描完成 %v/%v\n", common.End, common.Num)
		return
	}

	// 解析目标主机IP
	Hosts, err := common.ParseIP(info.Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Printf("[!] 解析主机错误: %v\n", err)
		return
	}

	// 初始化配置
	lib.Inithttp()
	ch := make(chan struct{}, common.Threads)
	wg := sync.WaitGroup{}
	web := strconv.Itoa(common.PORTList["web"])
	ms17010 := strconv.Itoa(common.PORTList["ms17010"])
	var AlivePorts, severports []string

	if len(Hosts) > 0 || len(common.HostPort) > 0 {
		// ICMP存活性检测
		if (common.NoPing == false && len(Hosts) > 1) || common.Scantype == "icmp" {
			Hosts = CheckLive(Hosts, common.Ping)
			fmt.Printf("[+] ICMP存活主机数量: %d\n", len(Hosts))
			if common.Scantype == "icmp" {
				common.LogWG.Wait()
				return
			}
		}

		// 端口扫描策略
		switch common.Scantype {
		case "webonly", "webpoc":
			AlivePorts = NoPortScan(Hosts, common.Ports)
		case "hostname":
			common.Ports = "139"
			AlivePorts = NoPortScan(Hosts, common.Ports)
		default:
			if len(Hosts) > 0 {
				AlivePorts = PortScan(Hosts, common.Ports, common.Timeout)
				fmt.Printf("[+] 存活端口数量: %d\n", len(AlivePorts))
				if common.Scantype == "portscan" {
					common.LogWG.Wait()
					return
				}
			}
		}

		// 处理自定义端口
		if len(common.HostPort) > 0 {
			AlivePorts = append(AlivePorts, common.HostPort...)
			AlivePorts = common.RemoveDuplicate(AlivePorts)
			common.HostPort = nil
			fmt.Printf("[+] 总计存活端口: %d\n", len(AlivePorts))
		}

		// 构建服务端口列表
		for _, port := range common.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}

		// 开始漏洞扫描
		fmt.Println("[*] 开始漏洞扫描...")
		for _, targetIP := range AlivePorts {
			hostParts := strings.Split(targetIP, ":")
			if len(hostParts) != 2 {
				fmt.Printf("[!] 无效的目标地址格式: %s\n", targetIP)
				continue
			}
			info.Host, info.Ports = hostParts[0], hostParts[1]

			if common.Scantype == "all" || common.Scantype == "main" {
				switch {
				case info.Ports == "135":
					AddScan(info.Ports, info, &ch, &wg)
					if common.IsWmi {
						AddScan("1000005", info, &ch, &wg)
					}
				case info.Ports == "445":
					AddScan(ms17010, info, &ch, &wg)
				case info.Ports == "9000":
					AddScan(web, info, &ch, &wg)
					AddScan(info.Ports, info, &ch, &wg)
				case IsContain(severports, info.Ports):
					AddScan(info.Ports, info, &ch, &wg)
				default:
					AddScan(web, info, &ch, &wg)
				}
			} else {
				scantype := strconv.Itoa(common.PORTList[common.Scantype])
				AddScan(scantype, info, &ch, &wg)
			}
		}
	}

	// URL扫描
	for _, url := range common.Urls {
		info.Url = url
		AddScan(web, info, &ch, &wg)
	}

	// 等待所有任务完成
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	fmt.Printf("[✓] 扫描已完成: %v/%v\n", common.End, common.Num)
}

// Mutex用于保护共享资源的并发访问
var Mutex = &sync.Mutex{}

// AddScan 添加扫描任务到并发队列
func AddScan(scantype string, info common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	// 获取信号量，控制并发数
	*ch <- struct{}{}
	// 添加等待组计数
	wg.Add(1)

	// 启动goroutine执行扫描任务
	go func() {
		defer func() {
			wg.Done() // 完成任务后减少等待组计数
			<-*ch     // 释放信号量
		}()

		// 增加总任务数
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()

		// 执行扫描
		ScanFunc(&scantype, &info)

		// 增加已完成任务数
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
	}()
}

// ScanFunc 通过反射调用对应的扫描插件
func ScanFunc(name *string, info *common.HostInfo) {
	// 异常恢复处理
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[!] 扫描错误 %v:%v - %v\n", info.Host, info.Ports, err)
		}
	}()

	// 通过反射获取插件函数
	f := reflect.ValueOf(PluginList[*name])
	// 构造参数并调用插件函数
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

// IsContain 检查切片中是否包含指定元素
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
