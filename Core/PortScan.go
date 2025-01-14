package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Addr 表示待扫描的地址
type Addr struct {
	ip   string // IP地址
	port int    // 端口号
}

// ScanResult 扫描结果
type ScanResult struct {
	Address string       // IP地址
	Port    int          // 端口号
	Service *ServiceInfo // 服务信息
}

func PortScan(hostslist []string, ports string, timeout int64) []string {
	var results []ScanResult
	var aliveAddrs []string // 新增：存储活跃地址
	var mu sync.Mutex

	// 解析端口列表
	probePorts := Common.ParsePort(ports)
	if len(probePorts) == 0 {
		Common.LogError(fmt.Sprintf("端口格式错误: %s", ports))
		return aliveAddrs
	}

	// 排除指定端口
	probePorts = excludeNoPorts(probePorts)

	// 创建通道
	workers := Common.ThreadNum
	addrs := make(chan Addr, 100)
	scanResults := make(chan ScanResult, 100)
	var wg sync.WaitGroup
	var workerWg sync.WaitGroup

	// 启动扫描协程
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for addr := range addrs {
				PortConnect(addr, scanResults, timeout, &wg)
			}
		}()
	}

	// 接收扫描结果
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range scanResults {
			mu.Lock()
			results = append(results, result)
			// 构造活跃地址字符串
			aliveAddr := fmt.Sprintf("%s:%d", result.Address, result.Port)
			aliveAddrs = append(aliveAddrs, aliveAddr)
			mu.Unlock()
		}
	}()

	// 添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			addrs <- Addr{host, port}
		}
	}

	close(addrs)
	workerWg.Wait()
	wg.Wait()
	close(scanResults)
	resultWg.Wait()

	return aliveAddrs
}

func PortConnect(addr Addr, results chan<- ScanResult, timeout int64, wg *sync.WaitGroup) {
	defer wg.Done()

	var isOpen bool
	var err error
	var conn net.Conn

	conn, err = Common.WrapperTcpWithTimeout("tcp4",
		fmt.Sprintf("%s:%v", addr.ip, addr.port),
		time.Duration(timeout)*time.Second)
	if err == nil {
		defer conn.Close()
		isOpen = true
	}

	if err != nil || !isOpen {
		return
	}

	address := fmt.Sprintf("%s:%d", addr.ip, addr.port)
	Common.LogSuccess(fmt.Sprintf("端口开放 %s", address))

	// 创建扫描结果
	result := ScanResult{
		Address: addr.ip,
		Port:    addr.port,
	}

	// 只在未跳过指纹识别时进行服务识别
	if !Common.SkipFingerprint && conn != nil {
		scanner := NewPortInfoScanner(addr.ip, addr.port, conn, time.Duration(timeout)*time.Second)
		if serviceInfo, err := scanner.Identify(); err == nil {
			result.Service = serviceInfo

			var logMsg strings.Builder
			logMsg.WriteString(fmt.Sprintf("服务识别 %s => ", address))

			if serviceInfo.Name != "unknown" {
				logMsg.WriteString(fmt.Sprintf("[%s]", serviceInfo.Name))
			}

			if serviceInfo.Version != "" {
				logMsg.WriteString(fmt.Sprintf(" 版本:%s", serviceInfo.Version))
			}

			if v, ok := serviceInfo.Extras["vendor_product"]; ok && v != "" {
				logMsg.WriteString(fmt.Sprintf(" 产品:%s", v))
			}
			if v, ok := serviceInfo.Extras["os"]; ok && v != "" {
				logMsg.WriteString(fmt.Sprintf(" 系统:%s", v))
			}
			if v, ok := serviceInfo.Extras["info"]; ok && v != "" {
				logMsg.WriteString(fmt.Sprintf(" 信息:%s", v))
			}

			if len(serviceInfo.Banner) > 0 && len(serviceInfo.Banner) < 100 {
				logMsg.WriteString(fmt.Sprintf(" Banner:[%s]", strings.TrimSpace(serviceInfo.Banner)))
			}

			Common.LogSuccess(logMsg.String())
		}
	}

	results <- result
}

// NoPortScan 生成端口列表(不进行扫描)
func NoPortScan(hostslist []string, ports string) []string {
	var AliveAddress []string

	// 解析并排除端口
	probePorts := excludeNoPorts(Common.ParsePort(ports))

	// 生成地址列表
	for _, port := range probePorts {
		for _, host := range hostslist {
			address := fmt.Sprintf("%s:%d", host, port)
			AliveAddress = append(AliveAddress, address)
		}
	}

	return AliveAddress
}

// excludeNoPorts 排除指定的端口
func excludeNoPorts(ports []int) []int {
	noPorts := Common.ParsePort(Common.ExcludePorts)
	if len(noPorts) == 0 {
		return ports
	}

	// 使用map过滤端口
	temp := make(map[int]struct{})
	for _, port := range ports {
		temp[port] = struct{}{}
	}

	for _, port := range noPorts {
		delete(temp, port)
	}

	// 转换为切片并排序
	var newPorts []int
	for port := range temp {
		newPorts = append(newPorts, port)
	}
	sort.Ints(newPorts)

	return newPorts
}

//func SynScan(ip string, port int, timeout int64) (bool, error) {
//	ifName := getInterfaceName()
//
//	sendConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
//	if err != nil {
//		return false, fmt.Errorf("发送套接字错误: %v", err)
//	}
//	defer sendConn.Close()
//
//	rawConn, err := ipv4.NewRawConn(sendConn)
//	if err != nil {
//		return false, fmt.Errorf("原始连接错误: %v", err)
//	}
//
//	dstIP := net.ParseIP(ip)
//	if dstIP == nil {
//		return false, fmt.Errorf("IP地址无效: %s", ip)
//	}
//
//	handle, err := pcap.OpenLive(ifName, 65536, true, pcap.BlockForever)
//	if err != nil {
//		ifaces, err := pcap.FindAllDevs()
//		if err != nil {
//			return false, fmt.Errorf("网络接口错误: %v", err)
//		}
//
//		var found bool
//		for _, iface := range ifaces {
//			handle, err = pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
//			if err == nil {
//				found = true
//				break
//			}
//		}
//
//		if !found {
//			return false, fmt.Errorf("未找到可用网络接口")
//		}
//	}
//	defer handle.Close()
//
//	srcPort := 12345 + port
//	filter := fmt.Sprintf("tcp and src port %d and dst port %d", port, srcPort)
//	if err := handle.SetBPFFilter(filter); err != nil {
//		return false, fmt.Errorf("过滤器错误: %v", err)
//	}
//
//	// TCP头部设置保持不变
//	tcpHeader := &ipv4.Header{
//		Version:  4,
//		Len:      20,
//		TotalLen: 40,
//		TTL:      64,
//		Protocol: 6,
//		Dst:      dstIP,
//	}
//
//	// SYN包构造保持不变
//	synPacket := make([]byte, 20)
//	binary.BigEndian.PutUint16(synPacket[0:2], uint16(srcPort))
//	binary.BigEndian.PutUint16(synPacket[2:4], uint16(port))
//	binary.BigEndian.PutUint32(synPacket[4:8], uint32(1))
//	binary.BigEndian.PutUint32(synPacket[8:12], uint32(0))
//	synPacket[12] = 0x50
//	synPacket[13] = 0x02
//	binary.BigEndian.PutUint16(synPacket[14:16], uint16(8192))
//	binary.BigEndian.PutUint16(synPacket[16:18], uint16(0))
//	binary.BigEndian.PutUint16(synPacket[18:20], uint16(0))
//
//	checksum := calculateTCPChecksum(synPacket, tcpHeader.Src, tcpHeader.Dst)
//	binary.BigEndian.PutUint16(synPacket[16:18], checksum)
//
//	if err := rawConn.WriteTo(tcpHeader, synPacket, nil); err != nil {
//		return false, fmt.Errorf("SYN包发送错误: %v", err)
//	}
//
//	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
//	packetSource.DecodeOptions.Lazy = true
//	packetSource.NoCopy = true
//
//	timeoutChan := time.After(time.Duration(timeout) * time.Second)
//
//	for {
//		select {
//		case packet := <-packetSource.Packets():
//			tcpLayer := packet.Layer(layers.LayerTypeTCP)
//			if tcpLayer == nil {
//				continue
//			}
//
//			tcp, ok := tcpLayer.(*layers.TCP)
//			if !ok {
//				continue
//			}
//
//			if tcp.SYN && tcp.ACK {
//				return true, nil
//			}
//
//			if tcp.RST {
//				return false, nil
//			}
//
//		case <-timeoutChan:
//			return false, nil
//		}
//	}
//}
//
//// calculateTCPChecksum 计算TCP校验和
//func calculateTCPChecksum(tcpHeader []byte, srcIP, dstIP net.IP) uint16 {
//	// 创建伪首部
//	pseudoHeader := make([]byte, 12)
//	copy(pseudoHeader[0:4], srcIP.To4())
//	copy(pseudoHeader[4:8], dstIP.To4())
//	pseudoHeader[8] = 0
//	pseudoHeader[9] = 6 // TCP协议号
//	pseudoHeader[10] = byte(len(tcpHeader) >> 8)
//	pseudoHeader[11] = byte(len(tcpHeader))
//
//	// 计算校验和
//	var sum uint32
//
//	// 计算伪首部的校验和
//	for i := 0; i < len(pseudoHeader)-1; i += 2 {
//		sum += uint32(pseudoHeader[i])<<8 | uint32(pseudoHeader[i+1])
//	}
//
//	// 计算TCP头的校验和
//	for i := 0; i < len(tcpHeader)-1; i += 2 {
//		sum += uint32(tcpHeader[i])<<8 | uint32(tcpHeader[i+1])
//	}
//
//	// 如果长度为奇数，处理最后一个字节
//	if len(tcpHeader)%2 == 1 {
//		sum += uint32(tcpHeader[len(tcpHeader)-1]) << 8
//	}
//
//	// 将高16位加到低16位
//	for sum > 0xffff {
//		sum = (sum >> 16) + (sum & 0xffff)
//	}
//
//	// 取反
//	return ^uint16(sum)
//}
//
//// 获取系统对应的接口名
//func getInterfaceName() string {
//	switch runtime.GOOS {
//	case "windows":
//		return "\\Device\\NPF_Loopback"
//	case "linux":
//		return "lo"
//	case "darwin":
//		return "lo0"
//	default:
//		return "lo"
//	}
//}
