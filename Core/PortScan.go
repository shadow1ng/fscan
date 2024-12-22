package Core

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/net/ipv4"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Addr 表示待扫描的地址
type Addr struct {
	ip   string // IP地址
	port int    // 端口号
}

func PortScan(hostslist []string, ports string, timeout int64) []string {
	var AliveAddress []string
	var mu sync.Mutex // 添加互斥锁保护 AliveAddress

	// 解析端口列表
	probePorts := Common.ParsePort(ports)
	if len(probePorts) == 0 {
		fmt.Printf("[-] 端口格式错误: %s, 请检查端口格式\n", ports)
		return AliveAddress
	}

	// 排除指定端口
	probePorts = excludeNoPorts(probePorts)

	// 创建通道
	workers := Common.ThreadNum
	addrs := make(chan Addr, 100)
	results := make(chan string, 100)
	var wg sync.WaitGroup
	var workerWg sync.WaitGroup

	// 启动扫描协程
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for addr := range addrs {
				PortConnect(addr, results, timeout, &wg)
			}
		}()
	}

	// 接收扫描结果
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range results {
			mu.Lock()
			AliveAddress = append(AliveAddress, result)
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

	// 按顺序关闭并等待
	close(addrs)
	workerWg.Wait() // 等待所有扫描worker完成
	wg.Wait()       // 等待所有扫描任务完成
	close(results)  // 关闭结果通道
	resultWg.Wait() // 等待结果处理完成

	return AliveAddress
}

func PortConnect(addr Addr, respondingHosts chan<- string, timeout int64, wg *sync.WaitGroup) {
	defer wg.Done()

	var isOpen bool
	var err error

	if Common.UseUdpScan {
		// UDP扫描
		isOpen, err = UDPScan(addr.ip, addr.port, timeout)
	} else if Common.UseSynScan {
		// SYN扫描
		isOpen, err = SynScan(addr.ip, addr.port, timeout)
	} else {
		// 标准TCP扫描
		conn, err := Common.WrapperTcpWithTimeout("tcp4",
			fmt.Sprintf("%s:%v", addr.ip, addr.port),
			time.Duration(timeout)*time.Second)
		if err == nil {
			defer conn.Close()
			isOpen = true
		}
	}

	if err != nil || !isOpen {
		return
	}

	// 记录开放端口
	address := fmt.Sprintf("%s:%d", addr.ip, addr.port)
	protocol := "TCP"
	if Common.UseUdpScan {
		protocol = "UDP"
	}
	result := fmt.Sprintf("[+] %s端口开放 %s", protocol, address)
	Common.LogSuccess(result)

	respondingHosts <- address
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

func SynScan(ip string, port int, timeout int64) (bool, error) {
	ifName := getInterfaceName()

	sendConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, fmt.Errorf("创建发送套接字失败: %v", err)
	}
	defer sendConn.Close()

	rawConn, err := ipv4.NewRawConn(sendConn)
	if err != nil {
		return false, fmt.Errorf("获取原始连接失败: %v", err)
	}

	dstIP := net.ParseIP(ip)
	if dstIP == nil {
		return false, fmt.Errorf("无效的IP地址: %s", ip)
	}

	// 打开正确的网络接口
	handle, err := pcap.OpenLive(ifName, 65536, true, pcap.BlockForever)
	if err != nil {
		// 如果失败，尝试查找可用接口
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			return false, fmt.Errorf("无法找到网络接口: %v", err)
		}

		// 遍历查找可用接口
		var found bool
		for _, iface := range ifaces {
			handle, err = pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
			if err == nil {
				found = true
				break
			}
		}

		if !found {
			return false, fmt.Errorf("无法打开任何网络接口")
		}
	}
	defer handle.Close()

	srcPort := 12345 + port
	filter := fmt.Sprintf("tcp and src port %d and dst port %d", port, srcPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		return false, fmt.Errorf("设置过滤器失败: %v", err)
	}

	tcpHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 40,
		TTL:      64,
		Protocol: 6,
		Dst:      dstIP,
	}

	synPacket := make([]byte, 20)
	binary.BigEndian.PutUint16(synPacket[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(synPacket[2:4], uint16(port))
	binary.BigEndian.PutUint32(synPacket[4:8], uint32(1))
	binary.BigEndian.PutUint32(synPacket[8:12], uint32(0))
	synPacket[12] = 0x50
	synPacket[13] = 0x02
	binary.BigEndian.PutUint16(synPacket[14:16], uint16(8192))
	binary.BigEndian.PutUint16(synPacket[16:18], uint16(0))
	binary.BigEndian.PutUint16(synPacket[18:20], uint16(0))

	checksum := calculateTCPChecksum(synPacket, tcpHeader.Src, tcpHeader.Dst)
	binary.BigEndian.PutUint16(synPacket[16:18], checksum)

	if err := rawConn.WriteTo(tcpHeader, synPacket, nil); err != nil {
		return false, fmt.Errorf("发送SYN包失败: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.NoCopy = true

	timeoutChan := time.After(time.Duration(timeout) * time.Second)

	for {
		select {
		case packet := <-packetSource.Packets():
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}

			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}

			if tcp.SYN && tcp.ACK {
				return true, nil
			}

			if tcp.RST {
				return false, nil
			}

		case <-timeoutChan:
			return false, nil
		}
	}
}

// calculateTCPChecksum 计算TCP校验和
func calculateTCPChecksum(tcpHeader []byte, srcIP, dstIP net.IP) uint16 {
	// 创建伪首部
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // TCP协议号
	pseudoHeader[10] = byte(len(tcpHeader) >> 8)
	pseudoHeader[11] = byte(len(tcpHeader))

	// 计算校验和
	var sum uint32

	// 计算伪首部的校验和
	for i := 0; i < len(pseudoHeader)-1; i += 2 {
		sum += uint32(pseudoHeader[i])<<8 | uint32(pseudoHeader[i+1])
	}

	// 计算TCP头的校验和
	for i := 0; i < len(tcpHeader)-1; i += 2 {
		sum += uint32(tcpHeader[i])<<8 | uint32(tcpHeader[i+1])
	}

	// 如果长度为奇数，处理最后一个字节
	if len(tcpHeader)%2 == 1 {
		sum += uint32(tcpHeader[len(tcpHeader)-1]) << 8
	}

	// 将高16位加到低16位
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	// 取反
	return ^uint16(sum)
}

func UDPScan(ip string, port int, timeout int64) (bool, error) {
	// 创建UDP套接字
	sendConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return false, fmt.Errorf("创建UDP套接字失败: %v", err)
	}
	defer sendConn.Close()

	// 设置目标地址
	dstAddr := &net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}

	// 发送空包
	_, err = sendConn.WriteTo([]byte{0x00}, dstAddr)
	if err != nil {
		return false, fmt.Errorf("发送UDP包失败: %v", err)
	}

	// 设置读取超时
	sendConn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// 尝试读取响应
	buffer := make([]byte, 65507) // UDP最大包大小
	n, _, err := sendConn.ReadFrom(buffer)

	// 如果收到ICMP不可达，说明端口关闭
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// 超时可能意味着端口开放但没有响应
			return true, nil
		}
		// 其他错误说明端口可能关闭
		return false, nil
	}

	// 收到响应说明端口开放
	return n > 0, nil
}

// 获取系统对应的接口名
func getInterfaceName() string {
	switch runtime.GOOS {
	case "windows":
		return "\\Device\\NPF_Loopback"
	case "linux":
		return "lo"
	case "darwin":
		return "lo0"
	default:
		return "lo"
	}
}
