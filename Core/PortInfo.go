package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"strings"
	"time"
)

// ServiceInfo 定义服务识别的结果信息
type ServiceInfo struct {
	Name    string            // 服务名称,如 http、ssh 等
	Banner  string            // 服务返回的横幅信息
	Version string            // 服务版本号
	Extras  map[string]string // 其他额外信息,如操作系统、产品名等
}

// Result 定义单次探测的结果
type Result struct {
	Service Service           // 识别出的服务信息
	Banner  string           // 服务横幅
	Extras  map[string]string // 额外信息
	Send    []byte           // 发送的探测数据
	Recv    []byte           // 接收到的响应数据
}

// Service 定义服务的基本信息
type Service struct {
	Name   string            // 服务名称
	Extras map[string]string // 服务的额外属性
}

// Info 定义单个端口探测的上下文信息
type Info struct {
	Address string    // 目标IP地址
	Port    int       // 目标端口
	Conn    net.Conn  // 网络连接
	Result  Result    // 探测结果
	Found   bool      // 是否成功识别服务
}

// PortInfoScanner 定义端口服务识别器
type PortInfoScanner struct {
	Address string        // 目标IP地址
	Port    int          // 目标端口
	Conn    net.Conn     // 网络连接
	Timeout time.Duration // 超时时间
	info    *Info        // 探测上下文
}

// 预定义的基础探测器
var (
	null   = new(Probe) // 空探测器,用于基本协议识别
	common = new(Probe) // 通用探测器,用于常见服务识别
)

// NewPortInfoScanner 创建新的端口服务识别器实例
func NewPortInfoScanner(addr string, port int, conn net.Conn, timeout time.Duration) *PortInfoScanner {
	return &PortInfoScanner{
		Address: addr,
		Port:    port, 
		Conn:    conn,
		Timeout: timeout,
		info: &Info{
			Address: addr,
			Port:    port,
			Conn:    conn,
			Result: Result{
				Service: Service{},
			},
		},
	}
}

// Identify 执行服务识别,返回识别结果
func (s *PortInfoScanner) Identify() (*ServiceInfo, error) {
	Common.LogDebug(fmt.Sprintf("开始识别服务 %s:%d", s.Address, s.Port))
	s.info.PortInfo()

	// 构造返回结果
	serviceInfo := &ServiceInfo{
		Name:    s.info.Result.Service.Name,
		Banner:  s.info.Result.Banner,
		Version: s.info.Result.Service.Extras["version"],
		Extras:  make(map[string]string),
	}

	// 复制额外信息
	for k, v := range s.info.Result.Service.Extras {
		serviceInfo.Extras[k] = v
	}

	Common.LogDebug(fmt.Sprintf("服务识别完成 %s:%d => %s", s.Address, s.Port, serviceInfo.Name))
	return serviceInfo, nil
}

// PortInfo 执行端口服务识别的主要逻辑
func (i *Info) PortInfo() {
	// 1. 首先尝试读取服务的初始响应
	if response, err := i.Read(); err == nil && len(response) > 0 {
		Common.LogDebug(fmt.Sprintf("收到初始响应: %d 字节", len(response)))

		// 使用基础探测器检查响应
		Common.LogDebug("尝试使用基础探测器(null/common)检查响应")
		if i.tryProbes(response, []*Probe{null, common}) {
			Common.LogDebug("基础探测器匹配成功")
			return
		}
		Common.LogDebug("基础探测器未匹配")
	} else if err != nil {
		Common.LogDebug(fmt.Sprintf("读取初始响应失败: %v", err))
	}

	// 记录已使用的探测器,避免重复使用
	usedProbes := make(map[string]struct{})

	// 2. 尝试使用端口专用探测器
	Common.LogDebug(fmt.Sprintf("尝试使用端口 %d 的专用探测器", i.Port))
	if i.processPortMapProbes(usedProbes) {
		Common.LogDebug("端口专用探测器匹配成功")
		return
	}
	Common.LogDebug("端口专用探测器未匹配")

	// 3. 使用默认探测器列表
	Common.LogDebug("尝试使用默认探测器列表")
	if i.processDefaultProbes(usedProbes) {
		Common.LogDebug("默认探测器匹配成功")
		return
	}
	Common.LogDebug("默认探测器未匹配")

	// 4. 如果所有探测都失败,标记为未知服务
	if strings.TrimSpace(i.Result.Service.Name) == "" {
		Common.LogDebug("未识别出服务,标记为 unknown")
		i.Result.Service.Name = "unknown"
	}
}

// tryProbes 尝试使用指定的探测器列表检查响应
func (i *Info) tryProbes(response []byte, probes []*Probe) bool {
	for _, probe := range probes {
		Common.LogDebug(fmt.Sprintf("尝试探测器: %s", probe.Name))
		i.GetInfo(response, probe)
		if i.Found {
			Common.LogDebug(fmt.Sprintf("探测器 %s 匹配成功", probe.Name))
			return true
		}
	}
	return false
}

// processPortMapProbes 处理端口映射中的专用探测器
func (i *Info) processPortMapProbes(usedProbes map[string]struct{}) bool {
	// 检查是否存在端口专用探测器
	if len(Common.PortMap[i.Port]) == 0 {
		Common.LogDebug(fmt.Sprintf("端口 %d 没有专用探测器", i.Port))
		return false
	}

	// 遍历端口专用探测器
	for _, name := range Common.PortMap[i.Port] {
		Common.LogDebug(fmt.Sprintf("尝试端口专用探测器: %s", name))
		usedProbes[name] = struct{}{} 
		probe := v.ProbesMapKName[name]

		// 解码探测数据
		probeData, err := DecodeData(probe.Data)
		if err != nil || len(probeData) == 0 {
			Common.LogDebug(fmt.Sprintf("探测器 %s 数据解码失败", name))
			continue
		}

		// 发送探测数据并获取响应
		Common.LogDebug(fmt.Sprintf("发送探测数据: %d 字节", len(probeData)))
		if response := i.Connect(probeData); len(response) > 0 {
			Common.LogDebug(fmt.Sprintf("收到响应: %d 字节", len(response)))

			// 使用当前探测器检查响应
			i.GetInfo(response, &probe)
			if i.Found {
				return true
			}

			// 根据探测器类型进行额外检查
			switch name {
			case "GenericLines":
				if i.tryProbes(response, []*Probe{null}) {
					return true
				}
			case "NULL":
				continue
			default:
				if i.tryProbes(response, []*Probe{common}) {
					return true
				}
			}
		}
	}
	return false
}

// processDefaultProbes 处理默认探测器列表
func (i *Info) processDefaultProbes(usedProbes map[string]struct{}) bool {
	failCount := 0
	const maxFailures = 10 // 最大失败次数

	// 遍历默认探测器列表
	for _, name := range Common.DefaultMap {
		// 跳过已使用的探测器
		if _, used := usedProbes[name]; used {
			continue
		}

		probe := v.ProbesMapKName[name]
		probeData, err := DecodeData(probe.Data)
		if err != nil || len(probeData) == 0 {
			continue
		}

		// 发送探测数据并获取响应
		response := i.Connect(probeData)
		if len(response) == 0 {
			failCount++
			if failCount > maxFailures {
				return false
			}
			continue
		}

		// 使用当前探测器检查响应
		i.GetInfo(response, &probe)
		if i.Found {
			return true
		}

		// 根据探测器类型进行额外检查
		switch name {
		case "GenericLines":
			if i.tryProbes(response, []*Probe{null}) {
				return true
			}
		case "NULL":
			continue
		default:
			if i.tryProbes(response, []*Probe{common}) {
				return true
			}
		}

		// 尝试使用端口映射中的其他探测器
		if len(Common.PortMap[i.Port]) > 0 {
			for _, mappedName := range Common.PortMap[i.Port] {
				usedProbes[mappedName] = struct{}{}
				mappedProbe := v.ProbesMapKName[mappedName]
				i.GetInfo(response, &mappedProbe)
				if i.Found {
					return true
				}
			}
		}
	}
	return false
}

// GetInfo 分析响应数据并提取服务信息
func (i *Info) GetInfo(response []byte, probe *Probe) {
	Common.LogDebug(fmt.Sprintf("开始分析响应数据,长度: %d", len(response)))

	// 响应数据有效性检查
	if len(response) <= 0 {
		Common.LogDebug("响应数据为空")
		return
	}

	result := &i.Result
	var (
		softMatch Match
		softFound bool
	)

	// 处理主要匹配规则
	Common.LogDebug(fmt.Sprintf("处理探测器 %s 的主要匹配规则", probe.Name))
	if matched, match := i.processMatches(response, probe.Matchs); matched {
		Common.LogDebug("找到硬匹配")
		return
	} else if match != nil {
		Common.LogDebug("找到软匹配")
		softFound = true
		softMatch = *match
	}

	// 处理回退匹配规则
	if probe.Fallback != "" {
		Common.LogDebug(fmt.Sprintf("尝试回退匹配: %s", probe.Fallback))
		if fbProbe, ok := v.ProbesMapKName[probe.Fallback]; ok {
			if matched, match := i.processMatches(response, fbProbe.Matchs); matched {
				Common.LogDebug("回退匹配成功")
				return
			} else if match != nil {
				Common.LogDebug("找到回退软匹配")
				softFound = true
				softMatch = *match
			}
		}
	}

	// 处理未找到匹配的情况
	if !i.Found {
		Common.LogDebug("未找到硬匹配,处理未匹配情况")
		i.handleNoMatch(response, result, softFound, softMatch)
	}
}

// processMatches 处理匹配规则集
func (i *Info) processMatches(response []byte, matches *[]Match) (bool, *Match) {
	Common.LogDebug(fmt.Sprintf("开始处理匹配规则,共 %d 条", len(*matches)))
	var softMatch *Match

	for _, match := range *matches {
		if !match.MatchPattern(response) {
			continue
		}

		if !match.IsSoft {
			Common.LogDebug(fmt.Sprintf("找到硬匹配: %s", match.Service))
			i.handleHardMatch(response, &match)
			return true, nil
		} else if softMatch == nil {
			Common.LogDebug(fmt.Sprintf("找到软匹配: %s", match.Service))
			tmpMatch := match
			softMatch = &tmpMatch
		}
	}

	return false, softMatch
}

// handleHardMatch 处理硬匹配结果
func (i *Info) handleHardMatch(response []byte, match *Match) {
	Common.LogDebug(fmt.Sprintf("处理硬匹配结果: %s", match.Service))
	result := &i.Result
	extras := match.ParseVersionInfo(response)
	extrasMap := extras.ToMap()

	result.Service.Name = match.Service
	result.Extras = extrasMap
	result.Banner = trimBanner(response)
	result.Service.Extras = extrasMap

	// 特殊处理 microsoft-ds 服务
	if result.Service.Name == "microsoft-ds" {
		Common.LogDebug("特殊处理 microsoft-ds 服务")
		result.Service.Extras["hostname"] = result.Banner
	}

	i.Found = true
	Common.LogDebug(fmt.Sprintf("服务识别结果: %s, Banner: %s", result.Service.Name, result.Banner))
}

// handleNoMatch 处理未找到匹配的情况
func (i *Info) handleNoMatch(response []byte, result *Result, softFound bool, softMatch Match) {
	Common.LogDebug("处理未匹配情况")
	result.Banner = trimBanner(response)

	if !softFound {
		// 尝试识别 HTTP 服务
		if strings.Contains(result.Banner, "HTTP/") ||
			strings.Contains(result.Banner, "html") {
			Common.LogDebug("识别为HTTP服务")
			result.Service.Name = "http"
		} else {
			Common.LogDebug("未知服务")
			result.Service.Name = "unknown"
		}
	} else {
		Common.LogDebug("使用软匹配结果")
		extras := softMatch.ParseVersionInfo(response)
		result.Service.Extras = extras.ToMap()
		result.Service.Name = softMatch.Service
		i.Found = true
		Common.LogDebug(fmt.Sprintf("软匹配服务: %s", result.Service.Name))
	}
}

// Connect 发送数据并获取响应
func (i *Info) Connect(msg []byte) []byte {
	i.Write(msg)
	reply, _ := i.Read()
	return reply
}

const WrTimeout = 5 // 默认读写超时时间(秒)

// Write 写入数据到连接
func (i *Info) Write(msg []byte) error {
	if i.Conn == nil {
		return nil
	}

	// 设置写入超时
	i.Conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))

	// 写入数据
	_, err := i.Conn.Write(msg)
	if err != nil && strings.Contains(err.Error(), "close") {
		i.Conn.Close()
		// 连接关闭时重试
		i.Conn, err = net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", i.Address, i.Port), time.Duration(6)*time.Second)
		if err == nil {
			i.Conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))
			_, err = i.Conn.Write(msg)
		}
	}

	// 记录发送的数据
	if err == nil {
		i.Result.Send = msg
	}

	return err
}

// Read 从连接读取响应
func (i *Info) Read() ([]byte, error) {
	if i.Conn == nil {
		return nil, nil
	}

	// 设置读取超时
	i.Conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))

	// 读取数据
	result, err := readFromConn(i.Conn)
	if err != nil && strings.Contains(err.Error(), "close") {
		return result, err
	}

	// 记录接收到的数据
	if len(result) > 0 {
		i.Result.Recv = result
	}

	return result, err
}

// readFromConn 从连接读取数据的辅助函数
func readFromConn(conn net.Conn) ([]byte, error) {
	size := 2 * 1024 // 读取缓冲区大小
	var result []byte

	for {
		buf := make([]byte, size)
		count, err := conn.Read(buf)

		if count > 0 {
			result = append(result, buf[:count]...)
		}

		if err != nil {
			if len(result) > 0 {
				return result, nil
			}
			if err == io.EOF {
				return result, nil
			}
			return result, err
		}

		if count < size {
			return result, nil
		}
	}
}
