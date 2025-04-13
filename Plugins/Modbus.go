package Plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"time"
)

// ModbusScanResult 表示 Modbus 扫描结果
type ModbusScanResult struct {
	Success    bool
	DeviceInfo string
	Error      error
}

// ModbusScan 执行 Modbus 服务扫描
func ModbusScan(info *Common.HostInfo) error {
	target := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始 Modbus 扫描: %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 执行扫描
	result := tryModbusScan(ctx, info, Common.Timeout, Common.MaxRetries)

	if result.Success {
		// 保存扫描结果
		saveModbusResult(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Modbus 扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		if result.Error != nil {
			Common.LogDebug(fmt.Sprintf("Modbus 扫描失败: %v", result.Error))
			return result.Error
		}
		Common.LogDebug("Modbus 扫描完成，未发现服务")
		return nil
	}
}

// tryModbusScan 尝试单个 Modbus 扫描
func tryModbusScan(ctx context.Context, info *Common.HostInfo, timeoutSeconds int64, maxRetries int) *ModbusScanResult {
	var lastErr error
	host, port := info.Host, info.Ports
	target := fmt.Sprintf("%s:%s", host, port)

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &ModbusScanResult{
				Success: false,
				Error:   fmt.Errorf("全局超时"),
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试 Modbus 扫描: %s", retry+1, target))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建单个连接超时的上下文
			connCtx, connCancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)

			// 创建结果通道
			resultChan := make(chan *ModbusScanResult, 1)

			// 在协程中执行扫描
			go func() {
				// 尝试建立连接
				var d net.Dialer
				conn, err := d.DialContext(connCtx, "tcp", target)
				if err != nil {
					select {
					case <-connCtx.Done():
					case resultChan <- &ModbusScanResult{Success: false, Error: err}:
					}
					return
				}
				defer conn.Close()

				// 构造 Modbus TCP 请求包 - 读取设备ID
				request := buildModbusRequest()

				// 设置读写超时
				conn.SetDeadline(time.Now().Add(time.Duration(timeoutSeconds) * time.Second))

				// 发送请求
				_, err = conn.Write(request)
				if err != nil {
					select {
					case <-connCtx.Done():
					case resultChan <- &ModbusScanResult{
						Success: false,
						Error:   fmt.Errorf("发送Modbus请求失败: %v", err),
					}:
					}
					return
				}

				// 读取响应
				response := make([]byte, 256)
				n, err := conn.Read(response)
				if err != nil {
					select {
					case <-connCtx.Done():
					case resultChan <- &ModbusScanResult{
						Success: false,
						Error:   fmt.Errorf("读取Modbus响应失败: %v", err),
					}:
					}
					return
				}

				// 验证响应
				if isValidModbusResponse(response[:n]) {
					// 获取设备信息
					deviceInfo := parseModbusResponse(response[:n])
					select {
					case <-connCtx.Done():
					case resultChan <- &ModbusScanResult{
						Success:    true,
						DeviceInfo: deviceInfo,
					}:
					}
					return
				}

				select {
				case <-connCtx.Done():
				case resultChan <- &ModbusScanResult{
					Success: false,
					Error:   fmt.Errorf("非Modbus服务或访问被拒绝"),
				}:
				}
			}()

			// 等待扫描结果或超时
			var result *ModbusScanResult
			select {
			case res := <-resultChan:
				result = res
			case <-connCtx.Done():
				if ctx.Err() != nil {
					connCancel()
					return &ModbusScanResult{
						Success: false,
						Error:   ctx.Err(),
					}
				}
				result = &ModbusScanResult{
					Success: false,
					Error:   fmt.Errorf("连接超时"),
				}
			}

			connCancel()

			if result.Success {
				return result
			}

			lastErr = result.Error
			if result.Error != nil {
				// 检查是否需要重试
				if retryErr := Common.CheckErrs(result.Error); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &ModbusScanResult{
		Success: false,
		Error:   lastErr,
	}
}

// buildModbusRequest 构建Modbus TCP请求包
func buildModbusRequest() []byte {
	request := make([]byte, 12)

	// Modbus TCP头部
	binary.BigEndian.PutUint16(request[0:], 0x0001) // 事务标识符
	binary.BigEndian.PutUint16(request[2:], 0x0000) // 协议标识符
	binary.BigEndian.PutUint16(request[4:], 0x0006) // 长度
	request[6] = 0x01                               // 单元标识符

	// Modbus 请求
	request[7] = 0x01                                // 功能码: Read Coils
	binary.BigEndian.PutUint16(request[8:], 0x0000)  // 起始地址
	binary.BigEndian.PutUint16(request[10:], 0x0001) // 读取数量

	return request
}

// isValidModbusResponse 验证Modbus响应是否有效
func isValidModbusResponse(response []byte) bool {
	if len(response) < 9 {
		return false
	}

	// 检查协议标识符
	protocolID := binary.BigEndian.Uint16(response[2:])
	if protocolID != 0 {
		return false
	}

	// 检查功能码
	funcCode := response[7]
	if funcCode == 0x81 { // 错误响应
		return false
	}

	return true
}

// parseModbusResponse 解析Modbus响应获取设备信息
func parseModbusResponse(response []byte) string {
	if len(response) < 9 {
		return ""
	}

	// 提取更多设备信息
	unitID := response[6]
	funcCode := response[7]

	// 简单的设备信息提取，实际应用中可以提取更多信息
	info := fmt.Sprintf("Unit ID: %d, Function: 0x%02X", unitID, funcCode)

	// 如果是读取线圈响应，尝试解析线圈状态
	if funcCode == 0x01 && len(response) >= 10 {
		byteCount := response[8]
		if byteCount > 0 && len(response) >= 9+int(byteCount) {
			coilValue := response[9] & 0x01 // 获取第一个线圈状态
			info += fmt.Sprintf(", Coil Status: %d", coilValue)
		}
	}

	return info
}

// saveModbusResult 保存Modbus扫描结果
func saveModbusResult(info *Common.HostInfo, target string, result *ModbusScanResult) {
	// 保存扫描结果
	scanResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":        info.Ports,
			"service":     "modbus",
			"type":        "unauthorized-access",
			"device_info": result.DeviceInfo,
		},
	}
	Common.SaveResult(scanResult)

	// 控制台输出
	Common.LogSuccess(fmt.Sprintf("Modbus服务 %s 无认证访问", target))
	if result.DeviceInfo != "" {
		Common.LogSuccess(fmt.Sprintf("设备信息: %s", result.DeviceInfo))
	}
}
