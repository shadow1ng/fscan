package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"strings"
	"time"
)

// MongodbScan 执行MongoDB未授权扫描
func MongodbScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始MongoDB扫描: %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 创建结果通道
	resultChan := make(chan struct {
		isUnauth bool
		err      error
	}, 1)

	// 在协程中执行扫描
	go func() {
		isUnauth, err := MongodbUnauth(ctx, info)
		select {
		case <-ctx.Done():
		case resultChan <- struct {
			isUnauth bool
			err      error
		}{isUnauth, err}:
		}
	}()

	// 等待结果或超时
	select {
	case result := <-resultChan:
		if result.err != nil {
			errlog := fmt.Sprintf("MongoDB %v %v", target, result.err)
			Common.LogError(errlog)
			return result.err
		} else if result.isUnauth {
			// 记录控制台输出
			Common.LogSuccess(fmt.Sprintf("MongoDB %v 未授权访问", target))

			// 保存未授权访问结果
			scanResult := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":     info.Ports,
					"service":  "mongodb",
					"type":     "unauthorized-access",
					"protocol": "mongodb",
				},
			}
			Common.SaveResult(scanResult)
		} else {
			Common.LogDebug(fmt.Sprintf("MongoDB %v 需要认证", target))
		}
		return nil
	case <-ctx.Done():
		Common.LogError(fmt.Sprintf("MongoDB扫描超时: %s", target))
		return fmt.Errorf("全局超时")
	}
}

// MongodbUnauth 检测MongoDB未授权访问
func MongodbUnauth(ctx context.Context, info *Common.HostInfo) (bool, error) {
	msgPacket := createOpMsgPacket()
	queryPacket := createOpQueryPacket()

	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("检测MongoDB未授权访问: %s", realhost))

	// 尝试OP_MSG查询
	Common.LogDebug("尝试使用OP_MSG协议")
	reply, err := checkMongoAuth(ctx, realhost, msgPacket)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("OP_MSG查询失败: %v, 尝试使用OP_QUERY协议", err))
		// 失败则尝试OP_QUERY查询
		reply, err = checkMongoAuth(ctx, realhost, queryPacket)
		if err != nil {
			Common.LogDebug(fmt.Sprintf("OP_QUERY查询也失败: %v", err))
			return false, err
		}
	}

	// 检查响应结果
	Common.LogDebug(fmt.Sprintf("收到响应，长度: %d", len(reply)))
	if strings.Contains(reply, "totalLinesWritten") {
		Common.LogDebug("响应中包含totalLinesWritten，确认未授权访问")
		return true, nil
	}

	Common.LogDebug("响应未包含预期内容，可能需要认证")
	return false, nil
}

// checkMongoAuth 检查MongoDB认证状态
func checkMongoAuth(ctx context.Context, address string, packet []byte) (string, error) {
	Common.LogDebug(fmt.Sprintf("建立MongoDB连接: %s", address))

	// 创建连接超时上下文
	connCtx, cancel := context.WithTimeout(ctx, time.Duration(Common.Timeout)*time.Second)
	defer cancel()

	// 使用带超时的连接
	var d net.Dialer
	conn, err := d.DialContext(connCtx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	// 设置读写超时
	if err := conn.SetDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return "", fmt.Errorf("设置超时失败: %v", err)
	}

	// 发送查询包
	Common.LogDebug("发送查询包")
	if _, err := conn.Write(packet); err != nil {
		return "", fmt.Errorf("发送查询失败: %v", err)
	}

	// 再次检查上下文是否已取消
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	// 读取响应
	Common.LogDebug("读取响应")
	reply := make([]byte, 2048)
	count, err := conn.Read(reply)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("读取响应失败: %v", err)
	}

	if count == 0 {
		return "", fmt.Errorf("收到空响应")
	}

	Common.LogDebug(fmt.Sprintf("成功接收响应，字节数: %d", count))
	return string(reply[:count]), nil
}

// createOpMsgPacket 创建OP_MSG查询包
func createOpMsgPacket() []byte {
	return []byte{
		0x69, 0x00, 0x00, 0x00, // messageLength
		0x39, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xdd, 0x07, 0x00, 0x00, // opCode OP_MSG
		0x00, 0x00, 0x00, 0x00, // flagBits
		// sections db.adminCommand({getLog: "startupWarnings"})
		0x00, 0x54, 0x00, 0x00, 0x00, 0x02, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00, 0x03, 0x6c, 0x73, 0x69, 0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x6e, 0x81, 0xf8, 0x8e, 0x37, 0x7b, 0x4c, 0x97, 0x84, 0x4e, 0x90, 0x62, 0x5a, 0x54, 0x3c, 0x93, 0x00, 0x00,
	}
}

// createOpQueryPacket 创建OP_QUERY查询包
func createOpQueryPacket() []byte {
	return []byte{
		0x48, 0x00, 0x00, 0x00, // messageLength
		0x02, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xd4, 0x07, 0x00, 0x00, // opCode OP_QUERY
		0x00, 0x00, 0x00, 0x00, // flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // fullCollectionName admin.$cmd
		0x00, 0x00, 0x00, 0x00, // numberToSkip
		0x01, 0x00, 0x00, 0x00, // numberToReturn
		// query db.adminCommand({getLog: "startupWarnings"})
		0x21, 0x00, 0x00, 0x00, 0x2, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x00,
	}
}
