package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// MongodbScan 执行MongoDB未授权扫描
func MongodbScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	isUnauth, err := MongodbUnauth(info)

	if err != nil {
		errlog := fmt.Sprintf("MongoDB %v %v", target, err)
		Common.LogError(errlog)
	} else if isUnauth {
		// 记录控制台输出
		Common.LogSuccess(fmt.Sprintf("MongoDB %v 未授权访问", target))

		// 保存未授权访问结果
		result := &Common.ScanResult{
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
		Common.SaveResult(result)
	}

	return err
}

// MongodbUnauth 检测MongoDB未授权访问
func MongodbUnauth(info *Common.HostInfo) (bool, error) {
	msgPacket := createOpMsgPacket()
	queryPacket := createOpQueryPacket()

	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 尝试OP_MSG查询
	reply, err := checkMongoAuth(realhost, msgPacket)
	if err != nil {
		// 失败则尝试OP_QUERY查询
		reply, err = checkMongoAuth(realhost, queryPacket)
		if err != nil {
			return false, err
		}
	}

	// 检查响应结果
	if strings.Contains(reply, "totalLinesWritten") {
		return true, nil
	}

	return false, nil
}

// checkMongoAuth 检查MongoDB认证状态
func checkMongoAuth(address string, packet []byte) (string, error) {
	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp", address, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 设置超时时间
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return "", err
	}

	// 发送查询包
	if _, err := conn.Write(packet); err != nil {
		return "", err
	}

	// 读取响应
	reply := make([]byte, 1024)
	count, err := conn.Read(reply)
	if err != nil {
		return "", err
	}

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
