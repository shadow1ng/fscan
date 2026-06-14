//go:build plugin_mqtt || !plugin_selective

package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

var mqttConnectPacket = []byte{
	0x10, 0x0c,
	0x00, 0x04, 'M', 'Q', 'T', 'T',
	0x04,
	0x02,
	0x00, 0x00,
	0x00, 0x00,
}

type MQTTPlugin struct {
	plugins.BasePlugin
}

func NewMQTTPlugin() *MQTTPlugin {
	return &MQTTPlugin{BasePlugin: plugins.NewBasePlugin("mqtt")}
}

func (p *MQTTPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "mqtt"}
	}
	defer conn.Close()

	if info.Port == 8883 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		conn, err = p.wrapTLS(ctx, conn)
		if err != nil {
			return &ScanResult{Success: false, Service: "mqtt"}
		}
		defer conn.Close()
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(mqttConnectPacket); err != nil {
		return &ScanResult{Success: false, Service: "mqtt"}
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return &ScanResult{Success: false, Service: "mqtt"}
	}

	banner, ok := parseMQTTConnack(header)
	if !ok {
		return &ScanResult{Success: false, Service: "mqtt"}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "mqtt",
		Banner:  banner,
	}
}

func (p *MQTTPlugin) wrapTLS(ctx context.Context, conn net.Conn) (net.Conn, error) {
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func parseMQTTConnack(data []byte) (string, bool) {
	if len(data) < 4 || data[0] != 0x20 || data[1] != 0x02 {
		return "", false
	}

	switch data[3] {
	case 0x00:
		return "MQTT CONNACK accepted", true
	case 0x01:
		return "MQTT CONNACK unacceptable protocol version", true
	case 0x02:
		return "MQTT CONNACK identifier rejected", true
	case 0x03:
		return "MQTT CONNACK server unavailable", true
	case 0x04:
		return "MQTT CONNACK bad username or password", true
	case 0x05:
		return "MQTT CONNACK not authorized", true
	default:
		return fmt.Sprintf("MQTT CONNACK return_code=%d", data[3]), true
	}
}

func init() {
	RegisterPluginWithPorts("mqtt", func() Plugin {
		return NewMQTTPlugin()
	}, []int{1883, 8883})
}
