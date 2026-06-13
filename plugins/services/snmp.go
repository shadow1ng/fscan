//go:build plugin_snmp || !plugin_selective

package services

import (
	"context"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type SNMPPlugin struct {
	plugins.BasePlugin
}

func NewSNMPPlugin() *SNMPPlugin {
	return &SNMPPlugin{BasePlugin: plugins.NewBasePlugin("snmp")}
}

func (p *SNMPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	target := info.Target()

	result := p.probe(ctx, target, "public", timeout, session)
	if result == nil {
		return &ScanResult{Success: false, Service: "snmp"}
	}

	if config.DisableBrute {
		return result
	}

	communities := p.buildCommunityList(config)
	alreadyProbed := "public"
	var found []string
	// 首次 probe 已确认服务存活，后续 community 用更短超时 + 连续失败快速退出
	bruteTimeout := 3 * time.Second
	consecutiveFails := 0
	for _, community := range communities {
		if community == alreadyProbed {
			continue
		}
		select {
		case <-ctx.Done():
			return result
		default:
		}
		if consecutiveFails >= 3 {
			break
		}
		if r := p.probe(ctx, target, community, bruteTimeout, session); r != nil && r.Success {
			found = append(found, community)
			consecutiveFails = 0
		} else {
			consecutiveFails++
		}
	}

	if len(found) > 0 {
		return &ScanResult{
			Success:  true,
			Type:     plugins.ResultTypeCredential,
			Service:  "snmp",
			Password: strings.Join(found, ","),
			Banner:   result.Banner,
		}
	}
	return result
}

func (p *SNMPPlugin) probe(ctx context.Context, target, community string, timeout time.Duration, session *common.ScanSession) *ScanResult {
	// 用 context 超时保护整个 probe（防止 UDP Write/Read 在某些内核下永久阻塞）
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := session.DialUDP(probeCtx, target, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 在 goroutine 中执行 I/O，context 超时时强制关闭连接
	type probeResult struct {
		sysDescr string
	}
	ch := make(chan *probeResult, 1)
	go func() {
		pkt := buildSNMPGetRequest(community, []int{1, 3, 6, 1, 2, 1, 1, 1, 0})
		if _, err := conn.Write(pkt); err != nil {
			ch <- nil
			return
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			ch <- nil
			return
		}
		ch <- &probeResult{sysDescr: parseSNMPResponse(buf[:n])}
	}()

	select {
	case <-probeCtx.Done():
		_ = conn.Close()
		return nil
	case r := <-ch:
		if r == nil || r.sysDescr == "" {
			return nil
		}
		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeService,
			Service: "snmp",
			Banner:  "community: " + community + " | " + r.sysDescr,
		}
	}
}

func (p *SNMPPlugin) buildCommunityList(config *common.Config) []string {
	// SNMP community 仅使用专用列表，不混入通用密码字典
	// 通用密码（如 123456、P@ssw0rd）不可能是 community string，混入会导致 60+ 次串行探测
	return []string{"public", "private", "community", "manager", "monitor", "admin", "snmp", "default"}
}

// SNMPv2c GetRequest 编码
func buildSNMPGetRequest(community string, oid []int) []byte {
	requestID := int(time.Now().UnixNano() & 0x7FFFFFFF)

	varbind, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      marshalOIDWithNull(oid),
	})

	varbindList, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      varbind,
	})

	reqIDBytes, _ := asn1.Marshal(requestID)
	errorStatusBytes, _ := asn1.Marshal(0)
	errorIndexBytes, _ := asn1.Marshal(0)

	var pduContent []byte
	pduContent = append(pduContent, reqIDBytes...)
	pduContent = append(pduContent, errorStatusBytes...)
	pduContent = append(pduContent, errorIndexBytes...)
	pduContent = append(pduContent, varbindList...)

	pdu := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0, // GetRequest-PDU
		IsCompound: true,
		Bytes:      pduContent,
	}
	pduBytes, _ := asn1.Marshal(pdu)

	versionBytes, _ := asn1.Marshal(1) // SNMPv2c
	communityBytes, _ := asn1.Marshal([]byte(community))

	var messageContent []byte
	messageContent = append(messageContent, versionBytes...)
	messageContent = append(messageContent, communityBytes...)
	messageContent = append(messageContent, pduBytes...)

	message, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      messageContent,
	})
	return message
}

func marshalOIDWithNull(oid []int) []byte {
	oidBytes, _ := asn1.Marshal(asn1.ObjectIdentifier(oid))
	nullBytes, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNull})
	var result []byte
	result = append(result, oidBytes...)
	result = append(result, nullBytes...)
	return result
}

func parseSNMPResponse(data []byte) string {
	var message asn1.RawValue
	if _, err := asn1.Unmarshal(data, &message); err != nil {
		return ""
	}
	if message.Tag != asn1.TagSequence {
		return ""
	}

	rest := message.Bytes
	// version
	var version asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &version)
	if len(rest) == 0 {
		return ""
	}
	// community
	var community asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &community)
	if len(rest) == 0 {
		return ""
	}
	// PDU (GetResponse = context-specific tag 2)
	var pdu asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &pdu); err != nil {
		return ""
	}

	pduRest := pdu.Bytes
	// skip requestID, errorStatus, errorIndex
	for i := 0; i < 3; i++ {
		var skip asn1.RawValue
		var err error
		pduRest, err = asn1.Unmarshal(pduRest, &skip)
		if err != nil || len(pduRest) == 0 {
			return ""
		}
	}

	// varbindList -> varbind -> (oid, value)
	var varbindList asn1.RawValue
	if _, err := asn1.Unmarshal(pduRest, &varbindList); err != nil {
		return ""
	}
	var varbind asn1.RawValue
	if _, err := asn1.Unmarshal(varbindList.Bytes, &varbind); err != nil {
		return ""
	}

	vbRest := varbind.Bytes
	// skip OID
	var oidVal asn1.RawValue
	vbRest, _ = asn1.Unmarshal(vbRest, &oidVal)
	if len(vbRest) == 0 {
		return ""
	}

	// value
	var value asn1.RawValue
	if _, err := asn1.Unmarshal(vbRest, &value); err != nil {
		return ""
	}

	if value.Tag == asn1.TagOctetString || value.Tag == asn1.TagUTF8String {
		s := strings.TrimSpace(string(value.Bytes))
		return truncateRunes(s, 200)
	}
	return fmt.Sprintf("(type=%d, len=%d)", value.Tag, len(value.Bytes))
}

func init() {
	RegisterUDPPluginWithPorts("snmp", func() Plugin {
		return NewSNMPPlugin()
	}, []int{161})
}
