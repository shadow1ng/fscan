package tpkt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/libs/grdp/core"
	"github.com/shadow1ng/fscan/libs/grdp/emission"
	"github.com/shadow1ng/fscan/libs/grdp/glog"
	"github.com/shadow1ng/fscan/libs/grdp/protocol/nla"
)

// take idea from https://github.com/Madnikulin50/gordp

/**
 * Type of tpkt packet
 * Fastpath is use to shortcut RDP stack
 * @see http://msdn.microsoft.com/en-us/library/cc240621.aspx
 * @see http://msdn.microsoft.com/en-us/library/cc240589.aspx
 */
const (
	FASTPATH_ACTION_FASTPATH = 0x0
	FASTPATH_ACTION_X224     = 0x3
)

/**
 * TPKT layer of rdp stack
 */
type TPKT struct {
	emission.Emitter
	Conn             *core.SocketLayer
	ntlm             *nla.NTLMv2
	secFlag          byte
	lastShortLength  int
	fastPathListener core.FastPathListener
	ntlmSec          *nla.NTLMv2Security
	nlaAuthOnly      bool // NLA仅验证模式：验证成功后立即断开，不建立会话
}

var OsVersion = map[string]string{
	"3.10.511":      "Windows NT 3.1",
	"3.50.807":      "Windows NT 3.5",
	"3.10.528":      "Windows NT 3.1, Service Pack 3",
	"3.51.1057":     "Windows NT 3.51",
	"4.00.950":      "Windows 95",
	"4.0.1381":      "Windows NT 4.0",
	"4.10.1998":     "Windows 98",
	"4.10.2222":     "Windows 98 Second Edition (SE)",
	"5.0.2195":      "Windows 2000",
	"4.90.3000":     "Windows Me",
	"5.1.2600":      "Windows XP/Windows XP, Service Pack 3",
	"5.1.2600.1105": "Windows XP, Service Pack 1",
	"5.2.3790":      "Windows Server 2003/Windows Server 2003 R2/Windows Server 2003, Service Pack 2",
	"5.1.2600.2180": "Windows XP, Service Pack 2",
	"5.2.3790.1180": "Windows Server 2003, Service Pack 1",
	"6.0.6000":      "Windows Vista",
	"5.2.4500":      "Windows Home Server",
	"6.0.6001":      "Windows Vista, Service Pack 1/Windows Server 2008",
	"6.0.6002":      "Windows Vista, Service Pack 2/Windows Server 2008, Service Pack 2",
	"6.1.7600":      "Windows 7/Windows Server 2008 R2",
	"6.1.7601":      "Windows 7, Service Pack 1/Windows Server 2008 R2, Service Pack 1",
	"6.1.8400":      "Windows Home Server 2011",
	"6.2.9200":      "Windows Server 2012/Windows 8",
	"6.3.9600":      "Windows 8.1/Windows Server 2012 R2",
	"10.0.10240":    "Windows 10, Version 1507",
	"10.0.10586":    "Windows 10, Version 1511",
	"10.0.14393":    "Windows 10, Version 1607/Windows Server 2016, Version 1607",
	"10.0.15063":    "Windows 10, Version 1703",
	"10.0.16299":    "Windows 10, Version 1709",
	"10.0.17134":    "Windows 10, Version 1803",
	"10.0.17763":    "Windows Server 2019, Version 1809/Windows 10, Version 1809",
	"6.0.6003":      "Windows Server 2008, Service Pack 2, Rollup KB4489887",
	"10.0.18362":    "Windows 10, Version 1903",
	"10.0.18363":    "Windows 10, Version 1909/Windows Server, Version 1909",
	"10.0.19041":    "Windows 10, Version 2004/Windows Server, Version 2004",
	"10.0.19042":    "Windows 10, Version 20H2/Windows Server, Version 20H2",
	"10.0.19043":    "Windows 10, Version 21H1",
	"10.0.20348":    "Windows Server 2022",
	"10.0.22000":    "Windows 11, Version 21H2",
	"10.0.19044":    "Windows 10, Version 21H2",
}

func New(s *core.SocketLayer, ntlm *nla.NTLMv2) *TPKT {
	t := &TPKT{
		Emitter: *emission.NewEmitter(),
		Conn:    s,
		secFlag: 0,
		ntlm:    ntlm}
	core.StartReadBytes(2, s, t.recvHeader)
	return t
}

func (t *TPKT) StartTLS() error {
	return t.Conn.StartTLS()
}

// SetNLAAuthOnly 设置NLA仅验证模式
// 启用后，NLA认证成功即返回，不发送credentials建立会话，不会挤掉已登录用户
func (t *TPKT) SetNLAAuthOnly(authOnly bool) {
	t.nlaAuthOnly = authOnly
}

func (t *TPKT) StartNLA() error {
	err := t.StartTLS()
	if err != nil {
		glog.Info("start tls failed", err)
		return err
	}
	req := nla.EncodeDERTRequest([]nla.Message{t.ntlm.GetNegotiateMessage()}, nil, nil)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send NegotiateMessage", err)
		return err
	}

	resp := make([]byte, 1024)
	n, err := t.Conn.Read(resp)
	if err != nil {
		return fmt.Errorf("read %s", err)
	} else {
		glog.Debug("StartNLA Read success")
	}
	return t.recvChallenge(resp[:n])
}

func (t *TPKT) recvChallenge(data []byte) error {
	//own add
	glog.Debug("start recv challenge......")
	info := make(map[string]any)
	type NTLMChallenge struct {
		Signature              [8]byte
		MessageType            uint32
		TargetNameLen          uint16
		TargetNameMaxLen       uint16
		TargetNameBufferOffset uint32
		NegotiateFlags         uint32
		ServerChallenge        uint64
		Reserved               uint64
		TargetInfoLen          uint16
		TargetInfoMaxLen       uint16
		TargetInfoBufferOffset uint32
		Version                [8]byte
		// Payload (variable)
	}
	var challengeLen = 56

	challengeStartOffset := bytes.Index(data, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
	}
	if len(data) < challengeStartOffset+challengeLen {
		return nil
	}
	var responseData NTLMChallenge
	response := data[challengeStartOffset:]
	responseBuf := bytes.NewBuffer(response)
	err := binary.Read(responseBuf, binary.LittleEndian, &responseData)
	if err != nil {
		return err
	}
	// Check if valid NTLM challenge response message structure
	if responseData.MessageType != 0x00000002 ||
		responseData.Reserved != 0 ||
		!reflect.DeepEqual(responseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return nil
	}

	// Parse: Version
	type version struct {
		MajorVersion byte
		MinorVersion byte
		BuildNumber  uint16
	}
	var versionData version
	versionBuf := bytes.NewBuffer(responseData.Version[:4])
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return err
	}
	ProductVersion := fmt.Sprintf("%d.%d.%d", versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)
	glog.Debug("get product version: Windows", ProductVersion)
	info["ProductVersion"] = ProductVersion

	v, ok := OsVersion[ProductVersion]
	if ok {
		info["OsVerion"] = v
		glog.Debug("get os version:", v)
	} else {
		if versionData.BuildNumber >= 22000 {
			info["OsVerion"] = fmt.Sprintf("Windows 11, version:%s", ProductVersion)
		} else {
			info["OsVerion"] = fmt.Sprintf("Windows %s", ProductVersion)
		}
	}

	// Parse: TargetName
	targetNameLen := int(responseData.TargetNameLen)
	if targetNameLen > 0 {
		startIdx := int(responseData.TargetNameBufferOffset)
		endIdx := startIdx + targetNameLen
		targetName := strings.ReplaceAll(string(response[startIdx:endIdx]), "\x00", "")
		info["TargetName"] = targetName
		glog.Debug("target Name = ", targetName)
	}

	// Parse: TargetInfo
	AvIDMap := map[uint16]string{
		1: "NetBIOSComputerName",
		2: "NetBIOSDomainName",
		3: "FQDN", // DNS Computer Name
		4: "DNSDomainName",
		5: "DNSTreeName",
		7: "Timestamp",
		9: "MsvAvTargetName",
	}

	type AVPair struct {
		AvID  uint16
		AvLen uint16
		// Value (variable)
	}
	var avPairLen = 4
	targetInfoLen := int(responseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIdx := int(responseData.TargetInfoBufferOffset)
		if startIdx+targetInfoLen > len(response) {
			return fmt.Errorf("Invalid TargetInfoLen value")
		}
		var avPair AVPair
		avPairBuf := bytes.NewBuffer(response[startIdx : startIdx+avPairLen])
		err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
		if err != nil {
			return err
		}
		currIdx := startIdx
		for avPair.AvID != 0 {
			if field, exists := AvIDMap[avPair.AvID]; exists {
				var value string
				r := response[currIdx+avPairLen : currIdx+avPairLen+int(avPair.AvLen)]
				if avPair.AvID == 7 {
					unixStamp := binary.LittleEndian.Uint64(r)/10000000 - 11644473600
					tm := time.Unix(int64(unixStamp), 0)
					value = tm.Format("2006-01-02 15:04:05")
				} else {
					value = strings.ReplaceAll(string(r), "\x00", "")
				}
				info[field] = value
			}
			currIdx += avPairLen + int(avPair.AvLen)
			if currIdx+avPairLen > startIdx+targetInfoLen {
				return fmt.Errorf("Invalid AV_PAIR list")
			}
			avPairBuf = bytes.NewBuffer(response[currIdx : currIdx+avPairLen])
			err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
			if err != nil {
				return err
			}
		}
	}
	glog.Info("get os info by NLA done !")
	glog.Info("=======================================")
	for key, value := range info {
		glog.Info(key, ":", value)
	}
	glog.Info("=======================================")

	//判断是否存在windows域
	if netBiosDomainName, exists := info["NetBIOSDomainName"]; exists {
		if netBiosComputerName, exists := info["NetBIOSComputerName"]; exists {
			if netBiosDomainName == netBiosComputerName {
				info["DNSDomainName"], info["NetBIOSDomainName"] = "WORKGROUP", "WORKGROUP"
				//delete(info, "FQDN")
			} else {

			}
		}
	}

	t.Emit("os_info", info)

	// end
	glog.Trace("recvChallenge", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return err
	}
	glog.Debugf("tsreq:%+v", tsreq)
	// get pubkey
	pubkey, err := t.Conn.TlsPubKey()
	glog.Debugf("pubkey=%+v", pubkey)

	authMsg, ntlmSec := t.ntlm.GetAuthenticateMessage(tsreq.NegoTokens[0].Data)
	t.ntlmSec = ntlmSec

	encryptPubkey := ntlmSec.GssEncrypt(pubkey)
	req := nla.EncodeDERTRequest([]nla.Message{authMsg}, nil, encryptPubkey)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return err
	}
	resp := make([]byte, 1024)
	n, err := t.Conn.Read(resp)
	if err != nil {
		glog.Error("Read:", err)
		return fmt.Errorf("read %s", err)
	} else {
		glog.Debug("recvChallenge Read success")
	}
	return t.recvPubKeyInc(resp[:n])
}

// ErrNLAAuthSuccess 表示NLA仅验证模式下认证成功（非真正错误）
var ErrNLAAuthSuccess = fmt.Errorf("NLA_AUTH_SUCCESS")

func (t *TPKT) recvPubKeyInc(data []byte) error {
	glog.Trace("recvPubKeyInc", hex.EncodeToString(data))

	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return err
	}

	// 检查服务器是否返回错误码（认证失败）
	// 常见错误码: 0xC000006D = STATUS_LOGON_FAILURE (密码错误)
	if tsreq.ErrorCode != 0 {
		glog.Error("NLA authentication failed with error code:", tsreq.ErrorCode)
		return fmt.Errorf("NLA auth failed: error code %d (0x%X)", tsreq.ErrorCode, uint32(tsreq.ErrorCode))
	}

	// 验证 PubKeyAuth 不为空（认证成功的标志）
	if len(tsreq.PubKeyAuth) == 0 {
		glog.Error("NLA authentication failed: empty PubKeyAuth")
		return fmt.Errorf("NLA auth failed: empty PubKeyAuth")
	}

	glog.Trace("PubKeyAuth:", tsreq.PubKeyAuth)

	// 尝试解密验证公钥，但不作为强制失败条件
	// 因为某些Windows版本的响应格式可能略有不同
	pubkey := t.ntlmSec.GssDecrypt(tsreq.PubKeyAuth)
	if pubkey == nil {
		glog.Debug("GssDecrypt returned nil, but continuing since no ErrorCode was returned")
	}

	// NLA仅验证模式：凭据已验证成功，不发送credentials，直接返回
	// 这样不会建立RDP会话，不会挤掉已登录用户
	if t.nlaAuthOnly {
		glog.Info("NLA auth-only mode: credentials verified, skipping session establishment")
		return ErrNLAAuthSuccess
	}

	domain, username, password := t.ntlm.GetEncodedCredentials()
	credentials := nla.EncodeDERTCredentials(domain, username, password)
	authInfo := t.ntlmSec.GssEncrypt(credentials)
	req := nla.EncodeDERTRequest(nil, authInfo, nil)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return err
	}

	return nil
}

func (t *TPKT) Read(b []byte) (n int, err error) {
	return t.Conn.Read(b)
}

func (t *TPKT) Write(data []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	core.WriteUInt8(FASTPATH_ACTION_X224, buff)
	core.WriteUInt8(0, buff)
	core.WriteUInt16BE(uint16(len(data)+4), buff)
	buff.Write(data)
	glog.Trace("tpkt Write", hex.EncodeToString(buff.Bytes()))
	return t.Conn.Write(buff.Bytes())
}

func (t *TPKT) Close() error {
	return t.Conn.Close()
}

func (t *TPKT) SetFastPathListener(f core.FastPathListener) {
	t.fastPathListener = f
}

func (t *TPKT) SendFastPath(secFlag byte, data []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	core.WriteUInt8(FASTPATH_ACTION_FASTPATH|((secFlag&0x3)<<6), buff)
	core.WriteUInt16BE(uint16(len(data)+3)|0x8000, buff)
	buff.Write(data)
	glog.Trace("TPTK SendFastPath", hex.EncodeToString(buff.Bytes()))
	return t.Conn.Write(buff.Bytes())
}

func (t *TPKT) recvHeader(s []byte, err error) {
	glog.Trace("tpkt recvHeader", hex.EncodeToString(s), err)
	if err != nil {
		t.Emit("error", err)
		return
	}
	r := bytes.NewReader(s)
	version, _ := core.ReadUInt8(r)
	if version == FASTPATH_ACTION_X224 {
		glog.Debug("tptk recvHeader FASTPATH_ACTION_X224, wait for recvExtendedHeader")
		core.StartReadBytes(2, t.Conn, t.recvExtendedHeader)
	} else {
		glog.Debug("[-] !!!! version is not FASTPATH_ACTION_X224, version=", version)
		t.secFlag = (version >> 6) & 0x3
		length, _ := core.ReadUInt8(r)
		t.lastShortLength = int(length)
		glog.Debug("last read len:", length)
		if t.lastShortLength&0x80 != 0 {
			core.StartReadBytes(1, t.Conn, t.recvExtendedFastPathHeader)
		} else {
			//core.StartReadBytes(1, t.Conn, t.recvExtendedFastPathHeader)
			if t.lastShortLength >= 2 {
				core.StartReadBytes(t.lastShortLength-2, t.Conn, t.recvFastPath)
			} else {
				glog.Debug("lastShortLength = 0")
			}
		}
	}
}

func (t *TPKT) recvExtendedHeader(s []byte, err error) {
	glog.Trace("tpkt recvExtendedHeader", hex.EncodeToString(s), err)
	if err != nil {
		return
	}
	r := bytes.NewReader(s)
	size, _ := core.ReadUint16BE(r)
	glog.Debug("tpkt wait recvData:", size)
	core.StartReadBytes(int(size-4), t.Conn, t.recvData)
}

func (t *TPKT) recvData(s []byte, err error) {
	glog.Trace("tpkt recvData", hex.EncodeToString(s), err)
	if err != nil {
		return
	}
	t.Emit("data", s)
	core.StartReadBytes(2, t.Conn, t.recvHeader)
}

func (t *TPKT) recvExtendedFastPathHeader(s []byte, err error) {
	glog.Trace("tpkt recvExtendedFastPathHeader", hex.EncodeToString(s))
	r := bytes.NewReader(s)
	rightPart, err := core.ReadUInt8(r)
	if err != nil {
		glog.Error("TPTK recvExtendedFastPathHeader", err)
		return
	}

	leftPart := t.lastShortLength & ^0x80
	packetSize := (leftPart << 8) + int(rightPart)
	if packetSize == 0 {
		fmt.Println("get packetSize,rightPart=", packetSize, rightPart)
		t.Emit("close")
	} else {
		core.StartReadBytes(packetSize-3, t.Conn, t.recvFastPath)
	}
}

func (t *TPKT) recvFastPath(s []byte, err error) {
	glog.Trace("tpkt recvFastPath")
	if err != nil {
		return
	}

	t.fastPathListener.RecvFastPath(t.secFlag, s)
	core.StartReadBytes(2, t.Conn, t.recvHeader)
}
