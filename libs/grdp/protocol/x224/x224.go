package x224

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/shadow1ng/fscan/libs/grdp/glog"

	"github.com/lunixbochs/struc"
	"github.com/shadow1ng/fscan/libs/grdp/core"
	"github.com/shadow1ng/fscan/libs/grdp/emission"
	"github.com/shadow1ng/fscan/libs/grdp/protocol/tpkt"
)

// take idea from https://github.com/Madnikulin50/gordp

/**
 * Message type present in X224 packet header
 */
type MessageType byte

const (
	TPDU_CONNECTION_REQUEST MessageType = 0xE0
	TPDU_CONNECTION_CONFIRM             = 0xD0
	TPDU_DISCONNECT_REQUEST             = 0x80
	TPDU_DATA                           = 0xF0
	TPDU_ERROR                          = 0x70
)

/**
 * Type of negotiation present in negotiation packet
 */
type NegotiationType byte

const (
	TYPE_RDP_NEG_REQ     NegotiationType = 0x01
	TYPE_RDP_NEG_RSP                     = 0x02
	TYPE_RDP_NEG_FAILURE                 = 0x03
)

/**
 * Protocols available for x224 layer
 */

const (
	PROTOCOL_RDP       uint32 = 0x00000000
	PROTOCOL_SSL              = 0x00000001
	PROTOCOL_HYBRID           = 0x00000002
	PROTOCOL_HYBRID_EX        = 0x00000008
)

/**
 * Use to negotiate security layer of RDP stack
 * In node-rdpjs only ssl is available
 * @param opt {object} component type options
 * @see request -> http://msdn.microsoft.com/en-us/library/cc240500.aspx
 * @see response -> http://msdn.microsoft.com/en-us/library/cc240506.aspx
 * @see failure ->http://msdn.microsoft.com/en-us/library/cc240507.aspx
 */
type Negotiation struct {
	Type   NegotiationType `struc:"byte"`
	Flag   uint8           `struc:"uint8"`
	Length uint16          `struc:"little"`
	Result uint32          `struc:"little"`
}

func NewNegotiation() *Negotiation {
	return &Negotiation{0, 0, 0x0008 /*constant*/, PROTOCOL_RDP}
}

const (
	//The server requires that the client support Enhanced RDP Security (section 5.4) with either TLS 1.0, 1.1 or 1.2 (section 5.4.5.1) or CredSSP (section 5.4.5.2). If only CredSSP was requested then the server only supports TLS.
	SSL_REQUIRED_BY_SERVER = 0x00000001

	//The server is configured to only use Standard RDP Security mechanisms (section 5.3) and does not support any External Security Protocols (section 5.4.5).
	SSL_NOT_ALLOWED_BY_SERVER = 0x00000002

	//The server does not possess a valid authentication certificate and cannot initialize the External Security Protocol Provider (section 5.4.5).
	SSL_CERT_NOT_ON_SERVER = 0x00000003

	//The list of requested security protocols is not consistent with the current security protocol in effect. This error is only possible when the Direct Approach (sections 5.4.2.2 and 1.3.1.2) is used and an External Security Protocol (section 5.4.5) is already being used.
	INCONSISTENT_FLAGS = 0x00000004

	//The server requires that the client support Enhanced RDP Security (section 5.4) with CredSSP (section 5.4.5.2).
	HYBRID_REQUIRED_BY_SERVER = 0x00000005

	//The server requires that the client support Enhanced RDP Security (section 5.4) with TLS 1.0, 1.1 or 1.2 (section 5.4.5.1) and certificate-based client authentication.<4>
	SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 0x00000006
)

/**
 * X224 client connection request
 * @param opt {object} component type options
 * @see	http://msdn.microsoft.com/en-us/library/cc240470.aspx
 */
type ClientConnectionRequestPDU struct {
	Len               uint8
	Code              MessageType
	Padding1          uint16
	Padding2          uint16
	Padding3          uint8
	Cookie            []byte
	requestedProtocol uint32
	ProtocolNeg       *Negotiation
}

func NewClientConnectionRequestPDU(cookie []byte, requestedProtocol uint32) *ClientConnectionRequestPDU {
	x := ClientConnectionRequestPDU{0, TPDU_CONNECTION_REQUEST, 0, 0, 0,
		cookie, requestedProtocol, NewNegotiation()}

	x.Len = 6
	if len(cookie) > 0 {
		x.Len += uint8(len(cookie) + 2)
	}
	if x.requestedProtocol > PROTOCOL_RDP {
		x.Len += 8
	}

	return &x
}

func (x *ClientConnectionRequestPDU) Serialize() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt8(x.Len, buff)
	core.WriteUInt8(uint8(x.Code), buff)
	core.WriteUInt16BE(x.Padding1, buff)
	core.WriteUInt16BE(x.Padding2, buff)
	core.WriteUInt8(x.Padding3, buff)

	if len(x.Cookie) > 0 {
		buff.Write(x.Cookie)
		core.WriteUInt8(0x0D, buff)
		core.WriteUInt8(0x0A, buff)
	}

	if x.requestedProtocol > PROTOCOL_RDP {
		struc.Pack(buff, x.ProtocolNeg)
	}

	return buff.Bytes()
}

/**
 * X224 Server connection confirm
 * @param opt {object} component type options
 * @see	http://msdn.microsoft.com/en-us/library/cc240506.aspx
 */
type ServerConnectionConfirm struct {
	Len         uint8
	Code        MessageType
	Padding1    uint16
	Padding2    uint16
	Padding3    uint8
	ProtocolNeg *Negotiation
}

/**
 * Header of each data message from x224 layer
 * @returns {type.Component}
 */
type DataHeader struct {
	Header      uint8       `struc:"little"`
	MessageType MessageType `struc:"uint8"`
	Separator   uint8       `struc:"little"`
}

func NewDataHeader() *DataHeader {
	return &DataHeader{2, TPDU_DATA /* constant */, 0x80 /*constant*/}
}

/**
 * Common X224 Automata
 * @param presentation {Layer} presentation layer
 */
type X224 struct {
	emission.Emitter
	transport         core.Transport
	requestedProtocol uint32
	selectedProtocol  uint32
	dataHeader        *DataHeader
}

func New(t core.Transport) *X224 {
	x := &X224{
		*emission.NewEmitter(),
		t,
		PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID,
		PROTOCOL_SSL,
		NewDataHeader(),
	}

	t.On("close", func() {
		x.Emit("close")
	}).On("error", func(err error) {
		x.Emit("error", err)
	})

	return x
}

func (x *X224) ServerChooseProtocol() uint32 {
	return x.selectedProtocol
}

func (x *X224) Read(b []byte) (n int, err error) {
	return x.transport.Read(b)
}

func (x *X224) Write(b []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	err = struc.Pack(buff, x.dataHeader)
	if err != nil {
		return 0, err
	}
	buff.Write(b)

	glog.Trace("x224 write:", hex.EncodeToString(buff.Bytes()))
	return x.transport.Write(buff.Bytes())
}

func (x *X224) Close() error {
	return x.transport.Close()
}

func (x *X224) SetRequestedProtocol(p uint32) {
	x.requestedProtocol = p
}

func (x *X224) Connect() error {
	if x.transport == nil {
		return errors.New("no transport")
	}
	cookie := "Cookie: mstshash=bob"
	message := NewClientConnectionRequestPDU([]byte(cookie), x.requestedProtocol)
	message.ProtocolNeg.Type = TYPE_RDP_NEG_REQ
	message.ProtocolNeg.Result = uint32(x.requestedProtocol)

	glog.Debug("x224 sendConnectionRequest", hex.EncodeToString(message.Serialize()))
	_, err := x.transport.Write(message.Serialize())
	x.transport.Once("data", x.recvConnectionConfirm)
	return err
}

func (x *X224) recvConnectionConfirm(s []byte) {
	/*
		在Windows的远程桌面协议（RDP）交互过程中，NLA是指网络级别身份验证（Network Level Authentication）。NLA是一种用于增强远程桌面连接安全性的机制。在启用了NLA的情况下，客户端必须在建立RDP会话之前通过网络级别的身份验证，这样可以防止未经授权的用户连接到远程桌面服务器。

		NLA的优点
		提高安全性：在建立RDP会话之前进行身份验证，确保只有经过验证的用户才能连接。
		减少资源消耗：因为身份验证是在连接建立之前完成的，可以减少未授权用户消耗的系统资源。
		RDP协议中的不同连接类型
		RDP协议有几种不同的连接类型，它们在使用NLA方面有所不同：

		PROTOCOL_RDP：标准的RDP连接方式。这是最早期的RDP连接类型，不使用任何额外的安全层。

		PROTOCOL_SSL：使用SSL/TLS加密的RDP连接方式。这种方式可以增强连接的安全性。

		PROTOCOL_HYBRID：混合连接方式，通常指的是使用NLA和TLS结合的连接方式。它先进行网络级别的身份验证（NLA），然后使用TLS加密传输数据。

		PROTOCOL_HYBRID_EX：这是PROTOCOL_HYBRID的扩展版本，可能包含额外的安全特性或增强功能，具体细节通常会在相关文档中描述。

		NLA与不同连接类型的关系
		PROTOCOL_RDP：不使用NLA，因为这是最基本的连接方式。
		PROTOCOL_SSL：可以与NLA结合使用。首先通过NLA进行身份验证，然后使用SSL/TLS加密数据传输。
		PROTOCOL_HYBRID：使用NLA进行身份验证，然后通过TLS加密数据传输。因此，NLA在这种连接类型中是必需的。
		PROTOCOL_HYBRID_EX：作为PROTOCOL_HYBRID的扩展版本，也可以使用NLA进行身份验证，并结合其他安全增强特性。

		总的来说，除了最基本的PROTOCOL_RDP之外，其他连接类型（PROTOCOL_SSL、PROTOCOL_HYBRID、PROTOCOL_HYBRID_EX）都可以使用或要求使用NLA来提高连接的安全性。
	*/

	/*
		总体而言，较早的Windows版本（如Windows 2000、Windows XP、Windows Server 2003等）默认使用基本的RDP协议（PROTOCOL_RDP），而现代的Windows版本（如Windows 7及之后的版本）默认启用网络级别身份验证（NLA）并支持SSL/TLS加密，以提高连接的安全性。具体的默认协议如下：

		Windows 2000、Windows XP、Windows Server 2003：	PROTOCOL_RDP
		Windows Vista、Windows Server 2008：				PROTOCOL_RDP（NLA可配置）
		Windows 7、Windows Server 2008 R2：				PROTOCOL_HYBRID（默认启用NLA）
		Windows 8、Windows Server 2012：					PROTOCOL_HYBRID（默认启用NLA）
		Windows 8.1、Windows Server 2012 R2：			PROTOCOL_HYBRID（默认启用NLA）
		Windows 10、Windows Server 2016：				PROTOCOL_HYBRID（默认启用NLA）
		Windows 10（1809及以上版本）、Windows Server 2019：PROTOCOL_HYBRID（默认启用NLA）
		Windows 11、Windows Server 2022：				PROTOCOL_HYBRID（默认启用NLA）

	*/
	glog.Debug("x224 recvConnectionConfirm ", hex.EncodeToString(s))
	r := bytes.NewReader(s)
	ln, _ := core.ReadUInt8(r)

	if ln > 6 {
		message := &ServerConnectionConfirm{}
		if err := struc.Unpack(bytes.NewReader(s), message); err != nil {
			glog.Error("ReadServerConnectionConfirm err", err)
			return
		}
		glog.Debugf("message: %+v", *message.ProtocolNeg)

		if message.ProtocolNeg.Type == TYPE_RDP_NEG_FAILURE {
			glog.Error(fmt.Sprintf("NODE_RDP_PROTOCOL_X224_NEG_FAILURE with code: %d,see https://msdn.microsoft.com/en-us/library/cc240507.aspx",
				message.ProtocolNeg.Result))
			//only use Standard RDP Security mechanisms
			if message.ProtocolNeg.Result == 2 {
				glog.Info("Only use Standard RDP Security mechanisms, Reconnect with Standard RDP")
			}
			switch message.ProtocolNeg.Result {
			case SSL_REQUIRED_BY_SERVER:
				// mean need use PROTOCOL_SSL
				glog.Info("The server requires that the client support Enhanced RDP Security")
				x.Emit("reconnect", PROTOCOL_SSL)
			case SSL_NOT_ALLOWED_BY_SERVER:
				// mean need to use PROTOCOL_RDP only
				glog.Info("The server is configured to only use Standard RDP Security mechanisms")
				x.Emit("reconnect", PROTOCOL_RDP)

			case SSL_CERT_NOT_ON_SERVER:
				glog.Info("The server does not possess a valid authentication certificate and cannot initialize the External Security Protocol Provider")
			case INCONSISTENT_FLAGS:
				glog.Info("The list of requested security protocols is not consistent with the current security protocol in effect. This error is only possible when the Direct Approach")
			case HYBRID_REQUIRED_BY_SERVER:
				glog.Info("The server requires that the client support Enhanced RDP Security (section 5.4) with CredSSP (section 5.4.5.2).")
				x.Emit("reconnect", PROTOCOL_HYBRID)
			case SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER:
				glog.Info("The server requires that the client support Enhanced RDP Security (section 5.4) with TLS 1.0, 1.1 or 1.2 (section 5.4.5.1) and certificate-based client authentication.<4>")
				x.Emit("reconnect", PROTOCOL_SSL)
				////The server requires that the client support Enhanced RDP Security (section 5.4) with either TLS 1.0, 1.1 or 1.2 (section 5.4.5.1) or CredSSP (section 5.4.5.2). If only CredSSP was requested then the server only supports TLS.
				//	SSL_REQUIRED_BY_SERVER = 0x00000001
				//
				//	//The server is configured to only use Standard RDP Security mechanisms (section 5.3) and does not support any External Security Protocols (section 5.4.5).
				//	SSL_NOT_ALLOWED_BY_SERVER = 0x00000002
				//
				//	//The server does not possess a valid authentication certificate and cannot initialize the External Security Protocol Provider (section 5.4.5).
				//	SSL_CERT_NOT_ON_SERVER = 0x00000003
				//
				//	//The list of requested security protocols is not consistent with the current security protocol in effect. This error is only possible when the Direct Approach (sections 5.4.2.2 and 1.3.1.2) is used and an External Security Protocol (section 5.4.5) is already being used.
				//	INCONSISTENT_FLAGS = 0x00000004
				//
				//	//The server requires that the client support Enhanced RDP Security (section 5.4) with CredSSP (section 5.4.5.2).
				//	HYBRID_REQUIRED_BY_SERVER = 0x00000005
				//
				//	//The server requires that the client support Enhanced RDP Security (section 5.4) with TLS 1.0, 1.1 or 1.2 (section 5.4.5.1) and certificate-based client authentication.<4>
				//	SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 0x00000006
			}

			x.Close()
			return
		}

		if message.ProtocolNeg.Type == TYPE_RDP_NEG_RSP {
			glog.Info("TYPE_RDP_NEG_RSP", message.ProtocolNeg.Result)
			x.selectedProtocol = message.ProtocolNeg.Result
		}
	} else {
		x.selectedProtocol = PROTOCOL_RDP
	}

	serverChooseProtocol := "other not support protocol"
	switch x.selectedProtocol {
	case PROTOCOL_RDP:
		serverChooseProtocol = "PROTOCOL_RDP"
		x.Emit("more_timeout")
	case PROTOCOL_SSL:
		serverChooseProtocol = "PROTOCOL_SSL"
	case PROTOCOL_HYBRID:
		serverChooseProtocol = "PROTOCOL_HYBRID"
	case PROTOCOL_HYBRID_EX:
		serverChooseProtocol = "PROTOCOL_HYBRID_EX"
	}
	glog.Info("Server choose protocol:", serverChooseProtocol)

	//if x.selectedProtocol == PROTOCOL_HYBRID_EX {
	//	glog.Error("NODE_RDP_PROTOCOL_HYBRID_EX_NOT_SUPPORTED")
	//	return
	//}

	if x.selectedProtocol == PROTOCOL_HYBRID_EX {
		glog.Info("*** NLA Security selected ***")
		err := x.transport.(*tpkt.TPKT).StartNLA()
		glog.Debug("nla end, err?:", err)
		if err != nil {
			x.transport.Emit("close")
			glog.Error("start NLA failed:", err)
			return
		}
		x.Emit("connect", uint32(x.selectedProtocol))
		return
	}

	x.transport.On("data", x.recvData)

	if x.selectedProtocol == PROTOCOL_RDP {
		glog.Info("*** RDP security selected ***")
		x.Emit("connect", x.selectedProtocol)
		return
	}

	if x.selectedProtocol == PROTOCOL_SSL {
		glog.Info("*** SSL security selected ***")
		err := x.transport.(*tpkt.TPKT).StartTLS()
		if err != nil {
			glog.Error("start tls failed:", err)
			return
		}
		x.Emit("connect", x.selectedProtocol)
		return
	}

	if x.selectedProtocol == PROTOCOL_HYBRID {
		glog.Info("*** NLA Security selected ***")
		err := x.transport.(*tpkt.TPKT).StartNLA()
		glog.Debug("nla end, err?:", err)
		if err != nil {
			// 检查是否是NLA仅验证模式的成功返回
			if err == tpkt.ErrNLAAuthSuccess {
				glog.Info("NLA auth-only mode: credentials verified successfully")
				x.Emit("error", err) // 通过 error 事件传播成功信号
				return
			}
			glog.Error("start NLA failed:", err)
			x.Emit("error", err)
			return
		}
		x.Emit("connect", x.selectedProtocol)
		return
	}
}

func (x *X224) recvData(s []byte) {
	glog.Trace("x224 recvData", hex.EncodeToString(s), "emit data")
	// x224 header takes 3 bytes
	x.Emit("data", s[3:])
}
