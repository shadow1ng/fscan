package gcc

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/shadow1ng/fscan/mylib/grdp/glog"

	"github.com/lunixbochs/struc"
	"github.com/shadow1ng/fscan/mylib/grdp/core"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/t125/per"
)

var t124_02_98_oid = []byte{0, 0, 20, 124, 0, 1}
var h221_cs_key = "Duca"
var h221_sc_key = "McDn"

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240509.aspx
 */
type Message uint16

const (
	//server -> client
	SC_CORE     Message = 0x0C01
	SC_SECURITY         = 0x0C02
	SC_NET              = 0x0C03
	//client -> server
	CS_CORE     = 0xC001
	CS_SECURITY = 0xC002
	CS_NET      = 0xC003
	CS_CLUSTER  = 0xC004
	CS_MONITOR  = 0xC005
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240510.aspx
 */
type ColorDepth uint16

const (
	RNS_UD_COLOR_8BPP      ColorDepth = 0xCA01
	RNS_UD_COLOR_16BPP_555            = 0xCA02
	RNS_UD_COLOR_16BPP_565            = 0xCA03
	RNS_UD_COLOR_24BPP                = 0xCA04
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240510.aspx
 */
type HighColor uint16

const (
	HIGH_COLOR_4BPP  HighColor = 0x0004
	HIGH_COLOR_8BPP            = 0x0008
	HIGH_COLOR_15BPP           = 0x000f
	HIGH_COLOR_16BPP           = 0x0010
	HIGH_COLOR_24BPP           = 0x0018
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240510.aspx
 */
type Support uint16

const (
	RNS_UD_24BPP_SUPPORT uint16 = 0x0001
	RNS_UD_16BPP_SUPPORT        = 0x0002
	RNS_UD_15BPP_SUPPORT        = 0x0004
	RNS_UD_32BPP_SUPPORT        = 0x0008
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240510.aspx
 */
type CapabilityFlag uint16

const (
	RNS_UD_CS_SUPPORT_ERRINFO_PDU        uint16 = 0x0001
	RNS_UD_CS_WANT_32BPP_SESSION                = 0x0002
	RNS_UD_CS_SUPPORT_STATUSINFO_PDU            = 0x0004
	RNS_UD_CS_STRONG_ASYMMETRIC_KEYS            = 0x0008
	RNS_UD_CS_UNUSED                            = 0x0010
	RNS_UD_CS_VALID_CONNECTION_TYPE             = 0x0020
	RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU        = 0x0040
	RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT        = 0x0080
	RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL        = 0x0100
	RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE         = 0x0200
	RNS_UD_CS_SUPPORT_HEARTBEAT_PDU             = 0x0400
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240510.aspx
 */
type ConnectionType uint8

const (
	CONNECTION_TYPE_MODEM          ConnectionType = 0x01
	CONNECTION_TYPE_BROADBAND_LOW                 = 0x02
	CONNECTION_TYPE_SATELLITEV                    = 0x03
	CONNECTION_TYPE_BROADBAND_HIGH                = 0x04
	CONNECTION_TYPE_WAN                           = 0x05
	CONNECTION_TYPE_LAN                           = 0x06
	CONNECTION_TYPE_AUTODETECT                    = 0x07
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240510.aspx
 */
type VERSION uint32

const (
	RDP_VERSION_4      VERSION = 0x00080001
	RDP_VERSION_5_PLUS         = 0x00080004
)

type Sequence uint16

const (
	RNS_UD_SAS_DEL Sequence = 0xAA03
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240511.aspx
 */
type EncryptionMethod uint32

const (
	ENCRYPTION_FLAG_40BIT  uint32 = 0x00000001
	ENCRYPTION_FLAG_128BIT        = 0x00000002
	ENCRYPTION_FLAG_56BIT         = 0x00000008
	FIPS_ENCRYPTION_FLAG          = 0x00000010
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240518.aspx
 */
type EncryptionLevel uint32

const (
	ENCRYPTION_LEVEL_NONE              EncryptionLevel = 0x00000000
	ENCRYPTION_LEVEL_LOW                               = 0x00000001
	ENCRYPTION_LEVEL_CLIENT_COMPATIBLE                 = 0x00000002
	ENCRYPTION_LEVEL_HIGH                              = 0x00000003
	ENCRYPTION_LEVEL_FIPS                              = 0x00000004
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240513.aspx
 */
type ChannelOptions uint32

const (
	CHANNEL_OPTION_INITIALIZED   ChannelOptions = 0x80000000
	CHANNEL_OPTION_ENCRYPT_RDP                  = 0x40000000
	CHANNEL_OPTION_ENCRYPT_SC                   = 0x20000000
	CHANNEL_OPTION_ENCRYPT_CS                   = 0x10000000
	CHANNEL_OPTION_PRI_HIGH                     = 0x08000000
	CHANNEL_OPTION_PRI_MED                      = 0x04000000
	CHANNEL_OPTION_PRI_LOW                      = 0x02000000
	CHANNEL_OPTION_COMPRESS_RDP                 = 0x00800000
	CHANNEL_OPTION_COMPRESS                     = 0x00400000
	CHANNEL_OPTION_SHOW_PROTOCOL                = 0x00200000
	REMOTE_CONTROL_PERSISTENT                   = 0x00100000
)

/**
 * IBM_101_102_KEYS is the most common keyboard type
 */
type KeyboardType uint32

const (
	KT_IBM_PC_XT_83_KEY KeyboardType = 0x00000001
	KT_OLIVETTI                      = 0x00000002
	KT_IBM_PC_AT_84_KEY              = 0x00000003
	KT_IBM_101_102_KEYS              = 0x00000004
	KT_NOKIA_1050                    = 0x00000005
	KT_NOKIA_9140                    = 0x00000006
	KT_JAPANESE                      = 0x00000007
)

/**
 * @see http://technet.microsoft.com/en-us/library/cc766503%28WS.10%29.aspx
 */
type KeyboardLayout uint32

const (
	ARABIC              KeyboardLayout = 0x00000401
	BULGARIAN                          = 0x00000402
	CHINESE_US_KEYBOARD                = 0x00000404
	CZECH                              = 0x00000405
	DANISH                             = 0x00000406
	GERMAN                             = 0x00000407
	GREEK                              = 0x00000408
	US                                 = 0x00000409
	SPANISH                            = 0x0000040a
	FINNISH                            = 0x0000040b
	FRENCH                             = 0x0000040c
	HEBREW                             = 0x0000040d
	HUNGARIAN                          = 0x0000040e
	ICELANDIC                          = 0x0000040f
	ITALIAN                            = 0x00000410
	JAPANESE                           = 0x00000411
	KOREAN                             = 0x00000412
	DUTCH                              = 0x00000413
	NORWEGIAN                          = 0x00000414
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240521.aspx
 */
type CertificateType uint32

const (
	CERT_CHAIN_VERSION_1 CertificateType = 0x00000001
	CERT_CHAIN_VERSION_2                 = 0x00000002
)

type ChannelDef struct {
	Name    string `struc:"little"`
	Options uint32 `struc:"little"`
}

type ClientCoreData struct {
	RdpVersion             VERSION        `struc:"uint32,little"`
	DesktopWidth           uint16         `struc:"little"`
	DesktopHeight          uint16         `struc:"little"`
	ColorDepth             ColorDepth     `struc:"little"`
	SasSequence            Sequence       `struc:"little"`
	KbdLayout              KeyboardLayout `struc:"little"`
	ClientBuild            uint32         `struc:"little"`
	ClientName             [32]byte       `struc:"[32]byte"`
	KeyboardType           uint32         `struc:"little"`
	KeyboardSubType        uint32         `struc:"little"`
	KeyboardFnKeys         uint32         `struc:"little"`
	ImeFileName            [64]byte       `struc:"[64]byte"`
	PostBeta2ColorDepth    ColorDepth     `struc:"little"`
	ClientProductId        uint16         `struc:"little"`
	SerialNumber           uint32         `struc:"little"`
	HighColorDepth         HighColor      `struc:"little"`
	SupportedColorDepths   uint16         `struc:"little"`
	EarlyCapabilityFlags   uint16         `struc:"little"`
	ClientDigProductId     [64]byte       `struc:"[64]byte"`
	ConnectionType         uint8          `struc:"uint8"`
	Pad1octet              uint8          `struc:"uint8"`
	ServerSelectedProtocol uint32         `struc:"little"`
}

func NewClientCoreData() *ClientCoreData {
	var ClientName [32]byte
	return &ClientCoreData{
		RDP_VERSION_5_PLUS, 1280, 800, RNS_UD_COLOR_8BPP,
		RNS_UD_SAS_DEL, US, 3790, ClientName, KT_IBM_101_102_KEYS,
		0, 12, [64]byte{}, RNS_UD_COLOR_8BPP, 1, 0, HIGH_COLOR_24BPP,
		RNS_UD_15BPP_SUPPORT | RNS_UD_16BPP_SUPPORT | RNS_UD_24BPP_SUPPORT | RNS_UD_32BPP_SUPPORT,
		RNS_UD_CS_SUPPORT_ERRINFO_PDU, [64]byte{}, 0, 0, 0}
}

func (data *ClientCoreData) Pack() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt16LE(CS_CORE, buff) // 01C0
	core.WriteUInt16LE(0xd8, buff)    // d800
	struc.Pack(buff, data)
	return buff.Bytes()
}

type ClientNetworkData struct {
	ChannelCount    uint32
	ChannelDefArray []ChannelDef
}

func NewClientNetworkData() *ClientNetworkData {
	n := &ClientNetworkData{ChannelDefArray: make([]ChannelDef, 0, 100)}

	/*var d1 ChannelDef
	d1.Name = plugin.RDPDR_SVC_CHANNEL_NAME
	d1.Options = uint32(CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP |
		CHANNEL_OPTION_COMPRESS_RDP)
	n.ChannelDefArray = append(n.ChannelDefArray, d1)

	var d2 ChannelDef
	d2.Name = plugin.RDPSND_SVC_CHANNEL_NAME
	d2.Options = uint32(CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP |
		CHANNEL_OPTION_COMPRESS_RDP | CHANNEL_OPTION_SHOW_PROTOCOL)
	n.ChannelDefArray = append(n.ChannelDefArray, d2)*/

	return n
}

func (n *ClientNetworkData) AddVirtualChannel(name string, option uint32) {
	var d ChannelDef
	d.Name = name
	d.Options = option
	n.ChannelDefArray = append(n.ChannelDefArray, d)
	n.ChannelCount++
}

func (n *ClientNetworkData) Pack() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt16LE(CS_NET, buff) // type
	length := uint16(n.ChannelCount*12 + 8)
	core.WriteUInt16LE(length, buff) // len 8
	core.WriteUInt32LE(n.ChannelCount, buff)
	for i := 0; i < int(n.ChannelCount); i++ {
		v := n.ChannelDefArray[i]
		name := make([]byte, 8)
		copy(name, []byte(v.Name))
		core.WriteBytes(name[:], buff)
		core.WriteUInt32LE(v.Options, buff)
	}
	return buff.Bytes()
}

type ClientSecurityData struct {
	EncryptionMethods    uint32
	ExtEncryptionMethods uint32
}

func NewClientSecurityData() *ClientSecurityData {
	return &ClientSecurityData{
		ENCRYPTION_FLAG_40BIT | ENCRYPTION_FLAG_56BIT | ENCRYPTION_FLAG_128BIT,
		00}
}

func (d *ClientSecurityData) Pack() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt16LE(CS_SECURITY, buff) // type
	core.WriteUInt16LE(0x0c, buff)        // len 12
	core.WriteUInt32LE(d.EncryptionMethods, buff)
	core.WriteUInt32LE(d.ExtEncryptionMethods, buff)
	return buff.Bytes()
}

type RSAPublicKey struct {
	Magic   uint32 `struc:"little"` //0x31415352
	Keylen  uint32 `struc:"little,sizeof=Modulus"`
	Bitlen  uint32 `struc:"little"`
	Datalen uint32 `struc:"little"`
	PubExp  uint32 `struc:"little"`
	Modulus []byte `struc:"little"`
	Padding []byte `struc:"[8]byte"`
}

type ProprietaryServerCertificate struct {
	DwSigAlgId        uint32       `struc:"little"` //0x00000001
	DwKeyAlgId        uint32       `struc:"little"` //0x00000001
	PublicKeyBlobType uint16       `struc:"little"` //0x0006
	PublicKeyBlobLen  uint16       `struc:"little,sizeof=PublicKeyBlob"`
	PublicKeyBlob     RSAPublicKey `struc:"little"`
	SignatureBlobType uint16       `struc:"little"` //0x0008
	SignatureBlobLen  uint16       `struc:"little,sizeof=SignatureBlob"`
	SignatureBlob     []byte       `struc:"little"`
	//PaddingLen        uint16       `struc:"little,sizeof=Padding,skip"`
	Padding []byte `struc:"[8]byte"`
}

func (p *ProprietaryServerCertificate) GetPublicKey() (*rsa.PublicKey, error) {
	b := new(big.Int).SetBytes(core.Reverse(p.PublicKeyBlob.Modulus))
	e := new(big.Int).SetInt64(int64(p.PublicKeyBlob.PubExp))
	return &rsa.PublicKey{N: b, E: int(e.Int64())}, nil
}
func (p *ProprietaryServerCertificate) Verify() bool {
	return true
}
func (p *ProprietaryServerCertificate) Encrypt() []byte {
	//todo
	return nil
}
func (p *ProprietaryServerCertificate) Unpack(r io.Reader) error {
	p.DwSigAlgId, _ = core.ReadUInt32LE(r)
	p.DwKeyAlgId, _ = core.ReadUInt32LE(r)
	p.PublicKeyBlobType, _ = core.ReadUint16LE(r)
	p.PublicKeyBlobLen, _ = core.ReadUint16LE(r)
	var b RSAPublicKey
	b.Magic, _ = core.ReadUInt32LE(r)
	b.Keylen, _ = core.ReadUInt32LE(r)
	b.Bitlen, _ = core.ReadUInt32LE(r)
	b.Datalen, _ = core.ReadUInt32LE(r)
	b.PubExp, _ = core.ReadUInt32LE(r)
	b.Modulus, _ = core.ReadBytes(int(b.Keylen)-8, r)
	b.Padding, _ = core.ReadBytes(8, r)
	p.PublicKeyBlob = b
	p.SignatureBlobType, _ = core.ReadUint16LE(r)
	p.SignatureBlobLen, _ = core.ReadUint16LE(r)
	p.SignatureBlob, _ = core.ReadBytes(int(p.SignatureBlobLen)-8, r)
	p.Padding, _ = core.ReadBytes(8, r)

	return nil
}

type CertBlob struct {
	CbCert uint32 `struc:"little,sizeof=AbCert"`
	AbCert []byte `struc:"little"`
}
type X509CertificateChain struct {
	NumCertBlobs  uint32     `struc:"little,sizeof=CertBlobArray"`
	CertBlobArray []CertBlob `struc:"little"`
	Padding       []byte     `struc:"[12]byte"`
}

func (x *X509CertificateChain) GetPublicKey() (*rsa.PublicKey, error) {
	if len(x.CertBlobArray) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	data := x.CertBlobArray[len(x.CertBlobArray)-1].AbCert
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	if cert.PublicKey == nil {
		var pubKeyInfo struct {
			Algorithm        pkix.AlgorithmIdentifier
			SubjectPublicKey asn1.BitString
		}
		_, err = asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &pubKeyInfo)
		if err != nil {
			return nil, fmt.Errorf("unmarshal public key info: %w", err)
		}
		rsaPublicKey, err := x509.ParsePKCS1PublicKey(pubKeyInfo.SubjectPublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 public key: %w", err)
		}
		return rsaPublicKey, nil
	}
	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}
	return rsaPublicKey, nil
}
func (x *X509CertificateChain) Verify() bool {
	return true
}
func (x *X509CertificateChain) Encrypt() []byte {
	//todo
	return nil
}
func (x *X509CertificateChain) Unpack(r io.Reader) error {
	return struc.Unpack(r, x)
}

type ServerCoreData struct {
	RdpVersion              VERSION `struc:"uint32,little"`
	ClientRequestedProtocol uint32  `struc:"little"`
	EarlyCapabilityFlags    uint32  `struc:"little"`
}

func NewServerCoreData() *ServerCoreData {
	return &ServerCoreData{
		RDP_VERSION_5_PLUS, 0, 0}
}

func (d *ServerCoreData) Serialize() []byte {
	return []byte{}
}

func (d *ServerCoreData) ScType() Message {
	return SC_CORE
}
func (d *ServerCoreData) Unpack(r io.Reader) error {
	version, _ := core.ReadUInt32LE(r)
	d.RdpVersion = VERSION(version)
	d.ClientRequestedProtocol, _ = core.ReadUInt32LE(r)
	d.EarlyCapabilityFlags, _ = core.ReadUInt32LE(r)

	return nil
	//return struc.Unpack(r, d)
}

type ServerNetworkData struct {
	MCSChannelId   uint16   `struc:"little"`
	ChannelCount   uint16   `struc:"little,sizeof=ChannelIdArray"`
	ChannelIdArray []uint16 `struc:"little"`
}

func NewServerNetworkData() *ServerNetworkData {
	return &ServerNetworkData{}
}
func (d *ServerNetworkData) ScType() Message {
	return SC_NET
}
func (d *ServerNetworkData) Unpack(r io.Reader) error {
	return struc.Unpack(r, d)
}

type CertData interface {
	GetPublicKey() (*rsa.PublicKey, error)
	Verify() bool
	Unpack(io.Reader) error
}
type ServerCertificate struct {
	DwVersion uint32
	CertData  CertData
}

func (sc *ServerCertificate) Unpack(r io.Reader) error {
	sc.DwVersion, _ = core.ReadUInt32LE(r)
	var cd CertData
	switch CertificateType(sc.DwVersion & 0x7fffffff) {
	case CERT_CHAIN_VERSION_1:
		glog.Debug("ProprietaryServerCertificate")
		cd = &ProprietaryServerCertificate{}
	case CERT_CHAIN_VERSION_2:
		glog.Debug("X509CertificateChain")
		cd = &X509CertificateChain{}
	default:
		glog.Error("Unsupported version:", sc.DwVersion&0x7fffffff)
		return errors.New("Unsupported version")
	}
	if cd != nil {
		err := cd.Unpack(r)
		if err != nil {
			glog.Error("Unpack:", err)
			return err
		}
	}
	sc.CertData = cd

	return nil
}

type ServerSecurityData struct {
	EncryptionMethod  uint32 `struc:"little"`
	EncryptionLevel   uint32 `struc:"little"`
	ServerRandomLen   uint32 //0x00000020
	ServerCertLen     uint32
	ServerRandom      []byte
	ServerCertificate ServerCertificate
}

func NewServerSecurityData() *ServerSecurityData {
	return &ServerSecurityData{
		0, 0, 0x00000020, 0, []byte{}, ServerCertificate{}}
}
func (d *ServerSecurityData) ScType() Message {
	return SC_SECURITY
}
func (s *ServerSecurityData) Unpack(r io.Reader) error {
	s.EncryptionMethod, _ = core.ReadUInt32LE(r)
	s.EncryptionLevel, _ = core.ReadUInt32LE(r)
	if !(s.EncryptionMethod == 0 && s.EncryptionLevel == 0) {
		s.ServerRandomLen, _ = core.ReadUInt32LE(r)
		s.ServerCertLen, _ = core.ReadUInt32LE(r)
		s.ServerRandom, _ = core.ReadBytes(int(s.ServerRandomLen), r)
		var sc ServerCertificate
		data, _ := core.ReadBytes(int(s.ServerCertLen), r)
		rd := bytes.NewReader(data)
		err := sc.Unpack(rd)
		if err != nil {
			return err
		}
		s.ServerCertificate = sc
	}

	return nil
}

func MakeConferenceCreateRequest(userData []byte) []byte {
	buff := &bytes.Buffer{}
	per.WriteChoice(0, buff)                        // 00
	per.WriteObjectIdentifier(t124_02_98_oid, buff) // 05:00:14:7c:00:01
	per.WriteLength(len(userData)+14, buff)
	per.WriteChoice(0, buff)                   // 00
	per.WriteSelection(0x08, buff)             // 08
	per.WriteNumericString("1", 1, buff)       // 00 10
	per.WritePadding(1, buff)                  // 00
	per.WriteNumberOfSet(1, buff)              // 01
	per.WriteChoice(0xc0, buff)                // c0
	per.WriteOctetStream(h221_cs_key, 4, buff) // 00 44:75:63:61
	per.WriteOctetStream(string(userData), 0, buff)
	return buff.Bytes()
}

type ScData interface {
	ScType() Message
	Unpack(io.Reader) error
}

func ReadConferenceCreateResponse(data []byte) []interface{} {
	ret := make([]interface{}, 0, 3)

	r := bytes.NewReader(data)
	per.ReadChoice(r)
	if !per.ReadObjectIdentifier(r, t124_02_98_oid) {
		glog.Error("NODE_RDP_PROTOCOL_T125_GCC_BAD_OBJECT_IDENTIFIER_T124")
		return ret
	}
	per.ReadLength(r)
	per.ReadChoice(r)
	per.ReadInteger16(r)
	per.ReadInteger(r)
	per.ReadEnumerates(r)
	per.ReadNumberOfSet(r)
	per.ReadChoice(r)

	if !per.ReadOctetStream(r, h221_sc_key, 4) {
		glog.Error("NODE_RDP_PROTOCOL_T125_GCC_BAD_H221_SC_KEY")
		return ret
	}

	ln, _ := per.ReadLength(r)
	for ln > 0 {
		t, _ := core.ReadUint16LE(r)
		glog.Debugf("Message type 0x%x,ln:%v", t, ln)
		l, _ := core.ReadUint16LE(r)
		dataBytes, _ := core.ReadBytes(int(l)-4, r)
		ln = ln - l
		var d ScData
		switch Message(t) {
		case SC_CORE:
			d = &ServerCoreData{}
		case SC_SECURITY:
			d = &ServerSecurityData{}
		case SC_NET:
			d = &ServerNetworkData{}
		default:
			glog.Error("Unknown type", t)
			continue
		}

		if d != nil {
			r := bytes.NewReader(dataBytes)
			err := d.Unpack(r)
			if err != nil {
				glog.Warn("Unpack:", err)
			}
			ret = append(ret, d)
		}
	}

	return ret
}
