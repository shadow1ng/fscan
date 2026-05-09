package sec

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/lunixbochs/struc"

	"github.com/shadow1ng/fscan/mylib/grdp/protocol/nla"

	"github.com/shadow1ng/fscan/mylib/grdp/core"
	"github.com/shadow1ng/fscan/mylib/grdp/emission"
	"github.com/shadow1ng/fscan/mylib/grdp/glog"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/lic"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/t125"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/t125/gcc"
)

/**
 * SecurityFlag
 * @see http://msdn.microsoft.com/en-us/library/cc240579.aspx
 */
const (
	EXCHANGE_PKT       uint16 = 0x0001
	TRANSPORT_REQ             = 0x0002
	TRANSPORT_RSP             = 0x0004
	ENCRYPT                   = 0x0008
	RESET_SEQNO               = 0x0010
	IGNORE_SEQNO              = 0x0020
	INFO_PKT                  = 0x0040
	LICENSE_PKT               = 0x0080
	LICENSE_ENCRYPT_CS        = 0x0200
	LICENSE_ENCRYPT_SC        = 0x0200
	REDIRECTION_PKT           = 0x0400
	SECURE_CHECKSUM           = 0x0800
	AUTODETECT_REQ            = 0x1000
	AUTODETECT_RSP            = 0x2000
	HEARTBEAT                 = 0x4000
	FLAGSHI_VALID             = 0x8000
)

const (
	INFO_MOUSE                  uint32 = 0x00000001
	INFO_DISABLECTRLALTDEL             = 0x00000002
	INFO_AUTOLOGON                     = 0x00000008
	INFO_UNICODE                       = 0x00000010
	INFO_MAXIMIZESHELL                 = 0x00000020
	INFO_LOGONNOTIFY                   = 0x00000040
	INFO_COMPRESSION                   = 0x00000080
	INFO_ENABLEWINDOWSKEY              = 0x00000100
	INFO_REMOTECONSOLEAUDIO            = 0x00002000
	INFO_FORCE_ENCRYPTED_CS_PDU        = 0x00004000
	INFO_RAIL                          = 0x00008000
	INFO_LOGONERRORS                   = 0x00010000
	INFO_MOUSE_HAS_WHEEL               = 0x00020000
	INFO_PASSWORD_IS_SC_PIN            = 0x00040000
	INFO_NOAUDIOPLAYBACK               = 0x00080000
	INFO_USING_SAVED_CREDS             = 0x00100000
	INFO_AUDIOCAPTURE                  = 0x00200000
	INFO_VIDEO_DISABLE                 = 0x00400000
	INFO_CompressionTypeMask           = 0x00001E00
)

const (
	AF_INET  uint16 = 0x00002
	AF_INET6        = 0x0017
)

const (
	PERF_DISABLE_WALLPAPER          uint32 = 0x00000001
	PERF_DISABLE_FULLWINDOWDRAG            = 0x00000002
	PERF_DISABLE_MENUANIMATIONS            = 0x00000004
	PERF_DISABLE_THEMING                   = 0x00000008
	PERF_DISABLE_CURSOR_SHADOW             = 0x00000020
	PERF_DISABLE_CURSORSETTINGS            = 0x00000040
	PERF_ENABLE_FONT_SMOOTHING             = 0x00000080
	PERF_ENABLE_DESKTOP_COMPOSITION        = 0x00000100
)

const (
	FASTPATH_OUTPUT_SECURE_CHECKSUM = 0x1
	FASTPATH_OUTPUT_ENCRYPTED       = 0x2
)

type ClientAutoReconnect struct {
	CbAutoReconnectLen uint16
	CbLen              uint32
	Version            uint32
	LogonId            uint32
	SecVerifier        []byte
}

func NewClientAutoReconnect(id uint32, random []byte) *ClientAutoReconnect {
	return &ClientAutoReconnect{
		CbAutoReconnectLen: 28,
		CbLen:              28,
		Version:            1,
		LogonId:            id,
		SecVerifier:        nla.HMAC_MD5(random, random),
	}
}

type RDPExtendedInfo struct {
	ClientAddressFamily uint16 `struc:"little"`
	CbClientAddress     uint16 `struc:"little,sizeof=ClientAddress"`
	ClientAddress       []byte `struc:"[]byte"`
	CbClientDir         uint16 `struc:"little,sizeof=ClientDir"`
	ClientDir           []byte `struc:"[]byte"`
	ClientTimeZone      []byte `struc:"[172]byte"`
	ClientSessionId     uint32 `struc:"litttle"`
	PerformanceFlags    uint32 `struc:"little"`
	AutoReconnect       *ClientAutoReconnect
}

func NewExtendedInfo(auto *ClientAutoReconnect) *RDPExtendedInfo {
	return &RDPExtendedInfo{
		ClientAddressFamily: AF_INET,
		ClientAddress:       []byte{0, 0},
		ClientDir:           []byte{0, 0},
		ClientTimeZone:      make([]byte, 172),
		ClientSessionId:     0,
		AutoReconnect:       auto,
	}
}

func (o *RDPExtendedInfo) Serialize() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt16LE(o.ClientAddressFamily, buff)
	core.WriteUInt16LE(uint16(len(o.ClientAddress)), buff)
	core.WriteBytes(o.ClientAddress, buff)
	core.WriteUInt16LE(uint16(len(o.ClientDir)), buff)
	core.WriteBytes(o.ClientDir, buff)
	core.WriteBytes(o.ClientTimeZone, buff)
	core.WriteUInt32LE(o.ClientSessionId, buff)
	core.WriteUInt32LE(o.PerformanceFlags, buff)

	if o.AutoReconnect != nil {
		core.WriteUInt16LE(o.AutoReconnect.CbAutoReconnectLen, buff)
		core.WriteUInt32LE(o.AutoReconnect.CbLen, buff)
		core.WriteUInt32LE(o.AutoReconnect.Version, buff)
		core.WriteUInt32LE(o.AutoReconnect.LogonId, buff)
		core.WriteBytes(o.AutoReconnect.SecVerifier, buff)
	}

	return buff.Bytes()
}

type RDPInfo struct {
	CodePage         uint32
	Flag             uint32
	CbDomain         uint16
	CbUserName       uint16
	CbPassword       uint16
	CbAlternateShell uint16
	CbWorkingDir     uint16
	Domain           []byte
	UserName         []byte
	Password         []byte
	AlternateShell   []byte
	WorkingDir       []byte
	ExtendedInfo     *RDPExtendedInfo
}

func NewRDPInfo() *RDPInfo {
	info := &RDPInfo{
		Flag: INFO_MOUSE | INFO_UNICODE | INFO_MAXIMIZESHELL |
			INFO_ENABLEWINDOWSKEY | INFO_DISABLECTRLALTDEL | INFO_MOUSE_HAS_WHEEL |
			INFO_FORCE_ENCRYPTED_CS_PDU | INFO_AUTOLOGON,
		Domain:         []byte{0, 0},
		UserName:       []byte{0, 0},
		Password:       []byte{0, 0},
		AlternateShell: []byte{0, 0},
		WorkingDir:     []byte{0, 0},
		ExtendedInfo:   NewExtendedInfo(nil),
	}
	return info
}

func (o *RDPInfo) SetClientAutoReconnect(auto *ClientAutoReconnect) {
	o.ExtendedInfo.AutoReconnect = auto
}

func (o *RDPInfo) SetClientInfo() {
	o.Flag |= INFO_LOGONNOTIFY | INFO_LOGONERRORS
}

func (o *RDPInfo) Serialize(hasExtended bool) []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt32LE(o.CodePage, buff)                      // 0000000
	core.WriteUInt32LE(o.Flag, buff)                          // 0530101
	core.WriteUInt16LE(uint16(len(o.Domain)-2), buff)         // 001c
	core.WriteUInt16LE(uint16(len(o.UserName)-2), buff)       // 0008
	core.WriteUInt16LE(uint16(len(o.Password)-2), buff)       //000c
	core.WriteUInt16LE(uint16(len(o.AlternateShell)-2), buff) //0000
	core.WriteUInt16LE(uint16(len(o.WorkingDir)-2), buff)     //0000
	core.WriteBytes(o.Domain, buff)
	core.WriteBytes(o.UserName, buff)
	core.WriteBytes(o.Password, buff)
	core.WriteBytes(o.AlternateShell, buff)
	core.WriteBytes(o.WorkingDir, buff)
	if hasExtended {
		core.WriteBytes(o.ExtendedInfo.Serialize(), buff)
	}
	return buff.Bytes()
}

type SecurityHeader struct {
	securityFlag   uint16
	securityFlagHi uint16
}

func readSecurityHeader(r io.Reader) *SecurityHeader {
	s := &SecurityHeader{}
	s.securityFlag, _ = core.ReadUint16LE(r)
	s.securityFlagHi, _ = core.ReadUint16LE(r)
	return s
}

type SEC struct {
	emission.Emitter
	transport   core.Transport
	info        *RDPInfo
	machineName string
	clientData  []interface{}
	serverData  []interface{}

	enableEncryption bool
	//Enable Secure Mac generation
	enableSecureCheckSum bool
	//counter before update
	nbEncryptedPacket int
	nbDecryptedPacket int

	currentDecrytKey  []byte
	currentEncryptKey []byte

	//current rc4 tab
	decryptRc4 *rc4.Cipher
	encryptRc4 *rc4.Cipher

	macKey  []byte
	macSalt []byte
}

func NewSEC(t core.Transport) *SEC {
	sec := &SEC{
		*emission.NewEmitter(),
		t,
		NewRDPInfo(),
		"",
		nil,
		nil,
		false,
		false,
		0,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	}

	t.On("close", func() {
		sec.Emit("close")
	}).On("error", func(err error) {
		sec.Emit("error", err)
	})
	return sec
}

func (s *SEC) Read(data []byte) (n int, err error) {
	return s.transport.Read(data)
}

func (s *SEC) Write(b []byte) (n int, err error) {
	if !s.enableEncryption {
		return s.transport.Write(b)
	}
	data := s.encrytData(b)
	return s.transport.Write(data)
}

func (s *SEC) Close() error {
	return s.transport.Close()
}

func (s *SEC) sendFlagged(flag uint16, data []byte) (n int, err error) {
	glog.Trace("sendFlagged:", hex.EncodeToString(data))
	b := s.encryt(flag, data)
	return s.transport.Write(b)
}

/*
@see: http://msdn.microsoft.com/en-us/library/cc241995.aspx
@param macSaltKey: {str} mac key
@param data: {str} data to sign
@return: {str} signature
*/
func macData(macSaltKey, data []byte) []byte {
	sha1Digest := sha1.New()
	md5Digest := md5.New()

	b := &bytes.Buffer{}
	core.WriteUInt32LE(uint32(len(data)), b)

	sha1Digest.Write(macSaltKey)
	for i := 0; i < 40; i++ {
		sha1Digest.Write([]byte("\x36"))
	}

	sha1Digest.Write(b.Bytes())
	sha1Digest.Write(data)

	sha1Sig := sha1Digest.Sum(nil)

	md5Digest.Write(macSaltKey)
	for i := 0; i < 48; i++ {
		md5Digest.Write([]byte("\x5c"))
	}

	md5Digest.Write(sha1Sig)

	return md5Digest.Sum(nil)
}
func (s *SEC) readEncryptedPayload(data []byte, checkSum bool) []byte {
	r := bytes.NewReader(data)
	sign, _ := core.ReadBytes(8, r)
	glog.Debug("read sign:", sign)
	encryptedPayload, _ := core.ReadBytes(r.Len(), r)
	if s.decryptRc4 == nil {
		s.decryptRc4, _ = rc4.NewCipher(s.currentDecrytKey)
	}
	s.nbDecryptedPacket++
	glog.Debug("nbDecryptedPacket:", s.nbDecryptedPacket)
	plaintext := make([]byte, len(encryptedPayload))
	s.decryptRc4.XORKeyStream(plaintext, encryptedPayload)

	return plaintext

}
func (s *SEC) writeEncryptedPayload(data []byte, checkSum bool) []byte {
	if s.nbEncryptedPacket == 4096 {

	}

	if checkSum {
		glog.Debug("need checkSum")
		return []byte{}
	}

	s.nbEncryptedPacket++
	glog.Debug("nbEncryptedPacket:", s.nbEncryptedPacket)
	b := &bytes.Buffer{}

	sign := macData(s.macKey, data)[:8]
	//sign := macData(s.macSalt, data)[:8]
	if s.encryptRc4 == nil {
		s.encryptRc4, _ = rc4.NewCipher(s.currentEncryptKey)
	}

	plaintext := make([]byte, len(data))
	s.encryptRc4.XORKeyStream(plaintext, data)
	b.Write(sign)
	b.Write(plaintext)
	glog.Debug("sign:", hex.EncodeToString(sign), "plaintext:", hex.EncodeToString(plaintext))
	return b.Bytes()
}

func (s *SEC) encryt(flag uint16, b []byte) []byte {
	data := b
	if flag&ENCRYPT != 0 {
		data = s.writeEncryptedPayload(b, flag&SECURE_CHECKSUM != 0)
	}
	buff := &bytes.Buffer{}
	core.WriteUInt16LE(flag, buff)
	core.WriteUInt16LE(0, buff)
	core.WriteBytes(data, buff)

	return buff.Bytes()
}
func (s *SEC) encrytData(b []byte) []byte {
	if !s.enableEncryption {
		return b
	}

	var flag uint16 = ENCRYPT
	if s.enableSecureCheckSum {
		flag |= SECURE_CHECKSUM
	}
	return s.encryt(flag, b)
}

func (s *SEC) decrytData(b []byte) []byte {
	if !s.enableEncryption {
		return b
	}

	r := bytes.NewReader(b)
	securityFlag, _ := core.ReadUint16LE(r)
	_, _ = core.ReadUint16LE(r) //securityFlagHi
	data, _ := core.ReadBytes(r.Len(), r)
	if securityFlag&ENCRYPT != 0 {
		data = s.readEncryptedPayload(data, securityFlag&SECURE_CHECKSUM != 0)
	}
	return data
}

type Client struct {
	*SEC
	userId    uint16
	channelId uint16
	//initialise decrypt and encrypt keys
	initialDecrytKey  []byte
	initialEncryptKey []byte

	fastPathListener core.FastPathListener
	channelSender    core.ChannelSender
}

func NewClient(t core.Transport) *Client {
	c := &Client{
		SEC: NewSEC(t),
	}
	t.On("connect", c.connect)
	return c
}

func (c *Client) SetClientAutoReconnect(id uint32, random []byte) {
	auto := NewClientAutoReconnect(id, random)
	c.info.SetClientAutoReconnect(auto)
}

func (c *Client) SetAlternateShell(shell string) {
	buff := &bytes.Buffer{}
	for _, ch := range utf16.Encode([]rune(shell)) {
		core.WriteUInt16LE(ch, buff)
	}
	core.WriteUInt16LE(0, buff)
	c.info.AlternateShell = buff.Bytes()
	c.info.Flag |= INFO_RAIL
}

func (c *Client) SetUser(user string) {
	buff := &bytes.Buffer{}
	for _, ch := range utf16.Encode([]rune(user)) {
		core.WriteUInt16LE(ch, buff)
	}
	core.WriteUInt16LE(0, buff)
	c.info.UserName = buff.Bytes()
}

func (c *Client) SetPwd(pwd string) {
	buff := &bytes.Buffer{}
	for _, ch := range utf16.Encode([]rune(pwd)) {
		core.WriteUInt16LE(ch, buff)
	}
	core.WriteUInt16LE(0, buff)
	c.info.Password = buff.Bytes()
}

func (c *Client) SetDomain(domain string) {
	buff := &bytes.Buffer{}
	for _, ch := range utf16.Encode([]rune(domain)) {
		core.WriteUInt16LE(ch, buff)
	}
	core.WriteUInt16LE(0, buff)
	c.info.Domain = buff.Bytes()
}

func (c *Client) connect(clientData []interface{}, serverData []interface{}, userId uint16, channels []t125.MCSChannelInfo) {
	glog.Debug("sec on connect:", clientData)
	glog.Debug("sec on connect:", serverData)
	glog.Debug("sec on connect:", userId)
	glog.Debug("sec on connect:", channels)
	c.clientData = clientData
	c.serverData = serverData
	c.userId = userId
	for _, channel := range channels {
		glog.Infof("channel: %s <%d>:", channel.Name, channel.ID)
		if channel.Name == t125.GLOBAL_CHANNEL_NAME {
			c.channelId = channel.ID
			//break
		}
	}
	c.enableEncryption = c.ClientCoreData().ServerSelectedProtocol == 0

	if c.enableEncryption {
		if !c.sendClientRandom() {
			return
		}
	}

	c.sendInfoPkt()
	c.transport.Once("sec", c.recvLicenceInfo)
}

func (c *Client) ClientCoreData() *gcc.ClientCoreData {
	return c.clientData[0].(*gcc.ClientCoreData)
}
func (c *Client) ClientSecurityData() *gcc.ClientSecurityData {
	return c.clientData[1].(*gcc.ClientSecurityData)
}
func (c *Client) ClientNetworkData() *gcc.ClientNetworkData {
	return c.clientData[2].(*gcc.ClientNetworkData)
}

func (c *Client) ServerSecurityData() *gcc.ServerSecurityData {
	return c.serverData[1].(*gcc.ServerSecurityData)
}

/*
@summary: generate 40 bits data from 128 bits data
@param data: {str} 128 bits data
@return: {str} 40 bits data
@see: http://msdn.microsoft.com/en-us/library/cc240785.aspx
*/
func gen40bits(data []byte) []byte {
	return append([]byte("\xd1\x26\x9e"), data[3:8]...)
}

/*
@summary: generate 56 bits data from 128 bits data
@param data: {str} 128 bits data
@return: {str} 56 bits data
@see: http://msdn.microsoft.com/en-us/library/cc240785.aspx
*/
func gen56bits(data []byte) []byte {
	return append([]byte("\xd1"), data[1:8]...)
}

/*
@summary: Generate particular signature from combination of sha1 and md5
@see: http://msdn.microsoft.com/en-us/library/cc241992.aspx
@param inputData: strange input (see doc)
@param salt: salt for context call
@param salt1: another salt (ex : client random)
@param salt2: another another salt (ex: server random)
@return : MD5(Salt + SHA1(Input + Salt + Salt1 + Salt2))
*/
func saltedHash(inputData, salt, salt1, salt2 []byte) []byte {
	sha1Digest := sha1.New()
	md5Digest := md5.New()

	sha1Digest.Write(inputData)
	sha1Digest.Write(salt[:48])
	sha1Digest.Write(salt1)
	sha1Digest.Write(salt2)
	sha1Sig := sha1Digest.Sum(nil)

	md5Digest.Write(salt[:48])
	md5Digest.Write(sha1Sig)

	return md5Digest.Sum(nil)[:16]
}

/*
@summary: MD5(in0[:16] + in1[:32] + in2[:32])
@param key: in 16
@param random1: in 32
@param random2: in 32
@return MD5(in0[:16] + in1[:32] + in2[:32])
*/
func finalHash(key, random1, random2 []byte) []byte {
	md5Digest := md5.New()
	md5Digest.Write(key)
	md5Digest.Write(random1)
	md5Digest.Write(random2)
	return md5Digest.Sum(nil)
}

/*
@summary: Generate master secret
@param secret: {str} secret
@param clientRandom : {str} client random
@param serverRandom : {str} server random
@see: http://msdn.microsoft.com/en-us/library/cc241992.aspx
*/
func masterSecret(secret, random1, random2 []byte) []byte {
	sh1 := saltedHash([]byte("A"), secret, random1, random2)
	sh2 := saltedHash([]byte("BB"), secret, random1, random2)
	sh3 := saltedHash([]byte("CCC"), secret, random1, random2)
	ms := bytes.NewBuffer(nil)
	ms.Write(sh1)
	ms.Write(sh2)
	ms.Write(sh3)
	return ms.Bytes()
}

/*
@summary: Generate master secret
@param secret: secret
@param clientRandom : client random
@param serverRandom : server random
*/
func sessionKeyBlob(secret, random1, random2 []byte) []byte {
	sh1 := saltedHash([]byte("X"), secret, random1, random2)
	sh2 := saltedHash([]byte("YY"), secret, random1, random2)
	sh3 := saltedHash([]byte("ZZZ"), secret, random1, random2)
	ms := bytes.NewBuffer(nil)
	ms.Write(sh1)
	ms.Write(sh2)
	ms.Write(sh3)
	return ms.Bytes()

}
func generateKeys(clientRandom, serverRandom []byte, method uint32) ([]byte, []byte, []byte, error) {
	if len(clientRandom) < 32 || len(serverRandom) < 32 {
		return nil, nil, nil, fmt.Errorf("invalid RDP random length: client=%d server=%d", len(clientRandom), len(serverRandom))
	}

	b := &bytes.Buffer{}
	b.Write(clientRandom[:24])
	b.Write(serverRandom[:24])
	preMasterHash := b.Bytes()
	glog.Debug("preMasterHash:", hex.EncodeToString(preMasterHash))

	masterHash := masterSecret(preMasterHash, clientRandom, serverRandom)
	glog.Debug("masterHash:", hex.EncodeToString(masterHash))

	sessionKey := sessionKeyBlob(masterHash, clientRandom, serverRandom)
	glog.Debug("sessionKey:", hex.EncodeToString(sessionKey))

	macKey128 := sessionKey[:16]
	initialFirstKey128 := finalHash(sessionKey[16:32], clientRandom, serverRandom)
	initialSecondKey128 := finalHash(sessionKey[32:48], clientRandom, serverRandom)

	glog.Debug("macKey128:", hex.EncodeToString(macKey128))
	glog.Debug("FirstKey128:", hex.EncodeToString(initialFirstKey128))
	glog.Debug("SecondKey128:", hex.EncodeToString(initialSecondKey128))
	//generate valid key
	if method == gcc.ENCRYPTION_FLAG_40BIT {
		return gen40bits(macKey128), gen40bits(initialFirstKey128), gen40bits(initialSecondKey128), nil
	} else if method == gcc.ENCRYPTION_FLAG_56BIT {
		return gen56bits(macKey128), gen56bits(initialFirstKey128), gen56bits(initialSecondKey128), nil
	}
	// method == gcc.ENCRYPTION_FLAG_128BIT
	return macKey128, initialFirstKey128, initialSecondKey128, nil

}

type ClientSecurityExchangePDU struct {
	Length                uint32 `struc:"little"`
	EncryptedClientRandom []byte `struc:"little"`
	Padding               []byte `struc:"[8]byte"`
}

func (e *ClientSecurityExchangePDU) serialize() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt32LE(e.Length, buff)
	core.WriteBytes(e.EncryptedClientRandom, buff)
	core.WriteBytes(e.Padding, buff)

	return buff.Bytes()
}
func (c *Client) sendClientRandom() bool {
	glog.Debug("send Client Random")

	clientRandom := core.Random(32)
	glog.Debug("clientRandom:", hex.EncodeToString(clientRandom))

	serverRandom := c.ServerSecurityData().ServerRandom
	glog.Debug("ServerRandom:", hex.EncodeToString(serverRandom))

	var err error
	c.macKey, c.initialDecrytKey, c.initialEncryptKey, err = generateKeys(clientRandom,
		serverRandom, c.ServerSecurityData().EncryptionMethod)
	if err != nil {
		glog.Error("generateKeys failed:", err)
		c.Emit("error", err)
		return false
	}

	//initialize keys
	c.currentDecrytKey = c.initialDecrytKey
	c.currentEncryptKey = c.initialEncryptKey

	//verify certificate
	if !c.ServerSecurityData().ServerCertificate.CertData.Verify() {
		glog.Warn("Cannot verify server identity")
	}

	serverPubKey, err := c.ServerSecurityData().ServerCertificate.CertData.GetPublicKey()
	if err != nil || serverPubKey == nil {
		glog.Error("GetPublicKey failed:", err)
		c.Emit("error", errors.New("failed to get server public key"))
		return false
	}
	ret, err := rsa.EncryptPKCS1v15(rand.Reader, serverPubKey, core.Reverse(clientRandom))
	if err != nil {
		glog.Error("EncryptPKCS1v15 err:", err)
		c.Emit("error", err)
		return false
	}
	message := ClientSecurityExchangePDU{}
	message.EncryptedClientRandom = core.Reverse(ret)
	message.Length = uint32(len(message.EncryptedClientRandom) + 8)
	message.Padding = make([]byte, 8)

	glog.Debug("message:", message)

	c.sendFlagged(EXCHANGE_PKT, message.serialize())
	return true
}
func (c *Client) sendInfoPkt() {
	var secFlag uint16 = INFO_PKT
	if c.enableEncryption {
		secFlag |= ENCRYPT
	}

	glog.Debug("RdpVersion:", c.ClientCoreData().RdpVersion, ":", gcc.RDP_VERSION_5_PLUS)
	c.sendFlagged(secFlag, c.info.Serialize(c.ClientCoreData().RdpVersion == gcc.RDP_VERSION_5_PLUS))
}

func (c *Client) recvLicenceInfo(channel string, s []byte) {
	glog.Debug("sec recvLicenceInfo", hex.EncodeToString(s))
	r := bytes.NewReader(s)
	h := readSecurityHeader(r)
	if (h.securityFlag & LICENSE_PKT) == 0 {
		c.Emit("error", errors.New("NODE_RDP_PROTOCOL_PDU_SEC_BAD_LICENSE_HEADER"))
		return
	}

	p := lic.ReadLicensePacket(r)
	switch p.BMsgtype {
	case lic.NEW_LICENSE:
		glog.Info("sec NEW_LICENSE")
		c.Emit("success")
		goto connect
	case lic.ERROR_ALERT:
		message := p.LicensingMessage.(*lic.ErrorMessage)
		glog.Info("sec ERROR_ALERT and ErrorCode:", message.DwErrorCode)
		if message.DwErrorCode == lic.STATUS_VALID_CLIENT && message.DwStateTransaction == lic.ST_NO_TRANSITION {
			goto connect
		}
		goto retry
	case lic.LICENSE_REQUEST:
		glog.Info("sec LICENSE_REQUEST")
		c.sendClientNewLicenseRequest(p.LicensingMessage.([]byte))
		goto retry
	case lic.PLATFORM_CHALLENGE:
		glog.Info("sec PLATFORM_CHALLENGE")
		c.sendClientChallengeResponse(p.LicensingMessage.([]byte))
		goto retry
	default:
		glog.Error("Not a valid license packet")
		c.Emit("error", errors.New("Not a valid license packet"))
		return
	}

connect:
	c.transport.On("sec", c.recvData)
	c.Emit("connect", c.clientData[0].(*gcc.ClientCoreData), c.userId, c.channelId)
	return

retry:
	c.transport.Once("sec", c.recvLicenceInfo)
	return
}

func (c *Client) sendClientNewLicenseRequest(data []byte) {
	var req lic.ServerLicenseRequest
	struc.Unpack(bytes.NewReader(data), &req)

	var sc gcc.ServerCertificate
	if c.ServerSecurityData().ServerCertificate.DwVersion != 0 {
		sc = c.ServerSecurityData().ServerCertificate
	} else {
		rd := bytes.NewReader(req.ServerCertificate.BlobData)
		err := sc.Unpack(rd)
		if err != nil {
			glog.Error("read serverCertificate err:", err)
			return
		}
	}

	serverRandom := req.ServerRandom
	clientRandom := core.Random(32)
	preMasterSecret := core.Random(48)
	masSecret := masterSecret(preMasterSecret, clientRandom, serverRandom)
	sessionKeyBlob := masterSecret(masSecret, serverRandom, clientRandom)
	//c.macKey = sessionKeyBlob[:16]
	c.macSalt = sessionKeyBlob[:16]
	c.initialDecrytKey = finalHash(sessionKeyBlob[16:32], clientRandom, serverRandom)

	//format message
	message := &lic.ClientNewLicenseRequest{}
	message.PreferredKeyExchangeAlg = 0x00000001
	message.PlatformId = 0x04000000 | 0x00010000
	message.ClientRandom = clientRandom

	buff := &bytes.Buffer{}

	serverPubKey, err := sc.CertData.GetPublicKey()
	if err != nil {
		glog.Error("GetPublicKey failed:", err)
		return
	}
	ret, err := rsa.EncryptPKCS1v15(rand.Reader, serverPubKey, core.Reverse(preMasterSecret))
	if err != nil {
		glog.Error("EncryptPKCS1v15 failed:", err)
		return
	}

	buff.Write(core.Reverse(ret))
	buff.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	message.EncryptedPreMasterSecret.BlobData = buff.Bytes()
	message.EncryptedPreMasterSecret.WBlobLen = uint16(buff.Len())
	message.EncryptedPreMasterSecret.WBlobType = lic.BB_RANDOM_BLOB

	buff.Reset()
	buff.Write(c.info.UserName)
	buff.Write([]byte{0x00})
	message.ClientUserName.BlobData = buff.Bytes()
	message.ClientUserName.WBlobLen = uint16(buff.Len())
	message.ClientUserName.WBlobType = lic.BB_CLIENT_USER_NAME_BLOB

	buff.Reset()
	buff.Write(c.ClientCoreData().ClientName[:])
	buff.Write([]byte{0x00})
	message.ClientMachineName.BlobData = buff.Bytes()
	message.ClientMachineName.WBlobLen = uint16(buff.Len())
	message.ClientMachineName.WBlobType = lic.BB_CLIENT_MACHINE_NAME_BLOB

	buff.Reset()
	err = struc.Pack(buff, message)
	if err != nil {
		glog.Error("err:", err)
	}

	c.sendFlagged(LICENSE_PKT, buff.Bytes())
}

func (c *Client) sendClientChallengeResponse(data []byte) {
	var pc lic.ServerPlatformChallenge
	struc.Unpack(bytes.NewReader(data), &pc)

	serverEncryptedChallenge := pc.EncryptedPlatformChallenge.BlobData
	//decrypt server challenge
	//it should be TEST word in unicode format
	rc, _ := rc4.NewCipher(c.initialDecrytKey)
	serverChallenge := make([]byte, 20)
	rc.XORKeyStream(serverChallenge, serverEncryptedChallenge)
	//if serverChallenge != "T\x00E\x00S\x00T\x00\x00\x00":
	//raise InvalidExpectedDataException("bad license server challenge")

	//generate hwid
	b := &bytes.Buffer{}
	b.Write(c.ClientCoreData().ClientName[:])
	b.Write(c.info.UserName)
	for i := 0; i < 2; i++ {
		b.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	hwid := b.Bytes()[:20]

	encryptedHWID := make([]byte, 20)
	rc.XORKeyStream(encryptedHWID, hwid)

	b.Reset()
	b.Write(serverChallenge)
	b.Write(hwid)

	message := &lic.ClientPLatformChallengeResponse{}
	message.EncryptedPlatformChallengeResponse.BlobData = serverEncryptedChallenge
	message.EncryptedHWID.BlobData = encryptedHWID
	//message.MACData = macData(c.macKey, b.Bytes())[:16]
	message.MACData = macData(c.macSalt, b.Bytes())[:16]

	b.Reset()
	struc.Pack(b, message)
	c.sendFlagged(LICENSE_PKT, b.Bytes())
}

func (c *Client) recvData(channel string, s []byte) {
	glog.Trace("sec recvData", hex.EncodeToString(s))
	glog.Debugf("channel<%s> data len: %d", channel, len(s))
	data := c.decrytData(s)
	if channel != t125.GLOBAL_CHANNEL_NAME {
		c.Emit("channel", channel, data)
		return
	}
	c.Emit("data", data)
}
func (c *Client) SetFastPathListener(f core.FastPathListener) {
	c.fastPathListener = f
}

func (c *Client) RecvFastPath(secFlag byte, s []byte) {
	data := s
	if c.enableEncryption && secFlag&FASTPATH_OUTPUT_ENCRYPTED != 0 {
		data = c.readEncryptedPayload(s, secFlag&FASTPATH_OUTPUT_SECURE_CHECKSUM != 0)
	}
	c.fastPathListener.RecvFastPath(secFlag, data)
}

func (c *Client) SetChannelSender(f core.ChannelSender) {
	c.channelSender = f
}

func (c *Client) SendToChannel(channel string, b []byte) (int, error) {
	if !c.enableEncryption {
		glog.Debug("Sec Client write", hex.EncodeToString(b))
		return c.channelSender.SendToChannel(channel, b)
	}
	var flag uint16 = ENCRYPT
	if c.enableSecureCheckSum {
		flag |= SECURE_CHECKSUM
	}
	data := c.writeEncryptedPayload(b, c.enableSecureCheckSum)

	buff := &bytes.Buffer{}
	core.WriteUInt16LE(flag, buff)
	core.WriteUInt16LE(0, buff)
	core.WriteBytes(data, buff)
	glog.Debug("Sec Client write", channel, hex.EncodeToString(buff.Bytes()))
	return c.channelSender.SendToChannel(channel, buff.Bytes())
}
