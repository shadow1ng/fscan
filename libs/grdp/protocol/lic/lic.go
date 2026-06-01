package lic

import (
	"io"

	"github.com/shadow1ng/fscan/libs/grdp/core"
)

const (
	LICENSE_REQUEST             = 0x01
	PLATFORM_CHALLENGE          = 0x02
	NEW_LICENSE                 = 0x03
	UPGRADE_LICENSE             = 0x04
	LICENSE_INFO                = 0x12
	NEW_LICENSE_REQUEST         = 0x13
	PLATFORM_CHALLENGE_RESPONSE = 0x15
	ERROR_ALERT                 = 0xFF
)

// error code
const (
	ERR_INVALID_SERVER_CERTIFICATE = 0x00000001
	ERR_NO_LICENSE                 = 0x00000002
	ERR_INVALID_SCOPE              = 0x00000004
	ERR_NO_LICENSE_SERVER          = 0x00000006
	STATUS_VALID_CLIENT            = 0x00000007
	ERR_INVALID_CLIENT             = 0x00000008
	ERR_INVALID_PRODUCTID          = 0x0000000B
	ERR_INVALID_MESSAGE_LEN        = 0x0000000C
	ERR_INVALID_MAC                = 0x00000003
)

// state transition
const (
	ST_TOTAL_ABORT          = 0x00000001
	ST_NO_TRANSITION        = 0x00000002
	ST_RESET_PHASE_TO_START = 0x00000003
	ST_RESEND_LAST_MESSAGE  = 0x00000004
)

/*
"""
@summary: Binary blob data type
@see: http://msdn.microsoft.com/en-us/library/cc240481.aspx
"""
*/
type BinaryBlobType uint16

const (
	BB_ANY_BLOB                 = 0x0000
	BB_DATA_BLOB                = 0x0001
	BB_RANDOM_BLOB              = 0x0002
	BB_CERTIFICATE_BLOB         = 0x0003
	BB_ERROR_BLOB               = 0x0004
	BB_ENCRYPTED_DATA_BLOB      = 0x0009
	BB_KEY_EXCHG_ALG_BLOB       = 0x000D
	BB_SCOPE_BLOB               = 0x000E
	BB_CLIENT_USER_NAME_BLOB    = 0x000F
	BB_CLIENT_MACHINE_NAME_BLOB = 0x0010
)

type ErrorMessage struct {
	DwErrorCode        uint32
	DwStateTransaction uint32
	Blob               []byte
}

func readErrorMessage(r io.Reader) *ErrorMessage {
	m := &ErrorMessage{}
	m.DwErrorCode, _ = core.ReadUInt32LE(r)
	m.DwStateTransaction, _ = core.ReadUInt32LE(r)
	return m
}

type LicensePacket struct {
	BMsgtype         uint8
	Flag             uint8
	WMsgSize         uint16
	LicensingMessage interface{}
}

func ReadLicensePacket(r io.Reader) *LicensePacket {
	l := &LicensePacket{}
	l.BMsgtype, _ = core.ReadUInt8(r)
	l.Flag, _ = core.ReadUInt8(r)
	l.WMsgSize, _ = core.ReadUint16LE(r)

	switch l.BMsgtype {
	case ERROR_ALERT:
		l.LicensingMessage = readErrorMessage(r)
	default:
		l.LicensingMessage, _ = core.ReadBytes(int(l.WMsgSize-4), r)
	}

	return l
}

/*
"""
@summary: Blob use by license manager to exchange security data
@see: http://msdn.microsoft.com/en-us/library/cc240481.aspx
"""
*/
type LicenseBinaryBlob struct {
	WBlobType uint16 `struc:"little"`
	WBlobLen  uint16 `struc:"little"`
	BlobData  []byte `struc:"sizefrom=WBlobLen"`
}

func NewLicenseBinaryBlob(WBlobType uint16) *LicenseBinaryBlob {
	return &LicenseBinaryBlob{}
}

/*
"""
@summary: License server product information
@see: http://msdn.microsoft.com/en-us/library/cc241915.aspx
"""
*/
type ProductInformation struct {
	DwVersion     uint32 `struc:"little"`
	CbCompanyName uint32 `struc:"little"`
	//may contain "Microsoft Corporation" from server microsoft
	PbCompanyName []byte `struc:"sizefrom=CbCompanyName"`
	CbProductId   uint32 `struc:"little"`
	//may contain "A02" from microsoft license server
	PbProductId []byte `struc:"sizefrom=CbProductId"`
}

/*
@summary:  Send by server to signal license request

	server -> client

@see: http://msdn.microsoft.com/en-us/library/cc241914.aspx
*/
type ServerLicenseRequest struct {
	ServerRandom      []byte             `struc:"[32]byte"`
	ProductInfo       ProductInformation `struc:"little"`
	KeyExchangeList   LicenseBinaryBlob  `struc:"little"`
	ServerCertificate LicenseBinaryBlob  `struc:"little"`
	//ScopeList         ScopeList
}

/*
@summary:  Send by client to ask new license for client.
            RDPY doesn'support license reuse, need it in futur version
@see: http://msdn.microsoft.com/en-us/library/cc241918.aspx
 	#RSA and must be only RSA
    #pure microsoft client ;-)
    #http://msdn.microsoft.com/en-us/library/1040af38-c733-4fb3-acd1-8db8cc979eda#id10
*/

type ClientNewLicenseRequest struct {
	PreferredKeyExchangeAlg  uint32            `struc:"little"`
	PlatformId               uint32            `struc:"little"`
	ClientRandom             []byte            `struc:"[32]byte"`
	EncryptedPreMasterSecret LicenseBinaryBlob `struc:"little"`
	ClientUserName           LicenseBinaryBlob `struc:"little"`
	ClientMachineName        LicenseBinaryBlob `struc:"little"`
}

/*
@summary: challenge send from server to client
@see: http://msdn.microsoft.com/en-us/library/cc241921.aspx
*/
type ServerPlatformChallenge struct {
	ConnectFlags               uint32
	EncryptedPlatformChallenge LicenseBinaryBlob
	MACData                    [16]byte
}

/*
"""
@summary: client challenge response
@see: http://msdn.microsoft.com/en-us/library/cc241922.aspx
"""
*/
type ClientPLatformChallengeResponse struct {
	EncryptedPlatformChallengeResponse LicenseBinaryBlob
	EncryptedHWID                      LicenseBinaryBlob
	MACData                            []byte //[16]byte
}
