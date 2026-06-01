package pdu

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/shadow1ng/fscan/libs/grdp/glog"

	"github.com/lunixbochs/struc"
	"github.com/shadow1ng/fscan/libs/grdp/core"
	"github.com/shadow1ng/fscan/libs/grdp/protocol/t125/gcc"
)

type CapsType uint16

const (
	CAPSTYPE_GENERAL                 CapsType = 0x0001
	CAPSTYPE_BITMAP                           = 0x0002
	CAPSTYPE_ORDER                            = 0x0003
	CAPSTYPE_BITMAPCACHE                      = 0x0004
	CAPSTYPE_CONTROL                          = 0x0005
	CAPSTYPE_ACTIVATION                       = 0x0007
	CAPSTYPE_POINTER                          = 0x0008
	CAPSTYPE_SHARE                            = 0x0009
	CAPSTYPE_COLORCACHE                       = 0x000A
	CAPSTYPE_SOUND                            = 0x000C
	CAPSTYPE_INPUT                            = 0x000D
	CAPSTYPE_FONT                             = 0x000E
	CAPSTYPE_BRUSH                            = 0x000F
	CAPSTYPE_GLYPHCACHE                       = 0x0010
	CAPSTYPE_OFFSCREENCACHE                   = 0x0011
	CAPSTYPE_BITMAPCACHE_HOSTSUPPORT          = 0x0012
	CAPSTYPE_BITMAPCACHE_REV2                 = 0x0013
	CAPSTYPE_VIRTUALCHANNEL                   = 0x0014
	CAPSTYPE_DRAWNINEGRIDCACHE                = 0x0015
	CAPSTYPE_DRAWGDIPLUS                      = 0x0016
	CAPSTYPE_RAIL                             = 0x0017
	CAPSTYPE_WINDOW                           = 0x0018
	CAPSETTYPE_COMPDESK                       = 0x0019
	CAPSETTYPE_MULTIFRAGMENTUPDATE            = 0x001A
	CAPSETTYPE_LARGE_POINTER                  = 0x001B
	CAPSETTYPE_SURFACE_COMMANDS               = 0x001C
	CAPSETTYPE_BITMAP_CODECS                  = 0x001D
	CAPSSETTYPE_FRAME_ACKNOWLEDGE             = 0x001E
)

func (c CapsType) String() string {
	switch c {
	case CAPSTYPE_GENERAL:
		return "CAPSTYPE_GENERAL"
	case CAPSTYPE_BITMAP:
		return "CAPSTYPE_BITMAP"
	case CAPSTYPE_ORDER:
		return "CAPSTYPE_ORDER"
	case CAPSTYPE_BITMAPCACHE:
		return "CAPSTYPE_BITMAPCACHE"
	case CAPSTYPE_CONTROL:
		return "CAPSTYPE_CONTROL"
	case CAPSTYPE_ACTIVATION:
		return "CAPSTYPE_ACTIVATION"
	case CAPSTYPE_POINTER:
		return "CAPSTYPE_POINTER"
	case CAPSTYPE_SHARE:
		return "CAPSTYPE_SHARE"
	case CAPSTYPE_COLORCACHE:
		return "CAPSTYPE_COLORCACHE"
	case CAPSTYPE_SOUND:
		return "CAPSTYPE_SOUND"
	case CAPSTYPE_INPUT:
		return "CAPSTYPE_INPUT"
	case CAPSTYPE_FONT:
		return "CAPSTYPE_FONT"
	case CAPSTYPE_BRUSH:
		return "CAPSTYPE_BRUSH"
	case CAPSTYPE_GLYPHCACHE:
		return "CAPSTYPE_GLYPHCACHE"
	case CAPSTYPE_OFFSCREENCACHE:
		return "CAPSTYPE_OFFSCREENCACHE"
	case CAPSTYPE_BITMAPCACHE_HOSTSUPPORT:
		return "CAPSTYPE_BITMAPCACHE_HOSTSUPPORT"
	case CAPSTYPE_BITMAPCACHE_REV2:
		return "CAPSTYPE_BITMAPCACHE_REV2"
	case CAPSTYPE_VIRTUALCHANNEL:
		return "CAPSTYPE_VIRTUALCHANNEL"
	case CAPSTYPE_DRAWNINEGRIDCACHE:
		return "CAPSTYPE_DRAWNINEGRIDCACHE"
	case CAPSTYPE_DRAWGDIPLUS:
		return "CAPSTYPE_DRAWGDIPLUS"
	case CAPSTYPE_RAIL:
		return "CAPSTYPE_RAIL"
	case CAPSTYPE_WINDOW:
		return "CAPSTYPE_WINDOW"
	case CAPSETTYPE_COMPDESK:
		return "CAPSETTYPE_COMPDESK"
	case CAPSETTYPE_MULTIFRAGMENTUPDATE:
		return "CAPSETTYPE_MULTIFRAGMENTUPDATE"
	case CAPSETTYPE_LARGE_POINTER:
		return "CAPSETTYPE_LARGE_POINTER"
	case CAPSETTYPE_SURFACE_COMMANDS:
		return "CAPSETTYPE_SURFACE_COMMANDS"
	case CAPSETTYPE_BITMAP_CODECS:
		return "CAPSETTYPE_BITMAP_CODECS"
	case CAPSSETTYPE_FRAME_ACKNOWLEDGE:
		return "CAPSSETTYPE_FRAME_ACKNOWLEDGE"
	}

	return "Unknown"
}

type MajorType uint16

const (
	OSMAJORTYPE_UNSPECIFIED MajorType = 0x0000
	OSMAJORTYPE_WINDOWS               = 0x0001
	OSMAJORTYPE_OS2                   = 0x0002
	OSMAJORTYPE_MACINTOSH             = 0x0003
	OSMAJORTYPE_UNIX                  = 0x0004
	OSMAJORTYPE_IOS                   = 0x0005
	OSMAJORTYPE_OSX                   = 0x0006
	OSMAJORTYPE_ANDROID               = 0x0007
)

type MinorType uint16

const (
	OSMINORTYPE_UNSPECIFIED    MinorType = 0x0000
	OSMINORTYPE_WINDOWS_31X              = 0x0001
	OSMINORTYPE_WINDOWS_95               = 0x0002
	OSMINORTYPE_WINDOWS_NT               = 0x0003
	OSMINORTYPE_OS2_V21                  = 0x0004
	OSMINORTYPE_POWER_PC                 = 0x0005
	OSMINORTYPE_MACINTOSH                = 0x0006
	OSMINORTYPE_NATIVE_XSERVER           = 0x0007
	OSMINORTYPE_PSEUDO_XSERVER           = 0x0008
	OSMINORTYPE_WINDOWS_RT               = 0x0009
)

const (
	FASTPATH_OUTPUT_SUPPORTED  uint16 = 0x0001
	NO_BITMAP_COMPRESSION_HDR         = 0x0400
	LONG_CREDENTIALS_SUPPORTED        = 0x0004
	AUTORECONNECT_SUPPORTED           = 0x0008
	ENC_SALTED_CHECKSUM               = 0x0010
)

type OrderFlag uint16

const (
	NEGOTIATEORDERSUPPORT   OrderFlag = 0x0002
	ZEROBOUNDSDELTASSUPPORT           = 0x0008
	COLORINDEXSUPPORT                 = 0x0020
	SOLIDPATTERNBRUSHONLY             = 0x0040
	ORDERFLAGS_EXTRA_FLAGS            = 0x0080
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240556.aspx
 */
type Order uint8

const (
	TS_NEG_DSTBLT_INDEX             Order = 0x00
	TS_NEG_PATBLT_INDEX                   = 0x01
	TS_NEG_SCRBLT_INDEX                   = 0x02
	TS_NEG_MEMBLT_INDEX                   = 0x03
	TS_NEG_MEM3BLT_INDEX                  = 0x04
	TS_NEG_DRAWNINEGRID_INDEX             = 0x07
	TS_NEG_LINETO_INDEX                   = 0x08
	TS_NEG_MULTI_DRAWNINEGRID_INDEX       = 0x09
	TS_NEG_SAVEBITMAP_INDEX               = 0x0B
	TS_NEG_MULTIDSTBLT_INDEX              = 0x0F
	TS_NEG_MULTIPATBLT_INDEX              = 0x10
	TS_NEG_MULTISCRBLT_INDEX              = 0x11
	TS_NEG_MULTIOPAQUERECT_INDEX          = 0x12
	TS_NEG_FAST_INDEX_INDEX               = 0x13
	TS_NEG_POLYGON_SC_INDEX               = 0x14
	TS_NEG_POLYGON_CB_INDEX               = 0x15
	TS_NEG_POLYLINE_INDEX                 = 0x16
	TS_NEG_FAST_GLYPH_INDEX               = 0x18
	TS_NEG_ELLIPSE_SC_INDEX               = 0x19
	TS_NEG_ELLIPSE_CB_INDEX               = 0x1A
	TS_NEG_GLYPH_INDEX_INDEX              = 0x1B
)

type OrderEx uint16

const (
	ORDERFLAGS_EX_CACHE_BITMAP_REV3_SUPPORT   OrderEx = 0x0002
	ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT         = 0x0004
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240563.aspx
 */

const (
	INPUT_FLAG_SCANCODES       uint16 = 0x0001
	INPUT_FLAG_MOUSEX                 = 0x0004
	INPUT_FLAG_FASTPATH_INPUT         = 0x0008
	INPUT_FLAG_UNICODE                = 0x0010
	INPUT_FLAG_FASTPATH_INPUT2        = 0x0020
	INPUT_FLAG_UNUSED1                = 0x0040
	INPUT_FLAG_UNUSED2                = 0x0080
	INPUT_FLAG_MOUSE_HWHEEL           = 0x0100
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240564.aspx
 */
type BrushSupport uint32

const (
	BRUSH_DEFAULT    BrushSupport = 0x00000000
	BRUSH_COLOR_8x8               = 0x00000001
	BRUSH_COLOR_FULL              = 0x00000002
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240565.aspx
 */
type GlyphSupport uint16

const (
	GLYPH_SUPPORT_NONE    GlyphSupport = 0x0000
	GLYPH_SUPPORT_PARTIAL              = 0x0001
	GLYPH_SUPPORT_FULL                 = 0x0002
	GLYPH_SUPPORT_ENCODE               = 0x0003
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240550.aspx
 */
type OffscreenSupportLevel uint32

const (
	OSL_FALSE OffscreenSupportLevel = 0x00000000
	OSL_TRUE                        = 0x00000001
)

/**
 * @see http://msdn.microsoft.com/en-us/library/cc240551.aspx
 */
type VirtualChannelCompressionFlag uint32

const (
	VCCAPS_NO_COMPR    VirtualChannelCompressionFlag = 0x00000000
	VCCAPS_COMPR_SC                                  = 0x00000001
	VCCAPS_COMPR_CS_8K                               = 0x00000002
)

type SoundFlag uint16

const (
	SOUND_NONE       SoundFlag = 0x0000
	SOUND_BEEPS_FLAG           = 0x0001
)

type RailsupportLevel uint32

const (
	RAIL_LEVEL_SUPPORTED                           = 0x00000001
	RAIL_LEVEL_DOCKED_LANGBAR_SUPPORTED            = 0x00000002
	RAIL_LEVEL_SHELL_INTEGRATION_SUPPORTED         = 0x00000004
	RAIL_LEVEL_LANGUAGE_IME_SYNC_SUPPORTED         = 0x00000008
	RAIL_LEVEL_SERVER_TO_CLIENT_IME_SYNC_SUPPORTED = 0x00000010
	RAIL_LEVEL_HIDE_MINIMIZED_APPS_SUPPORTED       = 0x00000020
	RAIL_LEVEL_WINDOW_CLOAKING_SUPPORTED           = 0x00000040
	RAIL_LEVEL_HANDSHAKE_EX_SUPPORTED              = 0x00000080
)

const (
	INPUT_EVENT_SYNC     = 0x0000
	INPUT_EVENT_UNUSED   = 0x0002
	INPUT_EVENT_SCANCODE = 0x0004
	INPUT_EVENT_UNICODE  = 0x0005
	INPUT_EVENT_MOUSE    = 0x8001
	INPUT_EVENT_MOUSEX   = 0x8002
)

const (
	PTRFLAGS_HWHEEL         = 0x0400
	PTRFLAGS_WHEEL          = 0x0200
	PTRFLAGS_WHEEL_NEGATIVE = 0x0100
	WheelRotationMask       = 0x01FF
	PTRFLAGS_MOVE           = 0x0800
	PTRFLAGS_DOWN           = 0x8000
	PTRFLAGS_BUTTON1        = 0x1000
	PTRFLAGS_BUTTON2        = 0x2000
	PTRFLAGS_BUTTON3        = 0x4000
)

const (
	KBDFLAGS_EXTENDED = 0x0100
	KBDFLAGS_DOWN     = 0x4000
	KBDFLAGS_RELEASE  = 0x8000
)

type SurfaceCmdFlags uint32

const (
	SURFCMDS_SET_SURFACE_BITS    = 0x00000002
	SURFCMDS_FRAME_MARKER        = 0x00000010
	SURFCMDS_STREAM_SURFACE_BITS = 0x00000040
)

type Capability interface {
	Type() CapsType
}

type GeneralCapability struct {
	// 010018000100030000020000000015040000000000000000
	OSMajorType             MajorType `struc:"little"`
	OSMinorType             MinorType `struc:"little"`
	ProtocolVersion         uint16    `struc:"little"`
	Pad2octetsA             uint16    `struc:"little"`
	GeneralCompressionTypes uint16    `struc:"little"`
	ExtraFlags              uint16    `struc:"little"`
	UpdateCapabilityFlag    uint16    `struc:"little"`
	RemoteUnshareFlag       uint16    `struc:"little"`
	GeneralCompressionLevel uint16    `struc:"little"`
	RefreshRectSupport      uint8     `struc:"little"`
	SuppressOutputSupport   uint8     `struc:"little"`
}

func (*GeneralCapability) Type() CapsType {
	return CAPSTYPE_GENERAL
}

type BitmapCapability struct {
	// 02001c00180001000100010000052003000000000100000001000000
	PreferredBitsPerPixel    gcc.HighColor `struc:"little"`
	Receive1BitPerPixel      uint16        `struc:"little"`
	Receive4BitsPerPixel     uint16        `struc:"little"`
	Receive8BitsPerPixel     uint16        `struc:"little"`
	DesktopWidth             uint16        `struc:"little"`
	DesktopHeight            uint16        `struc:"little"`
	Pad2octets               uint16        `struc:"little"`
	DesktopResizeFlag        uint16        `struc:"little"`
	BitmapCompressionFlag    uint16        `struc:"little"`
	HighColorFlags           uint8         `struc:"little"`
	DrawingFlags             uint8         `struc:"little"`
	MultipleRectangleSupport uint16        `struc:"little"`
	Pad2octetsB              uint16        `struc:"little"`
}

func (*BitmapCapability) Type() CapsType {
	return CAPSTYPE_BITMAP
}

type BitmapCacheCapability struct {
	// 04002800000000000000000000000000000000000000000000000000000000000000000000000000
	Pad1                  uint32 `struc:"little"`
	Pad2                  uint32 `struc:"little"`
	Pad3                  uint32 `struc:"little"`
	Pad4                  uint32 `struc:"little"`
	Pad5                  uint32 `struc:"little"`
	Pad6                  uint32 `struc:"little"`
	Cache0Entries         uint16 `struc:"little"`
	Cache0MaximumCellSize uint16 `struc:"little"`
	Cache1Entries         uint16 `struc:"little"`
	Cache1MaximumCellSize uint16 `struc:"little"`
	Cache2Entries         uint16 `struc:"little"`
	Cache2MaximumCellSize uint16 `struc:"little"`
}

func (*BitmapCacheCapability) Type() CapsType {
	return CAPSTYPE_BITMAPCACHE
}

type OrderCapability struct {
	// 030058000000000000000000000000000000000000000000010014000000010000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000008403000000000000000000
	TerminalDescriptor      [16]byte
	Pad4octetsA             uint32    `struc:"little"`
	DesktopSaveXGranularity uint16    `struc:"little"`
	DesktopSaveYGranularity uint16    `struc:"little"`
	Pad2octetsA             uint16    `struc:"little"`
	MaximumOrderLevel       uint16    `struc:"little"`
	NumberFonts             uint16    `struc:"little"`
	OrderFlags              OrderFlag `struc:"little"`
	OrderSupport            [32]byte
	TextFlags               uint16 `struc:"little"`
	OrderSupportExFlags     uint16 `struc:"little"`
	Pad4octetsB             uint32 `struc:"little"`
	DesktopSaveSize         uint32 `struc:"little"`
	Pad2octetsC             uint16 `struc:"little"`
	Pad2octetsD             uint16 `struc:"little"`
	TextANSICodePage        uint16 `struc:"little"`
	Pad2octetsE             uint16 `struc:"little"`
}

func (*OrderCapability) Type() CapsType {
	return CAPSTYPE_ORDER
}

type PointerCapability struct {
	ColorPointerFlag      uint16 `struc:"little"`
	ColorPointerCacheSize uint16 `struc:"little"`
	// old version of rdp doesn't support ...
	PointerCacheSize uint16 `struc:"little"` // only server need
}

func (*PointerCapability) Type() CapsType {
	return CAPSTYPE_POINTER
}

type InputCapability struct {
	// 0d005c001500000009040000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000
	Flags       uint16 `struc:"little"`
	Pad2octetsA uint16 `struc:"little"`
	// same value as gcc.ClientCoreSettings.kbdLayout
	KeyboardLayout gcc.KeyboardLayout `struc:"little"`
	// same value as gcc.ClientCoreSettings.keyboardType
	KeyboardType uint32 `struc:"little"`
	// same value as gcc.ClientCoreSettings.keyboardSubType
	KeyboardSubType uint32 `struc:"little"`
	// same value as gcc.ClientCoreSettings.keyboardFnKeys
	KeyboardFunctionKey uint32 `struc:"little"`
	// same value as gcc.ClientCoreSettingrrs.imeFileName
	ImeFileName [64]byte
	//need add 0c000000 in the end
}

func (*InputCapability) Type() CapsType {
	return CAPSTYPE_INPUT
}

type BrushCapability struct {
	// 0f00080000000000
	SupportLevel BrushSupport `struc:"little"`
}

func (*BrushCapability) Type() CapsType {
	return CAPSTYPE_BRUSH
}

type cacheEntry struct {
	Entries         uint16 `struc:"little"`
	MaximumCellSize uint16 `struc:"little"`
}

type GlyphCapability struct {
	// 10003400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	GlyphCache   [10]cacheEntry `struc:"little"`
	FragCache    uint32         `struc:"little"`
	SupportLevel GlyphSupport   `struc:"little"`
	Pad2octets   uint16         `struc:"little"`
}

func (*GlyphCapability) Type() CapsType {
	return CAPSTYPE_GLYPHCACHE
}

type OffscreenBitmapCacheCapability struct {
	// 11000c000000000000000000
	SupportLevel OffscreenSupportLevel `struc:"little"`
	CacheSize    uint16                `struc:"little"`
	CacheEntries uint16                `struc:"little"`
}

func (*OffscreenBitmapCacheCapability) Type() CapsType {
	return CAPSTYPE_OFFSCREENCACHE
}

type BitmapCache2Capability struct {
	BitmapCachePersist uint16   `struc:"little"`
	Pad2octets         uint8    `struc:"little"`
	CachesNum          uint8    `struc:"little"`
	BmpC0Cells         uint32   `struc:"little"`
	BmpC1Cells         uint32   `struc:"little"`
	BmpC2Cells         uint32   `struc:"little"`
	BmpC3Cells         uint32   `struc:"little"`
	BmpC4Cells         uint32   `struc:"little"`
	Pad2octets1        [12]byte `struc:"little"`
}

func (*BitmapCache2Capability) Type() CapsType {
	return CAPSTYPE_BITMAPCACHE_REV2
}

type VirtualChannelCapability struct {
	// 14000c000000000000000000
	Flags       VirtualChannelCompressionFlag `struc:"little"`
	VCChunkSize uint32                        `struc:"little"` // optional
}

func (*VirtualChannelCapability) Type() CapsType {
	return CAPSTYPE_VIRTUALCHANNEL
}

type SoundCapability struct {
	// 0c00080000000000
	Flags      SoundFlag `struc:"little"`
	Pad2octets uint16    `struc:"little"`
}

func (*SoundCapability) Type() CapsType {
	return CAPSTYPE_SOUND
}

type ControlCapability struct {
	ControlFlags     uint16 `struc:"little"`
	RemoteDetachFlag uint16 `struc:"little"`
	ControlInterest  uint16 `struc:"little"`
	DetachInterest   uint16 `struc:"little"`
}

func (*ControlCapability) Type() CapsType {
	return CAPSTYPE_CONTROL
}

type WindowActivationCapability struct {
	HelpKeyFlag          uint16 `struc:"little"`
	HelpKeyIndexFlag     uint16 `struc:"little"`
	HelpExtendedKeyFlag  uint16 `struc:"little"`
	WindowManagerKeyFlag uint16 `struc:"little"`
}

func (*WindowActivationCapability) Type() CapsType {
	return CAPSTYPE_ACTIVATION
}

type FontCapability struct {
	SupportFlags uint16 `struc:"little"`
	Pad2octets   uint16 `struc:"little"`
}

func (*FontCapability) Type() CapsType {
	return CAPSTYPE_FONT
}

type ColorCacheCapability struct {
	CacheSize  uint16 `struc:"little"`
	Pad2octets uint16 `struc:"little"`
}

func (*ColorCacheCapability) Type() CapsType {
	return CAPSTYPE_COLORCACHE
}

type ShareCapability struct {
	NodeId     uint16 `struc:"little"`
	Pad2octets uint16 `struc:"little"`
}

func (*ShareCapability) Type() CapsType {
	return CAPSTYPE_SHARE
}

type MultiFragmentUpdate struct {
	// 1a00080000000000
	MaxRequestSize uint32 `struc:"little"`
}

func (*MultiFragmentUpdate) Type() CapsType {
	return CAPSETTYPE_MULTIFRAGMENTUPDATE
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/52635737-d144-4f47-9c88-b48ceaf3efb4

type DrawGDIPlusCapability struct {
	SupportLevel             uint32
	GdipVersion              uint32
	CacheLevel               uint32
	GdipCacheEntries         [10]byte
	GdipCacheChunkSize       [8]byte
	GdipImageCacheProperties [6]byte
}

func (*DrawGDIPlusCapability) Type() CapsType {
	return CAPSTYPE_DRAWGDIPLUS
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/86507fed-a0ee-4242-b802-237534a8f65e
type BitmapCodec struct {
	GUID             [16]byte
	ID               uint8
	PropertiesLength uint16 `struc:"little,sizeof=Properties"`
	Properties       []byte
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/408b1878-9f6e-4106-8329-1af42219ba6a
type BitmapCodecS struct {
	Count uint8 `struc:"sizeof=Array"`
	Array []BitmapCodec
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/17e80f50-d163-49de-a23b-fd6456aa472f
type BitmapCodecsCapability struct {
	SupportedBitmapCodecs BitmapCodecS // A variable-length field containing a TS_BITMAPCODECS structure (section 2.2.7.2.10.1).
}

func (*BitmapCodecsCapability) Type() CapsType {
	return CAPSETTYPE_BITMAP_CODECS
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/fc05c385-46c3-42cb-9ed2-c475a3990e0b
type BitmapCacheHostSupportCapability struct {
	CacheVersion uint8
	Pad1         uint8
	Pad2         uint16
}

func (*BitmapCacheHostSupportCapability) Type() CapsType {
	return CAPSTYPE_BITMAPCACHE_HOSTSUPPORT
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/41323437-c753-460e-8108-495a6fdd68a8
type LargePointerCapability struct {
	SupportFlags uint16 `struc:"little"`
}

func (*LargePointerCapability) Type() CapsType {
	return CAPSETTYPE_LARGE_POINTER
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdperp/36a25e21-25e1-4954-aae8-09aaf6715c79
type RemoteProgramsCapability struct {
	RailSupportLevel uint32 `struc:"little"`
}

func (*RemoteProgramsCapability) Type() CapsType {
	return CAPSTYPE_RAIL
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdperp/82ec7a69-f7e3-4294-830d-666178b35d15
type WindowListCapability struct {
	WndSupportLevel     uint32 `struc:"little"`
	NumIconCaches       uint8
	NumIconCacheEntries uint16 `struc:"little"`
}

func (*WindowListCapability) Type() CapsType {
	return CAPSTYPE_WINDOW
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9132002f-f133-4a0f-ba2f-2dc48f1e7f93
type DesktopCompositionCapability struct {
	CompDeskSupportLevel uint16 `struc:"little"`
}

func (*DesktopCompositionCapability) Type() CapsType {
	return CAPSETTYPE_COMPDESK
}

// see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/aa953018-c0a8-4761-bb12-86586c2cd56a
type SurfaceCommandsCapability struct {
	CmdFlags uint32 `struc:"little"`
	Reserved uint32 `struc:"little"`
}

func (*SurfaceCommandsCapability) Type() CapsType {
	return CAPSETTYPE_SURFACE_COMMANDS
}

type FrameAcknowledgeCapability struct {
	FrameCount uint32 `struc:"little"`
}

func (*FrameAcknowledgeCapability) Type() CapsType {
	return CAPSSETTYPE_FRAME_ACKNOWLEDGE
}

type DrawNineGridCapability struct {
	SupportLevel uint32 `struc:"little"`
	CacheSize    uint16 `struc:"little"`
	CacheEntries uint16 `struc:"little"`
}

func (*DrawNineGridCapability) Type() CapsType {
	return CAPSTYPE_DRAWNINEGRIDCACHE
}

func readCapability(r io.Reader) (Capability, error) {
	capType, err := core.ReadUint16LE(r)
	if err != nil {
		return nil, err
	}
	capLen, err := core.ReadUint16LE(r)
	if err != nil {
		return nil, err
	}
	if int(capLen)-4 <= 0 {
		return nil, errors.New(fmt.Sprintf("Capability length expected %d", capLen))
	}

	capBytes, err := core.ReadBytes(int(capLen)-4, r)
	if err != nil {
		return nil, err
	}
	capReader := bytes.NewReader(capBytes)
	var c Capability
	glog.Debugf("Capability type 0x%04x", capType)
	switch CapsType(capType) {
	case CAPSTYPE_GENERAL:
		c = &GeneralCapability{}
	case CAPSTYPE_BITMAP:
		c = &BitmapCapability{}
	case CAPSTYPE_ORDER:
		c = &OrderCapability{}
	case CAPSTYPE_BITMAPCACHE:
		c = &BitmapCacheCapability{}
	case CAPSTYPE_POINTER:
		c = &PointerCapability{}
	case CAPSTYPE_INPUT:
		c = &InputCapability{}
	case CAPSTYPE_BRUSH:
		c = &BrushCapability{}
	case CAPSTYPE_GLYPHCACHE:
		c = &GlyphCapability{}
	case CAPSTYPE_OFFSCREENCACHE:
		c = &OffscreenBitmapCacheCapability{}
	case CAPSTYPE_VIRTUALCHANNEL:
		c = &VirtualChannelCapability{}
	case CAPSTYPE_SOUND:
		c = &SoundCapability{}
	case CAPSTYPE_CONTROL:
		c = &ControlCapability{}
	case CAPSTYPE_ACTIVATION:
		c = &WindowActivationCapability{}
	case CAPSTYPE_FONT:
		c = &FontCapability{}
	case CAPSTYPE_COLORCACHE:
		c = &ColorCacheCapability{}
	case CAPSTYPE_SHARE:
		c = &ShareCapability{}
	case CAPSETTYPE_MULTIFRAGMENTUPDATE:
		c = &MultiFragmentUpdate{}
	case CAPSTYPE_DRAWGDIPLUS:
		c = &DrawGDIPlusCapability{}
	case CAPSETTYPE_BITMAP_CODECS:
		c = &BitmapCodecsCapability{}
	case CAPSTYPE_BITMAPCACHE_HOSTSUPPORT:
		c = &BitmapCacheHostSupportCapability{}
	case CAPSETTYPE_LARGE_POINTER:
		c = &LargePointerCapability{}
	case CAPSTYPE_RAIL:
		c = &RemoteProgramsCapability{}
	case CAPSTYPE_WINDOW:
		c = &WindowListCapability{}
	case CAPSETTYPE_COMPDESK:
		c = &DesktopCompositionCapability{}
	case CAPSETTYPE_SURFACE_COMMANDS:
		c = &SurfaceCommandsCapability{}
	case CAPSSETTYPE_FRAME_ACKNOWLEDGE:
		c = &FrameAcknowledgeCapability{}
	default:
		err := errors.New(fmt.Sprintf("unsupported Capability type 0x%04x", capType))
		glog.Error(err)
		return nil, err
	}
	if err := struc.Unpack(capReader, c); err != nil {
		glog.Error("Capability unpack error", err, fmt.Sprintf("0x%04x", capType), hex.EncodeToString(capBytes))
		return nil, err
	}
	glog.Debugf("Capability<%s>: %+v", c.Type(), c)
	return c, nil
}
