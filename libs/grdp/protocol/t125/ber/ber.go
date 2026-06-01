package ber

import (
	"errors"
	"fmt"
	"io"

	"github.com/shadow1ng/fscan/libs/grdp/core"
)

const (
	CLASS_MASK uint8 = 0xC0
	CLASS_UNIV       = 0x00
	CLASS_APPL       = 0x40
	CLASS_CTXT       = 0x80
	CLASS_PRIV       = 0xC0
)

const (
	PC_MASK      uint8 = 0x20
	PC_PRIMITIVE       = 0x00
	PC_CONSTRUCT       = 0x20
)

const (
	TAG_MASK            uint8 = 0x1F
	TAG_BOOLEAN               = 0x01
	TAG_INTEGER               = 0x02
	TAG_BIT_STRING            = 0x03
	TAG_OCTET_STRING          = 0x04
	TAG_OBJECT_IDENFIER       = 0x06
	TAG_ENUMERATED            = 0x0A
	TAG_SEQUENCE              = 0x10
	TAG_SEQUENCE_OF           = 0x10
)

func berPC(pc bool) uint8 {
	if pc {
		return PC_CONSTRUCT
	}
	return PC_PRIMITIVE
}

func ReadEnumerated(r io.Reader) (uint8, error) {
	if !ReadUniversalTag(TAG_ENUMERATED, false, r) {
		return 0, errors.New("invalid ber tag")
	}
	length, err := ReadLength(r)
	if err != nil {
		return 0, err
	}
	if length != 1 {
		return 0, errors.New(fmt.Sprintf("enumerate size is wrong, get %v, expect 1", length))
	}
	return core.ReadUInt8(r)
}

func ReadUniversalTag(tag uint8, pc bool, r io.Reader) bool {
	bb, _ := core.ReadUInt8(r)
	return bb == (CLASS_UNIV|berPC(pc))|(TAG_MASK&tag)
}

func WriteUniversalTag(tag uint8, pc bool, w io.Writer) {
	core.WriteUInt8((CLASS_UNIV|berPC(pc))|(TAG_MASK&tag), w)
}

func ReadLength(r io.Reader) (int, error) {
	ret := 0
	size, _ := core.ReadUInt8(r)
	if size&0x80 > 0 {
		size = size &^ 0x80
		if size == 1 {
			r, err := core.ReadUInt8(r)
			if err != nil {
				return 0, err
			}
			ret = int(r)
		} else if size == 2 {
			r, err := core.ReadUint16BE(r)
			if err != nil {
				return 0, err
			}
			ret = int(r)
		} else {
			return 0, errors.New("BER length may be 1 or 2")
		}
	} else {
		ret = int(size)
	}
	return ret, nil
}

func WriteLength(size int, w io.Writer) {
	if size > 0x7f {
		core.WriteUInt8(0x82, w)
		core.WriteUInt16BE(uint16(size), w)
	} else {
		core.WriteUInt8(uint8(size), w)
	}
}

func ReadInteger(r io.Reader) (int, error) {
	if !ReadUniversalTag(TAG_INTEGER, false, r) {
		return 0, errors.New("Bad integer tag")
	}
	size, _ := ReadLength(r)
	switch size {
	case 1:
		num, _ := core.ReadUInt8(r)
		return int(num), nil
	case 2:
		num, _ := core.ReadUint16BE(r)
		return int(num), nil
	case 3:
		integer1, _ := core.ReadUInt8(r)
		integer2, _ := core.ReadUint16BE(r)
		return int(integer2) + (int(integer1) << 16), nil
	case 4:
		num, _ := core.ReadUInt32BE(r)
		return int(num), nil
	default:
		return 0, errors.New("wrong size")
	}
}

func WriteInteger(n int, w io.Writer) {
	WriteUniversalTag(TAG_INTEGER, false, w)
	if n <= 0xff {
		WriteLength(1, w)
		core.WriteUInt8(uint8(n), w)
	} else if n <= 0xffff {
		WriteLength(2, w)
		core.WriteUInt16BE(uint16(n), w)
	} else {
		WriteLength(4, w)
		core.WriteUInt32BE(uint32(n), w)
	}
}

func WriteOctetstring(str string, w io.Writer) {
	WriteUniversalTag(TAG_OCTET_STRING, false, w)
	WriteLength(len(str), w)
	core.WriteBytes([]byte(str), w)
}

func WriteBoolean(b bool, w io.Writer) {
	bb := uint8(0)
	if b {
		bb = uint8(0xff)
	}
	WriteUniversalTag(TAG_BOOLEAN, false, w)
	WriteLength(1, w)
	core.WriteUInt8(bb, w)
}

func ReadApplicationTag(tag uint8, r io.Reader) (int, error) {
	bb, _ := core.ReadUInt8(r)
	if tag > 30 {
		if bb != (CLASS_APPL|PC_CONSTRUCT)|TAG_MASK {
			return 0, errors.New("ReadApplicationTag invalid data")
		}
		bb, _ := core.ReadUInt8(r)
		if bb != tag {
			return 0, errors.New("ReadApplicationTag bad tag")
		}
	} else {
		if bb != (CLASS_APPL|PC_CONSTRUCT)|(TAG_MASK&tag) {
			return 0, errors.New("ReadApplicationTag invalid data2")
		}
	}
	return ReadLength(r)
}

func WriteApplicationTag(tag uint8, size int, w io.Writer) {
	if tag > 30 {
		core.WriteUInt8((CLASS_APPL|PC_CONSTRUCT)|TAG_MASK, w)
		core.WriteUInt8(tag, w)
		WriteLength(size, w)
	} else {
		core.WriteUInt8((CLASS_APPL|PC_CONSTRUCT)|(TAG_MASK&tag), w)
		WriteLength(size, w)
	}
}

func WriteEncodedDomainParams(data []byte, w io.Writer) {
	WriteUniversalTag(TAG_SEQUENCE, true, w)
	WriteLength(len(data), w)
	core.WriteBytes(data, w)
}
