//go:build plugin_oracle || !plugin_selective

package services

/*
Minimal Oracle TNS authentication probe.

Parts of the packet layout and password verifier handling are derived from
github.com/sijms/go-ora/v2, which is licensed under the MIT License:

Copyright (c) 2020 Samy Sultan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
*/

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	oraclePacketConnect  = 1
	oraclePacketAccept   = 2
	oraclePacketRefuse   = 4
	oraclePacketRedirect = 5
	oraclePacketData     = 6
	oraclePacketResend   = 11

	oracleNoNewPass   = 0x1
	oracleUserAndPass = 0x100

	oracleTypeRepNative    int16 = 0
	oracleTypeRepUniversal int16 = 1
	oracleTypeRepOracle    int16 = 10
)

var errOracleAuthFailed = errors.New("oracle authentication failed")

type oracleSession struct {
	conn              net.Conn
	in                []byte
	out               bytes.Buffer
	index             int
	version           uint16
	negotiatedOptions uint16
	sessionDataUnit   uint32
	transportDataUnit uint32
	acfl0             uint8
	acfl1             uint8
	handshakeComplete bool
	ttcVersion        uint8
	hasEOSCapability  bool
	hasFSAPCapability bool
	useBigClrChunks   bool
	clrChunkSize      int
	timeout           time.Duration
	summary           *oracleSummary
}

type oracleTCPNego struct {
	serverCharset         int
	serverFlags           uint8
	serverNCharset        int
	serverCompileTimeCaps []byte
	serverRuntimeCaps     []byte
}

type oracleSummary struct {
	retCode      int
	errorMessage []byte
}

func oracleRawAuth(ctx context.Context, host string, port int, serviceName, username, password string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	s := &oracleSession{
		conn:              conn,
		version:           317,
		sessionDataUnit:   0x200000,
		transportDataUnit: 0x200000,
		clrChunkSize:      0x40,
		timeout:           timeout,
	}
	if err := s.connect(ctx, host, port, serviceName); err != nil {
		return err
	}
	if s.acfl0&1 != 0 && s.acfl0&4 == 0 && s.acfl1&8 == 0 {
		if err := s.advancedNegotiation(); err != nil {
			return err
		}
	}
	nego, err := s.protocolNegotiation()
	if err != nil {
		return err
	}
	if err := s.dataTypeNegotiation(nego); err != nil {
		return err
	}
	return s.authenticate(nego, host, port, serviceName, username, password)
}

func (s *oracleSession) connect(ctx context.Context, host string, port int, serviceName string) error {
	connectData := oracleConnectData(host, port, serviceName)
	packetLen := 70 + len(connectData)
	if len(connectData) > 230 {
		packetLen = 70
	}
	buf := make([]byte, packetLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(packetLen))
	buf[4] = oraclePacketConnect
	binary.BigEndian.PutUint16(buf[8:10], 317)
	binary.BigEndian.PutUint16(buf[10:12], 300)
	binary.BigEndian.PutUint16(buf[12:14], 1|2048)
	binary.BigEndian.PutUint16(buf[14:16], 0xffff)
	binary.BigEndian.PutUint16(buf[16:18], 0xffff)
	buf[18] = 79
	buf[19] = 152
	binary.BigEndian.PutUint16(buf[22:24], 1)
	binary.BigEndian.PutUint16(buf[24:26], uint16(len(connectData)))
	binary.BigEndian.PutUint16(buf[26:28], 70)
	buf[32] = 1
	buf[33] = 1
	binary.BigEndian.PutUint32(buf[58:62], s.sessionDataUnit)
	binary.BigEndian.PutUint32(buf[62:66], s.transportDataUnit)
	if len(connectData) <= 230 {
		copy(buf[70:], connectData)
	}
	if err := s.writeRaw(ctx, buf); err != nil {
		return err
	}
	if len(connectData) > 230 {
		s.reset()
		s.putBytes([]byte(connectData)...)
		if err := s.writeData(); err != nil {
			return err
		}
	}
	p, err := s.readPacket()
	if err != nil {
		return err
	}
	switch p.typ {
	case oraclePacketAccept:
		if len(p.raw) < 40 {
			return errors.New("short oracle accept packet")
		}
		s.version = binary.BigEndian.Uint16(p.raw[8:10])
		s.negotiatedOptions = binary.BigEndian.Uint16(p.raw[10:12])
		s.sessionDataUnit = uint32(binary.BigEndian.Uint16(p.raw[12:14]))
		s.transportDataUnit = uint32(binary.BigEndian.Uint16(p.raw[14:16]))
		if s.version >= 315 {
			s.sessionDataUnit = binary.BigEndian.Uint32(p.raw[32:36])
			s.transportDataUnit = binary.BigEndian.Uint32(p.raw[36:40])
		}
		if s.transportDataUnit < s.sessionDataUnit {
			s.sessionDataUnit = s.transportDataUnit
		}
		s.acfl0 = p.raw[22]
		s.acfl1 = p.raw[23]
		s.handshakeComplete = true
		return nil
	case oraclePacketRefuse:
		return oracleRefuseError(p.raw)
	case oraclePacketRedirect:
		return errors.New("oracle redirect is not supported by lightweight auth")
	default:
		return fmt.Errorf("unexpected oracle packet type %d", p.typ)
	}
}

func oracleConnectData(host string, port int, serviceName string) string {
	user := os.Getenv("USER")
	if user == "" {
		user = "fscan"
	}
	cid := "(CID=(PROGRAM=fscan)(HOST=" + host + ")(USER=" + user + "))"
	address := fmt.Sprintf("(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d))", host, port)
	connectData := "(CONNECT_DATA=(SERVICE_NAME=" + serviceName + ")" + cid + ")"
	return "(DESCRIPTION=" + address + connectData + ")"
}

type oraclePacket struct {
	typ  uint8
	flag uint8
	raw  []byte
	data []byte
}

func (s *oracleSession) readPacket() (*oraclePacket, error) {
	header := make([]byte, 8)
	if err := s.readFull(header); err != nil {
		return nil, err
	}
	var length uint32
	if s.handshakeComplete && s.version >= 315 {
		length = binary.BigEndian.Uint32(header[0:4])
	} else {
		length = uint32(binary.BigEndian.Uint16(header[0:2]))
	}
	if length < 8 || length > 16*1024*1024 {
		return nil, fmt.Errorf("invalid oracle packet length %d", length)
	}
	raw := make([]byte, length)
	copy(raw, header)
	if err := s.readFull(raw[8:]); err != nil {
		return nil, err
	}
	p := &oraclePacket{typ: raw[4], flag: raw[5], raw: raw}
	if p.typ == oraclePacketData {
		if len(raw) < 10 {
			return nil, errors.New("short oracle data packet")
		}
		p.data = raw[10:]
		s.in = append(s.in, p.data...)
	}
	return p, nil
}

func (s *oracleSession) readFull(buf []byte) error {
	if s.timeout > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.timeout))
	}
	_, err := io.ReadFull(s.conn, buf)
	return err
}

func (s *oracleSession) writeRaw(ctx context.Context, buf []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.conn.SetWriteDeadline(deadline)
	} else if s.timeout > 0 {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	}
	_, err := s.conn.Write(buf)
	return err
}

func (s *oracleSession) writeData() error {
	payload := s.out.Bytes()
	if len(payload) == 0 {
		return s.writeDataPacket(nil, 0)
	}
	segmentLen := int(s.sessionDataUnit) - 64
	if segmentLen <= 0 {
		segmentLen = len(payload)
	}
	for len(payload) > segmentLen {
		if err := s.writeDataPacket(payload[:segmentLen], 0); err != nil {
			s.out.Reset()
			return err
		}
		payload = payload[segmentLen:]
	}
	err := s.writeDataPacket(payload, 0)
	s.out.Reset()
	return err
}

func (s *oracleSession) writeDataPacket(payload []byte, dataFlag uint16) error {
	length := uint32(len(payload) + 10)
	buf := make([]byte, length)
	if s.handshakeComplete && s.version >= 315 {
		binary.BigEndian.PutUint32(buf[0:4], length)
	} else {
		binary.BigEndian.PutUint16(buf[0:2], uint16(length))
	}
	buf[4] = oraclePacketData
	binary.BigEndian.PutUint16(buf[8:10], dataFlag)
	copy(buf[10:], payload)
	if s.timeout > 0 {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	}
	_, err := s.conn.Write(buf)
	return err
}

func (s *oracleSession) reset() {
	s.in = nil
	s.out.Reset()
	s.index = 0
	s.summary = nil
}

func (s *oracleSession) read(n int) ([]byte, error) {
	for s.index+n > len(s.in) {
		p, err := s.readPacket()
		if err != nil {
			return nil, err
		}
		if p.typ == oraclePacketResend {
			return nil, errors.New("oracle resend is not supported")
		}
		if p.typ != oraclePacketData {
			return nil, fmt.Errorf("expected oracle data packet, got %d", p.typ)
		}
	}
	ret := s.in[s.index : s.index+n]
	s.index += n
	return ret, nil
}

func (s *oracleSession) putBytes(data ...byte) {
	s.out.Write(data)
}

func (s *oracleSession) putString(v string) {
	s.putClr([]byte(v))
}

func (s *oracleSession) putInt(v interface{}, size uint8, bigEndian, compress bool) {
	num := toInt64(v)
	if compress {
		neg := num < 0
		encoded := uint64(num)
		if neg {
			encoded = uint64(-(num + 1)) + 1
		}
		temp := make([]byte, 8)
		binary.BigEndian.PutUint64(temp, encoded)
		temp = bytes.TrimLeft(temp, "\x00")
		if size > uint8(len(temp)) {
			size = uint8(len(temp))
		}
		if size == 0 {
			s.out.WriteByte(0)
			return
		}
		if neg {
			size |= 0x80
		}
		s.out.WriteByte(size)
		s.out.Write(temp)
		return
	}
	if size == 1 {
		s.out.WriteByte(uint8(num))
		return
	}
	temp := make([]byte, size)
	if bigEndian {
		switch size {
		case 2:
			binary.BigEndian.PutUint16(temp, uint16(num))
		case 4:
			binary.BigEndian.PutUint32(temp, uint32(num))
		case 8:
			binary.BigEndian.PutUint64(temp, uint64(num))
		}
	} else {
		switch size {
		case 2:
			binary.LittleEndian.PutUint16(temp, uint16(num))
		case 4:
			binary.LittleEndian.PutUint32(temp, uint32(num))
		case 8:
			binary.LittleEndian.PutUint64(temp, uint64(num))
		}
	}
	s.out.Write(temp)
}

func (s *oracleSession) putUint(v interface{}, size uint8, bigEndian, compress bool) {
	num := toUint64(v)
	if size == 1 {
		s.out.WriteByte(uint8(num))
		return
	}
	if compress {
		temp := make([]byte, 8)
		binary.BigEndian.PutUint64(temp, num)
		temp = bytes.TrimLeft(temp, "\x00")
		if size > uint8(len(temp)) {
			size = uint8(len(temp))
		}
		if size == 0 {
			s.out.WriteByte(0)
			return
		}
		s.out.WriteByte(size)
		s.out.Write(temp)
		return
	}
	temp := make([]byte, size)
	if bigEndian {
		switch size {
		case 2:
			binary.BigEndian.PutUint16(temp, uint16(num))
		case 4:
			binary.BigEndian.PutUint32(temp, uint32(num))
		case 8:
			binary.BigEndian.PutUint64(temp, num)
		}
	} else {
		switch size {
		case 2:
			binary.LittleEndian.PutUint16(temp, uint16(num))
		case 4:
			binary.LittleEndian.PutUint32(temp, uint32(num))
		case 8:
			binary.LittleEndian.PutUint64(temp, num)
		}
	}
	s.out.Write(temp)
}

func (s *oracleSession) putClr(data []byte) {
	if len(data) > 0xfc {
		s.out.WriteByte(0xfe)
		for start := 0; start < len(data); start += s.clrChunkSize {
			end := start + s.clrChunkSize
			if end > len(data) {
				end = len(data)
			}
			chunk := data[start:end]
			if s.useBigClrChunks {
				s.putInt(len(chunk), 4, true, true)
			} else {
				s.out.WriteByte(uint8(len(chunk)))
			}
			s.out.Write(chunk)
		}
		s.out.WriteByte(0)
		return
	}
	if len(data) == 0 {
		s.out.WriteByte(0)
		return
	}
	s.out.WriteByte(uint8(len(data)))
	s.out.Write(data)
}

func (s *oracleSession) putKeyValString(key, val string, num uint8) {
	s.putKeyVal([]byte(key), []byte(val), num)
}

func (s *oracleSession) putKeyVal(key, val []byte, num uint8) {
	if len(key) == 0 {
		s.out.WriteByte(0)
	} else {
		s.putUint(len(key), 4, true, true)
		s.putClr(key)
	}
	if len(val) == 0 {
		s.out.WriteByte(0)
	} else {
		s.putUint(len(val), 4, true, true)
		s.putClr(val)
	}
	s.putInt(num, 4, true, true)
}

func (s *oracleSession) getByte() (uint8, error) {
	b, err := s.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (s *oracleSession) getBytes(n int) ([]byte, error) {
	return s.read(n)
}

func (s *oracleSession) getInt(size int, compress, bigEndian bool) (int, error) {
	v, err := s.getInt64(size, compress, bigEndian)
	return int(v), err
}

func (s *oracleSession) getInt64(size int, compress, bigEndian bool) (int64, error) {
	neg := false
	if compress {
		b, err := s.read(1)
		if err != nil {
			return 0, err
		}
		size = int(b[0])
		if size&0x80 != 0 {
			neg = true
			size &= 0x7f
		}
		bigEndian = true
	}
	if size == 0 {
		return 0, nil
	}
	if size > 8 {
		return 0, fmt.Errorf("invalid oracle integer size %d", size)
	}
	b, err := s.read(size)
	if err != nil {
		return 0, err
	}
	tmp := make([]byte, 8)
	if bigEndian {
		copy(tmp[8-size:], b)
		v := int64(binary.BigEndian.Uint64(tmp))
		if neg {
			v = -v
		}
		return v, nil
	}
	copy(tmp[:size], b)
	v := int64(binary.LittleEndian.Uint64(tmp))
	if neg {
		v = -v
	}
	return v, nil
}

func (s *oracleSession) getNullTermString(maxSize int) (string, error) {
	oldIndex := s.index
	b, err := s.read(maxSize)
	if err != nil {
		return "", err
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		s.index = oldIndex + i + 1
		return string(b[:i]), nil
	}
	return string(b), nil
}

func (s *oracleSession) getClr() ([]byte, error) {
	nb, err := s.getByte()
	if err != nil {
		return nil, err
	}
	if nb == 0 || nb == 0xff || nb == 0xfd {
		return nil, nil
	}
	chunkSize := int(nb)
	var out bytes.Buffer
	if chunkSize == 0xfe {
		for {
			if s.useBigClrChunks {
				chunkSize, err = s.getInt(4, true, true)
			} else {
				nb, err = s.getByte()
				chunkSize = int(nb)
			}
			if err != nil || chunkSize == 0 {
				return out.Bytes(), err
			}
			chunk, err := s.getBytes(chunkSize)
			if err != nil {
				return nil, err
			}
			out.Write(chunk)
		}
	}
	chunk, err := s.getBytes(chunkSize)
	if err != nil {
		return nil, err
	}
	out.Write(chunk)
	return out.Bytes(), nil
}

func (s *oracleSession) getDlc() ([]byte, error) {
	length, err := s.getInt(4, true, true)
	if err != nil || length <= 0 {
		return nil, err
	}
	out, err := s.getClr()
	if len(out) > length {
		out = out[:length]
	}
	return out, err
}

func (s *oracleSession) getKeyVal() ([]byte, []byte, int, error) {
	key, err := s.getDlc()
	if err != nil {
		return nil, nil, 0, err
	}
	val, err := s.getDlc()
	if err != nil {
		return nil, nil, 0, err
	}
	num, err := s.getInt(4, true, true)
	return key, val, num, err
}

func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int16:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case uint8:
		return int64(n)
	case uint16:
		return int64(n)
	case uint32:
		return int64(n)
	case uint64:
		return int64(n)
	case uint:
		return int64(n)
	default:
		panic("oracle integer encoder expects an integer")
	}
}

func toUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case int:
		return uint64(n)
	case int16:
		return uint64(n)
	case int32:
		return uint64(n)
	case int64:
		return uint64(n)
	case uint8:
		return uint64(n)
	case uint16:
		return uint64(n)
	case uint32:
		return uint64(n)
	case uint64:
		return n
	case uint:
		return uint64(n)
	default:
		panic("oracle integer encoder expects an integer")
	}
}

func (s *oracleSession) advancedNegotiation() error {
	s.reset()
	s.writeANOHeader(101, 4, 0)
	s.writeANOServiceHeader(4, 3)
	s.writeANOVersion()
	s.writeANOBytes([]byte{0, 0, 16, 28, 102, 236, 40, 234})
	s.writeANOUB2Array([]int{4, 1, 2, 3})
	s.writeANOServiceHeader(1, 3)
	s.writeANOVersion()
	s.writeANOStatus(0xfcff)
	s.writeANOServiceHeader(2, 3)
	s.writeANOVersion()
	s.writeANOBytes([]byte{0})
	s.writeANOUB1(1)
	s.writeANOServiceHeader(3, 2)
	s.writeANOVersion()
	s.writeANOBytes([]byte{0})
	if err := s.writeData(); err != nil {
		return err
	}
	header, err := s.readANOHeader()
	if err != nil {
		return err
	}
	for i := 0; i < header.serviceCount; i++ {
		serviceType, subPackets, errCode, err := s.readANOServiceHeader()
		if err != nil {
			return err
		}
		if errCode != 0 {
			return fmt.Errorf("oracle advanced negotiation error ora-%d", errCode)
		}
		if err := s.readANOServiceData(serviceType, subPackets); err != nil {
			return err
		}
	}
	return nil
}

type oracleANOHeader struct {
	serviceCount int
}

func (s *oracleSession) writeANOHeader(length, serviceCount int, flags uint8) {
	s.putInt(uint64(0xdeadbeef), 4, true, false)
	s.putInt(length, 2, true, false)
	s.putInt(0x0b200200, 4, true, false)
	s.putInt(serviceCount, 2, true, false)
	s.putBytes(flags)
}

func (s *oracleSession) writeANOServiceHeader(serviceType, subPackets int) {
	s.putInt(serviceType, 2, true, false)
	s.putInt(subPackets, 2, true, false)
	s.putInt(0, 4, true, false)
}

func (s *oracleSession) writeANOPacketHeader(length, typ int) {
	s.putInt(length, 2, true, false)
	s.putInt(typ, 2, true, false)
}

func (s *oracleSession) writeANOVersion() {
	s.writeANOPacketHeader(4, 5)
	s.putInt(0x0b200200, 4, true, false)
}

func (s *oracleSession) writeANOStatus(status int) {
	s.writeANOPacketHeader(2, 6)
	s.putInt(status, 2, true, false)
}

func (s *oracleSession) writeANOBytes(b []byte) {
	s.writeANOPacketHeader(len(b), 1)
	s.putBytes(b...)
}

func (s *oracleSession) writeANOUB1(v uint8) {
	s.writeANOPacketHeader(1, 2)
	s.putBytes(v)
}

func (s *oracleSession) writeANOUB2Array(v []int) {
	s.writeANOPacketHeader(10+len(v)*2, 1)
	s.putInt(uint64(0xdeadbeef), 4, true, false)
	s.putInt(3, 2, true, false)
	s.putInt(len(v), 4, true, false)
	for _, n := range v {
		s.putInt(n, 2, true, false)
	}
}

func (s *oracleSession) readANOHeader() (*oracleANOHeader, error) {
	magic, err := s.getInt64(4, false, true)
	if err != nil {
		return nil, err
	}
	if magic != 0xdeadbeef {
		return nil, errors.New("oracle advanced negotiation header mismatch")
	}
	if _, err = s.getInt(2, false, true); err != nil {
		return nil, err
	}
	if _, err = s.getInt(4, false, true); err != nil {
		return nil, err
	}
	count, err := s.getInt(2, false, true)
	if err != nil {
		return nil, err
	}
	if _, err = s.getByte(); err != nil {
		return nil, err
	}
	return &oracleANOHeader{serviceCount: count}, nil
}

func (s *oracleSession) readANOServiceHeader() (int, int, int, error) {
	serviceType, err := s.getInt(2, false, true)
	if err != nil {
		return 0, 0, 0, err
	}
	subPackets, err := s.getInt(2, false, true)
	if err != nil {
		return 0, 0, 0, err
	}
	errCode, err := s.getInt(4, false, true)
	return serviceType, subPackets, errCode, err
}

func (s *oracleSession) readANOPacketHeader(expectType int) (int, error) {
	length, err := s.getInt(2, false, true)
	if err != nil {
		return 0, err
	}
	typ, err := s.getInt(2, false, true)
	if err != nil {
		return 0, err
	}
	if typ != expectType {
		return 0, fmt.Errorf("oracle advanced negotiation type mismatch: %d", typ)
	}
	return length, nil
}

func (s *oracleSession) readANOServiceData(serviceType, subPackets int) error {
	switch serviceType {
	case 1:
		if _, err := s.readANOVersion(); err != nil {
			return err
		}
		status, err := s.readANOStatus()
		if err != nil {
			return err
		}
		if status == 0xfaff && subPackets > 2 {
			if _, err = s.readANOUB1(); err != nil {
				return err
			}
			name, err := s.readANOString()
			if err != nil {
				return err
			}
			if name != "" && name != "TCPS" {
				return fmt.Errorf("unsupported oracle authentication service %s", name)
			}
		} else if status != 0xfbff {
			return errors.New("oracle advanced authentication negotiation failed")
		}
	case 2, 3:
		if _, err := s.readANOVersion(); err != nil {
			return err
		}
		algo, err := s.readANOUB1()
		if err != nil {
			return err
		}
		if algo != 0 {
			return fmt.Errorf("unsupported oracle advanced service algorithm %d", algo)
		}
		for i := 2; i < subPackets; i++ {
			if err := s.skipANOPacket(); err != nil {
				return err
			}
		}
	case 4:
		if _, err := s.readANOVersion(); err != nil {
			return err
		}
		if _, err := s.readANOStatus(); err != nil {
			return err
		}
		_, err := s.readANOBytes()
		return err
	default:
		for i := 0; i < subPackets; i++ {
			if err := s.skipANOPacket(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *oracleSession) readANOVersion() (uint32, error) {
	if _, err := s.readANOPacketHeader(5); err != nil {
		return 0, err
	}
	v, err := s.getInt(4, false, true)
	return uint32(v), err
}

func (s *oracleSession) readANOStatus() (int, error) {
	if _, err := s.readANOPacketHeader(6); err != nil {
		return 0, err
	}
	return s.getInt(2, false, true)
}

func (s *oracleSession) readANOUB1() (uint8, error) {
	if _, err := s.readANOPacketHeader(2); err != nil {
		return 0, err
	}
	return s.getByte()
}

func (s *oracleSession) readANOString() (string, error) {
	length, err := s.readANOPacketHeader(0)
	if err != nil {
		return "", err
	}
	b, err := s.getBytes(length)
	return string(b), err
}

func (s *oracleSession) readANOBytes() ([]byte, error) {
	length, err := s.readANOPacketHeader(1)
	if err != nil {
		return nil, err
	}
	return s.getBytes(length)
}

func (s *oracleSession) skipANOPacket() error {
	length, err := s.getInt(2, false, true)
	if err != nil {
		return err
	}
	if _, err = s.getInt(2, false, true); err != nil {
		return err
	}
	if length > 0 {
		_, err = s.getBytes(length)
	}
	return err
}

func (s *oracleSession) protocolNegotiation() (*oracleTCPNego, error) {
	s.reset()
	s.putBytes(1, 6, 0)
	s.putBytes([]byte("OracleClientGo\x00")...)
	if err := s.writeData(); err != nil {
		return nil, err
	}
	msg, err := s.getByte()
	if err != nil {
		return nil, err
	}
	if msg != 1 {
		return nil, fmt.Errorf("oracle protocol negotiation expected message 1, got %d", msg)
	}
	proto, err := s.getByte()
	if err != nil {
		return nil, err
	}
	if proto != 4 && proto != 5 && proto != 6 {
		return nil, errors.New("unsupported oracle server protocol version")
	}
	if _, err = s.getByte(); err != nil {
		return nil, err
	}
	if _, err = s.getNullTermString(50); err != nil {
		return nil, err
	}
	serverCharset, err := s.getInt(2, false, false)
	if err != nil {
		return nil, err
	}
	serverFlags, err := s.getByte()
	if err != nil {
		return nil, err
	}
	charsetElem, err := s.getInt(2, false, false)
	if err != nil {
		return nil, err
	}
	if charsetElem > 0 {
		if _, err = s.getBytes(charsetElem * 5); err != nil {
			return nil, err
		}
	}
	len1, err := s.getInt(2, false, true)
	if err != nil {
		return nil, err
	}
	numArray, err := s.getBytes(len1)
	if err != nil {
		return nil, err
	}
	if len(numArray) < 11 {
		return nil, errors.New("short oracle charset negotiation")
	}
	offset := int(6 + numArray[5] + numArray[6])
	if len(numArray) < offset+5 {
		return nil, errors.New("short oracle ncharset negotiation")
	}
	serverNCharset := int(binary.BigEndian.Uint16(numArray[offset+3 : offset+5]))
	len2, err := s.getByte()
	if err != nil {
		return nil, err
	}
	compileCaps, err := s.getBytes(int(len2))
	if err != nil {
		return nil, err
	}
	len3, err := s.getByte()
	if err != nil {
		return nil, err
	}
	runtimeCaps, err := s.getBytes(int(len3))
	if err != nil {
		return nil, err
	}
	if len(compileCaps) < 8 {
		return nil, errors.New("oracle server compile caps too short")
	}
	if len(compileCaps) > 15 && compileCaps[15]&1 != 0 {
		s.hasEOSCapability = true
	}
	if len(compileCaps) > 16 && compileCaps[16]&1 != 0 {
		s.hasFSAPCapability = true
	}
	if len(compileCaps) > 37 && compileCaps[37]&32 != 0 {
		s.useBigClrChunks = true
		s.clrChunkSize = 0x7fff
	}
	return &oracleTCPNego{
		serverCharset:         serverCharset,
		serverFlags:           serverFlags | 2,
		serverNCharset:        serverNCharset,
		serverCompileTimeCaps: compileCaps,
		serverRuntimeCaps:     runtimeCaps,
	}, nil
}

func (s *oracleSession) dataTypeNegotiation(nego *oracleTCPNego) error {
	compileCaps := []byte{
		6, 1, 0, 0, 106, 1, 1, 11,
		1, 1, 1, 1, 1, 1, 0, 41,
		144, 3, 7, 3, 0, 1, 0, 235,
		1, 0, 5, 1, 0, 0, 0, 24,
		0, 0, 7, 32, 2, 58, 0, 0,
		5, 0, 0, 0, 8,
	}
	if len(nego.serverCompileTimeCaps) <= 27 || nego.serverCompileTimeCaps[27] == 0 {
		compileCaps[27] = 0
	}
	if len(nego.serverCompileTimeCaps) > 7 && nego.serverCompileTimeCaps[7] < 7 {
		compileCaps[36] = 0
	}
	if len(nego.serverCompileTimeCaps) <= 37 || nego.serverCompileTimeCaps[37]&2 != 2 {
		compileCaps[37] = 0
		compileCaps[1] = 0
	}
	runtimeCaps := []byte{2, 1, 0, 0, 0, 0, 0}
	if len(nego.serverRuntimeCaps) < 2 || nego.serverRuntimeCaps[1]&1 != 1 {
		runtimeCaps[1] = 0
	}
	if len(nego.serverRuntimeCaps) > 6 {
		if nego.serverRuntimeCaps[6]&4 == 4 {
			runtimeCaps[6] |= 4
		}
		if nego.serverRuntimeCaps[6]&2 == 2 {
			runtimeCaps[6] |= 2
		}
	}
	typeReps := oracleTypeReps(nego, compileCaps)
	s.reset()
	s.putBytes(2)
	s.putInt(nego.serverCharset, 2, false, false)
	s.putInt(nego.serverCharset, 2, false, false)
	s.putBytes(nego.serverFlags, uint8(len(compileCaps)))
	s.putBytes(compileCaps...)
	s.putBytes(uint8(len(runtimeCaps)))
	s.putBytes(runtimeCaps...)
	if runtimeCaps[1]&1 == 1 {
		s.putBytes(oracleTZBytes()...)
		if compileCaps[37]&2 == 2 {
			s.putInt(0x20, 4, true, false)
		}
	}
	s.putInt(nego.serverNCharset, 2, false, false)
	if compileCaps[27] == 0 {
		for _, v := range typeReps {
			s.putBytes(uint8(v))
		}
		s.putBytes(0)
	} else {
		for _, v := range typeReps {
			s.putInt(v, 2, true, false)
		}
		s.putBytes(0, 0)
	}
	if err := s.writeData(); err != nil {
		return err
	}
	msg, err := s.getByte()
	if err != nil {
		return err
	}
	if msg != 2 {
		return fmt.Errorf("oracle data type negotiation expected message 2, got %d", msg)
	}
	if runtimeCaps[1] == 1 {
		if _, err = s.getBytes(11); err != nil {
			return err
		}
		if compileCaps[37]&2 == 2 {
			if _, err = s.getInt(4, false, true); err != nil {
				return err
			}
		}
	}
	level := 0
	for {
		var n int
		if compileCaps[27] == 0 {
			n, err = s.getInt(1, false, false)
		} else {
			n, err = s.getInt(2, false, true)
		}
		if err != nil {
			return err
		}
		if n == 0 && level == 0 {
			break
		}
		if n == 0 && level == 1 {
			level = 0
			continue
		}
		if level == 3 {
			level = 0
			continue
		}
		level++
	}
	if len(compileCaps) > 7 && len(nego.serverCompileTimeCaps) > 7 {
		s.ttcVersion = compileCaps[7]
		if nego.serverCompileTimeCaps[7] < s.ttcVersion {
			s.ttcVersion = nego.serverCompileTimeCaps[7]
		}
	}
	return nil
}

func oracleTypeReps(nego *oracleTCPNego, compileCaps []byte) []int16 {
	reps := make([]int16, 0, 96)
	add := func(dty, ndty, rep int16) {
		reps = append(reps, dty, ndty)
		if ndty != 0 {
			reps = append(reps, rep, 0)
		}
	}
	add(1, 1, oracleTypeRepUniversal)   // NCHAR
	add(2, 2, oracleTypeRepOracle)      // NUMBER
	add(8, 8, oracleTypeRepUniversal)   // LONG
	add(12, 12, oracleTypeRepOracle)    // DATE
	add(23, 23, oracleTypeRepUniversal) // RAW
	add(24, 24, oracleTypeRepUniversal) // LONG RAW
	add(25, 25, oracleTypeRepUniversal)
	add(26, 26, oracleTypeRepUniversal)
	add(27, 27, oracleTypeRepUniversal)
	add(28, 28, oracleTypeRepUniversal)
	add(29, 29, oracleTypeRepUniversal)
	add(30, 30, oracleTypeRepUniversal)
	add(31, 31, oracleTypeRepUniversal)
	add(32, 32, oracleTypeRepUniversal)
	add(33, 33, oracleTypeRepUniversal)
	add(10, 10, oracleTypeRepUniversal)
	add(11, 11, oracleTypeRepUniversal) // ROWID
	add(3, 2, oracleTypeRepOracle)
	add(4, 2, oracleTypeRepOracle)
	add(5, 1, oracleTypeRepUniversal)
	add(6, 2, oracleTypeRepOracle)
	add(7, 2, oracleTypeRepOracle)
	add(9, 1, oracleTypeRepUniversal) // VARCHAR
	add(15, 1, oracleTypeRepUniversal)
	add(39, 120, oracleTypeRepUniversal)
	add(58, 0, oracleTypeRepNative)
	add(68, 2, oracleTypeRepOracle)
	add(69, 0, oracleTypeRepNative)
	add(70, 0, oracleTypeRepNative)
	add(74, 0, oracleTypeRepNative)
	add(76, 0, oracleTypeRepNative)
	add(91, 2, oracleTypeRepOracle)
	add(94, 1, oracleTypeRepUniversal)
	add(95, 23, oracleTypeRepUniversal)
	add(96, 96, oracleTypeRepUniversal)
	add(97, 96, oracleTypeRepUniversal)
	add(100, 100, oracleTypeRepUniversal)
	add(101, 101, oracleTypeRepUniversal)
	add(102, 102, oracleTypeRepUniversal)
	add(104, 11, oracleTypeRepUniversal)
	add(105, 0, oracleTypeRepNative)
	add(106, 106, oracleTypeRepUniversal)
	add(112, 112, oracleTypeRepUniversal)
	add(113, 113, oracleTypeRepUniversal)
	add(114, 114, oracleTypeRepUniversal)
	add(115, 115, oracleTypeRepUniversal)
	add(116, 102, oracleTypeRepUniversal)
	add(118, 0, oracleTypeRepNative)
	add(119, 119, oracleTypeRepNative) // JSON
	add(127, 127, oracleTypeRepUniversal)
	add(208, 208, oracleTypeRepUniversal)
	_ = nego
	_ = compileCaps
	return reps
}

func oracleTZBytes() []byte {
	_, offset := time.Now().Zone()
	hours := int8(offset / 3600)
	minutes := int8((offset / 60) % 60)
	seconds := int8(offset % 60)
	return []byte{128, 0, 0, 0, uint8(hours + 60), uint8(minutes + 60), uint8(seconds + 60), 128, 0, 0, 0}
}

func (s *oracleSession) authenticate(nego *oracleTCPNego, host string, port int, serviceName, username, password string) error {
	s.reset()
	s.putBytes(3, 0x76, 0, 1)
	s.putUint(len(username), 4, true, true)
	s.putUint(oracleNoNewPass, 4, true, true)
	s.putBytes(1, 1, 5, 1, 1)
	if username != "" {
		s.putString(username)
	}
	clientHost, _ := os.Hostname()
	if clientHost == "" {
		clientHost = "fscan"
	}
	s.putKeyValString("AUTH_TERMINAL", clientHost, 0)
	s.putKeyValString("AUTH_PROGRAM_NM", "fscan", 0)
	s.putKeyValString("AUTH_MACHINE", clientHost, 0)
	s.putKeyValString("AUTH_PID", strconv.Itoa(os.Getpid()), 0)
	s.putKeyValString("AUTH_SID", os.Getenv("USER"), 0)
	if err := s.writeData(); err != nil {
		return err
	}
	auth, err := s.readAuthChallenge(username, password, nego)
	if err != nil {
		return err
	}
	return s.writeAuthResponse(auth, nego, host, port, serviceName, username)
}

type oracleAuthObject struct {
	eServerSessKey  string
	eClientSessKey  string
	ePassword       string
	eSpeedyKey      string
	serverSessKey   []byte
	clientSessKey   []byte
	salt            string
	pbkdf2ChkSalt   string
	pbkdf2VgenCount int
	pbkdf2SderCount int
	verifierType    int
	customHash      bool
}

func (s *oracleSession) readAuthChallenge(username, password string, nego *oracleTCPNego) (*oracleAuthObject, error) {
	auth := &oracleAuthObject{customHash: len(nego.serverCompileTimeCaps) > 4 && nego.serverCompileTimeCaps[4]&32 != 0}
	for {
		msg, err := s.getByte()
		if err != nil {
			return nil, err
		}
		switch msg {
		case 8:
			dictLen, err := s.getInt(4, true, true)
			if err != nil {
				return nil, err
			}
			for i := 0; i < dictLen; i++ {
				key, val, num, err := s.getKeyVal()
				if err != nil {
					return nil, err
				}
				switch string(key) {
				case "AUTH_SESSKEY":
					if auth.eServerSessKey == "" {
						auth.eServerSessKey = string(val)
					}
				case "AUTH_VFR_DATA":
					if auth.salt == "" {
						auth.salt = string(val)
						auth.verifierType = num
					}
				case "AUTH_PBKDF2_CSK_SALT":
					auth.pbkdf2ChkSalt = string(val)
					if len(auth.pbkdf2ChkSalt) != 32 {
						return nil, errors.New("oracle authentication protocol internal error")
					}
				case "AUTH_PBKDF2_VGEN_COUNT":
					auth.pbkdf2VgenCount, _ = strconv.Atoi(string(val))
					if auth.pbkdf2VgenCount < 4096 || auth.pbkdf2VgenCount > 100000000 {
						auth.pbkdf2VgenCount = 4096
					}
				case "AUTH_PBKDF2_SDER_COUNT":
					auth.pbkdf2SderCount, _ = strconv.Atoi(string(val))
					if auth.pbkdf2SderCount < 3 || auth.pbkdf2SderCount > 100000000 {
						auth.pbkdf2SderCount = 3
					}
				}
			}
		default:
			err := s.readMsg(msg)
			if err != nil {
				return nil, err
			}
			if msg == 4 {
				if s.hasError() {
					return nil, s.oracleError()
				}
				return auth.finish(username, password, nego)
			}
		}
	}
}

func (auth *oracleAuthObject) finish(username, password string, nego *oracleTCPNego) (*oracleAuthObject, error) {
	if len(auth.eServerSessKey) != 64 && len(auth.eServerSessKey) != 96 {
		return nil, errors.New("oracle session key should be either 64 or 96 bytes long")
	}
	var key []byte
	var speedyKey []byte
	padding := false
	var err error
	switch auth.verifierType {
	case 2361:
		key, err = oracleKeyFromUserPass(username, password)
	case 6949:
		if len(nego.serverCompileTimeCaps) > 4 && nego.serverCompileTimeCaps[4]&2 == 0 {
			padding = true
		}
		salt, err := hex.DecodeString(auth.salt)
		if err != nil {
			return nil, err
		}
		h := sha1.New()
		_, _ = h.Write(append([]byte(password), salt...))
		key = append(h.Sum(nil), 0, 0, 0, 0)
	case 18453:
		salt, err := hex.DecodeString(auth.salt)
		if err != nil {
			return nil, err
		}
		message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
		speedyKey = oracleGenerateSpeedyKey(message, []byte(password), auth.pbkdf2VgenCount)
		h := sha512.New()
		_, _ = h.Write(append(speedyKey, salt...))
		key = h.Sum(nil)[:32]
	default:
		return nil, fmt.Errorf("unsupported oracle verifier type %d", auth.verifierType)
	}
	if err != nil {
		return nil, err
	}
	auth.serverSessKey, err = oracleDecryptSessionKey(padding, key, auth.eServerSessKey)
	if err != nil {
		return nil, err
	}
	auth.clientSessKey = make([]byte, len(auth.serverSessKey))
	for {
		if _, err = rand.Read(auth.clientSessKey); err != nil {
			return nil, err
		}
		if !bytes.Equal(auth.clientSessKey, auth.serverSessKey) {
			break
		}
	}
	auth.eClientSessKey, err = oracleEncryptSessionKey(padding, key, auth.clientSessKey)
	if err != nil {
		return nil, err
	}
	newKey, err := auth.passwordEncKey(nego)
	if err != nil {
		return nil, err
	}
	auth.ePassword, err = oracleEncryptPassword([]byte(password), newKey, true)
	if err != nil {
		return nil, err
	}
	if auth.verifierType == 18453 {
		auth.eSpeedyKey, err = oracleEncryptPassword(speedyKey, newKey, false)
		if err != nil {
			return nil, err
		}
	}
	return auth, nil
}

func (s *oracleSession) writeAuthResponse(auth *oracleAuthObject, nego *oracleTCPNego, host string, port int, serviceName, username string) error {
	clientHost, _ := os.Hostname()
	if clientHost == "" {
		clientHost = "fscan"
	}
	keys := []struct {
		key  string
		val  string
		flag uint8
	}{
		{"AUTH_SESSKEY", auth.eClientSessKey, 1},
		{"AUTH_PASSWORD", auth.ePassword, 0},
	}
	if auth.eSpeedyKey != "" {
		keys = append(keys, struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_PBKDF2_SPEEDY_KEY", auth.eSpeedyKey, 0})
	}
	keys = append(keys,
		struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_TERMINAL", clientHost, 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_PROGRAM_NM", "fscan", 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_MACHINE", clientHost, 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_PID", strconv.Itoa(os.Getpid()), 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_SID", os.Getenv("USER"), 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_CONNECT_STRING", oracleConnectData(host, port, serviceName), 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"SESSION_CLIENT_CHARSET", strconv.Itoa(nego.serverCharset), 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"SESSION_CLIENT_LIB_TYPE", "0", 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"SESSION_CLIENT_DRIVER_NAME", "fscan", 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"SESSION_CLIENT_VERSION", "2.0.0.0", 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"SESSION_CLIENT_LOBATTR", "1", 0},
		struct {
			key  string
			val  string
			flag uint8
		}{"AUTH_ALTER_SESSION", oracleAlterSession(), 1},
	)
	s.reset()
	s.putBytes(3, 0x73, 0)
	if username != "" {
		s.putBytes(1)
		s.putInt(len(username), 4, true, true)
	} else {
		s.putBytes(0, 0)
	}
	s.putUint(oracleUserAndPass|oracleNoNewPass, 4, true, true)
	s.putBytes(1)
	s.putUint(len(keys), 4, true, true)
	s.putBytes(1, 1)
	if username != "" {
		s.putString(username)
	}
	for _, kv := range keys {
		if kv.val == "" && (kv.key == "AUTH_SESSKEY" || kv.key == "AUTH_PASSWORD") {
			continue
		}
		s.putKeyValString(kv.key, kv.val, kv.flag)
	}
	if err := s.writeData(); err != nil {
		return err
	}
	for {
		msg, err := s.getByte()
		if err != nil {
			return err
		}
		if err := s.readMsg(msg); err != nil {
			return err
		}
		if msg == 4 || msg == 9 {
			if s.hasError() {
				err := s.oracleError()
				if classifyOracleErrorType(err) == ErrorTypeAuth {
					return fmt.Errorf("%w: %v", errOracleAuthFailed, err)
				}
				return err
			}
			return nil
		}
	}
}

func oracleAlterSession() string {
	_, offset := time.Now().Zone()
	hours := int8(offset / 3600)
	minutes := int8((offset / 60) % 60)
	if minutes < 0 {
		minutes = -minutes
	}
	tz := fmt.Sprintf("%+03d:%02d", hours, minutes)
	return fmt.Sprintf("ALTER SESSION SET NLS_LANGUAGE='AMERICAN' NLS_TERRITORY='AMERICA'  TIME_ZONE='%s'\x00", tz)
}

func (s *oracleSession) readMsg(msg uint8) error {
	switch msg {
	case 4:
		sum, err := s.readSummary()
		if err != nil {
			return err
		}
		s.summary = sum
	case 8:
		size, err := s.getInt(2, true, true)
		if err != nil {
			return err
		}
		for i := 0; i < size; i++ {
			if _, err = s.getInt(4, true, true); err != nil {
				return err
			}
		}
		if _, err = s.getInt(2, true, true); err != nil {
			return err
		}
		size, err = s.getInt(2, true, true)
		if err != nil {
			return err
		}
		for i := 0; i < size; i++ {
			if _, _, _, err = s.getKeyVal(); err != nil {
				return err
			}
		}
		if s.ttcVersion >= 4 {
			qLen, err := s.getInt(4, true, true)
			if err != nil {
				return err
			}
			if qLen > 0 {
				if _, err = s.getBytes(qLen); err != nil {
					return err
				}
			}
		}
		if s.ttcVersion >= 7 {
			length, err := s.getInt(4, true, true)
			if err != nil {
				return err
			}
			for i := 0; i < length; i++ {
				if _, err = s.getInt(8, true, true); err != nil {
					return err
				}
			}
		}
	case 9:
		if s.hasEOSCapability {
			if _, err := s.getInt(4, true, true); err != nil {
				return err
			}
		}
		if s.hasFSAPCapability {
			if _, err := s.getInt(2, true, true); err != nil {
				return err
			}
		}
	case 15:
		if _, err := s.getInt(2, true, true); err != nil {
			return err
		}
		length, err := s.getInt(2, true, true)
		if err != nil {
			return err
		}
		if _, err = s.getInt(2, true, true); err != nil {
			return err
		}
		if length > 0 {
			_, err = s.getClr()
			return err
		}
	default:
		return fmt.Errorf("oracle TTC unexpected message %d", msg)
	}
	return nil
}

func (s *oracleSession) readSummary() (*oracleSummary, error) {
	sum := &oracleSummary{}
	var err error
	if s.hasEOSCapability {
		if _, err = s.getInt(4, true, true); err != nil {
			return nil, err
		}
	}
	if s.ttcVersion >= 3 && s.hasFSAPCapability {
		if _, err = s.getInt(2, true, true); err != nil {
			return nil, err
		}
	}
	if _, err = s.getInt(4, true, true); err != nil {
		return nil, err
	}
	sum.retCode, err = s.getInt(2, true, true)
	if err != nil {
		return nil, err
	}
	fields := []struct {
		size     int
		compress bool
	}{
		{2, true}, {2, true}, {2, true}, {2, true},
	}
	for _, f := range fields {
		if _, err = s.getInt(f.size, f.compress, true); err != nil {
			return nil, err
		}
	}
	if _, err = s.getByte(); err != nil {
		return nil, err
	}
	if _, err = s.getByte(); err != nil {
		return nil, err
	}
	if s.ttcVersion >= 4 {
		if _, err = s.getInt(2, true, true); err != nil {
			return nil, err
		}
		if _, err = s.getInt(2, true, true); err != nil {
			return nil, err
		}
	} else {
		if _, err = s.getByte(); err != nil {
			return nil, err
		}
		if _, err = s.getByte(); err != nil {
			return nil, err
		}
	}
	for _, size := range []int{1, 1, 4, 2, 1, 4, 2, 4, 1, 1, 2, 4} {
		if size == 1 {
			if _, err = s.getByte(); err != nil {
				return nil, err
			}
		} else {
			if _, err = s.getInt(size, true, true); err != nil {
				return nil, err
			}
		}
	}
	_, _ = s.getDlc()
	if s.ttcVersion < 7 {
		_, _ = s.getDlc()
		_, _ = s.getDlc()
		_, _ = s.getDlc()
	} else {
		if err = s.skipSummaryBindBlocks(); err != nil {
			return nil, err
		}
		sum.retCode, err = s.getInt(4, true, true)
		if err != nil {
			return nil, err
		}
		if _, err = s.getInt(8, true, true); err != nil {
			return nil, err
		}
	}
	if sum.retCode != 0 {
		sum.errorMessage, err = s.getClr()
		if err != nil {
			return nil, err
		}
	}
	return sum, nil
}

func (s *oracleSession) skipSummaryBindBlocks() error {
	length, err := s.getInt(2, true, true)
	if err != nil {
		return err
	}
	if length > 0 {
		flag, err := s.getByte()
		if err != nil {
			return err
		}
		chunked := flag == 0xfe
		for i := 0; i < length; i++ {
			if chunked {
				if s.useBigClrChunks {
					if _, err = s.getInt(4, true, true); err != nil {
						return err
					}
				} else if _, err = s.getByte(); err != nil {
					return err
				}
			}
			if _, err = s.getInt(2, true, true); err != nil {
				return err
			}
		}
		if chunked {
			if _, err = s.getByte(); err != nil {
				return err
			}
		}
	}
	length, err = s.getInt(4, true, true)
	if err != nil {
		return err
	}
	if length > 0 {
		flag, err := s.getByte()
		if err != nil {
			return err
		}
		chunked := flag == 0xfe
		for i := 0; i < length; i++ {
			if chunked {
				if s.useBigClrChunks {
					if _, err = s.getInt(4, true, true); err != nil {
						return err
					}
				} else if _, err = s.getByte(); err != nil {
					return err
				}
			}
			if _, err = s.getInt(4, true, true); err != nil {
				return err
			}
		}
		if chunked {
			if _, err = s.getByte(); err != nil {
				return err
			}
		}
	}
	length, err = s.getInt(2, true, true)
	if err != nil {
		return err
	}
	for i := 0; i < length; i++ {
		if _, err = s.getByte(); err != nil {
			return err
		}
		if _, err = s.getInt(2, true, true); err != nil {
			return err
		}
		if _, err = s.getClr(); err != nil {
			return err
		}
		if _, err = s.getByte(); err != nil {
			return err
		}
		if _, err = s.getByte(); err != nil {
			return err
		}
	}
	return nil
}

func (s *oracleSession) hasError() bool {
	return s.summary != nil && s.summary.retCode != 0 && s.summary.retCode != 1403
}

func (s *oracleSession) oracleError() error {
	if s.summary == nil {
		return errors.New("oracle error")
	}
	msg := string(s.summary.errorMessage)
	if msg == "" {
		msg = fmt.Sprintf("ORA-%05d", s.summary.retCode)
	}
	return fmt.Errorf("%s", msg)
}

func oracleRefuseError(raw []byte) error {
	if len(raw) < 12 {
		return errors.New("oracle connection refused")
	}
	dataLen := int(binary.BigEndian.Uint16(raw[10:12]))
	if len(raw) < 12+dataLen {
		return errors.New("oracle connection refused")
	}
	msg := string(raw[12 : 12+dataLen])
	code := oracleExtractCode(msg)
	if code == 0 {
		return fmt.Errorf("oracle connection refused: %s", msg)
	}
	return fmt.Errorf("ORA-%05d: %s", code, msg)
}

func oracleExtractCode(msg string) int {
	upper := strings.ToUpper(msg)
	for _, marker := range []string{"ERR=", "CODE="} {
		idx := strings.Index(upper, marker)
		if idx < 0 {
			continue
		}
		idx += len(marker)
		for idx < len(upper) && (upper[idx] < '0' || upper[idx] > '9') {
			idx++
		}
		start := idx
		for idx < len(upper) && upper[idx] >= '0' && upper[idx] <= '9' {
			idx++
		}
		if start < idx {
			code, _ := strconv.Atoi(upper[start:idx])
			return code
		}
	}
	return 0
}

func oracleGenerateSpeedyKey(buffer, key []byte, turns int) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(append(buffer, 0, 0, 0, 1))
	firstHash := mac.Sum(nil)
	tempHash := make([]byte, len(firstHash))
	copy(tempHash, firstHash)
	for i := 2; i <= turns; i++ {
		mac.Reset()
		mac.Write(tempHash)
		tempHash = mac.Sum(nil)
		for j := 0; j < 64; j++ {
			firstHash[j] ^= tempHash[j]
		}
	}
	return firstHash
}

func oracleKeyFromUserPass(username, password string) ([]byte, error) {
	username = strings.ToUpper(username)
	password = strings.ToUpper(password)
	extend := func(s string) []byte {
		out := make([]byte, len(s)*2)
		for i, c := range []byte(s) {
			out[i*2] = 0
			out[i*2+1] = c
		}
		return out
	}
	buf := append(extend(username), extend(password)...)
	if len(buf)%8 != 0 {
		buf = append(buf, make([]byte, 8-len(buf)%8)...)
	}
	desEnc := func(input, key []byte) ([]byte, error) {
		ret := make([]byte, 8)
		enc, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(input)/8; i++ {
			for j := 0; j < 8; j++ {
				ret[j] ^= input[i*8+j]
			}
			out := make([]byte, 8)
			enc.Encrypt(out, ret)
			copy(ret, out)
		}
		return ret, nil
	}
	key1, err := desEnc(buf, []byte{1, 35, 69, 103, 137, 171, 205, 239})
	if err != nil {
		return nil, err
	}
	key2, err := desEnc(buf, key1)
	if err != nil {
		return nil, err
	}
	return append(key2, make([]byte, 8)...), nil
}

func oracleDecryptSessionKey(padding bool, encKey []byte, sessionKey string) ([]byte, error) {
	data, err := hex.DecodeString(sessionKey)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(blk, make([]byte, 16)).CryptBlocks(out, data)
	cut := 0
	if padding && len(out) > 0 {
		n := int(out[len(out)-1])
		if n < blk.BlockSize() && n <= len(out) {
			ok := true
			for i := len(out) - n; i < len(out); i++ {
				if out[i] != byte(n) {
					ok = false
					break
				}
			}
			if ok {
				cut = n
			}
		}
	}
	return out[:len(out)-cut], nil
}

func oracleEncryptSessionKey(padding bool, encKey, sessionKey []byte) (string, error) {
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	origLen := len(sessionKey)
	sessionKey = oraclePKCS5Padding(sessionKey, blk.BlockSize())
	out := make([]byte, len(sessionKey))
	cipher.NewCBCEncrypter(blk, make([]byte, 16)).CryptBlocks(out, sessionKey)
	if !padding {
		return fmt.Sprintf("%X", out[:origLen]), nil
	}
	return fmt.Sprintf("%X", out), nil
}

func oracleEncryptPassword(password, key []byte, padding bool) (string, error) {
	prefix := make([]byte, 0x10)
	if _, err := rand.Read(prefix); err != nil {
		return "", err
	}
	return oracleEncryptSessionKey(padding, key, append(prefix, password...))
}

func (auth *oracleAuthObject) passwordEncKey(nego *oracleTCPNego) ([]byte, error) {
	hash := md5.New()
	key1 := auth.serverSessKey
	key2 := auth.clientSessKey
	start := 16
	if len(nego.serverCompileTimeCaps) > 4 && nego.serverCompileTimeCaps[4]&32 != 0 {
		var keyBuffer string
		var retLen int
		switch auth.verifierType {
		case 2361:
			keyBuffer = fmt.Sprintf("%X", append(key2[:len(key2)/2], key1[:len(key1)/2]...))
			retLen = 16
		case 6949:
			keyBuffer = fmt.Sprintf("%X", append(key2[:24], key1[:24]...))
			retLen = 24
		case 18453:
			keyBuffer = fmt.Sprintf("%X", append(key2, key1...))
			retLen = 32
		default:
			return nil, errors.New("unsupported oracle verifier type")
		}
		df2key, err := hex.DecodeString(auth.pbkdf2ChkSalt)
		if err != nil {
			return nil, err
		}
		return oracleGenerateSpeedyKey(df2key, []byte(keyBuffer), auth.pbkdf2SderCount)[:retLen], nil
	}
	switch auth.verifierType {
	case 2361:
		buf := make([]byte, 16)
		for i := 0; i < 16; i++ {
			buf[i] = key1[i+start] ^ key2[i+start]
		}
		_, _ = hash.Write(buf)
		return hash.Sum(nil), nil
	case 6949:
		buf := make([]byte, 24)
		for i := 0; i < 24; i++ {
			buf[i] = key1[i+start] ^ key2[i+start]
		}
		_, _ = hash.Write(buf[:16])
		ret := hash.Sum(nil)
		hash.Reset()
		_, _ = hash.Write(buf[16:])
		ret = append(ret, hash.Sum(nil)...)
		return ret[:24], nil
	default:
		return nil, errors.New("unsupported oracle verifier type")
	}
}

func oraclePKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	return append(src, bytes.Repeat([]byte{byte(padding)}, padding)...)
}
