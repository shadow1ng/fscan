//go:build plugin_mssql || !plugin_selective

package services

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"
	"unicode/utf16"
)

const (
	tdsPacketReply    = 4
	tdsPacketLogin7   = 16
	tdsPacketPrelogin = 18

	tdsStatusEOM = 1

	tdsVersion74        = 0x74000004
	tdsDefaultPacketLen = 4096

	tdsPreloginVersion    = 0
	tdsPreloginEncryption = 1
	tdsPreloginInstOpt    = 2
	tdsPreloginThreadID   = 3
	tdsPreloginMARS       = 4
	tdsPreloginTerminator = 0xff

	tdsEncryptNotSupported = 2

	tdsTokenError      = 0xaa
	tdsTokenInfo       = 0xab
	tdsTokenLoginAck   = 0xad
	tdsTokenEnvChange  = 0xe3
	tdsTokenDone       = 0xfd
	tdsTokenDoneProc   = 0xfe
	tdsTokenDoneInProc = 0xff

	tdsDoneError    = 0x0002
	tdsDoneSrvError = 0x0100

	tdsOptionUseDB   = 0x20
	tdsOptionSetLang = 0x80
	tdsOptionODBC    = 0x02

	tdsLoginHeaderLen = 94
)

type mssqlRawResult struct {
	sawPrelogin bool
	sawLoginAck bool
	errors      []mssqlRawError
}

func (r *mssqlRawResult) isMSSQL() bool {
	return r != nil && (r.sawPrelogin || r.sawLoginAck || len(r.errors) > 0)
}

type mssqlRawError struct {
	number  int32
	message string
}

func (e mssqlRawError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("mssql: error %d", e.number)
	}
	return "mssql: " + e.message
}

func mssqlRawLogin(ctx context.Context, host string, port int, username, password string, timeout time.Duration) (*mssqlRawResult, error) {
	target := net.JoinHostPort(host, fmt.Sprint(port))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	result := &mssqlRawResult{}
	if err := mssqlSendPrelogin(conn); err != nil {
		return result, err
	}
	if err := mssqlReadPrelogin(conn); err != nil {
		return result, err
	}
	result.sawPrelogin = true

	if err := mssqlSendLogin7(conn, host, username, password); err != nil {
		return result, err
	}
	if err := mssqlReadLoginResponse(conn, result); err != nil {
		return result, err
	}
	if len(result.errors) > 0 {
		return result, result.errors[len(result.errors)-1]
	}
	if !result.sawLoginAck {
		return result, fmt.Errorf("mssql: login acknowledgement not received")
	}
	return result, nil
}

func mssqlSendPrelogin(w io.Writer) error {
	fields := map[byte][]byte{
		tdsPreloginVersion:    {0, 0, 0, 0, 0, 0},
		tdsPreloginEncryption: {tdsEncryptNotSupported},
		tdsPreloginInstOpt:    {0},
		tdsPreloginThreadID:   {0, 0, 0, 0},
		tdsPreloginMARS:       {0},
	}

	keys := make([]int, 0, len(fields))
	for k := range fields {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	payload := bytes.NewBuffer(nil)
	offset := uint16(len(fields)*5 + 1)
	for _, key := range keys {
		value := fields[byte(key)]
		payload.WriteByte(byte(key))
		_ = binary.Write(payload, binary.BigEndian, offset)
		_ = binary.Write(payload, binary.BigEndian, uint16(len(value)))
		offset += uint16(len(value))
	}
	payload.WriteByte(tdsPreloginTerminator)
	for _, key := range keys {
		payload.Write(fields[byte(key)])
	}

	return mssqlWritePacket(w, tdsPacketPrelogin, payload.Bytes())
}

func mssqlReadPrelogin(r io.Reader) error {
	packetType, payload, err := mssqlReadMessage(r)
	if err != nil {
		return err
	}
	if packetType != tdsPacketReply {
		return fmt.Errorf("mssql: invalid prelogin response packet type %d", packetType)
	}
	if len(payload) == 0 {
		return fmt.Errorf("mssql: empty prelogin response")
	}

	fields, err := mssqlParsePreloginFields(payload)
	if err != nil {
		return err
	}
	if _, ok := fields[tdsPreloginEncryption]; !ok {
		return fmt.Errorf("mssql: prelogin response missing encryption field")
	}
	return nil
}

func mssqlParsePreloginFields(payload []byte) (map[byte][]byte, error) {
	fields := make(map[byte][]byte)
	for pos := 0; ; pos += 5 {
		if pos >= len(payload) {
			return nil, fmt.Errorf("mssql: invalid prelogin option table")
		}
		token := payload[pos]
		if token == tdsPreloginTerminator {
			return fields, nil
		}
		if pos+5 > len(payload) {
			return nil, fmt.Errorf("mssql: truncated prelogin option")
		}
		offset := int(binary.BigEndian.Uint16(payload[pos+1 : pos+3]))
		length := int(binary.BigEndian.Uint16(payload[pos+3 : pos+5]))
		if offset < 0 || length < 0 || offset+length > len(payload) {
			return nil, fmt.Errorf("mssql: invalid prelogin option bounds")
		}
		fields[token] = payload[offset : offset+length]
	}
}

func mssqlSendLogin7(w io.Writer, host, username, password string) error {
	hostname, _ := os.Hostname()
	values := []struct {
		text     string
		password bool
	}{
		{hostname, false},
		{username, false},
		{password, true},
		{"fscan", false},
		{host, false},
		{"fscan", false},
		{"", false},
		{"master", false},
		{"", false},
		{"", false},
	}

	encoded := make([][]byte, len(values))
	lengths := make([]uint16, len(values))
	for i, value := range values {
		if value.password {
			encoded[i] = mssqlEncodePassword(value.text)
		} else {
			encoded[i] = mssqlUCS2(value.text)
		}
		lengths[i] = uint16(len(encoded[i]) / 2)
	}

	offsets := make([]uint16, len(values))
	offset := uint16(tdsLoginHeaderLen)
	for i, value := range encoded {
		offsets[i] = offset
		offset += uint16(len(value))
	}

	body := bytes.NewBuffer(make([]byte, 0, int(offset)))
	put32 := func(v uint32) { _ = binary.Write(body, binary.LittleEndian, v) }
	put16 := func(v uint16) { _ = binary.Write(body, binary.LittleEndian, v) }

	put32(uint32(offset))
	put32(tdsVersion74)
	put32(tdsDefaultPacketLen)
	put32(0)
	put32(uint32(os.Getpid()))
	put32(0)
	body.WriteByte(tdsOptionUseDB | tdsOptionSetLang)
	body.WriteByte(tdsOptionODBC)
	body.WriteByte(0)
	body.WriteByte(0)
	put32(0)
	put32(0)

	for i := 0; i < 5; i++ {
		put16(offsets[i])
		put16(lengths[i])
	}
	put16(0)
	put16(0)
	for i := 5; i < 8; i++ {
		put16(offsets[i])
		put16(lengths[i])
	}
	body.Write([]byte{0, 0, 0, 0, 0, 0})
	put16(offsets[8])
	put16(0)
	for i := 8; i < 10; i++ {
		put16(offsets[i])
		put16(lengths[i])
	}
	put32(0)

	for _, value := range encoded {
		body.Write(value)
	}
	return mssqlWritePacket(w, tdsPacketLogin7, body.Bytes())
}

func mssqlReadLoginResponse(r io.Reader, result *mssqlRawResult) error {
	for {
		packetType, payload, err := mssqlReadMessage(r)
		if err != nil {
			return err
		}
		if packetType != tdsPacketReply {
			return fmt.Errorf("mssql: unexpected login response packet type %d", packetType)
		}
		done, err := mssqlParseLoginTokens(payload, result)
		if err != nil {
			return err
		}
		if done || result.sawLoginAck || len(result.errors) > 0 {
			return nil
		}
	}
}

func mssqlParseLoginTokens(payload []byte, result *mssqlRawResult) (bool, error) {
	pos := 0
	for pos < len(payload) {
		token := payload[pos]
		pos++
		switch token {
		case tdsTokenError:
			errMsg, next, err := mssqlParseErrorToken(payload, pos)
			if err != nil {
				return false, err
			}
			result.errors = append(result.errors, errMsg)
			pos = next
		case tdsTokenInfo:
			next, err := mssqlSkipUSVarError(payload, pos)
			if err != nil {
				return false, err
			}
			pos = next
		case tdsTokenEnvChange:
			next, err := mssqlSkipLen16(payload, pos)
			if err != nil {
				return false, err
			}
			pos = next
		case tdsTokenLoginAck:
			next, err := mssqlSkipLen16(payload, pos)
			if err != nil {
				return false, err
			}
			result.sawLoginAck = true
			pos = next
		case tdsTokenDone, tdsTokenDoneProc, tdsTokenDoneInProc:
			if pos+12 > len(payload) {
				return false, fmt.Errorf("mssql: truncated done token")
			}
			status := binary.LittleEndian.Uint16(payload[pos : pos+2])
			return status&(tdsDoneError|tdsDoneSrvError) == 0, nil
		default:
			return false, fmt.Errorf("mssql: unexpected login token 0x%02x", token)
		}
	}
	return false, nil
}

func mssqlParseErrorToken(payload []byte, pos int) (mssqlRawError, int, error) {
	if pos+2 > len(payload) {
		return mssqlRawError{}, pos, fmt.Errorf("mssql: truncated error token")
	}
	size := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	end := pos + 2 + size
	if size < 6 || end > len(payload) || pos+8 > len(payload) {
		return mssqlRawError{}, pos, fmt.Errorf("mssql: invalid error token size")
	}
	pos += 2
	number := int32(binary.LittleEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	pos += 2
	message, next, err := mssqlReadUSVarChar(payload, pos)
	if err != nil {
		return mssqlRawError{}, pos, err
	}
	return mssqlRawError{number: number, message: message}, end, mssqlEnsureSkipBVarStrings(payload, next, end)
}

func mssqlSkipUSVarError(payload []byte, pos int) (int, error) {
	if pos+2 > len(payload) {
		return pos, fmt.Errorf("mssql: truncated info token")
	}
	size := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	end := pos + 2 + size
	if size < 6 || end > len(payload) || pos+8 > len(payload) {
		return pos, fmt.Errorf("mssql: invalid info token size")
	}
	_, _, err := mssqlReadUSVarChar(payload, pos+8)
	return end, err
}

func mssqlEnsureSkipBVarStrings(payload []byte, pos, end int) error {
	for i := 0; i < 2; i++ {
		if pos >= end {
			return fmt.Errorf("mssql: truncated string in error token")
		}
		length := int(payload[pos]) * 2
		pos++
		if pos+length > end {
			return fmt.Errorf("mssql: invalid string in error token")
		}
		pos += length
	}
	if pos+4 > end {
		return fmt.Errorf("mssql: truncated error line number")
	}
	return nil
}

func mssqlSkipLen16(payload []byte, pos int) (int, error) {
	if pos+2 > len(payload) {
		return pos, fmt.Errorf("mssql: truncated token")
	}
	size := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	next := pos + 2 + size
	if next > len(payload) {
		return pos, fmt.Errorf("mssql: invalid token size")
	}
	return next, nil
}

func mssqlReadUSVarChar(payload []byte, pos int) (string, int, error) {
	if pos+2 > len(payload) {
		return "", pos, fmt.Errorf("mssql: truncated us varchar")
	}
	chars := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	size := chars * 2
	if pos+size > len(payload) {
		return "", pos, fmt.Errorf("mssql: invalid us varchar size")
	}
	return mssqlDecodeUCS2(payload[pos : pos+size]), pos + size, nil
}

func mssqlWritePacket(w io.Writer, packetType byte, payload []byte) error {
	if len(payload)+8 > 0xffff {
		return fmt.Errorf("mssql: packet too large")
	}
	header := []byte{packetType, tdsStatusEOM, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)+8))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func mssqlReadMessage(r io.Reader) (byte, []byte, error) {
	var packetType byte
	var payload []byte
	for {
		header := make([]byte, 8)
		if _, err := io.ReadFull(r, header); err != nil {
			return 0, nil, err
		}
		if packetType == 0 {
			packetType = header[0]
		} else if packetType != header[0] {
			return 0, nil, fmt.Errorf("mssql: packet type changed in message")
		}
		size := int(binary.BigEndian.Uint16(header[2:4]))
		if size < 8 {
			return 0, nil, fmt.Errorf("mssql: invalid packet size")
		}
		chunk := make([]byte, size-8)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return 0, nil, err
		}
		payload = append(payload, chunk...)
		if header[1]&tdsStatusEOM != 0 {
			return packetType, payload, nil
		}
	}
}

func mssqlUCS2(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

func mssqlDecodeUCS2(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	runes := make([]uint16, len(data)/2)
	for i := range runes {
		runes[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(runes))
}

func mssqlEncodePassword(password string) []byte {
	out := mssqlUCS2(password)
	for i, ch := range out {
		out[i] = (((ch << 4) & 0xff) | (ch >> 4)) ^ 0xa5
	}
	return out
}
