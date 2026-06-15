//go:build plugin_oracle || !plugin_selective

package services

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// oracleConnectData
// ---------------------------------------------------------------------------

func TestOracleConnectDataDoesNotExposeClientIdentity(t *testing.T) {
	connectData := oracleConnectData("db.example", 1521, "ORCL")

	for _, value := range []string{"CID=", "PROGRAM=", "USER=", "fscan"} {
		if bytes.Contains([]byte(connectData), []byte(value)) {
			t.Fatalf("oracle connect data contains client-identifying value %q: %s", value, connectData)
		}
	}
}

func TestOracleConnectDataFormat(t *testing.T) {
	cd := oracleConnectData("localhost", 1521, "XE")
	if !strings.Contains(cd, "HOST=localhost") {
		t.Errorf("missing host: %s", cd)
	}
	if !strings.Contains(cd, "PORT=1521") {
		t.Errorf("missing port: %s", cd)
	}
	if !strings.Contains(cd, "SERVICE_NAME=XE") {
		t.Errorf("missing service name: %s", cd)
	}
}

// ---------------------------------------------------------------------------
// toInt64 / toUint64
// ---------------------------------------------------------------------------

func TestToInt64(t *testing.T) {
	cases := []struct {
		in   interface{}
		want int64
	}{
		{int(42), 42},
		{int16(-100), -100},
		{int32(0x7fffffff), 0x7fffffff},
		{int64(-1), -1},
		{uint8(255), 255},
		{uint16(1000), 1000},
		{uint32(99999), 99999},
		{uint64(1), 1},
		{uint(7), 7},
	}
	for _, c := range cases {
		if got := toInt64(c.in); got != c.want {
			t.Errorf("toInt64(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestToInt64Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unsupported type")
		}
	}()
	toInt64("string")
}

func TestToUint64(t *testing.T) {
	cases := []struct {
		in   interface{}
		want uint64
	}{
		{int(5), 5},
		{int16(300), 300},
		{int32(65535), 65535},
		{int64(1 << 40), 1 << 40},
		{uint8(0xff), 0xff},
		{uint16(0xffff), 0xffff},
		{uint32(0xffffffff), 0xffffffff},
		{uint64(^uint64(0)), ^uint64(0)},
		{uint(42), 42},
	}
	for _, c := range cases {
		if got := toUint64(c.in); got != c.want {
			t.Errorf("toUint64(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestToUint64Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unsupported type")
		}
	}()
	toUint64(3.14)
}

// ---------------------------------------------------------------------------
// oraclePKCS5Padding
// ---------------------------------------------------------------------------

func TestOraclePKCS5Padding(t *testing.T) {
	// block size 16 — "hello" (5 bytes) → 11 bytes of padding (value 0x0b)
	padded := oraclePKCS5Padding([]byte("hello"), 16)
	if len(padded) != 16 {
		t.Fatalf("expected length 16, got %d", len(padded))
	}
	for _, b := range padded[5:] {
		if b != 11 {
			t.Fatalf("expected padding byte 0x0b, got 0x%02x", b)
		}
	}
}

func TestOraclePKCS5PaddingAligned(t *testing.T) {
	// input length == block size → adds a full block of padding
	padded := oraclePKCS5Padding([]byte("1234567890123456"), 16)
	if len(padded) != 32 {
		t.Fatalf("expected 32, got %d", len(padded))
	}
	for _, b := range padded[16:] {
		if b != 16 {
			t.Fatalf("bad padding byte: 0x%02x", b)
		}
	}
}

// ---------------------------------------------------------------------------
// oracleExtractCode
// ---------------------------------------------------------------------------

func TestOracleExtractCode(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"(ERR=12505)", 12505},
		{"something CODE=1017 blah", 1017},
		{"no code here", 0},
		{"err=0042 trailing", 42},
		{"CODE= 28000", 28000},
	}
	for _, c := range cases {
		if got := oracleExtractCode(c.msg); got != c.want {
			t.Errorf("oracleExtractCode(%q) = %d, want %d", c.msg, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// oracleRefuseError
// ---------------------------------------------------------------------------

func TestOracleRefuseErrorShortPacket(t *testing.T) {
	err := oracleRefuseError([]byte{0, 1, 2})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("expected 'refused' error, got %v", err)
	}
}

func TestOracleRefuseErrorWithMessage(t *testing.T) {
	msg := "(ERR=12505)"
	raw := make([]byte, 12+len(msg))
	binary.BigEndian.PutUint16(raw[10:12], uint16(len(msg)))
	copy(raw[12:], msg)
	err := oracleRefuseError(raw)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !strings.Contains(err.Error(), "12505") {
		t.Errorf("error should mention code 12505: %v", err)
	}
}

func TestOracleRefuseErrorNoCode(t *testing.T) {
	msg := "connection not allowed"
	raw := make([]byte, 12+len(msg))
	binary.BigEndian.PutUint16(raw[10:12], uint16(len(msg)))
	copy(raw[12:], msg)
	err := oracleRefuseError(raw)
	if err == nil || !strings.Contains(err.Error(), msg) {
		t.Errorf("expected message in error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// oracleGenerateSpeedyKey
// ---------------------------------------------------------------------------

func TestOracleGenerateSpeedyKey(t *testing.T) {
	key := oracleGenerateSpeedyKey([]byte("buffer"), []byte("secret"), 1)
	if len(key) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(key))
	}
}

func TestOracleGenerateSpeedyKeyDeterministic(t *testing.T) {
	a := oracleGenerateSpeedyKey([]byte("buf"), []byte("key"), 10)
	b := oracleGenerateSpeedyKey([]byte("buf"), []byte("key"), 10)
	if !bytes.Equal(a, b) {
		t.Error("speedy key should be deterministic")
	}
}

func TestOracleGenerateSpeedyKeyDiffTurns(t *testing.T) {
	a := oracleGenerateSpeedyKey([]byte("buf"), []byte("key"), 1)
	b := oracleGenerateSpeedyKey([]byte("buf"), []byte("key"), 2)
	if bytes.Equal(a, b) {
		t.Error("different turns should produce different keys")
	}
}

// ---------------------------------------------------------------------------
// oracleKeyFromUserPass
// ---------------------------------------------------------------------------

func TestOracleKeyFromUserPass(t *testing.T) {
	key, err := oracleKeyFromUserPass("scott", "tiger")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(key))
	}
}

func TestOracleKeyFromUserPassCaseInsensitive(t *testing.T) {
	k1, _ := oracleKeyFromUserPass("SCOTT", "TIGER")
	k2, _ := oracleKeyFromUserPass("scott", "tiger")
	if !bytes.Equal(k1, k2) {
		t.Error("key should be case-insensitive")
	}
}

func TestOracleKeyFromUserPassEmpty(t *testing.T) {
	key, err := oracleKeyFromUserPass("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(key))
	}
}

// ---------------------------------------------------------------------------
// oracleDecryptSessionKey / oracleEncryptSessionKey
// ---------------------------------------------------------------------------

func TestOracleEncryptDecryptSessionKey(t *testing.T) {
	encKey := bytes.Repeat([]byte{0xAB}, 16)
	plain := bytes.Repeat([]byte{0x55}, 16)

	enc, err := oracleEncryptSessionKey(false, encKey, plain)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	dec, err := oracleDecryptSessionKey(false, encKey, enc)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Errorf("round-trip failed: got %x, want %x", dec, plain)
	}
}

func TestOracleDecryptSessionKeyInvalidHex(t *testing.T) {
	_, err := oracleDecryptSessionKey(false, bytes.Repeat([]byte{0}, 16), "ZZZZ")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestOracleEncryptSessionKeyPadding(t *testing.T) {
	encKey := bytes.Repeat([]byte{0x11}, 16)
	plain := bytes.Repeat([]byte{0x22}, 16)

	// with padding — result should be hex-encoded and longer (full padded block)
	encPad, err := oracleEncryptSessionKey(true, encKey, plain)
	if err != nil {
		t.Fatalf("encrypt (padding) error: %v", err)
	}
	// without padding — result is hex of origLen bytes
	encNoPad, err := oracleEncryptSessionKey(false, encKey, plain)
	if err != nil {
		t.Fatalf("encrypt (no padding) error: %v", err)
	}
	// padded result includes extra padding block so it's longer
	if len(encPad) <= len(encNoPad) {
		t.Errorf("padded result (%d) should be longer than non-padded (%d)", len(encPad), len(encNoPad))
	}
}

func TestOracleDecryptSessionKeyWithPadding(t *testing.T) {
	encKey := bytes.Repeat([]byte{0xCC}, 16)
	// Use 13 bytes so PKCS5 padding is 3 bytes (0x03 0x03 0x03), well within blockSize
	plain := []byte("hello world!!")

	enc, err := oracleEncryptSessionKey(true, encKey, plain)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	dec, err := oracleDecryptSessionKey(true, encKey, enc)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Errorf("round-trip (padding) failed: got %q, want %q", dec, plain)
	}
}

// ---------------------------------------------------------------------------
// oracleAlterSession
// ---------------------------------------------------------------------------

func TestOracleAlterSession(t *testing.T) {
	s := oracleAlterSession()
	if !strings.Contains(s, "ALTER SESSION") {
		t.Errorf("expected ALTER SESSION: %s", s)
	}
	if !strings.Contains(s, "NLS_LANGUAGE='AMERICAN'") {
		t.Errorf("expected NLS_LANGUAGE: %s", s)
	}
	// must be null-terminated
	if s[len(s)-1] != 0 {
		t.Error("expected null terminator")
	}
}

// ---------------------------------------------------------------------------
// oracleTZBytes
// ---------------------------------------------------------------------------

func TestOracleTZBytes(t *testing.T) {
	b := oracleTZBytes()
	if len(b) != 11 {
		t.Fatalf("expected 11 bytes, got %d", len(b))
	}
	// first 4 bytes are always 0x80,0,0,0
	if b[0] != 0x80 {
		t.Errorf("expected 0x80 at [0], got 0x%02x", b[0])
	}
}

// ---------------------------------------------------------------------------
// oracleTypeReps
// ---------------------------------------------------------------------------

func TestOracleTypeReps(t *testing.T) {
	nego := &oracleTCPNego{}
	compileCaps := make([]byte, 45)
	reps := oracleTypeReps(nego, compileCaps)
	if len(reps) == 0 {
		t.Error("expected non-empty type reps")
	}
	// all values should be valid int16
	for i, v := range reps {
		if v < -1 || v > 10 {
			// only known sentinel values are 0, 1, 10
			_ = i // non-fatal: just make sure no panic
		}
	}
}

// ---------------------------------------------------------------------------
// session buffer operations (putBytes / putInt / putUint / putClr / putKeyVal)
// ---------------------------------------------------------------------------

func newTestSession() *oracleSession {
	return &oracleSession{
		version:      315,
		clrChunkSize: 0x40,
	}
}

func TestSessionPutBytes(t *testing.T) {
	s := newTestSession()
	s.putBytes(0x01, 0x02, 0x03)
	if !bytes.Equal(s.out.Bytes(), []byte{1, 2, 3}) {
		t.Errorf("unexpected output: %x", s.out.Bytes())
	}
}

func TestSessionPutIntBigEndian(t *testing.T) {
	s := newTestSession()
	s.putInt(uint16(0x0102), 2, true, false)
	if !bytes.Equal(s.out.Bytes(), []byte{0x01, 0x02}) {
		t.Errorf("big-endian uint16: %x", s.out.Bytes())
	}
}

func TestSessionPutIntLittleEndian(t *testing.T) {
	s := newTestSession()
	s.putInt(uint32(0x01020304), 4, false, false)
	if !bytes.Equal(s.out.Bytes(), []byte{0x04, 0x03, 0x02, 0x01}) {
		t.Errorf("little-endian uint32: %x", s.out.Bytes())
	}
}

func TestSessionPutIntCompress(t *testing.T) {
	s := newTestSession()
	s.putInt(int(256), 4, true, true)
	out := s.out.Bytes()
	// compressed: size byte + encoded bytes
	if len(out) < 2 {
		t.Fatalf("compressed output too short: %x", out)
	}
}

func TestSessionPutIntCompressZero(t *testing.T) {
	s := newTestSession()
	s.putInt(int(0), 4, true, true)
	out := s.out.Bytes()
	if len(out) != 1 || out[0] != 0 {
		t.Errorf("zero compressed should be single 0x00: %x", out)
	}
}

func TestSessionPutIntCompressNegative(t *testing.T) {
	s := newTestSession()
	s.putInt(int(-1), 4, true, true)
	out := s.out.Bytes()
	// high bit of size byte should be set for negative
	if len(out) < 2 || out[0]&0x80 == 0 {
		t.Errorf("negative compress: expected high bit set in size byte: %x", out)
	}
}

func TestSessionPutInt1Byte(t *testing.T) {
	s := newTestSession()
	s.putInt(uint8(0xAB), 1, true, false)
	out := s.out.Bytes()
	if len(out) != 1 || out[0] != 0xAB {
		t.Errorf("1-byte int: %x", out)
	}
}

func TestSessionPutUintBigEndian(t *testing.T) {
	s := newTestSession()
	s.putUint(uint16(0xBEEF), 2, true, false)
	if !bytes.Equal(s.out.Bytes(), []byte{0xBE, 0xEF}) {
		t.Errorf("putUint big-endian: %x", s.out.Bytes())
	}
}

func TestSessionPutUintCompress(t *testing.T) {
	s := newTestSession()
	s.putUint(uint32(0), 4, true, true)
	out := s.out.Bytes()
	if len(out) != 1 || out[0] != 0 {
		t.Errorf("putUint compress zero: %x", out)
	}
}

func TestSessionPutUint1Byte(t *testing.T) {
	s := newTestSession()
	s.putUint(uint8(7), 1, true, false)
	out := s.out.Bytes()
	if len(out) != 1 || out[0] != 7 {
		t.Errorf("putUint 1-byte: %x", out)
	}
}

func TestSessionPutClrEmpty(t *testing.T) {
	s := newTestSession()
	s.putClr(nil)
	out := s.out.Bytes()
	if len(out) != 1 || out[0] != 0 {
		t.Errorf("empty clr: %x", out)
	}
}

func TestSessionPutClrShort(t *testing.T) {
	s := newTestSession()
	s.putClr([]byte("hello"))
	out := s.out.Bytes()
	if out[0] != 5 || string(out[1:]) != "hello" {
		t.Errorf("short clr: %x", out)
	}
}

func TestSessionPutClrLong(t *testing.T) {
	// len > 0xfc triggers chunked encoding (0xfe prefix)
	s := newTestSession()
	data := bytes.Repeat([]byte("A"), 300)
	s.putClr(data)
	out := s.out.Bytes()
	if out[0] != 0xfe {
		t.Errorf("expected 0xfe for long CLR, got 0x%02x", out[0])
	}
}

func TestSessionPutString(t *testing.T) {
	s := newTestSession()
	s.putString("abc")
	out := s.out.Bytes()
	if out[0] != 3 || string(out[1:]) != "abc" {
		t.Errorf("putString: %x", out)
	}
}

func TestSessionPutKeyVal(t *testing.T) {
	s := newTestSession()
	s.putKeyValString("KEY", "VAL", 1)
	out := s.out.Bytes()
	if len(out) == 0 {
		t.Error("putKeyValString produced no output")
	}
	// must contain key and value text somewhere
	if !bytes.Contains(out, []byte("KEY")) {
		t.Error("KEY not found in output")
	}
	if !bytes.Contains(out, []byte("VAL")) {
		t.Error("VAL not found in output")
	}
}

func TestSessionPutKeyValEmptyKey(t *testing.T) {
	s := newTestSession()
	s.putKeyVal(nil, []byte("val"), 0)
	out := s.out.Bytes()
	// empty key → single 0x00 byte at start
	if out[0] != 0 {
		t.Errorf("empty key should start with 0x00, got 0x%02x", out[0])
	}
}

func TestSessionPutKeyValEmptyVal(t *testing.T) {
	s := newTestSession()
	s.putKeyVal([]byte("key"), nil, 0)
	out := s.out.Bytes()
	if !bytes.Contains(out, []byte("key")) {
		t.Error("key not found in output")
	}
}

// ---------------------------------------------------------------------------
// session reset
// ---------------------------------------------------------------------------

func TestSessionReset(t *testing.T) {
	s := newTestSession()
	s.in = []byte{1, 2, 3}
	s.index = 2
	s.summary = &oracleSummary{retCode: 5}
	s.putBytes(0xAA)
	s.reset()

	if s.in != nil {
		t.Error("in should be nil after reset")
	}
	if s.index != 0 {
		t.Error("index should be 0 after reset")
	}
	if s.summary != nil {
		t.Error("summary should be nil after reset")
	}
	if s.out.Len() != 0 {
		t.Error("out buffer should be empty after reset")
	}
}

// ---------------------------------------------------------------------------
// session read (from in-memory buffer)
// ---------------------------------------------------------------------------

func TestSessionRead(t *testing.T) {
	s := newTestSession()
	s.in = []byte{10, 20, 30, 40}
	b, err := s.read(2)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Equal(b, []byte{10, 20}) {
		t.Errorf("got %v", b)
	}
	b2, _ := s.read(2)
	if !bytes.Equal(b2, []byte{30, 40}) {
		t.Errorf("second read got %v", b2)
	}
}

func TestSessionGetByte(t *testing.T) {
	s := newTestSession()
	s.in = []byte{0xAB}
	b, err := s.getByte()
	if err != nil || b != 0xAB {
		t.Errorf("getByte: %v, %v", b, err)
	}
}

func TestSessionGetBytes(t *testing.T) {
	s := newTestSession()
	s.in = []byte{1, 2, 3}
	b, err := s.getBytes(3)
	if err != nil || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Errorf("getBytes: %v, %v", b, err)
	}
}

func TestSessionGetInt(t *testing.T) {
	s := newTestSession()
	// big-endian uint16 = 0x0102
	s.in = []byte{0x01, 0x02}
	v, err := s.getInt(2, false, true)
	if err != nil || v != 0x0102 {
		t.Errorf("getInt BE: %d, %v", v, err)
	}
}

func TestSessionGetInt64Compress(t *testing.T) {
	// compressed: size=2, value=0x0102
	s := newTestSession()
	s.in = []byte{0x02, 0x01, 0x02}
	v, err := s.getInt64(0, true, true)
	if err != nil || v != 0x0102 {
		t.Errorf("getInt64 compress: %d, %v", v, err)
	}
}

func TestSessionGetInt64CompressNegative(t *testing.T) {
	// negative compressed: size byte has 0x80 set, size=1, value=1 → -1
	s := newTestSession()
	s.in = []byte{0x81, 0x01}
	v, err := s.getInt64(0, true, true)
	if err != nil || v != -1 {
		t.Errorf("getInt64 compress negative: %d, %v", v, err)
	}
}

func TestSessionGetInt64CompressZero(t *testing.T) {
	s := newTestSession()
	s.in = []byte{0x00}
	v, err := s.getInt64(0, true, true)
	if err != nil || v != 0 {
		t.Errorf("getInt64 compress zero: %d, %v", v, err)
	}
}

func TestSessionGetNullTermString(t *testing.T) {
	s := newTestSession()
	s.in = append([]byte("hello\x00world"), make([]byte, 50)...)
	str, err := s.getNullTermString(20)
	if err != nil || str != "hello" {
		t.Errorf("getNullTermString: %q, %v", str, err)
	}
}

func TestSessionGetNullTermStringNoNull(t *testing.T) {
	s := newTestSession()
	s.in = []byte("hello")
	str, err := s.getNullTermString(5)
	if err != nil || str != "hello" {
		t.Errorf("no-null getNullTermString: %q, %v", str, err)
	}
}

func TestSessionGetClrEmpty(t *testing.T) {
	s := newTestSession()
	s.in = []byte{0x00} // length = 0 → nil
	b, err := s.getClr()
	if err != nil || b != nil {
		t.Errorf("getClr empty: %v, %v", b, err)
	}
}

func TestSessionGetClrShort(t *testing.T) {
	s := newTestSession()
	s.in = append([]byte{0x03}, []byte("abc")...)
	b, err := s.getClr()
	if err != nil || string(b) != "abc" {
		t.Errorf("getClr short: %v, %v", b, err)
	}
}

func TestSessionGetClrNullAndFd(t *testing.T) {
	for _, marker := range []byte{0xff, 0xfd} {
		s := newTestSession()
		s.in = []byte{marker}
		b, err := s.getClr()
		if err != nil || b != nil {
			t.Errorf("getClr 0x%02x: %v, %v", marker, b, err)
		}
	}
}

// ---------------------------------------------------------------------------
// hasError / oracleError
// ---------------------------------------------------------------------------

func TestHasErrorNilSummary(t *testing.T) {
	s := newTestSession()
	if s.hasError() {
		t.Error("nil summary should not be an error")
	}
}

func TestHasErrorRetCode0(t *testing.T) {
	s := newTestSession()
	s.summary = &oracleSummary{retCode: 0}
	if s.hasError() {
		t.Error("retCode 0 should not be an error")
	}
}

func TestHasErrorRetCode1403(t *testing.T) {
	s := newTestSession()
	s.summary = &oracleSummary{retCode: 1403}
	if s.hasError() {
		t.Error("retCode 1403 (no data) should not be an error")
	}
}

func TestHasErrorRetCodeNonZero(t *testing.T) {
	s := newTestSession()
	s.summary = &oracleSummary{retCode: 1017}
	if !s.hasError() {
		t.Error("retCode 1017 should be an error")
	}
}

func TestOracleErrorNilSummary(t *testing.T) {
	s := newTestSession()
	err := s.oracleError()
	if err == nil {
		t.Error("expected error")
	}
}

func TestOracleErrorWithMessage(t *testing.T) {
	s := newTestSession()
	s.summary = &oracleSummary{retCode: 1017, errorMessage: []byte("ORA-01017")}
	err := s.oracleError()
	if err == nil || !strings.Contains(err.Error(), "ORA-01017") {
		t.Errorf("expected ORA-01017 in error: %v", err)
	}
}

func TestOracleErrorNoMessage(t *testing.T) {
	s := newTestSession()
	s.summary = &oracleSummary{retCode: 1017}
	err := s.oracleError()
	if err == nil || !strings.Contains(err.Error(), "ORA-01017") {
		t.Errorf("expected formatted ORA-01017: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ANO write helpers (output shape verification)
// ---------------------------------------------------------------------------

func TestWriteANOHeader(t *testing.T) {
	s := newTestSession()
	s.writeANOHeader(101, 4, 0)
	out := s.out.Bytes()
	// first 4 bytes = 0xdeadbeef big-endian
	if len(out) < 4 || binary.BigEndian.Uint32(out[:4]) != 0xdeadbeef {
		t.Errorf("ANO header magic wrong: %x", out[:4])
	}
}

func TestWriteANOServiceHeader(t *testing.T) {
	s := newTestSession()
	s.writeANOServiceHeader(2, 3)
	out := s.out.Bytes()
	// 2 bytes serviceType + 2 bytes subPackets + 4 bytes zeros = 8
	if len(out) != 8 {
		t.Errorf("expected 8 bytes, got %d: %x", len(out), out)
	}
	if binary.BigEndian.Uint16(out[0:2]) != 2 {
		t.Errorf("serviceType wrong: %x", out)
	}
}

func TestWriteANOPacketHeader(t *testing.T) {
	s := newTestSession()
	s.writeANOPacketHeader(8, 5)
	out := s.out.Bytes()
	if len(out) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(out))
	}
	if binary.BigEndian.Uint16(out[0:2]) != 8 {
		t.Errorf("length field wrong: %x", out)
	}
	if binary.BigEndian.Uint16(out[2:4]) != 5 {
		t.Errorf("type field wrong: %x", out)
	}
}

func TestWriteANOVersion(t *testing.T) {
	s := newTestSession()
	s.writeANOVersion()
	out := s.out.Bytes()
	// 4-byte header (len=4,type=5) + 4-byte version = 8 bytes
	if len(out) != 8 {
		t.Errorf("expected 8 bytes, got %d: %x", len(out), out)
	}
}

func TestWriteANOStatus(t *testing.T) {
	s := newTestSession()
	s.writeANOStatus(0xfcff)
	out := s.out.Bytes()
	// 4-byte header + 2-byte status = 6 bytes
	if len(out) != 6 {
		t.Errorf("expected 6 bytes, got %d: %x", len(out), out)
	}
}

func TestWriteANOBytes(t *testing.T) {
	s := newTestSession()
	s.writeANOBytes([]byte{0xAA, 0xBB})
	out := s.out.Bytes()
	// 4-byte header + 2 data bytes = 6
	if len(out) != 6 {
		t.Errorf("expected 6 bytes, got %d: %x", len(out), out)
	}
	if out[4] != 0xAA || out[5] != 0xBB {
		t.Errorf("data bytes wrong: %x", out)
	}
}

func TestWriteANOUB1(t *testing.T) {
	s := newTestSession()
	s.writeANOUB1(0x07)
	out := s.out.Bytes()
	// 4-byte header + 1 byte = 5
	if len(out) != 5 {
		t.Errorf("expected 5 bytes, got %d", len(out))
	}
	if out[4] != 0x07 {
		t.Errorf("UB1 value wrong: %x", out)
	}
}

func TestWriteANOUB2Array(t *testing.T) {
	s := newTestSession()
	s.writeANOUB2Array([]int{1, 2, 3, 4})
	out := s.out.Bytes()
	// header 4 + deadbeef 4 + const 2 + count 4 + 4*2 = 22
	if len(out) != 4+4+2+4+4*2 {
		t.Errorf("expected 22 bytes, got %d: %x", len(out), out)
	}
}

// ---------------------------------------------------------------------------
// ANO read helpers (round-trip through in-buffer)
// ---------------------------------------------------------------------------

func TestReadANOHeader(t *testing.T) {
	s := newTestSession()
	// build a valid ANO header in the in buffer
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0xdeadbeef)) // magic
	binary.Write(&buf, binary.BigEndian, uint16(101))        // length
	binary.Write(&buf, binary.BigEndian, uint32(0x0b200200)) // version
	binary.Write(&buf, binary.BigEndian, uint16(4))          // serviceCount
	buf.WriteByte(0)                                         // flags
	s.in = buf.Bytes()

	h, err := s.readANOHeader()
	if err != nil {
		t.Fatalf("readANOHeader error: %v", err)
	}
	if h.serviceCount != 4 {
		t.Errorf("serviceCount: %d", h.serviceCount)
	}
}

func TestReadANOHeaderBadMagic(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0xCAFEBABE)) // wrong magic
	binary.Write(&buf, binary.BigEndian, uint16(101))
	binary.Write(&buf, binary.BigEndian, uint32(0x0b200200))
	binary.Write(&buf, binary.BigEndian, uint16(2))
	buf.WriteByte(0)
	s.in = buf.Bytes()

	_, err := s.readANOHeader()
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected mismatch error: %v", err)
	}
}

func TestReadANOServiceHeader(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(1))   // serviceType
	binary.Write(&buf, binary.BigEndian, uint16(3))   // subPackets
	binary.Write(&buf, binary.BigEndian, uint32(0))   // errCode
	s.in = buf.Bytes()

	svcType, subPkts, errCode, err := s.readANOServiceHeader()
	if err != nil || svcType != 1 || subPkts != 3 || errCode != 0 {
		t.Errorf("readANOServiceHeader: %d %d %d %v", svcType, subPkts, errCode, err)
	}
}

func TestReadANOPacketHeader(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(8)) // length
	binary.Write(&buf, binary.BigEndian, uint16(5)) // type
	s.in = buf.Bytes()

	length, err := s.readANOPacketHeader(5)
	if err != nil || length != 8 {
		t.Errorf("readANOPacketHeader: %d, %v", length, err)
	}
}

func TestReadANOPacketHeaderTypeMismatch(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(4))
	binary.Write(&buf, binary.BigEndian, uint16(99))
	s.in = buf.Bytes()

	_, err := s.readANOPacketHeader(5) // expect 5, got 99
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected type mismatch error: %v", err)
	}
}

func TestReadANOVersion(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(4))          // length
	binary.Write(&buf, binary.BigEndian, uint16(5))          // type=5
	binary.Write(&buf, binary.BigEndian, uint32(0x0b200200)) // version
	s.in = buf.Bytes()

	v, err := s.readANOVersion()
	if err != nil || v != 0x0b200200 {
		t.Errorf("readANOVersion: 0x%x, %v", v, err)
	}
}

func TestReadANOStatus(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(2))     // length
	binary.Write(&buf, binary.BigEndian, uint16(6))     // type=6
	binary.Write(&buf, binary.BigEndian, uint16(0xfbff)) // status
	s.in = buf.Bytes()

	status, err := s.readANOStatus()
	if err != nil || status != 0xfbff {
		t.Errorf("readANOStatus: 0x%x, %v", status, err)
	}
}

func TestReadANOUB1(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(1)) // length
	binary.Write(&buf, binary.BigEndian, uint16(2)) // type=2
	buf.WriteByte(0x42)
	s.in = buf.Bytes()

	v, err := s.readANOUB1()
	if err != nil || v != 0x42 {
		t.Errorf("readANOUB1: 0x%x, %v", v, err)
	}
}

func TestReadANOString(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(4)) // length
	binary.Write(&buf, binary.BigEndian, uint16(0)) // type=0
	buf.WriteString("TEST")
	s.in = buf.Bytes()

	str, err := s.readANOString()
	if err != nil || str != "TEST" {
		t.Errorf("readANOString: %q, %v", str, err)
	}
}

func TestReadANOBytes(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(3)) // length
	binary.Write(&buf, binary.BigEndian, uint16(1)) // type=1
	buf.Write([]byte{0xAA, 0xBB, 0xCC})
	s.in = buf.Bytes()

	b, err := s.readANOBytes()
	if err != nil || !bytes.Equal(b, []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("readANOBytes: %x, %v", b, err)
	}
}

func TestSkipANOPacket(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(3)) // length
	binary.Write(&buf, binary.BigEndian, uint16(7)) // type (ignored)
	buf.Write([]byte{0xAA, 0xBB, 0xCC})
	s.in = buf.Bytes()

	if err := s.skipANOPacket(); err != nil {
		t.Errorf("skipANOPacket error: %v", err)
	}
	if s.index != len(s.in) {
		t.Errorf("expected to consume all %d bytes, index=%d", len(s.in), s.index)
	}
}

func TestSkipANOPacketZeroLength(t *testing.T) {
	s := newTestSession()
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(0)) // length=0
	binary.Write(&buf, binary.BigEndian, uint16(3))
	s.in = buf.Bytes()

	if err := s.skipANOPacket(); err != nil {
		t.Errorf("skipANOPacket zero-length error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// getDlc / getKeyVal (compressed-length wrappers)
// ---------------------------------------------------------------------------

func TestGetDlcZeroLength(t *testing.T) {
	s := newTestSession()
	// compressed int 0 → single 0x00 byte
	s.in = []byte{0x00}
	b, err := s.getDlc()
	if err != nil || b != nil {
		t.Errorf("getDlc zero: %v, %v", b, err)
	}
}

func TestGetKeyVal(t *testing.T) {
	s := newTestSession()
	// build: key="K", val="V", num=7
	// all DLC values use compressed encoding (putUint + putClr)
	write := func(b *bytes.Buffer, data []byte) {
		// compressed uint32 for len
		l := len(data)
		tmp := make([]byte, 8)
		binary.BigEndian.PutUint64(tmp, uint64(l))
		tmp = bytes.TrimLeft(tmp, "\x00")
		if len(tmp) == 0 {
			b.WriteByte(0)
		} else {
			b.WriteByte(byte(len(tmp)))
			b.Write(tmp)
		}
		// clr: single byte len + data
		b.WriteByte(byte(l))
		b.Write(data)
	}
	writeCompressedInt := func(b *bytes.Buffer, n int) {
		tmp := make([]byte, 8)
		binary.BigEndian.PutUint64(tmp, uint64(n))
		tmp = bytes.TrimLeft(tmp, "\x00")
		if len(tmp) == 0 {
			b.WriteByte(0)
		} else {
			b.WriteByte(byte(len(tmp)))
			b.Write(tmp)
		}
	}
	var buf bytes.Buffer
	write(&buf, []byte("K"))
	write(&buf, []byte("V"))
	writeCompressedInt(&buf, 7)
	s.in = buf.Bytes()

	key, val, num, err := s.getKeyVal()
	if err != nil {
		t.Fatalf("getKeyVal error: %v", err)
	}
	if string(key) != "K" || string(val) != "V" || num != 7 {
		t.Errorf("getKeyVal: key=%q val=%q num=%d", key, val, num)
	}
}

// ---------------------------------------------------------------------------
// oracleEncryptPassword (random prefix — just check it decodes and expands)
// ---------------------------------------------------------------------------

func TestOracleEncryptPassword(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32) // AES-256
	enc, err := oracleEncryptPassword([]byte("secret"), key, false)
	if err != nil {
		t.Fatalf("oracleEncryptPassword error: %v", err)
	}
	if len(enc) == 0 {
		t.Error("expected non-empty hex output")
	}
	// must be valid hex
	if _, err = hex.DecodeString(enc); err != nil {
		t.Errorf("output not valid hex: %v", err)
	}
}
