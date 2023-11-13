package Plugins

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"strconv"
	"strings"
	"time"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

func Findnet(info *common.HostInfo) error {
	err := FindnetScan(info)
	return err
}

func FindnetScan(info *common.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, 135)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV1)
	if err != nil {
		return err
	}
	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV2)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 42 {
		return err
	}
	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag {
		return err
	}
	err = read(text, info.Host)
	return err
}

func HexUnicodeStringToString(src string) string {
	sText := ""
	if len(src)%4 != 0 {
		src += src[:len(src)-len(src)%4]
	}
	for i := 0; i < len(src); i = i + 4 {
		sText += "\\u" + src[i+2:i+4] + src[i:i+2]
	}

	textUnquoted := sText
	sUnicodev := strings.Split(textUnquoted, "\\u")
	var context string
	for _, v := range sUnicodev {
		if len(v) < 1 {
			continue
		}
		temp, err := strconv.ParseInt(v, 16, 32)
		if err != nil {
			return ""
		}
		context += fmt.Sprintf("%c", temp)
	}
	return context
}

func read(text []byte, host string) error {
	encodedStr := hex.EncodeToString(text)

	hn := ""
	for i := 0; i < len(encodedStr)-4; i = i + 4 {
		if encodedStr[i:i+4] == "0000" {
			break
		}
		hn += encodedStr[i : i+4]
	}

	var name string
	name = HexUnicodeStringToString(hn)

	hostnames := strings.Replace(encodedStr, "0700", "", -1)
	hostname := strings.Split(hostnames, "000000")
	result := "[*] NetInfo \n[*]" + host
	if name != "" {
		result += "\n   [->]" + name
	}
	hostname = hostname[1:]
	for i := 0; i < len(hostname); i++ {
		hostname[i] = strings.Replace(hostname[i], "00", "", -1)
		host, err := hex.DecodeString(hostname[i])
		if err != nil {
			return err
		}
		result += "\n   [->]" + string(host)
	}
	common.LogSuccess(result)
	return nil
}
