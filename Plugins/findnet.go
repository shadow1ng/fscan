package Plugins

import (
	"bytes"
	"net"
	"strings"
	"time"

	//"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	"../common"
)

var (
	buffer_v1, _  = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	buffer_v2, _  = hex.DecodeString("050000031000000018000000010000000000000000000500")
	buffer_v3, _  = hex.DecodeString("0900ffff0000")

)
func Findnet(info *common.HostInfo,ch chan int,wg *sync.WaitGroup) {
	FindnetScan(info)
	wg.Done()
	<- ch
}

func FindnetScan(info *common.HostInfo) {
	realhost:=fmt.Sprintf("%s:%d",info.Host,135)
	conn,err := net.DialTimeout("tcp",realhost,time.Duration(info.Timeout)*time.Second)
	if err != nil{
		return
	}
	conn.SetDeadline(time.Now().Add(time.Duration(info.Timeout)*time.Second))
	defer conn.Close()
	conn.Write(buffer_v1)
	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil{
		return
	}
	conn.Write(buffer_v2)
	if n, err := conn.Read(reply); err != nil || n < 42 {
		return
	}
	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], buffer_v3){
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag{
		return
	}
	read(text,info.Host)
}
func read(text []byte,host string)  {
	encodedStr := hex.EncodeToString(text)
	hostnames := strings.Replace(encodedStr, "0700", "", -1)
	hostname := strings.Split(hostnames, "000000")
	result := "NetInfo:\n[*]"+host
	for i := 0; i < len(hostname); i++ {
		hostname[i] = strings.Replace(hostname[i], "00", "", -1)
		host,err := hex.DecodeString(hostname[i])
		if err != nil{
			return
		}
		result += "\n   [->]"+string(host)
	}
	common.LogSuccess(result)
}


