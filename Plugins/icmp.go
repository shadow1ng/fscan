package Plugins

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

var icmp ICMP

var AliveHosts []string

var SysInfo = GetSys()

type ICMP struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
}

type SystemInfo struct {
	OS          string
	ARCH        string
	HostName    string
	Groupid     string
	Userid      string
	Username    string
	UserHomeDir string
}

func GetSys() SystemInfo {
	var sysinfo SystemInfo

	sysinfo.OS = runtime.GOOS
	sysinfo.ARCH = runtime.GOARCH
	name, err := os.Hostname()
	if err == nil {
		sysinfo.HostName = name
	}

	u, err := user.Current()
	sysinfo.Groupid = u.Gid
	sysinfo.Userid = u.Uid
	sysinfo.Username = u.Username
	sysinfo.UserHomeDir = u.HomeDir

	return sysinfo
}

func isping(ip string) bool {
	icmp.Type = 8
	icmp.Code = 0
	icmp.Checksum = 0
	icmp.Identifier = 0
	icmp.SequenceNum = 0

	recvBuf := make([]byte, 32)
	var buffer bytes.Buffer

	binary.Write(&buffer, binary.BigEndian, icmp)
	icmp.Checksum = CheckSum(buffer.Bytes())

	buffer.Reset()
	binary.Write(&buffer, binary.BigEndian, icmp)

	Time, _ := time.ParseDuration("3s")
	conn, err := net.DialTimeout("ip4:icmp", ip, Time)
	if err != nil {
		return false
	}
	defer conn.Close()
	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	num, err := conn.Read(recvBuf)
	if err != nil {
		return false
	}

	conn.SetReadDeadline(time.Time{})

	if string(recvBuf[0:num]) != "" {
		fmt.Printf("(ICMP) Target '%s' is alive\n", ip)
		return true
	}
	return false

}

func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}

func IcmpCheck(hostslist []string, IcmpThreads int) {
	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan int, IcmpThreads)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- 1
		go func(host string) {
			defer wg.Done()
			if isping(host) {
				mutex.Lock()
				AliveHosts = append(AliveHosts, host)
				mutex.Unlock()
			}
			<-limiter
		}(host)

	}
	wg.Wait()
}

func ExecCommandPing(ip string, bsenv string) bool {
	var command *exec.Cmd
	if SysInfo.OS == "windows" {
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if SysInfo.OS == "linux" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if SysInfo.OS == "darwin" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -W 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") {
			return true
		} else {
			return false
		}
	}
}

func PingCMDcheck(hostslist []string, bsenv string) {
	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan struct{}, 40)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer wg.Done()
			if ExecCommandPing(host, bsenv) {
				mutex.Lock()
				fmt.Printf("(Ping) Target '%s' is alive\n", host)
				AliveHosts = append(AliveHosts, host)
				mutex.Unlock()
			}
			<-limiter
		}(host)
	}
	wg.Wait()
}
func ICMPRun(hostslist []string, IcmpThreads int, Ping bool) []string {

	if SysInfo.OS == "windows" {
		if Ping == false {
			IcmpCheck(hostslist, IcmpThreads)
		} else {
			PingCMDcheck(hostslist, "")
		}
	} else if SysInfo.OS == "linux" {
		if SysInfo.Groupid == "0" || SysInfo.Userid == "0" || SysInfo.Username == "root" {
			if Ping == false {
				IcmpCheck(hostslist, IcmpThreads)
			} else {
				PingCMDcheck(hostslist, "/bin/bash")
			}
		} else {
			fmt.Println("The current user permissions unable to send icmp packets")
			fmt.Println("start ping")
			PingCMDcheck(hostslist, "/bin/bash")
		}
	} else if SysInfo.OS == "darwin" {
		if SysInfo.Groupid == "0" || SysInfo.Userid == "0" || SysInfo.Username == "root" {
			if Ping == false {
				IcmpCheck(hostslist, IcmpThreads)
			} else {
				PingCMDcheck(hostslist, "/bin/bash")
			}
		} else {
			fmt.Println("The current user permissions unable to send icmp packets")
			fmt.Println("start ping")
			PingCMDcheck(hostslist, "/bin/bash")
		}
	}
	return AliveHosts
}
