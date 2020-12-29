package Plugins

import (
	"bytes"
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

var AliveHosts []string

var SysInfo = GetSys()

type SystemInfo struct {
	OS string
	//ARCH        string
	HostName string
	Groupid  string
	Userid   string
	Username string
	//UserHomeDir string
}

func GetSys() SystemInfo {
	var sysinfo SystemInfo

	sysinfo.OS = runtime.GOOS
	//sysinfo.ARCH = runtime.GOARCH
	name, err := os.Hostname()
	if err == nil {
		sysinfo.HostName = name
	} else {
		name = "none"
	}

	u, err := user.Current()
	//fmt.Println(err,u)
	if err == nil {
		sysinfo.Groupid = u.Gid
		sysinfo.Userid = u.Uid
		sysinfo.Username = u.Username
		//sysinfo.UserHomeDir = u.HomeDir
	} else {
		sysinfo.Groupid = "1"
		sysinfo.Userid = "1"
		sysinfo.Username = name
		//sysinfo.UserHomeDir = u.HomeDir
	}

	return sysinfo
}

func isping(ip string) bool {
	IcmpByte := []byte{8, 0, 247, 255, 0, 0, 0, 0}
	Time, _ := time.ParseDuration("3s")
	conn, err := net.DialTimeout("ip4:icmp", ip, Time)
	if err != nil {
		return false
	}
	defer conn.Close()
	_, err = conn.Write(IcmpByte)
	if err != nil {
		return false
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 3)); err != nil {
		return false
	}

	recvBuf := make([]byte, 40)
	num, err := conn.Read(recvBuf[0:40])
	if err != nil {
		return false
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 3)); err != nil {
		return false
	}
	if string(recvBuf[0:num]) != "" {
		fmt.Printf("(ICMP) Target '%s' is alive\n", ip)
		return true
	}
	return false

}

func IcmpCheck(hostslist []string, IcmpThreads int) {
	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan struct{}, IcmpThreads)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
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
