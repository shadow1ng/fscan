package Plugins

import (
	"bytes"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/net/icmp"
	"log"
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
	OS       string
	HostName string
	Groupid  string
	Userid   string
	Username string
}

func GetSys() SystemInfo {
	var sysinfo SystemInfo

	sysinfo.OS = runtime.GOOS
	name, err := os.Hostname()
	if err == nil {
		sysinfo.HostName = name
	} else {
		name = "none"
	}

	u, err := user.Current()
	if err == nil {
		sysinfo.Groupid = u.Gid
		sysinfo.Userid = u.Uid
		sysinfo.Username = u.Username
	} else {
		sysinfo.Groupid = "1"
		sysinfo.Userid = "1"
		sysinfo.Username = name
	}

	return sysinfo
}

func IcmpCheck(hostslist []string) {
	TmpHosts := make(map[string]struct{})
	var chanHosts = make(chan string)
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	endflag := false
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			if endflag == true {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				chanHosts <- sourceIP.String()
			}
		}
	}()

	go func() {
		for ip := range chanHosts {
			if _, ok := TmpHosts[ip]; !ok {
				TmpHosts[ip] = struct{}{}
				if common.Silent == false {
					fmt.Printf("(icmp) Target '%s' is alive\n", ip)
				}
				AliveHosts = append(AliveHosts, ip)
			}
		}
	}()

	for _, host := range hostslist {
		write(host, conn)
	}

	if len(hostslist) > 255 {
		time.Sleep(6 * time.Second)
	} else {
		time.Sleep(3 * time.Second)
	}

	endflag = true
	close(chanHosts)
	conn.Close()
}

func write(ip string, conn *icmp.PacketConn) {
	dst, _ := net.ResolveIPAddr("ip", ip)
	IcmpByte := []byte{8, 0, 247, 255, 0, 0, 0, 0}
	conn.WriteTo(IcmpByte, dst)
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
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer wg.Done()
			if ExecCommandPing(host, bsenv) {
				mutex.Lock()
				if common.Silent == false {
					fmt.Printf("(Ping) Target '%s' is alive\n", host)
				}
				AliveHosts = append(AliveHosts, host)
				mutex.Unlock()
			}
			<-limiter
		}(host)
	}
	wg.Wait()
}
func ICMPRun(hostslist []string, Ping bool) []string {
	if SysInfo.OS == "windows" {
		if Ping == false {
			IcmpCheck(hostslist)
		} else {
			PingCMDcheck(hostslist, "")
		}
	} else if SysInfo.OS == "linux" {
		if SysInfo.Groupid == "0" || SysInfo.Userid == "0" || SysInfo.Username == "root" {
			if Ping == false {
				IcmpCheck(hostslist)
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
				IcmpCheck(hostslist)
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
