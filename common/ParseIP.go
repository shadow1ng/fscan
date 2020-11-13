package common

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var ParseIPErr error =errors.New("host parsing error\n" +
	"format: \n"+
	"192.168.1.1/24\n"+
	"192.168.1.1\n" +
	"192.168.1.1,192.168.1.2\n" +
	"192.168.1.1-255")

func ParseIP(ip string)([]string,error){
	reg:=regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Contains(ip[len(ip)-3:len(ip)],"/24"):
		return ParseIPA(ip)
	case strings.Contains(ip[len(ip)-3:len(ip)],"/16"):
		return ParseIPD(ip)
	case strings.Contains(ip[len(ip)-2:len(ip)],"/8"):
		return ParseIPE(ip)
	case strings.Contains(ip,","):
		return ParseIPB(ip)
	case strings.Count(ip,"-")==1:
		return ParseIPC(ip)
	case reg.MatchString(ip):
		_, err := net.LookupHost(ip)
		if err != nil {
			return nil,err
		}
		return []string{ip},nil
	default:
		testIP:=net.ParseIP(ip)
		if testIP==nil{
			return nil,ParseIPErr
		}
		return []string{ip},nil
	}
}

//Parsing CIDR IP
func ParseIPA(ip string)([]string,error){
	realIP:=ip[:len(ip)-3]
	testIP:=net.ParseIP(realIP)

	if testIP==nil{
		return nil,ParseIPErr
	}
	IPrange:=strings.Join(strings.Split(realIP,".")[0:3],".")
	var AllIP []string
	for i:=0;i<=255;i++{
		AllIP=append(AllIP,IPrange+"."+strconv.Itoa(i))
	}
	return AllIP,nil
}

//Resolving multiple IPS, for example: 192.168.111.1,192.168.111.2
func ParseIPB(ip string)([]string,error){
	IPList:=strings.Split(ip,",")
	for _,i:=range IPList{
		testIP:=net.ParseIP(i)
		if testIP==nil{
			return nil,ParseIPErr
		}
	}
	return IPList,nil

}

//Resolving a range of IP,for example: 192.168.111.1-255
func ParseIPC(ip string)([]string,error){
	IPRange:=strings.Split(ip,"-")
	testIP:=net.ParseIP(IPRange[0])
	Range,err:=strconv.Atoi(IPRange[1])
	if testIP==nil || Range>255 || err!=nil{
		return nil,ParseIPErr
	}
	SplitIP:=strings.Split(IPRange[0],".")
	ip1,err1:=strconv.Atoi(SplitIP[3])
	ip2,err2:=strconv.Atoi(IPRange[1])
	PrefixIP:=strings.Join(SplitIP[0:3],".")
	var AllIP []string
	if ip1>ip2 || err1!=nil || err2!=nil{
		return nil,ParseIPErr
	}
	for i:=ip1;i<=ip2;i++{
		AllIP=append(AllIP,PrefixIP+"."+strconv.Itoa(i))
	}
	return AllIP,nil

}

func ParseIPD(ip string)([]string,error){
	realIP:=ip[:len(ip)-3]
	testIP:=net.ParseIP(realIP)

	if testIP==nil{
		return nil,ParseIPErr
	}
	IPrange:=strings.Join(strings.Split(realIP,".")[0:2],".")
	var AllIP []string
	for a:=0;a<=255;a++{
		for b:=0;b<=255;b++{
			AllIP=append(AllIP,IPrange+"."+strconv.Itoa(a)+"."+strconv.Itoa(b))
		}
	}
	return AllIP,nil
}

func ParseIPE(ip string)([]string,error){
	realIP:=ip[:len(ip)-2]
	testIP:=net.ParseIP(realIP)

	if testIP==nil{
		return nil,ParseIPErr
	}
	IPrange:=strings.Join(strings.Split(realIP,".")[0:1],".")
	var AllIP []string
	for a:=0;a<=255;a++{
		for b:=0;b<=255;b++{
			AllIP=append(AllIP,IPrange+"."+strconv.Itoa(a)+"."+strconv.Itoa(b)+"."+strconv.Itoa(1))
			AllIP=append(AllIP,IPrange+"."+strconv.Itoa(a)+"."+strconv.Itoa(b)+"."+strconv.Itoa(254))
		}
	}
	return AllIP,nil
}