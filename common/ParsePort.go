package common
//
//import (
//	"errors"
//	"strconv"
//	"strings"
//)
//
//var ParsePortErr error =errors.New("Port parsing error")
//
//func ParsePort(port string)([]int,error){
//	RealPort,err:=strconv.Atoi(port)
//	switch {
//	case err==nil && CheckPort(RealPort):
//		return []int{RealPort},nil
//	case strings.Contains(port,","):
//		return ParsePortB(port)
//	case strings.Count(port,"-")==1:
//		return ParsePortC(port)
//	default:
//		return nil,ParsePortErr
//	}
//}
//
////Parsing multiple ports, for example: 22,80,3306
//func ParsePortB(port string)([]int ,error){
//	var AllPort []int
//	port1:=strings.Split(port,",")
//	for _,p:=range port1{
//		RealPort,err:=strconv.Atoi(p)
//		if !CheckPort(RealPort) && err!=nil{
//			return nil,ParsePortErr
//		}
//		AllPort=append(AllPort,RealPort)
//	}
//	return AllPort,nil
//}
//
////Parsing a range of port,for example: 22-3306
//func ParsePortC(port string)([]int ,error){
//	var AllPort []int
//	RangePort:=strings.Split(port,"-")
//	port1,err1:=strconv.Atoi(RangePort[0])
//	port2,err2:=strconv.Atoi(RangePort[1])
//	if port1>port2 || err1!=nil || err2!=nil || !CheckPort(port1) || !CheckPort(port2){
//		return nil,ParsePortErr
//	}
//	for i:=port1;i<=port2;i++{
//		AllPort=append(AllPort,i)
//	}
//	return AllPort,nil
//}
//
//
//func CheckPort(port int)bool{
//	if port<=0 || port >65535{
//		return false
//	}
//	return true
//}