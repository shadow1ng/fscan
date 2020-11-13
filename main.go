package main

import (
	"./Plugins"
	"./common"
	"fmt"
)


func main() {
	var Info common.HostInfo
	common.Flag(&Info) 	//fmt.Println(Info.Host,Info.Ports)
	common.Parse(&Info)
	Plugins.Scan(&Info)
	fmt.Println("scan end")
}




