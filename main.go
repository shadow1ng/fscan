package main

import (
	"./common"
	"./Plugins"
	"fmt"
)


func main() {
	var Info common.HostInfo
	common.Flag(&Info) 	//fmt.Println(Info.Host,Info.Ports)
	common.Parse(&Info)
	Plugins.Scan(&Info)
	fmt.Println("scan end")
}




