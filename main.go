package main

import (
	"github.com/shadow1ng/fscan/Plugins"
	"github.com/shadow1ng/fscan/common"
)

func main() {
	var Info common.HostInfo
	common.Flag(&Info) //fmt.Println(Info.Host,Info.Ports)
	common.Parse(&Info)
	Plugins.Scan(Info)
	common.LogPrint("scan end .")
}
