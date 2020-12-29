package main

import (
	"github.com/shadow1ng/fscan/Plugins"
	"github.com/shadow1ng/fscan/common"
)

func main() {
	var Info common.HostInfo
	common.Flag(&Info)
	common.Parse(&Info)
	Plugins.Scan(Info)
	print("scan end\n")
}
