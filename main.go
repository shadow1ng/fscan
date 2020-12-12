package main

import (
	"fmt"
	"github.com/shadow1ng/fscan/Plugins"
	"github.com/shadow1ng/fscan/common"
)

func main() {
	var Info common.HostInfo
	common.Flag(&Info)
	common.Parse(&Info)
	Plugins.Scan(Info)
	fmt.Println("scan end")
}
