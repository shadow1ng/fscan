//go:build web

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/web"

	// 导入统一插件系统
	_ "github.com/shadow1ng/fscan/plugins/local"
	_ "github.com/shadow1ng/fscan/plugins/services"
	_ "github.com/shadow1ng/fscan/plugins/web"
)

func main() {
	port := flag.Int("port", 10240, "Web server listen port")
	lang := flag.String("lang", "zh", "Language (zh/en)")
	flag.Parse()

	i18n.SetLanguage(*lang)

	fmt.Printf("fscan web v%s\n", common.GetVersion())

	if err := web.StartServer(*port); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
