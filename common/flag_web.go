//go:build web

package common

import (
	"flag"

	"github.com/shadow1ng/fscan/common/i18n"
)

// WebMode 表示是否启动Web管理界面
var WebMode bool

// WebPort Web服务器端口
var WebPort int

func init() {
	flag.BoolVar(&WebMode, "web", false, i18n.GetText("flag_web_mode"))
	flag.IntVar(&WebPort, "webport", 10240, i18n.GetText("flag_web_port"))
}
