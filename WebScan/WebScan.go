package WebScan

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"net/http"
	"strings"
)

//go:embed pocs
var Pocs embed.FS

func WebScan(info *common.HostInfo) {
	var pocinfo = common.Pocinfo
	buf := strings.Split(info.Url, "/")
	pocinfo.Target = strings.Join(buf[:3], "/")
	if pocinfo.PocName != "" {
		Execute(pocinfo)
		return
	}
	for _, infostr := range info.Infostr {
		pocinfo.PocName = lib.CheckInfoPoc(infostr)
		Execute(pocinfo)
	}
}

func Execute(PocInfo common.PocInfo) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webtitle %v %v", PocInfo.Target, err)
		common.LogError(errlog)
		return
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	if PocInfo.Cookie != "" {
		req.Header.Set("Cookie", PocInfo.Cookie)
	}
	lib.CheckMultiPoc(req, Pocs, PocInfo.Num, PocInfo.PocName)
}
