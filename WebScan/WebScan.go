package WebScan

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"log"
	"net/http"
	"time"
)

//go:embed pocs
var Pocs embed.FS

func WebScan(info *common.HostInfo) {
	var pocinfo = common.Pocinfo
	pocinfo.Target = info.Url
	err := Execute(pocinfo)
	if err != nil {
		errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		common.LogError(errlog)
	}
}

func Execute(PocInfo common.PocInfo) error {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	if PocInfo.Cookie != "" {
		req.Header.Set("Cookie", PocInfo.Cookie)
	}

	lib.CheckMultiPoc(req, Pocs, PocInfo.Num, PocInfo.PocName)
	return nil
}

func Inithttp(PocInfo common.PocInfo) {
	//PocInfo.Proxy = "http://127.0.0.1:8080"
	err := lib.InitHttpClient(PocInfo.Num, PocInfo.Proxy, time.Duration(PocInfo.Timeout)*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}
