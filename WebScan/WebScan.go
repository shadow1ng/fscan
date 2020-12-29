package WebScan

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"net/http"
	"time"
)

//go:embed pocs
var Pocs embed.FS

func WebScan(info *common.HostInfo) {
	info.PocInfo.Target = info.Url
	err := Execute(info.PocInfo)
	if err != nil && info.Debug {
		fmt.Println(info.Url, err)
	}
}

func Execute(PocInfo common.PocInfo) error {
	//PocInfo.Proxy = "http://127.0.0.1:8080"
	err := lib.InitHttpClient(PocInfo.Num, PocInfo.Proxy, time.Duration(PocInfo.Timeout)*time.Second)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	if PocInfo.Cookie != "" {
		req.Header.Set("Cookie", PocInfo.Cookie)
	}

	if PocInfo.PocName != "" {
		lib.CheckMultiPoc(req, Pocs, PocInfo.Num, PocInfo.PocName)
	} else {
		lib.CheckMultiPoc(req, Pocs, PocInfo.Num, "")
	}

	return nil
}
