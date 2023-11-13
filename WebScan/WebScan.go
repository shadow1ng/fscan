package WebScan

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed pocs
var Pocs embed.FS
var once sync.Once
var AllPocs []*lib.Poc

func WebScan(info *common.HostInfo) {
	once.Do(initpoc)
	var pocinfo = common.Pocinfo
	buf := strings.Split(info.Url, "/")
	pocinfo.Target = strings.Join(buf[:3], "/")

	if pocinfo.PocName != "" {
		Execute(pocinfo)
	} else {
		for _, infostr := range info.Infostr {
			pocinfo.PocName = lib.CheckInfoPoc(infostr)
			Execute(pocinfo)
		}
	}
}

func Execute(PocInfo common.PocInfo) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webpocinit %v %v", PocInfo.Target, err)
		common.LogError(errlog)
		return
	}
	req.Header.Set("User-agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}
	pocs := filterPoc(PocInfo.PocName)
	lib.CheckMultiPoc(req, pocs, common.PocNum)
}

func initpoc() {
	if common.PocPath == "" {
		entries, err := Pocs.ReadDir("pocs")
		if err != nil {
			fmt.Printf("[-] init poc error: %v", err)
			return
		}
		for _, one := range entries {
			path := one.Name()
			if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
				if poc, _ := lib.LoadPoc(path, Pocs); poc != nil {
					AllPocs = append(AllPocs, poc)
				}
			}
		}
	} else {
		fmt.Println("[+] load poc from " + common.PocPath)
		err := filepath.Walk(common.PocPath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil {
					return err
				}
				if !info.IsDir() {
					if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
						poc, _ := lib.LoadPocbyPath(path)
						if poc != nil {
							AllPocs = append(AllPocs, poc)
						}
					}
				}
				return nil
			})
		if err != nil {
			fmt.Printf("[-] init poc error: %v", err)
		}
	}
}

func filterPoc(pocname string) (pocs []*lib.Poc) {
	if pocname == "" {
		return AllPocs
	}
	for _, poc := range AllPocs {
		if strings.Contains(poc.Name, pocname) {
			pocs = append(pocs, poc)
		}
	}
	return
}
