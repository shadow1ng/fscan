package WebScan

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Config"
	"github.com/shadow1ng/fscan/WebScan/lib"
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

// WebScan 执行Web漏洞扫描
func WebScan(info *Config.HostInfo) {
	// 确保POC只初始化一次
	once.Do(initpoc)

	// 构建扫描信息
	var pocinfo = Common.Pocinfo
	urlParts := strings.Split(info.Url, "/")
	pocinfo.Target = strings.Join(urlParts[:3], "/")

	// 执行扫描
	if pocinfo.PocName != "" {
		// 指定POC扫描
		Execute(pocinfo)
	} else {
		// 根据指纹信息选择POC扫描
		for _, infostr := range info.Infostr {
			pocinfo.PocName = lib.CheckInfoPoc(infostr)
			Execute(pocinfo)
		}
	}
}

// Execute 执行具体的POC检测
func Execute(PocInfo Common.PocInfo) {
	// 创建基础HTTP请求
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		Common.LogError(fmt.Sprintf("初始化请求失败 %v: %v", PocInfo.Target, err))
		return
	}

	// 设置请求头
	req.Header.Set("User-agent", Common.UserAgent)
	req.Header.Set("Accept", Common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if Common.Cookie != "" {
		req.Header.Set("Cookie", Common.Cookie)
	}

	// 根据名称筛选POC并执行
	pocs := filterPoc(PocInfo.PocName)
	lib.CheckMultiPoc(req, pocs, Common.PocNum)
}

// initpoc 初始化POC加载
func initpoc() {
	if Common.PocPath == "" {
		// 从嵌入的POC目录加载
		entries, err := Pocs.ReadDir("pocs")
		if err != nil {
			Common.LogError(fmt.Sprintf("加载内置POC失败: %v", err))
			return
		}

		// 加载YAML格式的POC文件
		for _, entry := range entries {
			filename := entry.Name()
			if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
				if poc, err := lib.LoadPoc(filename, Pocs); err == nil && poc != nil {
					AllPocs = append(AllPocs, poc)
				}
			}
		}
	} else {
		// 从指定目录加载POC
		Common.LogSuccess(fmt.Sprintf("[*] 从目录加载POC: %s", Common.PocPath))
		err := filepath.Walk(Common.PocPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return err
			}

			if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
				if poc, err := lib.LoadPocbyPath(path); err == nil && poc != nil {
					AllPocs = append(AllPocs, poc)
				}
			}
			return nil
		})

		if err != nil {
			Common.LogError(fmt.Sprintf("[-] 加载外部POC失败: %v", err))
		}
	}
}

// filterPoc 根据POC名称筛选
func filterPoc(pocname string) []*lib.Poc {
	if pocname == "" {
		return AllPocs
	}

	var matchedPocs []*lib.Poc
	for _, poc := range AllPocs {
		if strings.Contains(poc.Name, pocname) {
			matchedPocs = append(matchedPocs, poc)
		}
	}
	return matchedPocs
}
