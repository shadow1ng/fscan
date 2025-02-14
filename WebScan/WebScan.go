package WebScan

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"net/http"
	"net/url"
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
func WebScan(info *Common.HostInfo) {
	once.Do(initpoc)

	var pocinfo = Common.Pocinfo

	// 自动构建URL
	if info.Url == "" {
		info.Url = fmt.Sprintf("http://%s:%s", info.Host, info.Ports)
	}

	urlParts := strings.Split(info.Url, "/")

	// 检查切片长度并构建目标URL
	if len(urlParts) >= 3 {
		pocinfo.Target = strings.Join(urlParts[:3], "/")
	} else {
		pocinfo.Target = info.Url
	}

	Common.LogDebug(fmt.Sprintf("扫描目标: %s", pocinfo.Target))

	// 如果是直接调用WebPoc（没有指定pocName），执行所有POC
	if pocinfo.PocName == "" && len(info.Infostr) == 0 {
		Common.LogDebug("直接调用WebPoc，执行所有POC")
		Execute(pocinfo)
	} else {
		// 根据指纹信息选择性执行POC
		if len(info.Infostr) > 0 {
			for _, infostr := range info.Infostr {
				pocinfo.PocName = lib.CheckInfoPoc(infostr)
				if pocinfo.PocName != "" {
					Common.LogDebug(fmt.Sprintf("根据指纹 %s 执行对应POC", infostr))
					Execute(pocinfo)
				}
			}
		} else if pocinfo.PocName != "" {
			// 指定了特定的POC
			Common.LogDebug(fmt.Sprintf("执行指定POC: %s", pocinfo.PocName))
			Execute(pocinfo)
		}
	}
}

// Execute 执行具体的POC检测
func Execute(PocInfo Common.PocInfo) {
	Common.LogDebug(fmt.Sprintf("开始执行POC检测，目标: %s", PocInfo.Target))

	// 确保URL格式正确
	if !strings.HasPrefix(PocInfo.Target, "http://") && !strings.HasPrefix(PocInfo.Target, "https://") {
		PocInfo.Target = "http://" + PocInfo.Target
	}

	// 验证URL格式
	_, err := url.Parse(PocInfo.Target)
	if err != nil {
		Common.LogError(fmt.Sprintf("无效的URL格式 %v: %v", PocInfo.Target, err))
		return
	}

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
	Common.LogDebug(fmt.Sprintf("筛选到的POC数量: %d", len(pocs)))
	lib.CheckMultiPoc(req, pocs, Common.PocNum)
}

// initpoc 初始化POC加载
func initpoc() {
	Common.LogDebug("开始初始化POC")

	if Common.PocPath == "" {
		Common.LogDebug("从内置目录加载POC")
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
				} else if err != nil {
				}
			}
		}
		Common.LogDebug(fmt.Sprintf("内置POC加载完成，共加载 %d 个", len(AllPocs)))
	} else {
		// 从指定目录加载POC
		Common.LogSuccess(fmt.Sprintf("从目录加载POC: %s", Common.PocPath))
		err := filepath.Walk(Common.PocPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return err
			}

			if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
				if poc, err := lib.LoadPocbyPath(path); err == nil && poc != nil {
					AllPocs = append(AllPocs, poc)
				} else if err != nil {
				}
			}
			return nil
		})

		if err != nil {
			Common.LogError(fmt.Sprintf("加载外部POC失败: %v", err))
		}
		Common.LogDebug(fmt.Sprintf("外部POC加载完成，共加载 %d 个", len(AllPocs)))
	}
}

// filterPoc 根据POC名称筛选
func filterPoc(pocname string) []*lib.Poc {
	Common.LogDebug(fmt.Sprintf("开始筛选POC，筛选条件: %s", pocname))

	if pocname == "" {
		Common.LogDebug(fmt.Sprintf("未指定POC名称，返回所有POC: %d 个", len(AllPocs)))
		return AllPocs
	}

	var matchedPocs []*lib.Poc
	for _, poc := range AllPocs {
		if strings.Contains(poc.Name, pocname) {
			matchedPocs = append(matchedPocs, poc)
		}
	}
	Common.LogDebug(fmt.Sprintf("POC筛选完成，匹配到 %d 个", len(matchedPocs)))
	return matchedPocs
}
