//go:build plugin_webpoc || !plugin_selective

package web

import (
	"context"
	"fmt"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
	WebScan "github.com/shadow1ng/fscan/webscan"
)

// CDN/WAF指纹列表，检测到这些指纹时跳过漏洞扫描
// 参考来源: wafw00f (https://github.com/EnableSecurity/wafw00f)
var cdnWafFingerprints = []string{
	// 国际CDN
	"CloudFlare", "Cloudfront", "Fastly", "Akamai", "KONA",
	"Incapsula", "Imperva", "Sucuri", "StackPath", "KeyCDN",
	"MaxCDN", "Edgecast", "Limelight", "CacheFly", "Azion",

	// 国际云WAF
	"AWSWAF", "AWS-WAF", "AWS ELB", "Azure", "AzureFrontDoor",
	"GoogleCloud", "GCP", "Armor",

	// 国际硬件/软件WAF
	"F5-BigIP", "F5BigIP", "Barracuda", "Fortinet", "FortiWeb", "FortiGate",
	"Palo Alto", "PaloAlto", "Citrix", "NetScaler", "Radware", "AppWall",
	"Imperva SecureSphere", "ModSecurity", "NAXSI",

	// 国内CDN
	"阿里云CDN", "阿里云盾", "AliYunDun", "AliCDN",
	"腾讯云", "QCloud", "腾讯CDN",
	"百度云", "Baidu", "百度CDN",
	"华为云", "HuaweiCloud",
	"七牛", "Qiniu",
	"网宿", "ChinaNetCenter", "ChinaCache",
	"蓝汛", "ChinaCache",
	"又拍云", "Upyun",
	"白山云", "BaishanCloud",

	// 国内WAF
	"360网站卫士", "360WAF", "奇安信",
	"绿盟", "NSFOCUS", "绿盟防火墙",
	"Topsec-Waf", "天融信",
	"Safe3", "Safe3WAF",
	"Safedog", "安全狗",
	"知道创宇", "Knownsec", "创宇盾",
	"加速乐", "Jiasule",
	"云锁", "Yunsuo",
	"云盾", "Yundun",
	"玄武盾", "XuanwuDun",
	"长亭", "Chaitin", "SafeLine",
	"安恒", "DBAppSecurity",
	"深信服", "Sangfor",
	"启明星辰", "Venustech",
	"山石网科", "Hillstone",
	"盛邦安全", "WebRAY",

	// 其他通用标识
	"WAF", "CDN", "Proxy", "Cache", "DDoS-Guard", "AntiDDoS",
}

// cdnWafFingerprintsLower 预转换的小写指纹列表（避免运行时重复转换）
var cdnWafFingerprintsLower []string

func init() {
	cdnWafFingerprintsLower = make([]string, len(cdnWafFingerprints))
	for i, fp := range cdnWafFingerprints {
		cdnWafFingerprintsLower[i] = strings.ToLower(fp)
	}
}

// WebPocPlugin Web漏洞扫描插件
type WebPocPlugin struct {
	plugins.BasePlugin
}

// NewWebPocPlugin 创建Web POC插件
func NewWebPocPlugin() *WebPocPlugin {
	return &WebPocPlugin{
		BasePlugin: plugins.NewBasePlugin("webpoc"),
	}
}

// Scan 执行Web POC扫描
// 注意：非全量模式下，POC扫描由webtitle插件在指纹识别后触发，此插件不执行
// 全量模式(-full)下，此插件独立执行全量POC扫描
func (p *WebPocPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *WebScanResult {
	config := session.Config
	if config.POC.Disabled {
		return &WebScanResult{
			Success: false,
			Error:   fmt.Errorf("POC扫描已禁用"),
		}
	}

	// 非全量模式：POC扫描由webtitle触发，此处跳过避免重复
	if !config.POC.Full {
		return &WebScanResult{
			Success: true,
			Skipped: true,
		}
	}

	// 全量模式：忽略指纹和CDN/WAF检测，直接扫描所有POC
	target := info.Target()
	common.LogDebug(fmt.Sprintf("WebPOC %s 全量扫描模式", target))
	WebScan.WebScan(ctx, info, config)

	return &WebScanResult{
		Type:    plugins.ResultTypeWeb,
		Success: true,
	}
}

// matchCDNorWAF 检查指纹是否匹配CDN/WAF
func matchCDNorWAF(fingerprints []string) string {
	for _, fp := range fingerprints {
		fpLower := strings.ToLower(fp)
		for i, cdnLower := range cdnWafFingerprintsLower {
			if strings.Contains(fpLower, cdnLower) {
				return cdnWafFingerprints[i] // 返回原始大小写的名称
			}
		}
	}
	return ""
}

// init 自动注册插件
func init() {
	RegisterWebPlugin("webpoc", func() WebPlugin {
		return NewWebPocPlugin()
	})
}
