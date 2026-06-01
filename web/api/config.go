//go:build web

package api

import (
	"net/http"
)

// ScanPreset 扫描预设
type ScanPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	NameEn      string `json:"name_en"`
	Description string `json:"description"`
	DescEn      string `json:"description_en"`
	Ports       string `json:"ports"`
	ScanMode    string `json:"scan_mode"`
	ThreadNum   int    `json:"thread_num"`
	Timeout     int    `json:"timeout"`
}

// PluginInfo 插件信息
type PluginInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // service, web, local
	Description string `json:"description"`
	DescEn      string `json:"description_en"`
	Enabled     bool   `json:"enabled"`
}

// ConfigHandler 配置处理器
type ConfigHandler struct{}

// NewConfigHandler 创建配置处理器
func NewConfigHandler() *ConfigHandler {
	return &ConfigHandler{}
}

// 预设配置
var presets = []ScanPreset{
	{
		ID:          "quick",
		Name:        "快速扫描",
		NameEn:      "Quick Scan",
		Description: "仅扫描常用端口，速度最快",
		DescEn:      "Scan common ports only, fastest speed",
		Ports:       "21,22,23,80,443,445,1433,3306,3389,6379,8080",
		ScanMode:    "all",
		ThreadNum:   1000,
		Timeout:     2,
	},
	{
		ID:          "standard",
		Name:        "标准扫描",
		NameEn:      "Standard Scan",
		Description: "扫描主要端口，平衡速度和覆盖",
		DescEn:      "Scan main ports, balance between speed and coverage",
		Ports:       "21,22,23,25,80,110,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9000,27017",
		ScanMode:    "all",
		ThreadNum:   600,
		Timeout:     3,
	},
	{
		ID:          "full",
		Name:        "完整扫描",
		NameEn:      "Full Scan",
		Description: "扫描所有常用端口，最完整",
		DescEn:      "Scan all common ports, most comprehensive",
		Ports:       "1-1000,1433,1521,3306,3389,5432,5900,6379,8000-9000,27017",
		ScanMode:    "all",
		ThreadNum:   400,
		Timeout:     5,
	},
	{
		ID:          "stealth",
		Name:        "隐蔽扫描",
		NameEn:      "Stealth Scan",
		Description: "低速扫描，减少被检测风险",
		DescEn:      "Low-speed scan, reduce detection risk",
		Ports:       "21,22,23,80,443,445,3389,8080",
		ScanMode:    "all",
		ThreadNum:   50,
		Timeout:     10,
	},
	{
		ID:          "web",
		Name:        "Web专项",
		NameEn:      "Web Focus",
		Description: "专注Web服务和漏洞检测",
		DescEn:      "Focus on web services and vulnerability detection",
		Ports:       "80,443,8080,8443,8000,8888,9000,9090,9999",
		ScanMode:    "all",
		ThreadNum:   200,
		Timeout:     5,
	},
}

// 插件列表
var plugins = []PluginInfo{
	// 服务类
	{Name: "ssh", Type: "service", Description: "SSH服务检测与爆破", DescEn: "SSH service detection and brute force", Enabled: true},
	{Name: "smb", Type: "service", Description: "SMB服务检测与爆破", DescEn: "SMB service detection and brute force", Enabled: true},
	{Name: "rdp", Type: "service", Description: "RDP服务检测", DescEn: "RDP service detection", Enabled: true},
	{Name: "mysql", Type: "service", Description: "MySQL数据库检测与爆破", DescEn: "MySQL database detection and brute force", Enabled: true},
	{Name: "mssql", Type: "service", Description: "MSSQL数据库检测与爆破", DescEn: "MSSQL database detection and brute force", Enabled: true},
	{Name: "postgresql", Type: "service", Description: "PostgreSQL数据库检测与爆破", DescEn: "PostgreSQL database detection and brute force", Enabled: true},
	{Name: "redis", Type: "service", Description: "Redis服务检测与未授权访问", DescEn: "Redis service detection and unauthorized access", Enabled: true},
	{Name: "mongodb", Type: "service", Description: "MongoDB数据库检测", DescEn: "MongoDB database detection", Enabled: true},
	{Name: "ftp", Type: "service", Description: "FTP服务检测与爆破", DescEn: "FTP service detection and brute force", Enabled: true},
	{Name: "telnet", Type: "service", Description: "Telnet服务检测", DescEn: "Telnet service detection", Enabled: true},

	// Web类
	{Name: "webinfo", Type: "web", Description: "Web指纹识别", DescEn: "Web fingerprinting", Enabled: true},
	{Name: "poc", Type: "web", Description: "POC漏洞检测", DescEn: "POC vulnerability detection", Enabled: true},

	// 本地类
	{Name: "cleaner", Type: "local", Description: "痕迹清理", DescEn: "Trace cleaning", Enabled: false},
}

// Presets 获取扫描预设
func (h *ConfigHandler) Presets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, presets)
}

// Plugins 获取插件列表
func (h *ConfigHandler) Plugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, plugins)
}
