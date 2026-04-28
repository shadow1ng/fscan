//go:build web

package api

import (
	"net/http"

	"github.com/shadow1ng/fscan/web/ws"
)

// RegisterRoutes 注册所有API路由
func RegisterRoutes(mux *http.ServeMux, hub *ws.Hub) {
	// 扫描管理
	scanHandler := NewScanHandler(hub)
	mux.HandleFunc("/api/scan/start", scanHandler.Start)
	mux.HandleFunc("/api/scan/stop", scanHandler.Stop)
	mux.HandleFunc("/api/scan/status", scanHandler.Status)

	// 结果查询
	resultHandler := NewResultHandler()
	mux.HandleFunc("/api/results", resultHandler.List)
	mux.HandleFunc("/api/results/export", resultHandler.Export)
	mux.HandleFunc("/api/results/clear", resultHandler.Clear)

	// 配置
	configHandler := NewConfigHandler()
	mux.HandleFunc("/api/config/presets", configHandler.Presets)
	mux.HandleFunc("/api/config/plugins", configHandler.Plugins)

	// 项目缓存
	projectHandler := NewProjectHandler()
	mux.HandleFunc("/api/projects", projectHandler.List)
	mux.HandleFunc("/api/projects/create", projectHandler.Create)
	mux.HandleFunc("/api/projects/get", projectHandler.Get)
	mux.HandleFunc("/api/projects/delete", projectHandler.Delete)
	mux.HandleFunc("/api/projects/cache", projectHandler.Cache)

	// 系统信息
	mux.HandleFunc("/api/system/info", systemInfo)
	mux.HandleFunc("/api/health", healthCheck)
}

// healthCheck 健康检查
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// systemInfo 系统信息
func systemInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"version":"2.1.1","build":"web"}`))
}
