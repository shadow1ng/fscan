//go:build web

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/core"
	"github.com/shadow1ng/fscan/web/ws"
)

// ScanState 扫描状态
type ScanState int32

const (
	ScanStateIdle ScanState = iota
	ScanStateRunning
	ScanStateStopping
)

// ScanRequest 扫描请求
type ScanRequest struct {
	// 目标
	Host         string `json:"host"`
	Ports        string `json:"ports"`
	ExcludeHosts string `json:"exclude_hosts"`
	ExcludePorts string `json:"exclude_ports"`

	// 扫描控制
	ScanMode        string `json:"scan_mode"`
	ThreadNum       int    `json:"thread_num"`
	Timeout         int    `json:"timeout"`
	ModuleThreadNum int    `json:"module_thread_num"`
	DisablePing     bool   `json:"disable_ping"`
	DisableBrute    bool   `json:"disable_brute"`
	AliveOnly       bool   `json:"alive_only"`

	// 认证
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`

	// POC
	PocPath  string `json:"poc_path"`
	PocName  string `json:"poc_name"`
	PocFull  bool   `json:"poc_full"`
	DisablePoc bool `json:"disable_poc"`

	// 项目缓存
	ProjectID string `json:"project_id,omitempty"`
}

// ScanStatus 扫描状态响应
type ScanStatus struct {
	State     string    `json:"state"`
	StartTime time.Time `json:"start_time,omitempty"`
	Progress  float64   `json:"progress"`
	Stats     ScanStats `json:"stats"`
}

// ScanStats 扫描统计
type ScanStats struct {
	HostsScanned  int `json:"hosts_scanned"`
	PortsScanned  int `json:"ports_scanned"`
	ServicesFound int `json:"services_found"`
	VulnsFound    int `json:"vulns_found"`
}

// ScanHandler 扫描处理器
type ScanHandler struct {
	hub       *ws.Hub
	state     int32
	startTime time.Time
	cancelFn  context.CancelFunc
	mu        sync.RWMutex
	results   *ResultStore
}

// NewScanHandler 创建扫描处理器
func NewScanHandler(hub *ws.Hub) *ScanHandler {
	return &ScanHandler{
		hub:     hub,
		results: globalResultStore,
	}
}

// Start 启动扫描
func (h *ScanHandler) Start(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否已在扫描
	if !atomic.CompareAndSwapInt32(&h.state, int32(ScanStateIdle), int32(ScanStateRunning)) {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "scan already running",
		})
		return
	}

	// 解析请求
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		atomic.StoreInt32(&h.state, int32(ScanStateIdle))
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request: " + err.Error(),
		})
		return
	}

	// 验证必填参数
	if req.Host == "" {
		atomic.StoreInt32(&h.state, int32(ScanStateIdle))
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "host is required",
		})
		return
	}

	h.mu.Lock()
	h.startTime = time.Now()
	h.mu.Unlock()

	// 清空旧结果
	h.results.Clear()

	// 广播扫描开始
	h.hub.Broadcast(ws.MsgScanStarted, map[string]interface{}{
		"host":       req.Host,
		"start_time": h.startTime,
	})

	// 异步执行扫描
	go h.runScan(req)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "started",
		"start_time": h.startTime,
	})
}

// runScan 执行扫描
func (h *ScanHandler) runScan(req ScanRequest) {
	ctx, cancel := context.WithCancel(context.Background())

	h.mu.Lock()
	h.cancelFn = cancel
	h.mu.Unlock()

	defer func() {
		cancel()
		h.mu.Lock()
		h.cancelFn = nil
		h.mu.Unlock()
		common.ClearResultCallback()
		atomic.StoreInt32(&h.state, int32(ScanStateIdle))
		h.hub.Broadcast(ws.MsgScanCompleted, map[string]interface{}{
			"duration": time.Since(h.startTime).Seconds(),
			"stats":    h.results.Stats(),
		})
	}()

	// 构建HostInfo
	info := common.HostInfo{
		Host: req.Host,
	}

	// 构建FlagVars
	fv := &common.FlagVars{}
	fv.Ports = req.Ports
	if fv.Ports == "" {
		fv.Ports = "21,22,23,25,80,110,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9000,27017"
	}
	fv.ExcludeHosts = req.ExcludeHosts
	fv.ExcludePorts = req.ExcludePorts
	fv.ScanMode = req.ScanMode
	if fv.ScanMode == "" {
		fv.ScanMode = "all"
	}
	fv.ThreadNum = req.ThreadNum
	if fv.ThreadNum <= 0 {
		fv.ThreadNum = 600
	}
	fv.TimeoutSec = int64(req.Timeout)
	if fv.TimeoutSec == 0 {
		fv.TimeoutSec = 3
	}
	fv.ModuleThreadNum = req.ModuleThreadNum
	if fv.ModuleThreadNum <= 0 {
		fv.ModuleThreadNum = 20
	}
	fv.DisablePing = req.DisablePing
	fv.DisableBrute = req.DisableBrute
	fv.AliveOnly = req.AliveOnly
	fv.Username = req.Username
	fv.Password = req.Password
	fv.Domain = req.Domain
	fv.PocPath = req.PocPath
	fv.PocName = req.PocName
	fv.PocFull = req.PocFull
	fv.DisablePocScan = req.DisablePoc
	fv.DisableSave = true // Web模式不保存到文件
	fv.Silent = true      // 静默模式

	// 构建Config和Session
	config := common.BuildConfigFromFlags(fv)
	state := common.NewState()
	session := common.NewScanSession(config, state, fv)

	// 过渡桥：全局状态同步（待 Phase 5 移除）
	common.SetGlobalConfig(config)
	common.SetGlobalState(state)

	// 项目缓存注入：把已知的 host:port 加入扫描目标
	if req.ProjectID != "" {
		if cached := globalProjectStore.CachedHostPorts(req.ProjectID); len(cached) > 0 {
			state.SetHostPorts(cached)
		}
	}

	// 设置WebSocket结果回调
	common.SetResultCallback(func(result interface{}) {
		item := h.results.Add(result)
		if item != nil {
			h.hub.Broadcast(ws.MsgScanResult, item)
		}
	})

	// 执行扫描
	core.RunScan(ctx, info, session)

	// 项目缓存回写：合并本次扫描结果
	if req.ProjectID != "" {
		items := h.results.List()
		if len(items) > 0 {
			_ = globalProjectStore.MergeResults(req.ProjectID, items)
		}
	}
}

// Stop 停止扫描
func (h *ScanHandler) Stop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if atomic.LoadInt32(&h.state) != int32(ScanStateRunning) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "no scan running",
		})
		return
	}

	atomic.StoreInt32(&h.state, int32(ScanStateStopping))

	h.mu.Lock()
	if h.cancelFn != nil {
		h.cancelFn()
	}
	h.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "stopping",
	})
}

// Status 获取扫描状态
func (h *ScanHandler) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := atomic.LoadInt32(&h.state)
	stateStr := "idle"
	switch ScanState(state) {
	case ScanStateRunning:
		stateStr = "running"
	case ScanStateStopping:
		stateStr = "stopping"
	}

	h.mu.RLock()
	startTime := h.startTime
	h.mu.RUnlock()

	// 从 ProgressManager 获取进度百分比
	progress := common.GetProgressPercent()

	status := ScanStatus{
		State:     stateStr,
		StartTime: startTime,
		Progress:  progress,
		Stats:     h.results.Stats(),
	}

	writeJSON(w, http.StatusOK, status)
}

// writeJSON 写入JSON响应
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
