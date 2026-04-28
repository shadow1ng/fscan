//go:build web

package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ProjectCache 项目缓存：跨扫描持久化已知资产
type ProjectCache struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Hosts     map[string]int64 `json:"hosts"`      // IP → 最后发现时间戳(unix)
	Ports     map[string]int64 `json:"ports"`       // "IP:Port" → 最后发现时间戳(unix)
	Results   []ResultItem     `json:"results"`     // 历史结果(合并去重)
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// ProjectStore 项目存储管理
type ProjectStore struct {
	mu       sync.RWMutex
	projects map[string]*ProjectCache
	dir      string
}

var globalProjectStore *ProjectStore

func init() {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".fscan", "projects")
	globalProjectStore = &ProjectStore{
		projects: make(map[string]*ProjectCache),
		dir:      dir,
	}
	globalProjectStore.loadAll()
}

// loadAll 从磁盘加载所有项目
func (ps *ProjectStore) loadAll() {
	_ = os.MkdirAll(ps.dir, 0750)
	entries, err := os.ReadDir(ps.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(ps.dir, e.Name()))
		if err != nil {
			continue
		}
		var p ProjectCache
		if json.Unmarshal(data, &p) == nil && p.ID != "" {
			ps.projects[p.ID] = &p
		}
	}
}

// save 持久化单个项目
func (ps *ProjectStore) save(p *ProjectCache) error {
	_ = os.MkdirAll(ps.dir, 0750)
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(ps.dir, p.ID+".json"), data, 0640)
}

// Get 获取项目
func (ps *ProjectStore) Get(id string) *ProjectCache {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.projects[id]
}

// List 列出所有项目
func (ps *ProjectStore) List() []*ProjectCache {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	list := make([]*ProjectCache, 0, len(ps.projects))
	for _, p := range ps.projects {
		list = append(list, p)
	}
	return list
}

// Create 创建项目
func (ps *ProjectStore) Create(name string) (*ProjectCache, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	id := genID()
	p := &ProjectCache{
		ID:        id,
		Name:      name,
		Hosts:     make(map[string]int64),
		Ports:     make(map[string]int64),
		Results:   make([]ResultItem, 0),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := ps.save(p); err != nil {
		return nil, err
	}
	ps.projects[id] = p
	return p, nil
}

// Delete 删除项目
func (ps *ProjectStore) Delete(id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.projects, id)
	return os.Remove(filepath.Join(ps.dir, id+".json"))
}

// MergeResults 将扫描结果合并进项目缓存
func (ps *ProjectStore) MergeResults(id string, items []ResultItem) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	p, ok := ps.projects[id]
	if !ok {
		return fmt.Errorf("project not found: %s", id)
	}

	now := time.Now().Unix()

	// 构建已有结果的去重集合
	seen := make(map[string]bool, len(p.Results))
	for _, r := range p.Results {
		seen[resultKey(r)] = true
	}

	for _, item := range items {
		// 更新资产缓存
		switch strings.ToLower(item.Type) {
		case "host":
			if item.Target != "" {
				p.Hosts[item.Target] = now
			}
		case "port", "service":
			if item.Target != "" {
				p.Ports[item.Target] = now
				// 提取 host 部分也记入 Hosts
				if host := extractHost(item.Target); host != "" {
					p.Hosts[host] = now
				}
			}
		}

		// 合并去重
		key := resultKey(item)
		if !seen[key] {
			seen[key] = true
			p.Results = append(p.Results, item)
		}
	}

	p.UpdatedAt = time.Now()
	return ps.save(p)
}

// CachedHostPorts 返回缓存的 host:port 列表（供注入扫描）
func (ps *ProjectStore) CachedHostPorts(id string) []string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	p, ok := ps.projects[id]
	if !ok {
		return nil
	}
	result := make([]string, 0, len(p.Ports))
	for hp := range p.Ports {
		result = append(result, hp)
	}
	return result
}

func resultKey(r ResultItem) string {
	return fmt.Sprintf("%s|%s|%s", r.Type, r.Target, r.Status)
}

func genID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ─── HTTP Handlers ──────────────────────────────────────────────────────────

type ProjectHandler struct {
	store *ProjectStore
}

func NewProjectHandler() *ProjectHandler {
	return &ProjectHandler{store: globalProjectStore}
}

// List 列出所有项目
func (h *ProjectHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, h.store.List())
}

// Create 创建项目
func (h *ProjectHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	p, err := h.store.Create(req.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// Get 获取项目详情
func (h *ProjectHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	p := h.store.Get(id)
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// Delete 删除项目
func (h *ProjectHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	if err := h.store.Delete(req.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Cache 查看项目缓存摘要
func (h *ProjectHandler) Cache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	p := h.store.Get(id)
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hosts":        len(p.Hosts),
		"ports":        len(p.Ports),
		"results":      len(p.Results),
		"cached_ports": h.store.CachedHostPorts(id),
	})
}
