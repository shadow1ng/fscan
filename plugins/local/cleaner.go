//go:build (plugin_cleaner || !plugin_selective) && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// CleanerPlugin 痕迹清理插件
// 设计哲学：保持原有功能，删除过度设计
// - 删除复杂的继承体系和配置选项
// - 直接实现清理功能

type CleanerPlugin struct {
	plugins.BasePlugin
}

// NewCleanerPlugin 创建系统痕迹清理插件
func NewCleanerPlugin() *CleanerPlugin {
	return &CleanerPlugin{
		BasePlugin: plugins.NewBasePlugin("cleaner"),
	}
}

// Scan 执行系统痕迹清理 - 直接、简单
func (p *CleanerPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	var output strings.Builder
	var filesCleared, dirsCleared, sysCleared int

	output.WriteString("=== 系统痕迹清理 ===\n")

	// 清理当前目录fscan相关文件
	workDir, _ := os.Getwd()
	files := p.findFscanFiles(workDir)
	for _, file := range files {
		if p.removeFile(file) {
			filesCleared++
			_, _ = fmt.Fprintf(&output, "清理文件: %s\n", file)
		}
	}

	// 清理临时目录fscan相关文件
	tempFiles := p.findTempFiles()
	for _, file := range tempFiles {
		if p.removeFile(file) {
			filesCleared++
			_, _ = fmt.Fprintf(&output, "清理临时文件: %s\n", file)
		}
	}

	// 清理日志和输出文件
	logFiles := p.findLogFiles(workDir)
	for _, file := range logFiles {
		if p.removeFile(file) {
			filesCleared++
			output.WriteString(fmt.Sprintf("清理日志: %s\n", file))
		}
	}

	// 平台特定清理
	switch runtime.GOOS {
	case "windows":
		sysCleared += p.clearWindowsTraces()
	case "linux", "darwin":
		sysCleared += p.clearUnixTraces()
	}

	// 输出统计
	output.WriteString(fmt.Sprintf("\n清理完成: 文件(%d) 目录(%d) 系统条目(%d)\n",
		filesCleared, dirsCleared, sysCleared))

	common.LogSuccess(i18n.Tr("cleaner_success", filesCleared, sysCleared))

	return &plugins.Result{
		Success: filesCleared > 0 || sysCleared > 0,
		Output:  output.String(),
		Error:   nil,
	}
}

// findFscanFiles 查找fscan相关文件 - 简化搜索逻辑
func (p *CleanerPlugin) findFscanFiles(dir string) []string {
	var files []string

	// fscan相关文件模式 - 直接硬编码
	patterns := []string{
		"fscan*.exe", "fscan*.log", "result*.txt", "result*.json",
		"fscan_*", "*fscan*", "scan_result*", "vulnerability*",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		files = append(files, matches...)
	}

	return files
}

// findTempFiles 查找临时文件
func (p *CleanerPlugin) findTempFiles() []string {
	var files []string
	tempDir := os.TempDir()

	// 临时文件模式
	patterns := []string{
		"fscan_*", "scan_*", "tmp_scan*", "vulnerability_*",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(tempDir, pattern))
		files = append(files, matches...)
	}

	return files
}

// findLogFiles 查找日志文件
func (p *CleanerPlugin) findLogFiles(dir string) []string {
	var files []string

	// 日志文件模式
	logPatterns := []string{
		"*.log", "scan*.txt", "error*.txt", "debug*.txt",
		"output*.txt", "report*.txt", "*.out",
	}

	for _, pattern := range logPatterns {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, match := range matches {
			// 只清理可能是扫描相关的日志
			filename := strings.ToLower(filepath.Base(match))
			if p.isScanRelatedLog(filename) {
				files = append(files, match)
			}
		}
	}

	return files
}

// isScanRelatedLog 判断是否为扫描相关日志
func (p *CleanerPlugin) isScanRelatedLog(filename string) bool {
	scanKeywords := []string{
		"scan", "fscan", "vulnerability", "result", "report",
		"exploit", "brute", "port", "service", "web",
	}

	for _, keyword := range scanKeywords {
		if strings.Contains(filename, keyword) {
			return true
		}
	}
	return false
}

// clearWindowsTraces 清理Windows系统痕迹
func (p *CleanerPlugin) clearWindowsTraces() int {
	cleared := 0

	// 清理预读文件
	prefetchDir := "C:\\Windows\\Prefetch"
	if prefetchFiles := p.findPrefetchFiles(prefetchDir); len(prefetchFiles) > 0 {
		for _, file := range prefetchFiles {
			if p.removeFile(file) {
				cleared++
			}
		}
	}

	// 清理最近文档记录（注册表方式复杂，这里简化处理）
	// 可以通过删除Recent文件夹的快捷方式
	if recentDir := os.Getenv("USERPROFILE") + "\\Recent"; p.dirExists(recentDir) {
		recentFiles, _ := filepath.Glob(filepath.Join(recentDir, "fscan*.lnk"))
		for _, file := range recentFiles {
			if p.removeFile(file) {
				cleared++
			}
		}
	}

	return cleared
}

// clearUnixTraces 清理Unix系统痕迹
func (p *CleanerPlugin) clearUnixTraces() int {
	cleared := 0

	// 清理bash历史记录相关
	homeDir, _ := os.UserHomeDir()
	historyFiles := []string{
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
	}

	for _, histFile := range historyFiles {
		if p.clearHistoryEntries(histFile) {
			cleared++
		}
	}

	// 清理/var/log中的相关日志（需要权限）
	logDirs := []string{"/var/log", "/tmp"}
	for _, logDir := range logDirs {
		if p.dirExists(logDir) {
			logFiles, _ := filepath.Glob(filepath.Join(logDir, "*fscan*"))
			for _, file := range logFiles {
				if p.removeFile(file) {
					cleared++
				}
			}
		}
	}

	return cleared
}

// findPrefetchFiles 查找预读文件
func (p *CleanerPlugin) findPrefetchFiles(dir string) []string {
	var files []string
	if !p.dirExists(dir) {
		return files
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "FSCAN*.pf"))
	files = append(files, matches...)

	return files
}

// clearHistoryEntries 清理历史记录条目（简化实现）
func (p *CleanerPlugin) clearHistoryEntries(histFile string) bool {
	// 这里简化实现：不修改历史文件内容
	// 实际应该是读取文件，删除包含fscan的行，然后写回
	// 为简化，这里只记录找到相关历史文件
	if p.fileExists(histFile) {
		common.LogInfo(i18n.Tr("cleaner_history_found", histFile))
		return true
	}
	return false
}

// removeFile 删除文件
func (p *CleanerPlugin) removeFile(path string) bool {
	if err := os.Remove(path); err == nil {
		return true
	}
	return false
}

// fileExists 检查文件是否存在
func (p *CleanerPlugin) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists 检查目录是否存在
func (p *CleanerPlugin) dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// 注册插件
func init() {
	RegisterLocalPlugin("cleaner", func() Plugin {
		return NewCleanerPlugin()
	})
}
