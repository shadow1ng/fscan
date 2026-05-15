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

type CleanerPlugin struct {
	plugins.BasePlugin
}

func NewCleanerPlugin() *CleanerPlugin {
	return &CleanerPlugin{BasePlugin: plugins.NewBasePlugin("cleaner")}
}

func (p *CleanerPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	var output strings.Builder
	var cleaned int

	// 清理工作目录下的 fscan 产物
	workDir, _ := os.Getwd()
	cleaned += p.cleanFiles(&output, workDir, []string{
		"result.txt", "result.json", "result.csv",
		"fscan_debug.log",
	})

	// 清理临时目录
	cleaned += p.cleanGlob(&output, os.TempDir(), "fscan_*")

	// 清理自身可执行文件（如果在工作目录）
	if exe, err := os.Executable(); err == nil {
		base := filepath.Base(exe)
		if strings.Contains(strings.ToLower(base), "fscan") && filepath.Dir(exe) == workDir {
			cleaned += p.cleanFiles(&output, workDir, []string{base})
		}
	}

	// 平台特定清理
	switch runtime.GOOS {
	case "windows":
		cleaned += p.cleanWindows(&output)
	case "linux", "darwin":
		cleaned += p.cleanUnix(&output)
	}

	common.LogSuccess(i18n.Tr("cleaner_success", cleaned, 0))

	return &plugins.Result{
		Success: cleaned > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func (p *CleanerPlugin) cleanFiles(output *strings.Builder, dir string, names []string) int {
	cleaned := 0
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err == nil {
			output.WriteString(fmt.Sprintf("[清理] %s\n", path))
			cleaned++
		}
	}
	return cleaned
}

func (p *CleanerPlugin) cleanGlob(output *strings.Builder, dir, pattern string) int {
	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	cleaned := 0
	for _, f := range matches {
		if err := os.Remove(f); err == nil {
			output.WriteString(fmt.Sprintf("[清理] %s\n", f))
			cleaned++
		}
	}
	return cleaned
}

func (p *CleanerPlugin) cleanWindows(output *strings.Builder) int {
	cleaned := 0
	// Prefetch 中的 fscan 记录
	cleaned += p.cleanGlob(output, `C:\Windows\Prefetch`, "FSCAN*.pf")
	// Recent 中的 fscan 快捷方式
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		cleaned += p.cleanGlob(output, filepath.Join(profile, "Recent"), "fscan*.lnk")
	}
	return cleaned
}

func (p *CleanerPlugin) cleanUnix(output *strings.Builder) int {
	cleaned := 0
	homeDir, _ := os.UserHomeDir()

	// 从 history 文件中删除 fscan 相关行
	histFiles := []string{
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
	}
	for _, hf := range histFiles {
		if p.scrubHistory(hf) {
			output.WriteString(fmt.Sprintf("[清理] %s 中的 fscan 记录\n", hf))
			cleaned++
		}
	}

	// /tmp 下的 fscan 残留
	cleaned += p.cleanGlob(output, "/tmp", "fscan_*")
	cleaned += p.cleanGlob(output, "/tmp", ".fscan*")

	return cleaned
}

func (p *CleanerPlugin) scrubHistory(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	var kept []string
	removed := false
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "fscan") {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return false
	}
	return os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0600) == nil
}

func init() {
	RegisterLocalPlugin("cleaner", func() Plugin {
		return NewCleanerPlugin()
	})
}
