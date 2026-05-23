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

	// 清理 fscan 产物文件
	workDir, _ := os.Getwd()
	cleaned += p.cleanFiles(&output, workDir, []string{
		"result.txt", "result.json", "result.csv",
		"fscan_debug.log",
	})
	cleaned += p.cleanGlob(&output, os.TempDir(), "fscan_*")

	// 清理持久化痕迹（平台特定）
	cleaned += cleanPersistence(&output)

	// 平台通用文件清理
	switch runtime.GOOS {
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
			fmt.Fprintln(output, i18n.Tr("cleaner_removed", path))
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
			fmt.Fprintln(output, i18n.Tr("cleaner_removed", f))
			cleaned++
		}
	}
	return cleaned
}

func (p *CleanerPlugin) cleanUnix(output *strings.Builder) int {
	cleaned := 0
	homeDir, _ := os.UserHomeDir()

	histFiles := []string{
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
	}
	for _, hf := range histFiles {
		if p.scrubHistory(hf) {
			fmt.Fprintln(output, i18n.Tr("cleaner_history_removed", hf))
			cleaned++
		}
	}

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
