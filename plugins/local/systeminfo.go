//go:build (plugin_systeminfo || !plugin_selective) && !no_local

package local

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// SystemInfoPlugin 系统信息收集插件
// 设计哲学：纯信息收集，无攻击性功能
// - 删除复杂的继承体系
// - 收集基本系统信息
// - 跨平台支持，运行时适配
type SystemInfoPlugin struct {
	plugins.BasePlugin
}

// NewSystemInfoPlugin 创建系统信息插件
func NewSystemInfoPlugin() *SystemInfoPlugin {
	return &SystemInfoPlugin{
		BasePlugin: plugins.NewBasePlugin("systeminfo"),
	}
}

// Scan 执行系统信息收集 - 直接、简单、有效
func (p *SystemInfoPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	var output strings.Builder

	output.WriteString("=== 系统信息收集 ===\n")
	common.LogSuccess(i18n.GetText("systeminfo_start"))

	// 基本系统信息
	output.WriteString(fmt.Sprintf("操作系统: %s\n", runtime.GOOS))
	output.WriteString(fmt.Sprintf("架构: %s\n", runtime.GOARCH))
	output.WriteString(fmt.Sprintf("CPU核心数: %d\n", runtime.NumCPU()))

	common.LogInfo(i18n.Tr("systeminfo_os", runtime.GOOS))
	common.LogInfo(i18n.Tr("systeminfo_arch", runtime.GOARCH))
	common.LogInfo(i18n.Tr("systeminfo_cpu", runtime.NumCPU()))

	// 主机名
	if hostname, err := os.Hostname(); err == nil {
		output.WriteString(fmt.Sprintf("主机名: %s\n", hostname))
		common.LogInfo(i18n.Tr("systeminfo_hostname", hostname))
	}

	// 当前用户
	if currentUser, err := user.Current(); err == nil {
		output.WriteString(fmt.Sprintf("当前用户: %s\n", currentUser.Username))
		common.LogInfo(i18n.Tr("systeminfo_user", currentUser.Username))
		if currentUser.HomeDir != "" {
			output.WriteString(fmt.Sprintf("用户目录: %s\n", currentUser.HomeDir))
			common.LogInfo(i18n.Tr("systeminfo_homedir", currentUser.HomeDir))
		}
	}

	// 工作目录
	if workDir, err := os.Getwd(); err == nil {
		output.WriteString(fmt.Sprintf("工作目录: %s\n", workDir))
		common.LogInfo(i18n.Tr("systeminfo_workdir", workDir))
	}

	// 临时目录
	output.WriteString(fmt.Sprintf("临时目录: %s\n", os.TempDir()))
	common.LogInfo(i18n.Tr("systeminfo_tempdir", os.TempDir()))

	// 环境变量关键信息
	if path := os.Getenv("PATH"); path != "" {
		pathCount := len(strings.Split(path, string(os.PathListSeparator)))
		output.WriteString(fmt.Sprintf("PATH变量条目: %d个\n", pathCount))
		common.LogInfo(i18n.Tr("systeminfo_pathcount", pathCount))
	}

	// 平台特定信息
	platformInfo := p.getPlatformSpecificInfo()
	if platformInfo != "" {
		output.WriteString("\n=== 平台特定信息 ===\n")
		output.WriteString(platformInfo)
		// 输出平台特定信息到控制台
		p.logPlatformInfo()
	}

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// getPlatformSpecificInfo 获取平台特定信息 - 运行时适配，不做预检查
func (p *SystemInfoPlugin) getPlatformSpecificInfo() string {
	var info strings.Builder

	switch runtime.GOOS {
	case "windows":
		// Windows版本信息
		if output, err := p.runCommand("cmd", "/c", "ver"); err == nil {
			info.WriteString(i18n.Tr("systeminfo_winver", strings.TrimSpace(output)) + "\n")
		}

		// 域信息
		if output, err := p.runCommand("cmd", "/c", "echo %USERDOMAIN%"); err == nil {
			domain := strings.TrimSpace(output)
			if domain != "" && domain != "%USERDOMAIN%" {
				info.WriteString(i18n.Tr("systeminfo_domain", domain) + "\n")
			}
		}

	case "linux", "darwin":
		// Unix系统信息
		if output, err := p.runCommand("uname", "-a"); err == nil {
			info.WriteString(i18n.Tr("systeminfo_kernel", strings.TrimSpace(output)) + "\n")
		}

		// 发行版信息（Linux）
		if runtime.GOOS == "linux" {
			if output, err := p.runCommand("lsb_release", "-d"); err == nil {
				info.WriteString(i18n.Tr("systeminfo_distro", strings.TrimSpace(output)) + "\n")
			} else if p.fileExists("/etc/os-release") {
				info.WriteString(i18n.GetText("systeminfo_distro_exists") + "\n")
			}
		}

		// whoami
		if output, err := p.runCommand("whoami"); err == nil {
			info.WriteString(i18n.Tr("systeminfo_whoami", strings.TrimSpace(output)) + "\n")
		}
	}

	return info.String()
}

// runCommand 执行命令 - 简单包装，无复杂错误处理
func (p *SystemInfoPlugin) runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	return string(output), err
}

// fileExists 检查文件是否存在
func (p *SystemInfoPlugin) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// logPlatformInfo 输出平台特定信息到控制台
func (p *SystemInfoPlugin) logPlatformInfo() {
	switch runtime.GOOS {
	case "windows":
		// Windows版本信息
		if output, err := p.runCommand("cmd", "/c", "ver"); err == nil {
			common.LogInfo(i18n.Tr("systeminfo_winver", strings.TrimSpace(output)))
		}

		// 域信息
		if output, err := p.runCommand("cmd", "/c", "echo %USERDOMAIN%"); err == nil {
			domain := strings.TrimSpace(output)
			if domain != "" && domain != "%USERDOMAIN%" {
				common.LogInfo(i18n.Tr("systeminfo_domain", domain))
			}
		}

	case "linux", "darwin":
		// Unix系统信息
		if output, err := p.runCommand("uname", "-a"); err == nil {
			common.LogInfo(i18n.Tr("systeminfo_kernel", strings.TrimSpace(output)))
		}

		// 发行版信息（Linux）
		if runtime.GOOS == "linux" {
			if output, err := p.runCommand("lsb_release", "-d"); err == nil {
				common.LogInfo(i18n.Tr("systeminfo_distro", strings.TrimSpace(output)))
			} else if p.fileExists("/etc/os-release") {
				common.LogInfo(i18n.GetText("systeminfo_distro_exists"))
			}
		}

		// whoami
		if output, err := p.runCommand("whoami"); err == nil {
			common.LogInfo(i18n.Tr("systeminfo_whoami", strings.TrimSpace(output)))
		}
	}
}

// 注册插件
func init() {
	RegisterLocalPlugin("systeminfo", func() Plugin {
		return NewSystemInfoPlugin()
	})
}
