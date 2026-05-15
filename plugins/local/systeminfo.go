//go:build (plugin_systeminfo || !plugin_selective) && !no_local

package local

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

type SystemInfoPlugin struct {
	plugins.BasePlugin
	output strings.Builder
}

func NewSystemInfoPlugin() *SystemInfoPlugin {
	return &SystemInfoPlugin{
		BasePlugin: plugins.NewBasePlugin("systeminfo"),
	}
}

func (p *SystemInfoPlugin) log(key string, args ...interface{}) {
	msg := i18n.Tr(key, args...)
	common.LogInfo(msg)
	p.output.WriteString(msg + "\n")
}

func (p *SystemInfoPlugin) logSuccess(key string, args ...interface{}) {
	msg := i18n.Tr(key, args...)
	common.LogSuccess(msg)
	p.output.WriteString(msg + "\n")
}

func (p *SystemInfoPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	common.LogSuccess(i18n.GetText("systeminfo_start"))

	p.collectBasicInfo()
	p.collectNetworkInfo()
	p.collectPrivilegeInfo()
	p.collectPlatformInfo()
	p.collectSensitiveEnvVars()

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  p.output.String(),
	}
}

func (p *SystemInfoPlugin) collectBasicInfo() {
	p.log("systeminfo_os", runtime.GOOS)
	p.log("systeminfo_arch", runtime.GOARCH)
	p.log("systeminfo_cpu", runtime.NumCPU())

	if hostname, err := os.Hostname(); err == nil {
		p.log("systeminfo_hostname", hostname)
	}
	if u, err := user.Current(); err == nil {
		p.log("systeminfo_user", u.Username)
		if u.HomeDir != "" {
			p.log("systeminfo_homedir", u.HomeDir)
		}
	}
	if wd, err := os.Getwd(); err == nil {
		p.log("systeminfo_workdir", wd)
	}
	p.log("systeminfo_tempdir", os.TempDir())
}

func (p *SystemInfoPlugin) collectNetworkInfo() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		var ips []string
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}
		p.log("systeminfo_iface", iface.Name, strings.Join(ips, ", "), iface.HardwareAddr.String())
	}
}

func (p *SystemInfoPlugin) collectPrivilegeInfo() {
	switch runtime.GOOS {
	case "windows":
		if out, err := p.runCommand("net", "session"); err == nil {
			_ = out
			p.logSuccess("systeminfo_privilege", "Administrator")
		} else {
			p.log("systeminfo_privilege", "Normal User")
		}
		if out, err := p.runCommand("whoami", "/groups"); err == nil {
			if strings.Contains(out, "S-1-5-32-544") {
				p.logSuccess("systeminfo_privilege_group", "Administrators")
			}
		}
	case "linux", "darwin":
		if uid := os.Getuid(); uid == 0 {
			p.logSuccess("systeminfo_privilege", "root")
		} else {
			p.log("systeminfo_privilege", fmt.Sprintf("uid=%d", uid))
		}
		if out, err := p.runCommand("id"); err == nil {
			p.log("systeminfo_id_info", strings.TrimSpace(out))
		}
	}
}

func (p *SystemInfoPlugin) collectPlatformInfo() {
	switch runtime.GOOS {
	case "windows":
		p.collectWindowsInfo()
	case "linux":
		p.collectLinuxInfo()
	case "darwin":
		p.collectDarwinInfo()
	}
}

func (p *SystemInfoPlugin) collectWindowsInfo() {
	if out, err := p.runCommand("cmd", "/c", "ver"); err == nil {
		p.log("systeminfo_winver", strings.TrimSpace(out))
	}
	if out, err := p.runCommand("cmd", "/c", "echo %USERDOMAIN%"); err == nil {
		domain := strings.TrimSpace(out)
		if domain != "" && domain != "%USERDOMAIN%" {
			p.log("systeminfo_domain", domain)
		}
	}

	// 防火墙状态
	if out, err := p.runCommand("netsh", "advfirewall", "show", "allprofiles", "state"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "ON") || strings.Contains(line, "OFF") {
				p.log("systeminfo_firewall", line)
			}
		}
	}

	// 已安装补丁
	if out, err := p.runCommand("wmic", "qfe", "get", "HotFixID,InstalledOn"); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		patches := 0
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "KB") {
				patches++
			}
		}
		if patches > 0 {
			p.log("systeminfo_patches", patches)
		}
	}

	// 已安装的杀软 (WMI)
	if out, err := p.runCommand("wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntiVirusProduct", "get", "displayName"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && line != "displayName" {
				p.logSuccess("systeminfo_antivirus", line)
			}
		}
	}
}

func (p *SystemInfoPlugin) collectLinuxInfo() {
	if out, err := p.runCommand("uname", "-a"); err == nil {
		p.log("systeminfo_kernel", strings.TrimSpace(out))
	}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name := strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				p.log("systeminfo_distro", name)
				break
			}
		}
	}

	// 防火墙
	if out, err := p.runCommand("iptables", "-L", "-n", "--line-numbers"); err == nil {
		ruleCount := 0
		for _, line := range strings.Split(out, "\n") {
			if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
				ruleCount++
			}
		}
		p.log("systeminfo_firewall_rules", ruleCount)
	}

	// sudo 权限
	if out, err := p.runCommand("sudo", "-l", "-n"); err == nil {
		if strings.Contains(out, "ALL") {
			p.logSuccess("systeminfo_sudo", "ALL commands")
		} else if strings.Contains(out, "NOPASSWD") {
			p.logSuccess("systeminfo_sudo", "NOPASSWD entries found")
		}
	}
}

func (p *SystemInfoPlugin) collectDarwinInfo() {
	if out, err := p.runCommand("uname", "-a"); err == nil {
		p.log("systeminfo_kernel", strings.TrimSpace(out))
	}
	if out, err := p.runCommand("sw_vers"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				p.log("systeminfo_macos_detail", line)
			}
		}
	}
}

func (p *SystemInfoPlugin) collectSensitiveEnvVars() {
	keywords := []string{
		"password", "passwd", "secret", "key", "token",
		"auth", "credential", "api_key", "access_key",
	}
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		name := strings.ToLower(parts[0])
		for _, kw := range keywords {
			if strings.Contains(name, kw) {
				display := parts[1]
				if len(display) > 8 {
					display = display[:8] + "***"
				}
				p.logSuccess("systeminfo_sensitive_env", parts[0], display)
				break
			}
		}
	}
}

func (p *SystemInfoPlugin) runCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func init() {
	RegisterLocalPlugin("systeminfo", func() Plugin {
		return NewSystemInfoPlugin()
	})
}
