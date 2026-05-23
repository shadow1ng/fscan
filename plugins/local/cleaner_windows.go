//go:build (plugin_cleaner || !plugin_selective) && windows && !no_local

package local

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shadow1ng/fscan/common/i18n"
)

func cleanPersistence(output *strings.Builder) int {
	cleaned := 0

	// 1. 清理 Winlogon 劫持——恢复默认值
	cleaned += fixWinlogon(output)

	// 2. 清理 IFEO 映像劫持
	cleaned += cleanIFEO(output)

	// 3. 清理注册表 Run 键
	cleaned += cleanRegistryRun(output)

	// 4. 清理计划任务
	cleaned += cleanScheduledTasks(output)

	// 5. 清理服务
	cleaned += cleanServices(output)

	// 6. 清理启动文件夹
	cleaned += cleanStartupFolders(output)

	// 7. 清理 BITS 任务
	cleaned += cleanBITS(output)

	// 8. 清理 WMI 事件订阅
	cleaned += cleanWMI(output)

	// 9. 清理 Prefetch
	cleaned += cleanPrefetch(output)

	return cleaned
}

func fixWinlogon(output *strings.Builder) int {
	cleaned := 0
	key := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

	// 检查 Shell 是否被篡改
	if out, err := exec.Command("reg", "query", key, "/v", "Shell").CombinedOutput(); err == nil {
		val := extractRegValue(string(out))
		if val != "explorer.exe" && val != "" {
			exec.Command("reg", "add", key, "/v", "Shell", "/t", "REG_SZ", "/d", "explorer.exe", "/f").Run()
			output.WriteString(i18n.Tr("cleaner_restore_winlogon_shell", val, "explorer.exe") + "\n")
			cleaned++
		}
	}

	// 检查 Userinit 是否被篡改
	if out, err := exec.Command("reg", "query", key, "/v", "Userinit").CombinedOutput(); err == nil {
		val := extractRegValue(string(out))
		defaultVal := `C:\Windows\system32\userinit.exe,`
		if val != defaultVal && val != strings.TrimSuffix(defaultVal, ",") && val != "" {
			exec.Command("reg", "add", key, "/v", "Userinit", "/t", "REG_SZ", "/d", defaultVal, "/f").Run()
			output.WriteString(i18n.Tr("cleaner_restore_winlogon_userinit", val, defaultVal) + "\n")
			cleaned++
		}
	}
	return cleaned
}

func cleanIFEO(output *strings.Builder) int {
	cleaned := 0
	targets := []string{"sethc.exe", "utilman.exe", "narrator.exe"}
	for _, t := range targets {
		key := fmt.Sprintf(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s`, t)
		if out, err := exec.Command("reg", "query", key, "/v", "Debugger").CombinedOutput(); err == nil && strings.Contains(string(out), "Debugger") {
			exec.Command("reg", "delete", key, "/f").Run()
			output.WriteString(i18n.Tr("cleaner_ifeo_removed", t) + "\n")
			cleaned++
		}
	}
	return cleaned
}

func cleanRegistryRun(output *strings.Builder) int {
	cleaned := 0
	keys := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	markers := []string{"fscan", "test_payload", "WindowsUpdate_", "SystemUpdate_", "SetupComplete_"}

	for _, key := range keys {
		out, err := exec.Command("reg", "query", key).CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			for _, m := range markers {
				if strings.Contains(line, m) {
					fields := strings.Fields(strings.TrimSpace(line))
					if len(fields) > 0 {
						exec.Command("reg", "delete", key, "/v", fields[0], "/f").Run()
						output.WriteString(i18n.Tr("cleaner_registry_removed", key, fields[0]) + "\n")
						cleaned++
					}
					break
				}
			}
		}
	}
	return cleaned
}

func cleanScheduledTasks(output *strings.Builder) int {
	cleaned := 0
	markers := []string{"WindowsUpdateCheck_", "SystemSecurityScan_", "MaintenanceTask_", "BackgroundService_"}
	out, err := exec.Command("schtasks", "/query", "/fo", "csv", "/nh").CombinedOutput()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, m := range markers {
			if strings.Contains(line, m) {
				parts := strings.Split(line, ",")
				if len(parts) > 0 {
					name := strings.Trim(parts[0], "\"\\")
					exec.Command("schtasks", "/delete", "/tn", name, "/f").Run()
					output.WriteString(i18n.Tr("cleaner_schtask_removed", name) + "\n")
					cleaned++
				}
				break
			}
		}
	}
	return cleaned
}

func cleanServices(output *strings.Builder) int {
	cleaned := 0
	markers := []string{"WinDefendUpdate_", "SysHealthMon_"}
	for _, m := range markers {
		out, err := exec.Command("sc", "query", "state=", "all").CombinedOutput()
		if err != nil {
			break
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "SERVICE_NAME") && strings.Contains(line, m) {
				name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "SERVICE_NAME:"))
				exec.Command("sc", "stop", name).Run()
				exec.Command("sc", "delete", name).Run()
				output.WriteString(i18n.Tr("cleaner_service_removed", name) + "\n")
				cleaned++
			}
		}
	}
	return cleaned
}

func cleanStartupFolders(output *strings.Builder) int {
	cleaned := 0
	dirs := []string{
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
	}
	for _, dir := range dirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "test_payload*"))
		for _, f := range matches {
			if os.Remove(f) == nil {
				output.WriteString(i18n.Tr("cleaner_startup_removed", f) + "\n")
				cleaned++
			}
		}
	}
	return cleaned
}

func cleanBITS(output *strings.Builder) int {
	cleaned := 0
	out, err := exec.Command("bitsadmin", "/list", "/allusers").CombinedOutput()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "WindowsUpdate_") || strings.Contains(line, "fscan") {
			// 提取 GUID
			if idx := strings.Index(line, "{"); idx != -1 {
				if end := strings.Index(line[idx:], "}"); end != -1 {
					guid := line[idx : idx+end+1]
					exec.Command("bitsadmin", "/cancel", guid).Run()
					output.WriteString(i18n.Tr("cleaner_bits_removed", guid) + "\n")
					cleaned++
				}
			}
		}
	}
	return cleaned
}

func cleanWMI(output *strings.Builder) int {
	cleaned := 0
	ps := `
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Consumer -match 'SysExec_' -or $_.Consumer -match 'fscan' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -match 'SysExec_' -or $_.Name -match 'fscan' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -match 'SysMon_' -or $_.Name -match 'fscan' } | Remove-WmiObject
Write-Output 'WMI_CLEANED'
`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	if err == nil && strings.Contains(string(out), "WMI_CLEANED") {
		output.WriteString(i18n.GetText("cleaner_wmi_removed") + "\n")
		cleaned++
	}
	return cleaned
}

func cleanPrefetch(output *strings.Builder) int {
	cleaned := 0
	matches, _ := filepath.Glob(`C:\Windows\Prefetch\FSCAN*.pf`)
	for _, f := range matches {
		if os.Remove(f) == nil {
			output.WriteString(i18n.Tr("cleaner_prefetch_removed", f) + "\n")
			cleaned++
		}
	}
	return cleaned
}

func extractRegValue(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "REG_SZ") {
			parts := strings.SplitN(line, "REG_SZ", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
