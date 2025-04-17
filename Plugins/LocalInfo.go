package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// 文件扫描黑名单,跳过这些类型和目录
	blacklist = []string{
		".exe", ".dll", ".png", ".jpg", ".bmp", ".xml", ".bin",
		".dat", ".manifest", "locale", "winsxs", "windows\\sys",
	}

	// 敏感文件关键词白名单
	whitelist = []string{
		"密码", "账号", "账户", "配置", "服务器",
		"数据库", "备忘", "常用", "通讯录",
	}

	// Linux系统关键配置文件路径
	linuxSystemPaths = []string{
		// Apache配置
		"/etc/apache/httpd.conf",
		"/etc/httpd/conf/httpd.conf",
		"/etc/httpd/httpd.conf",
		"/usr/local/apache/conf/httpd.conf",
		"/home/httpd/conf/httpd.conf",
		"/usr/local/apache2/conf/httpd.conf",
		"/usr/local/httpd/conf/httpd.conf",
		"/etc/apache2/sites-available/000-default.conf",
		"/etc/apache2/sites-enabled/*",
		"/etc/apache2/sites-available/*",
		"/etc/apache2/apache2.conf",

		// Nginx配置
		"/etc/nginx/nginx.conf",
		"/etc/nginx/conf.d/nginx.conf",

		// 系统配置文件
		"/etc/hosts.deny",
		"/etc/bashrc",
		"/etc/issue",
		"/etc/issue.net",
		"/etc/ssh/ssh_config",
		"/etc/termcap",
		"/etc/xinetd.d/*",
		"/etc/mtab",
		"/etc/vsftpd/vsftpd.conf",
		"/etc/xinetd.conf",
		"/etc/protocols",
		"/etc/logrotate.conf",
		"/etc/ld.so.conf",
		"/etc/resolv.conf",
		"/etc/sysconfig/network",
		"/etc/sendmail.cf",
		"/etc/sendmail.cw",

		// proc信息
		"/proc/mounts",
		"/proc/cpuinfo",
		"/proc/meminfo",
		"/proc/self/environ",
		"/proc/1/cmdline",
		"/proc/1/mountinfo",
		"/proc/1/fd/*",
		"/proc/1/exe",
		"/proc/config.gz",

		// 用户配置文件
		"/root/.ssh/authorized_keys",
		"/root/.ssh/id_rsa",
		"/root/.ssh/id_rsa.keystore",
		"/root/.ssh/id_rsa.pub",
		"/root/.ssh/known_hosts",
		"/root/.bash_history",
		"/root/.mysql_history",
	}

	// Windows系统关键配置文件路径
	windowsSystemPaths = []string{
		"C:\\boot.ini",
		"C:\\windows\\systems32\\inetsrv\\MetaBase.xml",
		"C:\\windows\\repair\\sam",
		"C:\\windows\\system32\\config\\sam",
	}
)

// LocalInfoScan 本地信息收集主函数
func LocalInfoScan(info *Common.HostInfo) (err error) {
	Common.LogBase("开始本地信息收集...")

	// 获取用户主目录
	home, err := os.UserHomeDir()
	if err != nil {
		Common.LogError(fmt.Sprintf("获取用户主目录失败: %v", err))
		return err
	}

	// 扫描固定位置的敏感文件
	scanFixedLocations(home)

	// 根据规则搜索敏感文件
	searchSensitiveFiles()

	Common.LogBase("本地信息收集完成")
	return nil
}

// scanFixedLocations 扫描固定位置的敏感文件
func scanFixedLocations(home string) {
	var paths []string

	switch runtime.GOOS {
	case "windows":
		// 添加Windows固定路径
		paths = append(paths, windowsSystemPaths...)
		paths = append(paths, []string{
			filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data"),
			filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Local State"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data"),
			filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
		}...)

	case "linux":
		// 添加Linux固定路径
		paths = append(paths, linuxSystemPaths...)
		paths = append(paths, []string{
			filepath.Join(home, ".config", "google-chrome", "Default", "Login Data"),
			filepath.Join(home, ".mozilla", "firefox"),
		}...)
	}

	for _, path := range paths {
		// 处理通配符路径
		if strings.Contains(path, "*") {
			var _ = strings.ReplaceAll(path, "*", "")
			if files, err := filepath.Glob(path); err == nil {
				for _, file := range files {
					checkAndLogFile(file)
				}
			}
			continue
		}

		checkAndLogFile(path)
	}
}

// checkAndLogFile 检查并记录敏感文件
func checkAndLogFile(path string) {
	if _, err := os.Stat(path); err == nil {
		Common.LogSuccess(fmt.Sprintf("发现敏感文件: %s", path))
	}
}

// searchSensitiveFiles 搜索敏感文件
func searchSensitiveFiles() {
	var searchPaths []string

	switch runtime.GOOS {
	case "windows":
		// Windows下常见的敏感目录
		home, _ := os.UserHomeDir()
		searchPaths = []string{
			"C:\\Users\\Public\\Documents",
			"C:\\Users\\Public\\Desktop",
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		}
	case "linux":
		// Linux下常见的敏感目录
		home, _ := os.UserHomeDir()
		searchPaths = []string{
			"/home",
			"/opt",
			"/usr/local",
			"/var/www",
			"/var/log",
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
		}
	}

	// 在限定目录下搜索
	for _, searchPath := range searchPaths {
		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// 跳过黑名单目录和文件
			for _, black := range blacklist {
				if strings.Contains(strings.ToLower(path), black) {
					return filepath.SkipDir
				}
			}

			// 检查白名单关键词
			for _, white := range whitelist {
				fileName := strings.ToLower(info.Name())
				if strings.Contains(fileName, white) {
					Common.LogSuccess(fmt.Sprintf("发现潜在敏感文件: %s", path))
					break
				}
			}
			return nil
		})
	}
}
