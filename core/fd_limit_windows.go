//go:build windows

package core

// Windows 没有 RLIMIT_NOFILE，句柄上限由系统管理
func getFDLimit() int {
	return 0
}
