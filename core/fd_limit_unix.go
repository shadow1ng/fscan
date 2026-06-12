//go:build !windows

package core

import "syscall"

func getFDLimit() int {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0
	}
	return int(lim.Cur)
}
