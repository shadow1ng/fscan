//go:build !windows

package Plugins

import "github.com/shadow1ng/fscan/Common"

func MiniDump(info *Common.HostInfo) (err error) {
	return nil
}
