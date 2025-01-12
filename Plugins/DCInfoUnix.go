//go:build !windows

package Plugins

import "github.com/shadow1ng/fscan/Common"

func DCInfoScan(info *Common.HostInfo) (err error) {
	return nil
}
