//go:build !debug
// +build !debug

package debug

import "testing"

func TestStubStartStop(t *testing.T) {
	Start()
	Stop()
}
