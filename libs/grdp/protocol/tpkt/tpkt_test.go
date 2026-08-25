package tpkt

import (
	"testing"

	"github.com/shadow1ng/fscan/libs/grdp/glog"
)

func TestRecvFastPathWithoutListenerDoesNotPanic(t *testing.T) {
	glog.SetLevel(glog.NONE)
	tpkt := &TPKT{}
	tpkt.recvFastPath([]byte{0x00}, nil)
}
