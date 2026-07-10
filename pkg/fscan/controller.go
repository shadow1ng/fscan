package fscan

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
)

// ScanController provides pause/resume control and live stats for an
// in-progress scan. It is safe for concurrent use.
type ScanController struct {
	mu      sync.Mutex
	paused  int32
	gate    chan struct{}
	stateMu sync.Mutex
	states  []*common.State
	start   time.Time
}

func newScanController() *ScanController {
	gate := make(chan struct{})
	close(gate)
	return &ScanController{
		gate:  gate,
		start: time.Now(),
	}
}

func (c *ScanController) Pause() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.CompareAndSwapInt32(&c.paused, 0, 1) {
		c.gate = make(chan struct{})
	}
}

func (c *ScanController) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.CompareAndSwapInt32(&c.paused, 1, 0) {
		close(c.gate)
	}
}

func (c *ScanController) IsPaused() bool {
	return atomic.LoadInt32(&c.paused) == 1
}

func (c *ScanController) pauseGate(ctx context.Context) error {
	c.mu.Lock()
	gate := c.gate
	c.mu.Unlock()
	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *ScanController) addState(s *common.State) {
	c.stateMu.Lock()
	c.states = append(c.states, s)
	c.stateMu.Unlock()
}

func (c *ScanController) Stats() ScanStats {
	c.stateMu.Lock()
	states := c.states
	c.stateMu.Unlock()

	duration := time.Since(c.start)
	// Windows can report zero for two reads within the same clock tick. A
	// controller is already running once it is observable, so expose the
	// smallest positive duration instead of a misleading zero value.
	if duration <= 0 {
		duration = time.Nanosecond
	}
	stats := ScanStats{Duration: duration}
	for _, s := range states {
		stats.TasksTotal += s.GetEnd()
		stats.TasksCompleted += s.GetNum()
		stats.Packets += s.GetPacketCount()
		stats.TCPPackets += s.GetTCPPacketCount()
		stats.TCPSuccessPackets += s.GetTCPSuccessPacketCount()
		stats.TCPFailedPackets += s.GetTCPFailedPacketCount()
		stats.UDPPackets += s.GetUDPPacketCount()
		stats.HTTPPackets += s.GetHTTPPacketCount()
		stats.ResourceExhausted += s.GetResourceExhaustedCount()
	}
	return stats
}

func (c *ScanController) progress() ScanProgress {
	stats := c.Stats()
	return ScanProgress{
		TasksTotal:     stats.TasksTotal,
		TasksCompleted: stats.TasksCompleted,
		Duration:       stats.Duration,
		Packets:        stats.Packets,
		TCPPackets:     stats.TCPPackets,
		HTTPPackets:    stats.HTTPPackets,
		Paused:         c.IsPaused(),
	}
}
