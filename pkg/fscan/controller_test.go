package fscan

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanControllerPauseResume(t *testing.T) {
	ctrl := newScanController()

	if ctrl.IsPaused() {
		t.Fatal("new controller should not be paused")
	}
	ctrl.Pause()
	if !ctrl.IsPaused() {
		t.Fatal("should be paused after Pause()")
	}
	ctrl.Pause()
	if !ctrl.IsPaused() {
		t.Fatal("double Pause should still be paused")
	}
	ctrl.Resume()
	if ctrl.IsPaused() {
		t.Fatal("should not be paused after Resume()")
	}
	ctrl.Resume()
	if ctrl.IsPaused() {
		t.Fatal("double Resume should still be unpaused")
	}
}

func TestScanControllerPauseGateBlocks(t *testing.T) {
	ctrl := newScanController()
	ctx := context.Background()

	if err := ctrl.pauseGate(ctx); err != nil {
		t.Fatalf("unpaused gate should not block: %v", err)
	}

	ctrl.Pause()
	done := make(chan error, 1)
	go func() {
		done <- ctrl.pauseGate(ctx)
	}()

	select {
	case <-done:
		t.Fatal("paused gate should block")
	case <-time.After(50 * time.Millisecond):
	}

	ctrl.Resume()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("resumed gate error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gate should unblock after Resume")
	}
}

func TestScanControllerPauseGateContextCancel(t *testing.T) {
	ctrl := newScanController()
	ctrl.Pause()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ctrl.pauseGate(ctx)
	}()

	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("gate error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gate should return on context cancel")
	}
}

func TestScanControllerStatsWithoutState(t *testing.T) {
	ctrl := newScanController()
	stats := ctrl.Stats()
	if stats.Duration <= 0 {
		t.Fatal("duration should be positive")
	}
	if stats.TasksTotal != 0 || stats.Packets != 0 {
		t.Fatalf("stats without state should be zero: %+v", stats)
	}
}

func TestScanControllerProgress(t *testing.T) {
	ctrl := newScanController()
	ctrl.Pause()
	p := ctrl.progress()
	if !p.Paused {
		t.Fatal("progress should report paused")
	}
	ctrl.Resume()
	p = ctrl.progress()
	if p.Paused {
		t.Fatal("progress should report unpaused")
	}
}

func TestScanWithControllerCompletes(t *testing.T) {
	listener := startTestFTPListener(t)
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ctrl, reportCh, errCh := scanner.ScanWithController(ctx, Target{Host: "127.0.0.1", Ports: []int{port}})

	stats := ctrl.Stats()
	if stats.Duration <= 0 {
		t.Fatal("live stats duration should be positive")
	}

	report := <-reportCh
	err := <-errCh
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) == 0 {
		t.Fatal("expected results")
	}
	if report.Summary.Total != len(report.Results) {
		t.Fatalf("summary mismatch: %+v", report.Summary)
	}
}

func TestScanWithControllerPauseResume(t *testing.T) {
	first := startTestFTPListener(t)
	defer first.Close()
	second := startTestFTPListener(t)
	defer second.Close()

	port1 := first.Addr().(*net.TCPAddr).Port
	port2 := second.Addr().(*net.TCPAddr).Port

	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ctrl, reportCh, errCh := scanner.ScanWithController(ctx,
		Target{Host: "127.0.0.1", Ports: []int{port1}},
		Target{Host: "127.0.0.1", Ports: []int{port2}},
	)

	ctrl.Pause()
	if !ctrl.IsPaused() {
		t.Fatal("should be paused")
	}
	ctrl.Resume()

	report := <-reportCh
	err := <-errCh
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) == 0 {
		t.Fatal("expected results after resume")
	}
}

func TestOnProgressCalled(t *testing.T) {
	listener := startTestFTPListener(t)
	defer listener.Close()

	var called int32
	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
		OnProgress: func(p ScanProgress) {
			atomic.AddInt32(&called, 1)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	port := listener.Addr().(*net.TCPAddr).Port
	_, err := scanner.Scan(ctx, Target{Host: "127.0.0.1", Ports: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	// OnProgress fires every 500ms; scan takes at least a moment
	// We mainly verify it doesn't panic; calls may be 0 for very fast scans
}

func TestTaskIDInjected(t *testing.T) {
	listener := startTestFTPListener(t)
	defer listener.Close()

	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
		TaskID:       "task-abc-123",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	port := listener.Addr().(*net.TCPAddr).Port
	results, err := scanner.Scan(ctx, Target{Host: "127.0.0.1", Ports: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	for _, r := range results {
		taskID, ok := r.DetailString("task_id")
		if !ok || taskID != "task-abc-123" {
			t.Fatalf("result missing task_id: %#v", r.Details)
		}
	}
}

func TestTaskIDNotInjectedWhenEmpty(t *testing.T) {
	listener := startTestFTPListener(t)
	defer listener.Close()

	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	port := listener.Addr().(*net.TCPAddr).Port
	results, err := scanner.Scan(ctx, Target{Host: "127.0.0.1", Ports: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if _, ok := r.Details["task_id"]; ok {
			t.Fatalf("task_id should not be present when TaskID is empty: %#v", r.Details)
		}
	}
}

func TestScanWithControllerCanceledContext(t *testing.T) {
	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Plugins:      []string{"redis"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, reportCh, errCh := scanner.ScanWithController(ctx, Target{Host: "127.0.0.1", Ports: []int{6379}})
	<-reportCh
	err := <-errCh
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func startTestFTPListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("220 test FTP\r\n"))
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
			}(conn)
		}
	}()
	return listener
}
