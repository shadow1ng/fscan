package fscan

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type progressPlugin struct {
	plugins.BasePlugin
	observed <-chan struct{}
}

func (p *progressPlugin) Scan(ctx context.Context, _ *common.HostInfo, session *common.ScanSession) *plugins.Result {
	session.State.IncrementPacketCount()
	select {
	case <-p.observed:
	case <-ctx.Done():
	}
	return &plugins.Result{Skipped: true}
}

func TestOnProgressIncludesScanStateWithoutController(t *testing.T) {
	const name = "test_progress_state"
	observed := make(chan struct{})
	plugins.RegisterWithTypes(name, func() plugins.Plugin {
		return &progressPlugin{BasePlugin: plugins.NewBasePlugin(name), observed: observed}
	}, []int{10001}, []string{plugins.PluginTypeService})
	var once sync.Once
	scanner := NewScanner(Config{
		Plugins: []string{name},
		OnProgress: func(p ScanProgress) {
			if p.Packets > 0 {
				once.Do(func() { close(observed) })
			}
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := scanner.Scan(ctx, Target{Host: "127.0.0.1:10001"})
	select {
	case <-observed:
	default:
		t.Fatalf("OnProgress never observed the active scan state: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
}
