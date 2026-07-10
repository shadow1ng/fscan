package output

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiskResultStoreDeduplicatesAndMerges(t *testing.T) {
	store, err := newDiskResultStore(filepath.Join(t.TempDir(), "results.json"))
	if err != nil {
		t.Fatalf("newDiskResultStore: %v", err)
	}
	defer func() {
		_ = store.Close()
		_ = store.Remove()
	}()

	host := &ScanResult{Time: time.Now(), Type: TypeHost, Target: "192.0.2.1", Status: "alive"}
	if err := store.Add(host); err != nil {
		t.Fatalf("Add host: %v", err)
	}
	if err := store.Add(host); err != nil {
		t.Fatalf("Add duplicate host: %v", err)
	}
	if err := store.Add(&ScanResult{Type: TypePort, Target: "192.0.2.1", Details: map[string]interface{}{"port": 443}}); err != nil {
		t.Fatalf("Add port: %v", err)
	}
	if err := store.Add(&ScanResult{Type: TypeService, Target: "192.0.2.1:443", Details: map[string]interface{}{"service": "https", "server": "nginx"}}); err != nil {
		t.Fatalf("Add service: %v", err)
	}
	if err := store.Add(&ScanResult{Type: TypeService, Target: "192.0.2.1:443", Details: map[string]interface{}{"title": "Example", "fingerprints": []string{"nginx"}}}); err != nil {
		t.Fatalf("Merge service: %v", err)
	}

	hosts, ports, services, vulns, err := store.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if hosts != 1 || ports != 1 || services != 1 || vulns != 0 {
		t.Fatalf("summary = %d/%d/%d/%d", hosts, ports, services, vulns)
	}

	var merged *ScanResult
	if err := store.ForEach(TypeService, func(result *ScanResult) error {
		merged = result
		return nil
	}); err != nil {
		t.Fatalf("ForEach: %v", err)
	}
	if merged == nil || merged.Details["server"] != "nginx" || merged.Details["title"] != "Example" {
		t.Fatalf("merged service = %#v", merged)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if info, err := os.Stat(store.Path()); err != nil || info.Size() == 0 {
		t.Fatalf("store stat = %#v, %v", info, err)
	}
}

func TestStreamingWriterRemovesStoreOnlyAfterSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	writer, err := NewJSONWriter(path)
	if err != nil {
		t.Fatalf("NewJSONWriter: %v", err)
	}
	storePath := writer.store.Path()
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("store should exist while writer is active: %v", err)
	}
	if err := writer.Write(&ScanResult{Type: TypeHost, Target: "192.0.2.10"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Fatalf("store should be removed after success, stat error = %v", err)
	}
	if _, err := os.Stat(path + ".realtime.tmp"); !os.IsNotExist(err) {
		t.Fatalf("realtime log should be removed after success, stat error = %v", err)
	}
}

func TestStreamingWriterKeepsRecoveryArtifactsOnFinalWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	writer, err := NewJSONWriter(path)
	if err != nil {
		t.Fatalf("NewJSONWriter: %v", err)
	}
	storePath := writer.store.Path()
	if err := writer.Write(&ScanResult{Type: TypeHost, Target: "192.0.2.20"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.file.Close(); err != nil {
		t.Fatalf("close final file: %v", err)
	}
	if err := writer.Close(); err == nil {
		t.Fatal("Close should report the final output failure")
	}
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("store should be retained after failure: %v", err)
	}
	if _, err := os.Stat(path + ".realtime.tmp"); err != nil {
		t.Fatalf("realtime log should be retained after failure: %v", err)
	}
	_ = os.Remove(storePath)
	_ = os.Remove(path + ".realtime.tmp")
}

func TestDiskResultStoreKeepsHeapBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping streaming heap test in short mode")
	}
	store, err := newDiskResultStore(filepath.Join(t.TempDir(), "large.json"))
	if err != nil {
		t.Fatalf("newDiskResultStore: %v", err)
	}
	defer func() {
		_ = store.Close()
		_ = store.Remove()
	}()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	payload := strings.Repeat("x", 2048)
	const resultCount = 10_000
	for i := 0; i < resultCount; i++ {
		result := &ScanResult{
			Type:   TypeHost,
			Target: fmt.Sprintf("198.51.100.%d", i),
			Details: map[string]interface{}{
				"payload": payload,
			},
		}
		if err := store.Add(result); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	heapGrowth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if heapGrowth > 12<<20 {
		t.Fatalf("heap grew by %d bytes while streaming %d results", heapGrowth, resultCount)
	}
	storeInfo, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("stat result store: %v", err)
	}
	t.Logf("streamed %d results: heap growth=%d bytes, disk store=%d bytes", resultCount, heapGrowth, storeInfo.Size())
	hosts, _, _, _, err := store.Summary()
	if err != nil || hosts != resultCount {
		t.Fatalf("stored hosts = %d, err = %v", hosts, err)
	}
}
