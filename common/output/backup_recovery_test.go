package output

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWritersPreserveBackupOnFinalWriteFailure(t *testing.T) {
	for _, format := range []Format{FormatTXT, FormatJSON, FormatCSV} {
		t.Run(string(format), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result."+string(format))
			manager, err := NewManager(DefaultManagerConfig(path, format))
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			if err := manager.SaveResult(&ScanResult{Type: TypeHost, Target: "127.0.0.1"}); err != nil {
				t.Fatal(err)
			}
			backupPath := path + ".realtime.tmp"
			before, err := os.ReadFile(backupPath)
			if err != nil || len(before) == 0 {
				t.Fatalf("backup before Close: %q, %v", before, err)
			}
			var file *os.File
			switch writer := manager.writer.(type) {
			case *TXTWriter:
				file = writer.file
			case *JSONWriter:
				file = writer.file
			case *CSVWriter:
				file = writer.file
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := manager.Close(); err == nil {
				t.Fatal("final write failure was not reported")
			}
			after, err := os.ReadFile(backupPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("recovery backup was lost after final write failed: %q, %v", after, err)
			}
		})
	}
}
