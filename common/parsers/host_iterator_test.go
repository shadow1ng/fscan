package parsers

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestHostIteratorCIDRBatch(t *testing.T) {
	iter, err := NewHostIterator("192.168.1.0/30", "", "")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorDoesNotExpandWholeRangeAtOnce(t *testing.T) {
	iter, err := NewHostIterator("10", "", "")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 3)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorExcludeCIDR(t *testing.T) {
	iter, err := NewHostIterator("192.168.1.0/29", "", "192.168.1.2-192.168.1.4")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"192.168.1.1", "192.168.1.5", "192.168.1.6"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorAcceptsMultipleExcludeSources(t *testing.T) {
	iter, err := NewHostIterator("192.168.1.0/29", "", "192.168.1.2", "192.168.1.5")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"192.168.1.1", "192.168.1.3", "192.168.1.4", "192.168.1.6"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorReadsLongHostFileLine(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts.txt"
	longPrefix := strings.Repeat("a", 70*1024)
	host := longPrefix + ".example.com"
	if err := os.WriteFile(path, []byte(host+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	iter, err := NewHostIterator("", path)
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 1)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}
	if !reflect.DeepEqual(batch, []string{host}) {
		t.Fatalf("batch = %#v, want long host", batch)
	}
}
