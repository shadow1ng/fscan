package parsers

import (
	"context"
	"reflect"
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
