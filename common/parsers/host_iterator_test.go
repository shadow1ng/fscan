package parsers

import (
	"context"
	"errors"
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

func TestMultiHostSourceAndMatcherCIDR(t *testing.T) {
	src := &multiHostSource{sources: []hostSource{
		&singleHostSource{host: "192.168.1.1"},
		&singleHostSource{host: "192.168.1.2"},
	}}

	host, ok, err := src.Next()
	if err != nil || !ok || host != "192.168.1.1" {
		t.Fatalf("first Next = %q/%v/%v", host, ok, err)
	}
	host, ok, err = src.Next()
	if err != nil || !ok || host != "192.168.1.2" {
		t.Fatalf("second Next = %q/%v/%v", host, ok, err)
	}
	host, ok, err = src.Next()
	if err != nil || ok || host != "" {
		t.Fatalf("exhausted Next = %q/%v/%v", host, ok, err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	matcher := newHostMatcher()
	if err := matcher.add("192.168.1.0/30,example.com"); err != nil {
		t.Fatalf("matcher add error = %v", err)
	}
	if !matcher.match("192.168.1.1") || !matcher.match("192.168.1.2") || !matcher.match("example.com") {
		t.Fatal("matcher should match CIDR hosts and exact host")
	}
	if matcher.match("192.168.1.3") || matcher.match("nope.example") {
		t.Fatal("matcher matched hosts outside its rules")
	}
	if err := matcher.add("2001:db8::/126"); err == nil {
		t.Fatal("IPv6 CIDR should be rejected by IPv4-only matcher")
	}
}

func TestCloseHostSourcesIgnoresCloseErrors(t *testing.T) {
	first := &closeTrackingSource{err: errors.New("close failed")}
	second := &closeTrackingSource{}

	closeHostSources([]hostSource{first, second})

	if !first.closed || !second.closed {
		t.Fatalf("sources closed = %v/%v, want both true", first.closed, second.closed)
	}
}

type closeTrackingSource struct {
	closed bool
	err    error
}

func (s *closeTrackingSource) Next() (string, bool, error) {
	return "", false, nil
}

func (s *closeTrackingSource) Close() error {
	s.closed = true
	return s.err
}
