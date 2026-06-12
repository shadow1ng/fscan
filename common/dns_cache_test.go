package common

import "testing"

func TestDNSCacheResolveIPAndCacheHit(t *testing.T) {
	cache := &dnsCache{}

	first, err := cache.ResolveIP("127.0.0.1")
	if err != nil {
		t.Fatalf("ResolveIP loopback error = %v", err)
	}
	second, err := cache.ResolveIP("127.0.0.1")
	if err != nil {
		t.Fatalf("ResolveIP cached loopback error = %v", err)
	}
	if first != second {
		t.Fatal("ResolveIP should return cached address on second lookup")
	}

	if _, err := cache.ResolveIP("bad host with spaces"); err == nil {
		t.Fatal("ResolveIP should reject an invalid host")
	}
}
