package main

import "testing"

func TestUnroutableSetMatchesTheSentinelAddress(t *testing.T) {
	set, err := NewUnroutableSet(DefaultUnroutableCIDRs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !set.Contains("192.0.2.1") {
		t.Error("192.0.2.1 is TEST-NET-1 — it must be recognised as unroutable")
	}
	if !set.Contains("192.0.2.254") {
		t.Error("the whole 192.0.2.0/24 is reserved, not just .1")
	}
	if !set.Contains("0.0.0.0") {
		t.Error("0.0.0.0 must be recognised — it is never a valid source address")
	}
}

func TestUnroutableSetLeavesRealAddressesAlone(t *testing.T) {
	set, err := NewUnroutableSet(DefaultUnroutableCIDRs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, ip := range []string{"1.2.3.4", "5.6.7.8", "2a00:1234::1"} {
		if set.Contains(ip) {
			t.Errorf("%s is a routable address and must be authorised normally", ip)
		}
	}
}

// Private addresses are deliberately absent from the defaults: an internal
// FQDN resolving into RFC 1918 space is a case we want to keep syncing.
func TestUnroutableSetDoesNotBlockPrivateAddresses(t *testing.T) {
	set, err := NewUnroutableSet(DefaultUnroutableCIDRs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, ip := range []string{"10.1.2.3", "172.16.0.9", "192.168.1.10"} {
		if set.Contains(ip) {
			t.Errorf("%s is private, not unroutable — blocking it would break internal sync", ip)
		}
	}
}

func TestNilUnroutableSetBlocksNothing(t *testing.T) {
	var set *UnroutableSet
	if set.Contains("192.0.2.1") {
		t.Error("a nil set must block nothing, so an unconfigured reconciler behaves as before")
	}
}

func TestEmptyUnroutableSetBlocksNothing(t *testing.T) {
	set, err := NewUnroutableSet([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if set.Contains("192.0.2.1") {
		t.Error("an explicitly empty list means the operator disabled the feature")
	}
}

func TestNewUnroutableSetRejectsMalformedCIDR(t *testing.T) {
	if _, err := NewUnroutableSet([]string{"192.0.2.0/24", "not-a-cidr"}); err == nil {
		t.Fatal("expected an error for a malformed CIDR")
	}
}

// A bare address is a common operator slip; accept it as a single host rather
// than failing, mirroring how the reconciler already canonicalises entries.
func TestNewUnroutableSetAcceptsBareAddress(t *testing.T) {
	set, err := NewUnroutableSet([]string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !set.Contains("192.0.2.1") {
		t.Error("a bare address must be treated as a single-host range")
	}
	if set.Contains("192.0.2.2") {
		t.Error("a bare address must not widen to its enclosing network")
	}
}

func TestUnroutableSetIgnoresUnparseableInput(t *testing.T) {
	set, err := NewUnroutableSet(DefaultUnroutableCIDRs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if set.Contains("definitely-not-an-ip") {
		t.Error("a non-address must not be reported as unroutable")
	}
}

// Overlaps is the prefix-shaped counterpart of Contains, and it is a safety
// control: a prefix that intersects a never-authorise range must be refused
// however it intersects — contained in one, containing one, or identical.
//
// The cross-family rows pin behaviour verified against Go's net package on
// 2026-08-15 rather than assumed. A genuine IPv6 prefix does not overlap an
// IPv4 range. The IPv4-mapped form does, because IPNet.Contains normalises
// through To4() — and that is the direction we want, since the result is a
// rejection.
func TestUnroutableSetOverlapsPrefixes(t *testing.T) {
	set, err := NewUnroutableSet([]string{"192.0.2.0/24", "2001:db8::/32", "127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewUnroutableSet: %v", err)
	}
	cases := []struct {
		name   string
		prefix string
		want   bool
	}{
		{"identical to a blocked range", "192.0.2.0/24", true},
		{"contained in a blocked range", "192.0.2.128/25", true},
		{"containing a blocked range", "192.0.0.0/16", true},
		{"the default route swallows everything", "0.0.0.0/0", true},
		{"a real CDN prefix is untouched", "104.16.0.0/13", false},
		{"a disjoint v4 prefix", "198.51.100.0/24", false},
		{"an IPv6 prefix inside a blocked v6 range", "2001:db8:1::/48", true},
		{"a real CDN v6 prefix is untouched", "2a06:98c0::/29", false},
		{"the v6 default route", "::/0", true},
		{"an IPv4-mapped prefix over a blocked v4 range", "::ffff:127.0.0.1/120", true},
		{"not a CIDR at all", "192.0.2.1", false},
		{"nonsense", "hello", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := set.Overlaps(c.prefix); got != c.want {
				t.Errorf("Overlaps(%q) = %v, want %v", c.prefix, got, c.want)
			}
		})
	}
}

func TestNilUnroutableSetOverlapsNothing(t *testing.T) {
	var set *UnroutableSet
	if set.Overlaps("0.0.0.0/0") {
		t.Error("a nil set must block nothing, not everything")
	}
}
