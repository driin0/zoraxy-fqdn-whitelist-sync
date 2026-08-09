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
