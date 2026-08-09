package main

import (
	"net"
	"reflect"
	"testing"
)

func TestNewResolverQueriesTheConfiguredDNSServer(t *testing.T) {
	addr, queries := startFakeDNS(t, "203.0.113.42")

	ips, err := NewResolver([]string{addr}).Resolve("host.example.net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ips) != 1 || ips[0] != "203.0.113.42" {
		t.Errorf("ips = %v, want [203.0.113.42] from the configured server", ips)
	}
	select {
	case q := <-queries:
		if q != "host.example.net" {
			t.Errorf("queried name = %q, want host.example.net", q)
		}
	default:
		t.Error("the configured DNS server was never queried — the system resolver was used instead")
	}
}

func TestNewResolverWithEmptyServerUsesSystemResolver(t *testing.T) {
	ips, err := NewResolver([]string{""}).Resolve("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected the system resolver to resolve localhost")
	}
}

// stubResolver returns a fixed result, recording whether it was called.
type stubResolver struct {
	ips    []string
	err    error
	called bool
}

func (s *stubResolver) Resolve(string) ([]string, error) {
	s.called = true
	return s.ips, s.err
}

func notFoundErr() error {
	return &net.DNSError{Err: "no such host", Name: "x.example.com", IsNotFound: true}
}

func networkErr() error {
	return &net.DNSError{Err: "i/o timeout", Name: "x.example.com", IsTimeout: true}
}

func TestFallbackResolverUsesSecondServerOnNetworkError(t *testing.T) {
	first := &stubResolver{err: networkErr()}
	second := &stubResolver{ips: []string{"203.0.113.7"}}

	ips, err := (FallbackResolver{resolvers: []Resolver{first, second}}).Resolve("a.example.com")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(ips, []string{"203.0.113.7"}) {
		t.Errorf("ips = %v, want [203.0.113.7] from the second server", ips)
	}
	if !second.called {
		t.Error("the second server was never tried")
	}
}

func TestFallbackResolverDoesNotFallBackOnNameNotFound(t *testing.T) {
	first := &stubResolver{err: notFoundErr()}
	second := &stubResolver{ips: []string{"203.0.113.7"}}

	_, err := (FallbackResolver{resolvers: []Resolver{first, second}}).Resolve("a.example.com")

	if !IsNameNotFound(err) {
		t.Errorf("err = %v, want a name-not-found error propagated as-is", err)
	}
	if second.called {
		t.Error("the second server was queried for a name that authoritatively does not exist")
	}
}

func TestFallbackResolverReturnsLastErrorWhenAllFail(t *testing.T) {
	first := &stubResolver{err: networkErr()}
	second := &stubResolver{err: networkErr()}

	_, err := (FallbackResolver{resolvers: []Resolver{first, second}}).Resolve("a.example.com")

	if err == nil {
		t.Fatal("expected an error when every server failed")
	}
	if IsNameNotFound(err) {
		t.Error("a network failure must not be reported as name-not-found — it would trigger removal")
	}
}

func TestIsNameNotFoundDistinguishesFailureKinds(t *testing.T) {
	if !IsNameNotFound(notFoundErr()) {
		t.Error("NXDOMAIN must be classified as name-not-found")
	}
	if IsNameNotFound(networkErr()) {
		t.Error("a timeout must not be classified as name-not-found")
	}
	if IsNameNotFound(nil) {
		t.Error("nil must not be classified as name-not-found")
	}
}

func TestNewResolverWithNoServersUsesSystemResolver(t *testing.T) {
	ips, err := NewResolver(nil).Resolve("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected the system resolver to resolve localhost")
	}
}

func TestNetResolverResolvesLocalhost(t *testing.T) {
	ips, err := NetResolver{}.Resolve("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP for localhost")
	}
	foundLoopback := false
	for _, ip := range ips {
		if ip == "127.0.0.1" || ip == "::1" {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Errorf("ips = %v, expected a loopback address", ips)
	}
}

func TestNetResolverErrorsOnBogusName(t *testing.T) {
	_, err := NetResolver{}.Resolve("this-name-does-not-exist.invalid")
	if err == nil {
		t.Fatal("expected error for unresolvable name, got nil")
	}
}
