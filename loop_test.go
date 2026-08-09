package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestReconcileLoopRebuildsResolverOnDNSServerChange proves DNS servers edited
// in the UI take effect on the next cycle without restarting the plugin —
// the loop must build its resolver from the current config, not capture one
// at startup.
func TestReconcileLoopRebuildsResolverOnDNSServerChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"dns_servers":["1.1.1.1"],"rules":[]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	store := NewConfigStore(cfg, p)

	built := make(chan string, 8)
	newResolver := func(servers []string) Resolver {
		built <- strings.Join(servers, ",")
		return &fakeResolver{m: map[string][]string{}}
	}

	trigger := make(chan struct{}, 1)
	go runReconcileLoop(newFakeClient(), newResolver, store, &StatusStore{}, trigger)

	if got := recvWithin(t, built); got != "1.1.1.1" {
		t.Errorf("first cycle used %q, want 1.1.1.1", got)
	}

	if err := store.SetDNSServers([]string{"9.9.9.9", "8.8.8.8"}); err != nil {
		t.Fatalf("SetDNSServers: %v", err)
	}
	trigger <- struct{}{}

	if got := recvWithin(t, built); got != "9.9.9.9,8.8.8.8" {
		t.Errorf("cycle after the change used %q, want 9.9.9.9,8.8.8.8", got)
	}
}

// The grace window is useless if the failure clock restarts every cycle.
//
// This test uses a 1-second grace window (not the default 3600s) and forces
// a second cycle strictly after that window has expired, then asserts on
// expiry — the only observable that distinguishes the two designs:
//   - one Reconciler kept for the whole run: the window opened on cycle 1
//     and, having expired, cycle 2 fails closed and removes the IP.
//   - a Reconciler rebuilt every cycle (the regression this test guards
//     against): failingSince is discarded each time, so cycle 2 sees a fresh
//     failure, restarts the window, and never removes the IP.
//
// Using the default 3600s grace with a couple of wall-clock seconds of
// observation cannot tell these apart (this used to be exactly what let the
// regression slip through); shrinking the grace to 1s and waiting past it
// makes cycle 2's behaviour the discriminator.
func TestReconcileLoopPreservesGraceStateAcrossCycles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"dns_failure_grace_seconds":1,"rules":[{"rule_id":"default","fqdns":["a.example.com"]}]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	store := NewConfigStore(cfg, p)

	// A routable address, not one of the documentation/TEST-NET ranges: this
	// config has no unroutable_cidrs key, so LoadConfig fills in
	// DefaultUnroutableCIDRs, which — as of the fix making the grace path
	// honour the blocklist too — would otherwise revoke a 203.0.113.0/24
	// fixture immediately and defeat what this test is actually exercising.
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "1.2.3.4/32", Comment: "fqdn-sync:a.example.com"},
	}
	trigger := make(chan struct{}, 1)
	status := &StatusStore{}
	go runReconcileLoop(client, func([]string) Resolver { return &failingResolver{err: networkErr()} }, store, status, trigger)

	// Cycle 1 is the loop's synchronous first run: it starts the 1s grace
	// window and must remove nothing yet.
	var firstRun time.Time
	waitDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitDeadline) {
		if lastRun, _ := status.Snapshot(); !lastRun.IsZero() {
			firstRun = lastRun
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if firstRun.IsZero() {
		t.Fatal("the loop never completed its first cycle")
	}
	if removed := client.removedCopy(); len(removed) > 0 {
		t.Fatalf("removed %v on the first cycle, want nothing (the grace window just opened)", removed)
	}

	// Wait until strictly more than the 1-second window has elapsed since
	// the first cycle, then force a second cycle.
	for time.Since(firstRun) <= 1*time.Second {
		time.Sleep(10 * time.Millisecond)
	}
	trigger <- struct{}{}

	// Poll for the removal instead of sleeping a fixed amount, so a slow
	// machine does not flake the test.
	pollDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(pollDeadline) {
		if removed := client.removedCopy(); len(removed) > 0 {
			if !reflect.DeepEqual(removed, []string{"1.2.3.4/32"}) {
				t.Fatalf("removed = %v, want [1.2.3.4/32]", removed)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("1.2.3.4/32 was never removed after the grace window expired")
}

// The loop is where the config meets the reconciler; without this wiring the
// blocklist would be configurable but never applied.
func TestReconcileLoopAppliesTheConfiguredUnroutableCIDRs(t *testing.T) {
	client := &fakeClient{entries: map[string][]WhitelistEntry{"default": {}}}
	cfg := &Config{
		IntervalSeconds: 15,
		UnroutableCIDRs: DefaultUnroutableCIDRs,
		Rules: []RuleConfig{{RuleID: "default", FQDNs: []string{
			"down.example.com", "up.example.com",
		}}},
	}
	store := NewConfigStore(cfg, filepath.Join(t.TempDir(), "config.json"))
	newResolver := func([]string) Resolver {
		return &fakeResolver{m: map[string][]string{
			"down.example.com": {"192.0.2.1"},
			"up.example.com":   {"1.2.3.4"},
		}}
	}

	go runReconcileLoop(client, newResolver, store, &StatusStore{}, make(chan struct{}, 1))

	// Wait for the routable address to land. Without this the assertion below
	// would also hold if the loop never ran at all, and the test would pass
	// while proving nothing.
	deadline := time.Now().Add(2 * time.Second)
	for !reflect.DeepEqual(client.addedCopy(), []string{"1.2.3.4/32"}) {
		if time.Now().After(deadline) {
			t.Fatalf("added = %v, want exactly [1.2.3.4/32] — the sentinel must be filtered out", client.addedCopy())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func recvWithin(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a reconcile cycle to build a resolver")
		return ""
	}
}
