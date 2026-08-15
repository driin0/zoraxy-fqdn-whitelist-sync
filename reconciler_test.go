package main

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	m    map[string][]string
	fail map[string]bool
}

func (f *fakeResolver) Resolve(fqdn string) ([]string, error) {
	if f.fail[fqdn] {
		return nil, fmt.Errorf("nxdomain")
	}
	return f.m[fqdn], nil
}

// fakeClient is used both by single-goroutine reconciler tests (which read
// its entries/added/removed fields directly, synchronously, with no
// concurrent writer) and by the reconcile-loop tests (which start the loop
// in its own goroutine and poll results from the test goroutine while it
// runs). The mutex only matters for the latter: it makes ListWhitelistIP /
// AddWhitelistIP / RemoveWhitelistIP safe to call concurrently with the
// addedCopy/removedCopy accessors below.
type fakeClient struct {
	mu      sync.Mutex
	entries map[string][]WhitelistEntry
	added   []string
	removed []string
	listErr error
}

func (c *fakeClient) ListWhitelistIP(ruleID string) ([]WhitelistEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listErr != nil {
		return nil, c.listErr
	}
	return c.entries[ruleID], nil
}

func (c *fakeClient) AddWhitelistIP(ruleID, ip, comment string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.added = append(c.added, ip)
	for i := range c.entries[ruleID] {
		if c.entries[ruleID][i].IP == ip {
			c.entries[ruleID][i].Comment = comment // overwrite, like the real map
			return nil
		}
	}
	c.entries[ruleID] = append(c.entries[ruleID], WhitelistEntry{EntryType: 1, IP: ip, Comment: comment})
	return nil
}

func (c *fakeClient) RemoveWhitelistIP(ruleID, ip string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := []WhitelistEntry{}
	for _, e := range c.entries[ruleID] {
		if e.IP != ip {
			kept = append(kept, e)
		}
	}
	c.entries[ruleID] = kept
	c.removed = append(c.removed, ip)
	return nil
}

// addedCopy and removedCopy return a snapshot of the added/removed IP lists
// taken under the lock. Tests that poll a fakeClient from a different
// goroutine than the one driving the reconciler (e.g. the reconcile-loop
// tests in loop_test.go) must use these instead of reading the added/removed
// fields directly, to avoid racing with the loop goroutine's writes.
func (c *fakeClient) addedCopy() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.added))
	copy(out, c.added)
	return out
}

func (c *fakeClient) removedCopy() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.removed))
	copy(out, c.removed)
	return out
}

// setListErr changes what ListWhitelistIP returns while the reconcile loop is
// already running, so a test can model Zoraxy's API coming up late.
func (c *fakeClient) setListErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listErr = err
}

func newFakeClient() *fakeClient {
	return &fakeClient{entries: map[string][]WhitelistEntry{}}
}

func TestReconcileAddsNewResolvedIP(t *testing.T) {
	client := newFakeClient()
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Added, []string{"203.0.113.7/32"}) {
		t.Errorf("added = %v, want [203.0.113.7/32]", res.Added)
	}
	if len(client.entries["default"]) != 1 || client.entries["default"][0].Comment != "fqdn-sync:a.example.com" {
		t.Errorf("entries = %+v, unexpected", client.entries["default"])
	}
}

func TestReconcileRemovesStaleManagedIP(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7", Comment: "fqdn-sync:a.example.com"},
	}
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.9"}}}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Added, []string{"203.0.113.9/32"}) {
		t.Errorf("added = %v, want [203.0.113.9/32]", res.Added)
	}
	if !reflect.DeepEqual(res.Removed, []string{"203.0.113.7"}) {
		t.Errorf("removed = %v, want [203.0.113.7]", res.Removed)
	}
}

func TestReconcileNeverTouchesUnmanagedEntries(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "10.0.0.5", Comment: "static office server"},
		{EntryType: 1, IP: "192.168.1.0/24", Comment: ""},
	}
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if len(res.Removed) != 0 {
		t.Errorf("removed = %v, want none (static entries must be untouched)", res.Removed)
	}
	if len(client.removed) != 0 {
		t.Errorf("client removed %v, want none", client.removed)
	}
}

func TestReconcileFailClosedRemovesIPWhenResolutionFails(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7", Comment: "fqdn-sync:a.example.com"},
	}
	resolver := &fakeResolver{fail: map[string]bool{"a.example.com": true}}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Removed, []string{"203.0.113.7"}) {
		t.Errorf("removed = %v, want [203.0.113.7] (fail-closed)", res.Removed)
	}
	if len(res.Errors) == 0 {
		t.Error("expected a resolution error to be recorded")
	}
}

func TestReconcileIsolatesFailingFQDN(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
		{EntryType: 1, IP: "198.51.100.2/32", Comment: "fqdn-sync:b.example.com"},
	}
	resolver := &fakeResolver{
		m:    map[string][]string{"b.example.com": {"198.51.100.2"}},
		fail: map[string]bool{"a.example.com": true},
	}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com", "b.example.com"}})

	if !reflect.DeepEqual(res.Removed, []string{"203.0.113.7/32"}) {
		t.Errorf("removed = %v, want only a's IP", res.Removed)
	}
	if len(res.Added) != 0 {
		t.Errorf("added = %v, want none (b already present)", res.Added)
	}
}

func TestReconcileNoOpWhenStable(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if len(res.Added) != 0 || len(res.Removed) != 0 {
		t.Errorf("added=%v removed=%v, want no changes", res.Added, res.Removed)
	}
	if len(client.added) != 0 || len(client.removed) != 0 {
		t.Errorf("client add=%v remove=%v, want no API calls", client.added, client.removed)
	}
}

func TestReconcileDedupsSharedIP(t *testing.T) {
	client := newFakeClient()
	resolver := &fakeResolver{m: map[string][]string{
		"a.example.com": {"203.0.113.7"},
		"b.example.com": {"203.0.113.7"},
	}}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com", "b.example.com"}})

	if !reflect.DeepEqual(res.Added, []string{"203.0.113.7/32"}) {
		t.Errorf("added = %v, want single [203.0.113.7/32]", res.Added)
	}
	if len(client.entries["default"]) != 1 {
		t.Errorf("entries = %d, want 1 (deduped)", len(client.entries["default"]))
	}
}

func TestReconcileDoesNotClobberCollidingAdminIP(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7", Comment: "static office server"},
	}
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}
	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if len(res.Added) != 0 {
		t.Errorf("added = %v, want none (admin IP already present)", res.Added)
	}
	if len(res.Removed) != 0 {
		t.Errorf("removed = %v, want none", res.Removed)
	}
	if len(client.added) != 0 {
		t.Errorf("client added = %v, want none", client.added)
	}
	if len(client.removed) != 0 {
		t.Errorf("client removed = %v, want none", client.removed)
	}

	var found *WhitelistEntry
	for i := range client.entries["default"] {
		if client.entries["default"][i].IP == "203.0.113.7" {
			found = &client.entries["default"][i]
			break
		}
	}
	if found == nil {
		t.Fatal("admin entry for 203.0.113.7 was removed from the store")
	}
	if found.Comment != "static office server" {
		t.Errorf("admin entry comment = %q, want unchanged %q (must not be converted to plugin-owned)", found.Comment, "static office server")
	}
}

func TestReconcileAllHandlesMultipleRulesIndependently(t *testing.T) {
	client := newFakeClient()
	resolver := &fakeResolver{m: map[string][]string{
		"a.example.com": {"203.0.113.7"},
		"c.example.com": {"192.0.2.50"},
	}}
	cfg := &Config{
		IntervalSeconds: 300,
		Rules: []RuleConfig{
			{RuleID: "default", FQDNs: []string{"a.example.com"}},
			{RuleID: "admin", FQDNs: []string{"c.example.com"}},
		},
	}
	results := NewReconciler(client, resolver, 0).All(cfg, false)

	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if len(client.entries["default"]) != 1 || client.entries["default"][0].IP != "203.0.113.7/32" {
		t.Errorf("default entries = %+v, unexpected", client.entries["default"])
	}
	if len(client.entries["admin"]) != 1 || client.entries["admin"][0].IP != "192.0.2.50/32" {
		t.Errorf("admin entries = %+v, unexpected", client.entries["admin"])
	}
}

func TestReconcileWritesIPv4AsCIDR(t *testing.T) {
	client := newFakeClient()
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}

	NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(client.added, []string{"203.0.113.7/32"}) {
		t.Errorf("added = %v, want [203.0.113.7/32] — a bare IPv4 relies on wildcard matching only", client.added)
	}
}

func TestReconcileWritesIPv6AsCIDR(t *testing.T) {
	client := newFakeClient()
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"2001:db8::1"}}}

	NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(client.added, []string{"2001:db8::1/128"}) {
		t.Errorf("added = %v, want [2001:db8::1/128] — Zoraxy never matches a bare IPv6", client.added)
	}
}

// A whitelist written by an older version holds bare IPs. The next cycle must
// converge it to CIDR, and must add the new entry before removing the old one
// so the address is never briefly unauthorised.
func TestReconcileMigratesBareManagedEntryToCIDR(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7", Comment: "fqdn-sync:a.example.com"},
	}
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}

	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Added, []string{"203.0.113.7/32"}) {
		t.Errorf("Added = %v, want [203.0.113.7/32]", res.Added)
	}
	if !reflect.DeepEqual(res.Removed, []string{"203.0.113.7"}) {
		t.Errorf("Removed = %v, want [203.0.113.7] (the bare form)", res.Removed)
	}
	if len(client.added) == 0 || len(client.removed) == 0 {
		t.Fatal("expected both an add and a remove")
	}
}

func TestReconcileLeavesExistingCIDREntryAlone(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	resolver := &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}

	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if len(res.Added) != 0 || len(res.Removed) != 0 {
		t.Errorf("Added = %v, Removed = %v, want no churn on an already-correct entry", res.Added, res.Removed)
	}
}

// Reproduces a whitelist seen in the wild: the plugin owns a bare IP while an
// admin has manually whitelisted the same address in CIDR form. The bare
// duplicate must go, the admin entry must survive untouched, and no third
// copy may appear.
func TestReconcileDropsBareDuplicateOfAdminCIDREntry(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "1.2.3.4", Comment: "fqdn-sync:host.example.com"},
		{EntryType: 1, IP: "1.2.3.4/32", Comment: ""},
	}
	resolver := &fakeResolver{m: map[string][]string{
		"host.example.com": {"1.2.3.4"},
	}}

	res := NewReconciler(client, resolver, 0).Rule(RuleConfig{RuleID: "default", FQDNs: []string{"host.example.com"}})

	if len(res.Added) != 0 {
		t.Errorf("Added = %v, want none — the address is already authorised by the admin entry", res.Added)
	}
	if !reflect.DeepEqual(res.Removed, []string{"1.2.3.4"}) {
		t.Errorf("Removed = %v, want [1.2.3.4] (the bare duplicate)", res.Removed)
	}
	remaining := client.entries["default"]
	if len(remaining) != 1 || remaining[0].IP != "1.2.3.4/32" || remaining[0].Comment != "" {
		t.Errorf("remaining = %+v, want only the untouched admin entry", remaining)
	}
}

// failingResolver fails every lookup with the given error.
type failingResolver struct{ err error }

func (f *failingResolver) Resolve(string) ([]string, error) { return nil, f.err }

// swappableResolver lets a test change resolution behaviour between cycles.
type swappableResolver struct{ inner Resolver }

func (s *swappableResolver) Resolve(fqdn string) ([]string, error) { return s.inner.Resolve(fqdn) }

func graceReconciler(client ZoraxyClient, resolver Resolver, grace time.Duration, clock *time.Time) *Reconciler {
	r := NewReconciler(client, resolver, grace)
	r.now = func() time.Time { return *clock }
	return r
}

func TestGraceKeepsLastKnownIPsWhileWindowIsOpen(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	r := graceReconciler(client, &failingResolver{err: networkErr()}, time.Hour, &clock)
	rule := RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}}

	r.Rule(rule) // first failure starts the window
	clock = clock.Add(30 * time.Minute)
	res := r.Rule(rule) // still inside it

	if len(res.Removed) != 0 {
		t.Errorf("Removed = %v, want nothing removed inside the grace window", res.Removed)
	}
	if len(client.entries["default"]) != 1 {
		t.Errorf("entries = %+v, want the last known IP kept", client.entries["default"])
	}
	if len(res.Errors) == 0 {
		t.Error("expected the grace state to be reported, not hidden")
	}
}

func TestGraceExpiresAndFailsClosed(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	r := graceReconciler(client, &failingResolver{err: networkErr()}, time.Hour, &clock)
	rule := RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}}

	r.Rule(rule)
	clock = clock.Add(61 * time.Minute)
	res := r.Rule(rule)

	if !reflect.DeepEqual(res.Removed, []string{"203.0.113.7/32"}) {
		t.Errorf("Removed = %v, want the IP dropped once the window closed", res.Removed)
	}
}

func TestNameNotFoundRemovesImmediatelyDespiteGrace(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	r := graceReconciler(client, &failingResolver{err: notFoundErr()}, 24*time.Hour, &clock)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Removed, []string{"203.0.113.7/32"}) {
		t.Errorf("Removed = %v, want immediate removal — the record is gone, not unknown", res.Removed)
	}
}

func TestSuccessResetsTheGraceWindow(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	flaky := &swappableResolver{inner: &failingResolver{err: networkErr()}}
	r := graceReconciler(client, flaky, time.Hour, &clock)
	rule := RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}}

	r.Rule(rule)                        // failure at T
	clock = clock.Add(50 * time.Minute) // still inside the window
	flaky.inner = &fakeResolver{m: map[string][]string{"a.example.com": {"203.0.113.7"}}}
	r.Rule(rule) // success: the window must reset
	flaky.inner = &failingResolver{err: networkErr()}
	clock = clock.Add(50 * time.Minute) // 100 min after the first failure
	res := r.Rule(rule)                 // only 50 min since the reset

	if len(res.Removed) != 0 {
		t.Errorf("Removed = %v, want nothing — the window restarted after the success", res.Removed)
	}
}

// mixedResolver resolves some names and fails others with a caller-chosen
// error, so a test can put one FQDN inside the grace window while another
// resolves normally.
type mixedResolver struct {
	m    map[string][]string
	errs map[string]error
}

func (m *mixedResolver) Resolve(fqdn string) ([]string, error) {
	if err, bad := m.errs[fqdn]; bad {
		return nil, err
	}
	return m.m[fqdn], nil
}

func errorMentioning(errs []string, fqdn string) string {
	for _, e := range errs {
		if strings.Contains(e, fqdn) {
			return e
		}
	}
	return ""
}

// An FQDN that owns no whitelist entry has no last known IPs to keep, so the
// grace path must not claim it kept any: the message would assert the opposite
// of what happened. Reviewer's scenario: a.example.com owns 1.2.3.4/32 and
// roams to 5.6.7.8, while b.example.com fails for an unknown reason inside a
// fresh window. 1.2.3.4/32 is removed (it is a's, and a moved), so b kept
// nothing.
func TestGraceMessageIsHonestWhenFQDNOwnsNoEntries(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "1.2.3.4/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	resolver := &mixedResolver{
		m:    map[string][]string{"a.example.com": {"5.6.7.8"}},
		errs: map[string]error{"b.example.com": networkErr()},
	}
	r := graceReconciler(client, resolver, time.Hour, &clock)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com", "b.example.com"}})

	msg := errorMentioning(res.Errors, "b.example.com")
	if msg == "" {
		t.Fatalf("Errors = %v, want one mentioning b.example.com", res.Errors)
	}
	if strings.Contains(msg, "keeping last known IPs") {
		t.Errorf("error for b.example.com = %q, must not claim to keep IPs it did not keep (Removed = %v)", msg, res.Removed)
	}
}

// A failingSince entry that outlives its FQDN's presence in the config makes
// the grace window look long expired when the FQDN comes back, silently
// disabling the protection. Removing an FQDN from the config must forget its
// failure history.
func TestRemovingFQDNFromConfigForgetsItsFailureWindow(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	r := graceReconciler(client, &failingResolver{err: networkErr()}, time.Hour, &clock)

	with := &Config{Rules: []RuleConfig{{RuleID: "default", FQDNs: []string{"a.example.com"}}}}
	without := &Config{Rules: []RuleConfig{{RuleID: "default", FQDNs: []string{}}}}

	r.All(with, false)    // first failure opens the window at T0
	r.All(without, false) // operator removes the FQDN; its entry goes with it
	clock = clock.Add(2 * time.Hour)
	// The operator re-adds the FQDN and its last known IP is back in the
	// whitelist (restored by hand, or never dropped on another rule).
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	results := r.All(with, false) // re-added, DNS still down: a fresh window is due

	res := results[0]
	if len(res.Removed) != 0 {
		t.Errorf("Removed = %v, want nothing — the window must restart for a re-added FQDN", res.Removed)
	}
	msg := errorMentioning(res.Errors, "a.example.com")
	if !strings.Contains(msg, "keeping last known IPs") {
		t.Errorf("error = %q, want the grace state to be reported", msg)
	}
}

// The grace state must be a first-class part of the result, not just prose in
// Errors: the UI has to render "protected, still authorised" differently from
// "revoked", otherwise silent degradation is invisible to the operator.
func TestGraceIsReportedAsAStateWithTheKeptIPs(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	r := graceReconciler(client, &failingResolver{err: networkErr()}, time.Hour, &clock)
	rule := RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}}

	r.Rule(rule) // opens the window
	clock = clock.Add(30 * time.Minute)
	res := r.Rule(rule)

	if res.Grace["a.example.com"] == "" {
		t.Errorf("Grace = %v, want a remaining time for a.example.com", res.Grace)
	}
	if !reflect.DeepEqual(res.Resolved["a.example.com"], []string{"203.0.113.7/32"}) {
		t.Errorf("Resolved[a.example.com] = %v, want the kept IPs so the UI can show them", res.Resolved["a.example.com"])
	}
}

// A failure with no IPs kept is not a grace state as far as the UI is
// concerned: nothing is protected, so it must render as an error.
func TestGraceIsNotReportedWhenNothingWasKept(t *testing.T) {
	client := newFakeClient()
	clock := time.Unix(1_700_000_000, 0)
	r := graceReconciler(client, &failingResolver{err: networkErr()}, time.Hour, &clock)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if len(res.Grace) != 0 {
		t.Errorf("Grace = %v, want empty — no IPs were kept", res.Grace)
	}
}

func TestZeroGraceFailsClosedImmediately(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	clock := time.Unix(1_700_000_000, 0)
	r := graceReconciler(client, &failingResolver{err: networkErr()}, 0, &clock)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Removed, []string{"203.0.113.7/32"}) {
		t.Errorf("Removed = %v, want today's immediate fail-closed behaviour", res.Removed)
	}
}

func TestRuleDoesNotWhitelistAnUnroutableAddress(t *testing.T) {
	client := &fakeClient{entries: map[string][]WhitelistEntry{"default": {}}}
	r := NewReconciler(client, &fakeResolver{m: map[string][]string{
		"down.example.com": {"192.0.2.1"},
	}}, 0)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"down.example.com"}})

	if len(client.added) != 0 {
		t.Errorf("added = %v, want nothing — 192.0.2.1 must never be authorised", client.added)
	}
	if !reflect.DeepEqual(res.Offline["down.example.com"], []string{"192.0.2.1"}) {
		t.Errorf("Offline = %v, want the sentinel address reported", res.Offline)
	}
	if len(res.Resolved["down.example.com"]) != 0 {
		t.Errorf("Resolved = %v, want no routable IPs", res.Resolved["down.example.com"])
	}
}

// The whole point of the sentinel: the device's previous address must lose
// its authorisation as soon as the DDNS says it is unreachable.
func TestRuleRevokesThePreviousAddressWhenTheDeviceGoesOffline(t *testing.T) {
	client := &fakeClient{entries: map[string][]WhitelistEntry{
		"default": {{EntryType: 1, IP: "1.2.3.4/32", Comment: MarkerPrefix + "down.example.com"}},
	}}
	r := NewReconciler(client, &fakeResolver{m: map[string][]string{
		"down.example.com": {"192.0.2.1"},
	}}, time.Hour)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"down.example.com"}})

	if !reflect.DeepEqual(res.Removed, []string{"1.2.3.4/32"}) {
		t.Errorf("Removed = %v, want the stale address revoked at once", res.Removed)
	}
	if len(res.Grace) != 0 {
		t.Errorf("Grace = %v, want none — the name resolved, this is not a DNS failure", res.Grace)
	}
	// The old address being gone is not enough to prove the sentinel itself
	// was never authorised: without this the test would stay green even if
	// the filter were deleted entirely, since the revocation above follows
	// merely from the old IP no longer being desired. Guard against that.
	if len(client.added) != 0 {
		t.Errorf("added = %v, want nothing — the sentinel must never replace the revoked address", client.added)
	}
}

func TestRuleKeepsRoutableAddressesWhenOnlySomeAreSentinels(t *testing.T) {
	client := &fakeClient{entries: map[string][]WhitelistEntry{"default": {}}}
	r := NewReconciler(client, &fakeResolver{m: map[string][]string{
		"mixed.example.com": {"192.0.2.1", "1.2.3.4"},
	}}, 0)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"mixed.example.com"}})

	if !reflect.DeepEqual(client.added, []string{"1.2.3.4/32"}) {
		t.Errorf("added = %v, want only the routable address", client.added)
	}
	if !reflect.DeepEqual(res.Resolved["mixed.example.com"], []string{"1.2.3.4"}) {
		t.Errorf("Resolved = %v, want only the routable address", res.Resolved["mixed.example.com"])
	}
}

// With no set configured the reconciler must behave exactly as before, which
// is what lets the existing suite keep using 192.0.2.x and 203.0.113.x.
func TestRuleWithoutAnUnroutableSetAuthorisesEverything(t *testing.T) {
	client := &fakeClient{entries: map[string][]WhitelistEntry{"default": {}}}
	r := NewReconciler(client, &fakeResolver{m: map[string][]string{
		"a.example.com": {"192.0.2.1"},
	}}, 0)

	r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(client.added, []string{"192.0.2.1/32"}) {
		t.Errorf("added = %v, want the address authorised when no set is configured", client.added)
	}
}

// A device that comes back must not be judged against the outage clock of a
// previous DNS failure.
func TestOfflineClearsTheFailureClock(t *testing.T) {
	client := &fakeClient{entries: map[string][]WhitelistEntry{"default": {}}}
	resolver := &fakeResolver{m: map[string][]string{"down.example.com": {"192.0.2.1"}}}
	r := NewReconciler(client, resolver, time.Hour)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)
	r.failingSince["down.example.com"] = r.now().Add(-30 * time.Minute)

	r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"down.example.com"}})

	if _, still := r.failingSince["down.example.com"]; still {
		t.Error("a successful resolution must clear the failure clock, sentinel or not")
	}
}

// The grace path must not re-authorise a blocklisted address just because it
// was already sitting in the whitelist when an unknown resolve failure opened
// the window. This happens either because an operator adds a range to
// unroutable_cidrs while the FQDN is already failing (the very reason the
// list is configurable), or because a build that had already written a
// sentinel entry gets upgraded. Uses fakeResolver's generic failure (not
// IsNameNotFound), so this goes through the grace branch, not the immediate
// NXDOMAIN one.
func TestGraceRevokesOwnedAddressOnBlocklist(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "192.0.2.77/32", Comment: "fqdn-sync:a.example.com"},
	}
	resolver := &fakeResolver{fail: map[string]bool{"a.example.com": true}}
	r := NewReconciler(client, resolver, time.Hour)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Removed, []string{"192.0.2.77/32"}) {
		t.Errorf("Removed = %v, want the blocklisted address revoked despite the grace window being open", res.Removed)
	}
	if len(client.entries["default"]) != 0 {
		t.Errorf("entries = %+v, want the blocklisted address gone from the whitelist", client.entries["default"])
	}
	// Filtering left nothing to keep, so this must be reported exactly like
	// the existing "FQDN owns no entries" case: no Grace entry, no claim of
	// keeping IPs. Reintroducing that dishonesty here would be as bad as the
	// bug this test guards against.
	if len(res.Grace) != 0 {
		t.Errorf("Grace = %v, want none — nothing was actually kept", res.Grace)
	}
	if len(res.Resolved["a.example.com"]) != 0 {
		t.Errorf("Resolved[a.example.com] = %v, want none kept", res.Resolved["a.example.com"])
	}
	msg := errorMentioning(res.Errors, "a.example.com")
	if strings.Contains(msg, "keeping last known IPs") {
		t.Errorf("error = %q, must not claim to keep an address that was revoked", msg)
	}
}

// Same guarantee as above, for an IPv6 owned entry. IPv6 is the family that
// motivates writing CIDR form at all (see toCIDR): a bare IPv6 address matches
// nothing in Zoraxy's whitelist matcher, so ownedAddressIsUnroutable strips
// the /128 mask before checking the blocklist. A version of that function
// that special-cased IPv6 out (e.g. an early return for any canonical entry
// containing ":") would leave a blocklisted IPv6 address authorised across
// the whole grace window.
func TestGraceRevokesOwnedIPv6AddressOnBlocklist(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "2001:db8::5/128", Comment: "fqdn-sync:a.example.com"},
	}
	resolver := &fakeResolver{fail: map[string]bool{"a.example.com": true}}
	r := NewReconciler(client, resolver, time.Hour)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.com"}})

	if !reflect.DeepEqual(res.Removed, []string{"2001:db8::5/128"}) {
		t.Errorf("Removed = %v, want the blocklisted IPv6 address revoked despite the grace window being open", res.Removed)
	}
	if len(client.entries["default"]) != 0 {
		t.Errorf("entries = %+v, want the blocklisted address gone from the whitelist", client.entries["default"])
	}
	if len(res.Grace) != 0 {
		t.Errorf("Grace = %v, want none — nothing was actually kept", res.Grace)
	}
	if len(res.Resolved["a.example.com"]) != 0 {
		t.Errorf("Resolved[a.example.com] = %v, want none kept", res.Resolved["a.example.com"])
	}
	msg := errorMentioning(res.Errors, "a.example.com")
	if strings.Contains(msg, "keeping last known IPs") {
		t.Errorf("error = %q, must not claim to keep an address that was revoked", msg)
	}
}

type fakeFetcher struct {
	prefixes []string
	err      error
	calls    int
}

func (f *fakeFetcher) Fetch(p Provider) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return append([]string(nil), f.prefixes...), nil
}

func newProviderReconciler(client ZoraxyClient, fetcher ProviderFetcher) *Reconciler {
	r := NewReconciler(client, &fakeResolver{m: map[string][]string{}}, 0)
	r.Fetcher = fetcher
	r.ProviderPeriod = 12 * time.Hour
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)
	return r
}

func TestProviderPassAddsFetchedPrefixes(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13", "2400:cb00::/32"}}
	r := newProviderReconciler(client, fetcher)

	res := r.Rule(RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}})

	if len(res.Added) != 2 {
		t.Fatalf("added %v, want both prefixes", res.Added)
	}
	entries, _ := client.ListWhitelistIP("default")
	for _, e := range entries {
		if e.Comment != MarkerPrefix+"cloudflare" {
			t.Errorf("entry %q is tagged %q, want %q", e.IP, e.Comment, MarkerPrefix+"cloudflare")
		}
	}
	if len(res.Providers) != 1 || res.Providers[0].Error != "" {
		t.Errorf("provider status = %+v, want one healthy entry", res.Providers)
	}
}

// Not time to refetch: the cache answers and the network is not touched. This
// asserts on the call counter rather than inferring it from timing.
func TestProviderPassUsesTheCacheBeforeTheIntervalElapses(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)
	rule := RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}}

	r.Rule(rule)
	if fetcher.calls != 1 {
		t.Fatalf("first cycle made %d calls, want 1", fetcher.calls)
	}
	r.Rule(rule)
	r.Rule(rule)
	if fetcher.calls != 1 {
		t.Errorf("made %d calls, want 1 — the interval had not elapsed", fetcher.calls)
	}
}

// A failure must never revoke. The prefixes already fetched stay authorised
// and the status says stale.
func TestProviderFailureKeepsTheCachedPrefixes(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)
	rule := RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}}

	r.Rule(rule)
	fetcher.err = fmt.Errorf("connection refused")
	r.now = func() time.Time { return time.Now().Add(24 * time.Hour) } // force a refetch
	res := r.Rule(rule)

	if len(res.Removed) != 0 {
		t.Errorf("removed %v — a failed fetch must never revoke", res.Removed)
	}
	entries, _ := client.ListWhitelistIP("default")
	if len(entries) != 1 {
		t.Errorf("whitelist holds %d entries, want the cached prefix kept", len(entries))
	}
	if len(res.Providers) != 1 || res.Providers[0].Error == "" || len(res.Providers[0].Prefixes) == 0 {
		t.Errorf("status = %+v, want stale: an error reported and prefixes still held", res.Providers)
	}
}

// The failure that happens before anything was ever fetched, with entries
// already in the whitelist from a previous run: those entries are the
// fallback, which is why the plugin needs no persistent cache of its own.
func TestProviderFailureWithEmptyCacheKeepsOwnedEntries(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "104.16.0.0/13", Comment: MarkerPrefix + "cloudflare"},
	}
	fetcher := &fakeFetcher{err: fmt.Errorf("connection refused")}
	r := newProviderReconciler(client, fetcher)

	res := r.Rule(RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}})

	if len(res.Removed) != 0 {
		t.Errorf("removed %v, want nothing removed", res.Removed)
	}
	if len(res.Providers) != 1 || len(res.Providers[0].Prefixes) != 1 {
		t.Errorf("status = %+v, want the owned entry reported as still held", res.Providers)
	}
}

// The one state where a provider authorises nothing: nothing cached, nothing
// owned. It must be reported as an error, not as an empty success.
func TestProviderFailureWithNothingToFallBackOnReportsAnError(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{err: fmt.Errorf("connection refused")}
	r := newProviderReconciler(client, fetcher)

	res := r.Rule(RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}})

	if len(res.Added) != 0 {
		t.Errorf("added %v, want nothing", res.Added)
	}
	if len(res.Providers) != 1 || res.Providers[0].Error == "" || len(res.Providers[0].Prefixes) != 0 {
		t.Errorf("status = %+v, want an error with no prefixes", res.Providers)
	}
}

// A failing provider must be retried sooner than the normal interval, or a
// transient failure leaves it stale for half a day.
func TestProviderRetriesSoonerAfterAFailure(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{err: fmt.Errorf("connection refused")}
	r := newProviderReconciler(client, fetcher)
	rule := RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}}

	base := time.Now()
	r.now = func() time.Time { return base }
	r.Rule(rule)
	if fetcher.calls != 1 {
		t.Fatalf("calls = %d, want 1", fetcher.calls)
	}
	r.now = func() time.Time { return base.Add(providerRetryInterval - time.Second) }
	r.Rule(rule)
	if fetcher.calls != 1 {
		t.Errorf("calls = %d, want no retry before the retry interval", fetcher.calls)
	}
	r.now = func() time.Time { return base.Add(providerRetryInterval + time.Second) }
	r.Rule(rule)
	if fetcher.calls != 2 {
		t.Errorf("calls = %d, want a retry once the retry interval passed", fetcher.calls)
	}
}

// A prefix that overlaps the never-authorise list fails the whole fetch. It
// is not dropped with the rest applied: a list that has already shown an
// anomaly is not a list to take the rest of.
func TestProviderFetchOverlappingAnUnroutableRangeIsRejectedWhole(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13", "192.0.2.0/25"}}
	r := newProviderReconciler(client, fetcher)

	res := r.Rule(RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}})

	if len(res.Added) != 0 {
		t.Errorf("added %v, want the whole answer refused", res.Added)
	}
	if len(res.Providers) != 1 || res.Providers[0].Error == "" {
		t.Errorf("status = %+v, want the fetch reported as failed", res.Providers)
	}
}

func TestUnknownProviderBehavesLikeAFailedFetch(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "104.16.0.0/13", Comment: MarkerPrefix + "mystery"},
	}
	fetcher := &fakeFetcher{prefixes: []string{"1.2.3.0/24"}}
	r := newProviderReconciler(client, fetcher)

	res := r.Rule(RuleConfig{RuleID: "default", Providers: []string{"mystery"}})

	if fetcher.calls != 0 {
		t.Errorf("an unknown provider must not be fetched, calls = %d", fetcher.calls)
	}
	if len(res.Removed) != 0 {
		t.Errorf("removed %v — an unknown provider must not revoke anything", res.Removed)
	}
	if len(res.Providers) != 1 || res.Providers[0].Error == "" {
		t.Errorf("status = %+v, want an error", res.Providers)
	}
}

// The one legitimate revocation: the operator took the provider off the rule.
func TestRemovingAProviderFromTheRuleRemovesItsEntries(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "104.16.0.0/13", Comment: MarkerPrefix + "cloudflare"},
	}
	r := newProviderReconciler(client, &fakeFetcher{})

	res := r.Rule(RuleConfig{RuleID: "default"})

	if len(res.Removed) != 1 || res.Removed[0] != "104.16.0.0/13" {
		t.Errorf("removed %v, want the deconfigured provider's prefix", res.Removed)
	}
}

// FQDNs and providers share a rule without disturbing each other, and neither
// touches an entry an administrator added by hand.
func TestFQDNsAndProvidersCoexistAndAdminEntriesSurvive(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "10.0.0.0/8", Comment: "added by hand"},
	}
	r := newProviderReconciler(client, &fakeFetcher{prefixes: []string{"104.16.0.0/13"}})
	// 203.0.113.0/24 is in the default never-authorise list; use a routable one.
	r.Resolver = &fakeResolver{m: map[string][]string{"a.example.net": {"198.18.0.9"}}}

	res := r.Rule(RuleConfig{RuleID: "default", FQDNs: []string{"a.example.net"}, Providers: []string{"cloudflare"}})

	if len(res.Added) != 2 {
		t.Fatalf("added %v, want one FQDN address and one provider prefix", res.Added)
	}
	entries, _ := client.ListWhitelistIP("default")
	found := false
	for _, e := range entries {
		if e.IP == "10.0.0.0/8" && e.Comment == "added by hand" {
			found = true
		}
	}
	if !found {
		t.Error("the administrator's entry was modified or removed")
	}
}

// State is keyed by provider, not by rule, so the same provider on two rules
// is fetched once.
func TestTheSameProviderOnTwoRulesFetchesOnce(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)

	cfg := &Config{Rules: []RuleConfig{
		{RuleID: "default", Providers: []string{"cloudflare"}},
		{RuleID: "other", Providers: []string{"cloudflare"}},
	}}
	r.All(cfg, false)

	if fetcher.calls != 1 {
		t.Errorf("calls = %d, want 1 for the same provider on two rules", fetcher.calls)
	}
}

// A forced refresh overrides the schedule, but not more often than the floor.
func TestForcedRefreshOverridesTheScheduleOnceAMinute(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)
	cfg := &Config{Rules: []RuleConfig{{RuleID: "default", Providers: []string{"cloudflare"}}}}

	base := time.Now()
	r.now = func() time.Time { return base }
	r.All(cfg, false)
	if fetcher.calls != 1 {
		t.Fatalf("calls = %d, want the first cycle to fetch", fetcher.calls)
	}
	r.All(cfg, true)
	if fetcher.calls != 2 {
		t.Errorf("calls = %d, want a forced refresh to refetch", fetcher.calls)
	}
	r.All(cfg, true)
	if fetcher.calls != 2 {
		t.Errorf("calls = %d, want the force floor to swallow the second force", fetcher.calls)
	}
	r.now = func() time.Time { return base.Add(providerForceFloor + time.Second) }
	r.All(cfg, true)
	if fetcher.calls != 3 {
		t.Errorf("calls = %d, want a force honoured again past the floor", fetcher.calls)
	}
}

// Mirrors the failingSince cleanup: state for a provider nobody configures any
// more must not linger and later be mistaken for a fresh fetch.
func TestProviderStateIsForgottenWhenDeconfigured(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)

	withProvider := &Config{Rules: []RuleConfig{{RuleID: "default", Providers: []string{"cloudflare"}}}}
	r.All(withProvider, false)
	r.All(&Config{Rules: []RuleConfig{{RuleID: "default"}}}, false)
	r.All(withProvider, false)

	if fetcher.calls != 2 {
		t.Errorf("calls = %d, want the re-added provider to fetch afresh", fetcher.calls)
	}
}

// Fix round 1, F1: forceThisCycle used to stay true for every rule in the
// cycle, so a provider shared by two rules was fetched twice under a forced
// refresh instead of once. A failing provider on N rules would have been
// retried N times inside the same cycle for the same reason.
func TestForcedRefreshFetchesASharedProviderOnceNotOncePerRule(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)
	cfg := &Config{Rules: []RuleConfig{
		{RuleID: "default", Providers: []string{"cloudflare"}},
		{RuleID: "other", Providers: []string{"cloudflare"}},
	}}

	r.All(cfg, true)

	if fetcher.calls != 1 {
		t.Errorf("calls = %d, want exactly 1 for one provider shared by two rules under force", fetcher.calls)
	}
}

// Fix round 1, F2: main.go constructs the Reconciler before Task 7 assigns a
// Fetcher, so a hand-edited "providers" key must fail like an ordinary fetch
// rather than dereference a nil interface and kill the reconcile-loop
// goroutine.
func TestNilFetcherBehavesLikeAFailedFetchInsteadOfPanicking(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "104.16.0.0/13", Comment: MarkerPrefix + "cloudflare"},
	}
	r := NewReconciler(client, &fakeResolver{m: map[string][]string{}}, 0)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)
	// r.Fetcher intentionally left nil.

	res := r.Rule(RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}})

	if len(res.Removed) != 0 {
		t.Errorf("removed %v, want nothing removed", res.Removed)
	}
	if len(res.Providers) != 1 || res.Providers[0].Error == "" || len(res.Providers[0].Prefixes) != 1 {
		t.Errorf("status = %+v, want an error with the owned entry still reported as held", res.Providers)
	}
}

// Fix round 1, F3: before Task 7 wires ProviderPeriod from config each cycle,
// the field's zero value must not mean "due again immediately" — that would
// turn every tick into a fetch instead of honouring any interval at all.
func TestZeroProviderPeriodDoesNotForceARefetchEveryCycle(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := NewReconciler(client, &fakeResolver{m: map[string][]string{}}, 0)
	r.Fetcher = fetcher
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)
	// r.ProviderPeriod intentionally left at its zero value.
	rule := RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}}

	r.Rule(rule)
	if fetcher.calls != 1 {
		t.Fatalf("first cycle made %d calls, want 1", fetcher.calls)
	}
	r.Rule(rule)
	if fetcher.calls != 1 {
		t.Errorf("calls = %d, want 1 — a zero ProviderPeriod must not force a refetch on every cycle", fetcher.calls)
	}
}

// Fix round 1, F4: ownedAddressIsUnroutable used to test only a provider
// prefix's bare network address for membership in the blocklist, which is
// the wrong question for anything wider than a single host. A /13 already
// whitelisted from Cloudflare, and a /16 the operator later adds to
// unroutable_cidrs that falls entirely inside it, must be caught by overlap
// even though the /13's own network address sits outside the /16 — the exact
// case Contains missed and the README's "never authorises an unroutable
// address" promise depends on.
//
// This covers the empty-cache branch only: the fetcher errors, so nothing is
// cached and the fallback to the owned entries is what runs. The warm-cache
// branch — the one taken on 1,439 of the day's 1,440 ticks — is covered by
// TestACachedProviderPrefixOverlappingANewlyBlockedRangeIsRevokedWithoutARefetch.
func TestOwnedProviderPrefixOverlappingANewlyBlockedRangeIsRevokedWithAnEmptyCache(t *testing.T) {
	client := newFakeClient()
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "104.16.0.0/13", Comment: MarkerPrefix + "cloudflare"},
	}
	fetcher := &fakeFetcher{err: fmt.Errorf("connection refused")}
	r := newProviderReconciler(client, fetcher)
	blocklist := append(append([]string{}, DefaultUnroutableCIDRs...), "104.20.0.0/16")
	r.Unroutable, _ = NewUnroutableSet(blocklist)

	res := r.Rule(RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}})

	if len(res.Removed) != 1 || res.Removed[0] != "104.16.0.0/13" {
		t.Errorf("removed %v, want the /13 revoked: it overlaps the newly blocked /16", res.Removed)
	}
	if len(res.Providers) != 1 || len(res.Providers[0].Prefixes) != 0 {
		t.Errorf("status = %+v, want nothing reported as held", res.Providers)
	}
}

// Fix round 2, F1: the warm cache reached `desired` without ever being tested
// against unroutable_cidrs again, and the cache is what answers on 1,439 of the
// day's 1,440 ticks. Adding a range from the panel therefore changed nothing
// for up to twelve hours, and the refetch that eventually rejected the list
// left the cache in place, so the prefix stayed authorised indefinitely.
func TestACachedProviderPrefixOverlappingANewlyBlockedRangeIsRevokedWithoutARefetch(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)
	rule := RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}}

	r.Rule(rule) // fetch succeeds: cache warm, next attempt twelve hours away
	// What the operator does from the panel, mid-interval.
	r.Unroutable, _ = NewUnroutableSet(append(append([]string{}, DefaultUnroutableCIDRs...), "104.20.0.0/16"))

	res := r.Rule(rule)

	if fetcher.calls != 1 {
		t.Fatalf("calls = %d, want 1 — this cycle must not be due for a refetch", fetcher.calls)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "104.16.0.0/13" {
		t.Errorf("removed %v, want the cached /13 revoked: it overlaps the newly blocked /16", res.Removed)
	}
	if entries, _ := client.ListWhitelistIP("default"); len(entries) != 0 {
		t.Errorf("whitelist holds %v, want the blocked prefix gone", entries)
	}
	if len(res.Providers) != 1 || len(res.Providers[0].Prefixes) != 0 || res.Providers[0].Error == "" {
		t.Errorf("status = %+v, want nothing held and the reason reported", res.Providers)
	}
}

// The rejected cache is refused whole, but the fallback that follows filters
// the owned entries one at a time, so blocking one range does not revoke the
// ranges the operator never objected to.
func TestBlockingOneProviderPrefixLeavesTheProvidersOtherPrefixesAuthorised(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13", "2400:cb00::/32"}}
	r := newProviderReconciler(client, fetcher)
	rule := RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}}

	r.Rule(rule)
	r.Unroutable, _ = NewUnroutableSet(append(append([]string{}, DefaultUnroutableCIDRs...), "104.20.0.0/16"))

	res := r.Rule(rule)

	if len(res.Removed) != 1 || res.Removed[0] != "104.16.0.0/13" {
		t.Fatalf("removed %v, want only the overlapping prefix", res.Removed)
	}
	entries, _ := client.ListWhitelistIP("default")
	if len(entries) != 1 || entries[0].IP != "2400:cb00::/32" {
		t.Errorf("whitelist holds %v, want the prefix nobody blocked still authorised", entries)
	}
}

// The cache is kept rather than cleared when it fails the test, because it is
// upstream data and not an authorisation, and it is tested again before every
// use. Taking the range back out of unroutable_cidrs therefore restores the
// prefixes on the next tick instead of at the next scheduled fetch, which can
// be twelve hours away.
func TestARejectedCacheAuthorisesAgainOnceTheBlockedRangeIsRemoved(t *testing.T) {
	client := newFakeClient()
	fetcher := &fakeFetcher{prefixes: []string{"104.16.0.0/13"}}
	r := newProviderReconciler(client, fetcher)
	rule := RuleConfig{RuleID: "default", Providers: []string{"cloudflare"}}

	r.Rule(rule)
	r.Unroutable, _ = NewUnroutableSet(append(append([]string{}, DefaultUnroutableCIDRs...), "104.20.0.0/16"))
	r.Rule(rule)
	r.Unroutable, _ = NewUnroutableSet(DefaultUnroutableCIDRs)

	res := r.Rule(rule)

	if fetcher.calls != 1 {
		t.Fatalf("calls = %d, want no refetch: the recovery must come from the cache", fetcher.calls)
	}
	if len(res.Added) != 1 || res.Added[0] != "104.16.0.0/13" {
		t.Errorf("added %v, want the prefix authorised again", res.Added)
	}
	if len(res.Providers) != 1 || res.Providers[0].Error != "" {
		t.Errorf("status = %+v, want the provider reported healthy again", res.Providers)
	}
}
