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
	results := NewReconciler(client, resolver, 0).All(cfg)

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

	r.All(with)    // first failure opens the window at T0
	r.All(without) // operator removes the FQDN; its entry goes with it
	clock = clock.Add(2 * time.Hour)
	// The operator re-adds the FQDN and its last known IP is back in the
	// whitelist (restored by hand, or never dropped on another rule).
	client.entries["default"] = []WhitelistEntry{
		{EntryType: 1, IP: "203.0.113.7/32", Comment: "fqdn-sync:a.example.com"},
	}
	results := r.All(with) // re-added, DNS still down: a fresh window is due

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
