package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestLoadConfigValid(t *testing.T) {
	p := writeTempConfig(t, `{
		"interval_seconds": 120,
		"rules": [
			{"rule_id": "default", "fqdns": ["a.example.com", "b.example.com"]},
			{"rule_id": "admin", "fqdns": ["c.example.com"]}
		]
	}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IntervalSeconds != 120 {
		t.Errorf("interval = %d, want 120", cfg.IntervalSeconds)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(cfg.Rules))
	}
	if cfg.Rules[0].RuleID != "default" || len(cfg.Rules[0].FQDNs) != 2 {
		t.Errorf("rule[0] = %+v, unexpected", cfg.Rules[0])
	}
}

func TestLoadConfigDefaultsInterval(t *testing.T) {
	p := writeTempConfig(t, `{"interval_seconds": 0, "rules": []}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IntervalSeconds != DefaultIntervalSeconds {
		t.Errorf("interval = %d, want default %d", cfg.IntervalSeconds, DefaultIntervalSeconds)
	}
}

func loadStore(t *testing.T, content string) *ConfigStore {
	t.Helper()
	p := writeTempConfig(t, content)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return NewConfigStore(cfg, p)
}

func TestConfigStoreAddFQDNPersistsAndSnapshots(t *testing.T) {
	s := loadStore(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":[]}]}`)
	if err := s.AddFQDN("default", "casa.example.com"); err != nil {
		t.Fatalf("add: %v", err)
	}
	snap := s.Snapshot()
	if len(snap.Rules) != 1 || len(snap.Rules[0].FQDNs) != 1 || snap.Rules[0].FQDNs[0] != "casa.example.com" {
		t.Fatalf("snapshot = %+v, unexpected", snap.Rules)
	}
	// persisted?
	reloaded, err := LoadConfig(s.path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Rules[0].FQDNs) != 1 || reloaded.Rules[0].FQDNs[0] != "casa.example.com" {
		t.Errorf("persisted = %+v, unexpected", reloaded.Rules)
	}
}

func TestConfigStoreAddCreatesRuleWhenAbsent(t *testing.T) {
	s := loadStore(t, `{"interval_seconds":300,"rules":[]}`)
	if err := s.AddFQDN("newrule", "a.example.com"); err != nil {
		t.Fatalf("add: %v", err)
	}
	snap := s.Snapshot()
	if len(snap.Rules) != 1 || snap.Rules[0].RuleID != "newrule" {
		t.Fatalf("rules = %+v, want one 'newrule'", snap.Rules)
	}
}

func TestConfigStoreAddRejectsDuplicateAndInvalid(t *testing.T) {
	s := loadStore(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":["a.example.com"]}]}`)
	if err := s.AddFQDN("default", "a.example.com"); err == nil {
		t.Error("expected duplicate error")
	}
	if err := s.AddFQDN("default", "not a hostname"); err == nil {
		t.Error("expected invalid-fqdn error")
	}
	if err := s.AddFQDN("default", ""); err == nil {
		t.Error("expected empty-fqdn error")
	}
}

func TestConfigStoreRemoveLeavesEmptyRule(t *testing.T) {
	s := loadStore(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":["a.example.com"]}]}`)
	if err := s.RemoveFQDN("default", "a.example.com"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	snap := s.Snapshot()
	if len(snap.Rules) != 1 || len(snap.Rules[0].FQDNs) != 0 {
		t.Fatalf("rule must remain with empty fqdns, got %+v", snap.Rules)
	}
	if err := s.RemoveFQDN("default", "missing.example.com"); err == nil {
		t.Error("expected not-found error")
	}
}

func TestConfigStoreSetIntervalFloor(t *testing.T) {
	s := loadStore(t, `{"interval_seconds":300,"rules":[]}`)
	if err := s.SetInterval(10); err == nil {
		t.Error("expected error for interval < 15")
	}
	if err := s.SetInterval(30); err != nil {
		t.Fatalf("valid interval: %v", err)
	}
	if s.Snapshot().IntervalSeconds != 30 {
		t.Errorf("interval = %d, want 30", s.Snapshot().IntervalSeconds)
	}
}

func TestConfigStoreSnapshotIsDeepCopy(t *testing.T) {
	s := loadStore(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":["a.example.com"]}]}`)
	snap := s.Snapshot()
	snap.Rules[0].FQDNs[0] = "mutated"
	snap.Rules[0].RuleID = "mutated"
	again := s.Snapshot()
	if again.Rules[0].FQDNs[0] != "a.example.com" || again.Rules[0].RuleID != "default" {
		t.Errorf("store was mutated through snapshot: %+v", again.Rules)
	}
}

func TestLoadConfigReadsDNSServersList(t *testing.T) {
	p := writeTempConfig(t, `{"dns_servers":["1.1.1.1","8.8.8.8"],"rules":[]}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(cfg.DNSServers, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("dns_servers = %v, want [1.1.1.1 8.8.8.8]", cfg.DNSServers)
	}
}

// Configs written before the list existed still carry the single-valued field.
func TestLoadConfigMigratesLegacySingleDNSServer(t *testing.T) {
	p := writeTempConfig(t, `{"dns_server":"1.1.1.1","rules":[]}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(cfg.DNSServers, []string{"1.1.1.1"}) {
		t.Errorf("dns_servers = %v, want [1.1.1.1] migrated from dns_server", cfg.DNSServers)
	}
	if cfg.DNSServer != "" {
		t.Errorf("legacy dns_server = %q, want cleared after migration", cfg.DNSServer)
	}
}

func TestLoadConfigPrefersListOverLegacyField(t *testing.T) {
	p := writeTempConfig(t, `{"dns_server":"9.9.9.9","dns_servers":["1.1.1.1"],"rules":[]}`)
	cfg, _ := LoadConfig(p)
	if !reflect.DeepEqual(cfg.DNSServers, []string{"1.1.1.1"}) {
		t.Errorf("dns_servers = %v, want the explicit list to win", cfg.DNSServers)
	}
}

func TestLoadConfigDefaultsGraceToOneHour(t *testing.T) {
	p := writeTempConfig(t, `{"rules":[]}`)
	cfg, _ := LoadConfig(p)
	if cfg.GraceSeconds != DefaultGraceSeconds {
		t.Errorf("grace = %d, want %d", cfg.GraceSeconds, DefaultGraceSeconds)
	}
}

func TestLoadConfigKeepsExplicitZeroGrace(t *testing.T) {
	p := writeTempConfig(t, `{"dns_failure_grace_seconds":0,"rules":[]}`)
	cfg, _ := LoadConfig(p)
	if cfg.GraceSeconds != 0 {
		t.Errorf("grace = %d, want 0 preserved (explicit immediate fail-closed)", cfg.GraceSeconds)
	}
}

func TestSetDNSServersPersists(t *testing.T) {
	p := writeTempConfig(t, `{"rules":[]}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)

	if err := store.SetDNSServers([]string{"1.1.1.1", "8.8.8.8"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reloaded, _ := LoadConfig(p)
	if !reflect.DeepEqual(reloaded.DNSServers, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("persisted = %v, want [1.1.1.1 8.8.8.8]", reloaded.DNSServers)
	}
}

func TestSetDNSServersRejectsInvalidEntry(t *testing.T) {
	p := writeTempConfig(t, `{"rules":[]}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)

	if err := store.SetDNSServers([]string{"1.1.1.1", "http://nope"}); err == nil {
		t.Error("expected an error for an invalid server in the list")
	}
	if len(store.Snapshot().DNSServers) != 0 {
		t.Error("an invalid list must not be partially applied")
	}
}

func TestSetGraceSecondsPersistsAndRejectsNegative(t *testing.T) {
	p := writeTempConfig(t, `{"rules":[]}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)

	if err := store.SetGraceSeconds(120); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := store.Snapshot().GraceSeconds; got != 120 {
		t.Errorf("grace = %d, want 120", got)
	}
	if err := store.SetGraceSeconds(-1); err == nil {
		t.Error("expected an error for a negative grace window")
	}
}

func TestParseDNSServersSplitsAndTrims(t *testing.T) {
	got := ParseDNSServers(" 1.1.1.1 , 8.8.8.8 ,, ")
	if !reflect.DeepEqual(got, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("ParseDNSServers = %v, want [1.1.1.1 8.8.8.8]", got)
	}
	if got := ParseDNSServers("   "); len(got) != 0 {
		t.Errorf("ParseDNSServers(blank) = %v, want empty (system resolver)", got)
	}
}

func TestCloneConfigCopiesDNSServersIndependently(t *testing.T) {
	c := &Config{DNSServers: []string{"1.1.1.1"}, GraceSeconds: 60}
	clone := cloneConfig(c)
	clone.DNSServers[0] = "8.8.8.8"
	if c.DNSServers[0] != "1.1.1.1" {
		t.Error("cloneConfig shared the DNSServers backing array")
	}
	if clone.GraceSeconds != 60 {
		t.Errorf("cloned grace = %d, want 60", clone.GraceSeconds)
	}
}

func TestLoadConfigDefaultsUnroutableCIDRs(t *testing.T) {
	p := writeTempConfig(t, `{"rules": []}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(cfg.UnroutableCIDRs, DefaultUnroutableCIDRs) {
		t.Errorf("UnroutableCIDRs = %v, want the defaults", cfg.UnroutableCIDRs)
	}
}

// An operator who empties the list has switched the feature off on purpose;
// silently restoring the defaults would override that decision.
func TestLoadConfigHonoursExplicitEmptyUnroutableCIDRs(t *testing.T) {
	p := writeTempConfig(t, `{"unroutable_cidrs": [], "rules": []}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.UnroutableCIDRs) != 0 {
		t.Errorf("UnroutableCIDRs = %v, want an empty list", cfg.UnroutableCIDRs)
	}
}

func TestLoadConfigKeepsCustomUnroutableCIDRs(t *testing.T) {
	p := writeTempConfig(t, `{"unroutable_cidrs": ["198.18.0.0/15"], "rules": []}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(cfg.UnroutableCIDRs, []string{"198.18.0.0/15"}) {
		t.Errorf("UnroutableCIDRs = %v, want [198.18.0.0/15]", cfg.UnroutableCIDRs)
	}
}

// A malformed unroutable_cidrs entry must refuse to start the plugin rather
// than silently starting with no blocklist at all (Unroutable would stay nil
// until the first successful compile, which is fail-open on a fail-closed
// path).
func TestLoadConfigRejectsMalformedUnroutableCIDR(t *testing.T) {
	p := writeTempConfig(t, `{"unroutable_cidrs": ["nonsense"], "rules": []}`)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("expected an error for a malformed unroutable_cidrs entry")
	}
}

func TestParseCIDRListSplitsAndTrims(t *testing.T) {
	got := ParseCIDRList(" 192.0.2.0/24 , 0.0.0.0/8 ,, ")
	if !reflect.DeepEqual(got, []string{"192.0.2.0/24", "0.0.0.0/8"}) {
		t.Errorf("ParseCIDRList = %v, want the two trimmed entries", got)
	}
}

func TestSetUnroutableCIDRsPersists(t *testing.T) {
	p := writeTempConfig(t, `{"rules": []}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)

	if err := store.SetUnroutableCIDRs([]string{"198.18.0.0/15"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reloaded, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reflect.DeepEqual(reloaded.UnroutableCIDRs, []string{"198.18.0.0/15"}) {
		t.Errorf("persisted = %v, want [198.18.0.0/15]", reloaded.UnroutableCIDRs)
	}
}

func TestSetUnroutableCIDRsRejectsMalformedAndKeepsPrevious(t *testing.T) {
	p := writeTempConfig(t, `{"rules": []}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)

	if err := store.SetUnroutableCIDRs([]string{"192.0.2.0/24", "nonsense"}); err == nil {
		t.Fatal("expected an error for a malformed entry")
	}
	if !reflect.DeepEqual(store.Snapshot().UnroutableCIDRs, DefaultUnroutableCIDRs) {
		t.Error("a rejected list must leave the previous one untouched")
	}
}

// The empty list must survive a save/reload round-trip. With omitempty it
// would vanish from the file and come back as the defaults on restart —
// silently re-enabling a feature the operator turned off.
func TestSetUnroutableCIDRsPersistsEmptyList(t *testing.T) {
	p := writeTempConfig(t, `{"rules": []}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)

	if err := store.SetUnroutableCIDRs([]string{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reloaded, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.UnroutableCIDRs) != 0 {
		t.Errorf("reloaded = %v, want the empty list to survive a restart", reloaded.UnroutableCIDRs)
	}
}

// A plugin installed from the plugin manager arrives as a bare binary with no
// config beside it. It has to write one and start, not exit.
func TestLoadConfigCreatesTheDefaultWhenTheFileIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IntervalSeconds != DefaultIntervalSeconds {
		t.Errorf("IntervalSeconds = %d, want %d", cfg.IntervalSeconds, DefaultIntervalSeconds)
	}
	if cfg.GraceSeconds != DefaultGraceSeconds {
		t.Errorf("GraceSeconds = %d, want %d", cfg.GraceSeconds, DefaultGraceSeconds)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("Rules = %v, want none — a fresh install idles until configured", cfg.Rules)
	}
	if !reflect.DeepEqual(cfg.UnroutableCIDRs, DefaultUnroutableCIDRs) {
		t.Errorf("UnroutableCIDRs = %v, want the defaults", cfg.UnroutableCIDRs)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the config file was not written: %v", err)
	}

	// The file it writes must load back identically, or the defaults drift the
	// first time the UI saves.
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reloading the written default failed: %v", err)
	}
	if !reflect.DeepEqual(cfg, reloaded) {
		t.Errorf("reloaded = %+v, want %+v", reloaded, cfg)
	}
}

// Creating a missing config must not turn into silently replacing a broken
// one: a corrupt file is an operator problem, not a reason to lose settings.
func TestLoadConfigStillRejectsAMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{ not json"), 0o644); err != nil {
		t.Fatalf("setting up the fixture failed: %v", err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("want an error for malformed JSON, got nil — a corrupt config must never be silently replaced")
	}
}

// Loading an existing config must leave the file exactly as it found it. This
// is what makes upgrading in place safe: the operator replaces the binary,
// restarts, and the file describing who may reach their services is still the
// file they wrote. A load that rewrote it would reorder keys, drop anything a
// newer schema does not model, and put a truncated access policy on the table
// if the process died mid-write — all for a normalisation that only ever
// matters in memory.
//
// The fixture is chosen to provoke every path that changes the loaded struct:
// an interval under the floor, the superseded dns_server, and no grace,
// unroutable or provider keys at all. It is also the shape a config written by
// v1.1.2 has, which is the upgrade this guards.
func TestLoadingAConfigNeverRewritesTheFileOnDisk(t *testing.T) {
	const original = `{
  "interval_seconds": 5,
  "dns_server": "10.0.0.1",
  "rules": [
    {"rule_id": "default", "fqdns": ["a.example.com"]}
  ]
}`
	path := writeTempConfig(t, original)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-reading the config failed: %v", err)
	}
	if string(after) != original {
		t.Errorf("loading rewrote the file.\n--- before ---\n%s\n--- after ---\n%s", original, after)
	}

	// Without these, a LoadConfig that did nothing whatsoever would pass the
	// check above. The point is that it normalises and declines to persist it.
	if cfg.IntervalSeconds != MinIntervalSeconds {
		t.Errorf("IntervalSeconds = %d, want it clamped to %d", cfg.IntervalSeconds, MinIntervalSeconds)
	}
	if !reflect.DeepEqual(cfg.DNSServers, []string{"10.0.0.1"}) || cfg.DNSServer != "" {
		t.Errorf("legacy DNS server not migrated: DNSServers = %v, DNSServer = %q", cfg.DNSServers, cfg.DNSServer)
	}
	if cfg.GraceSeconds != DefaultGraceSeconds {
		t.Errorf("GraceSeconds = %d, want the default %d", cfg.GraceSeconds, DefaultGraceSeconds)
	}
	if cfg.ProviderIntervalSeconds != DefaultProviderIntervalSeconds {
		t.Errorf("ProviderIntervalSeconds = %d, want the default %d", cfg.ProviderIntervalSeconds, DefaultProviderIntervalSeconds)
	}
	if !reflect.DeepEqual(cfg.UnroutableCIDRs, DefaultUnroutableCIDRs) {
		t.Errorf("UnroutableCIDRs = %v, want the defaults", cfg.UnroutableCIDRs)
	}
	if len(cfg.Rules) != 1 || len(cfg.Rules[0].Providers) != 0 {
		t.Errorf("rules = %+v, want one rule that gained no providers", cfg.Rules)
	}
}

// The config is not a secret, but world-readable it is the access policy in
// the clear: which DDNS names are authorised, which internal resolvers are
// used. 0600 costs nothing and applies to files created before this change
// too, because the temp file carries its own mode through the rename.
func TestSaveConfigWritesOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	// Start from a world-readable file, as an install predating this change would.
	if err := os.WriteFile(p, []byte(`{"rules":[]}`), 0o644); err != nil {
		t.Fatalf("seeding the config: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := saveConfig(cfg, p); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("config mode is %v, want 0600", got)
	}
}

// createDefaultConfig must go through the same hardened path, or a fresh
// install is world-readable until its first edit.
func TestCreatedDefaultConfigIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if _, err := LoadConfig(p); err != nil {
		t.Fatalf("load config: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("created config mode is %v, want 0600", got)
	}
}

// The temp file must not survive a successful save: a leftover .tmp is a
// second copy of the same policy sitting next to the hardened one.
func TestSaveConfigLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := saveConfig(cfg, p); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("the temp file survived the save (stat err = %v)", err)
	}
}

// A config written before providers existed must load byte-for-byte the same
// and simply gain the defaults. There is no migration here and there must
// never need to be one.
func TestLoadConfigDefaultsProviderInterval(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"interval_seconds":30,"rules":[{"rule_id":"default","fqdns":["a.example.net"]}]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ProviderIntervalSeconds != DefaultProviderIntervalSeconds {
		t.Errorf("provider interval = %d, want %d", cfg.ProviderIntervalSeconds, DefaultProviderIntervalSeconds)
	}
	if len(cfg.Rules) != 1 || len(cfg.Rules[0].Providers) != 0 {
		t.Errorf("an old rule must load with no providers, got %+v", cfg.Rules)
	}
}

func TestLoadConfigClampsProviderIntervalToTheFloor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"provider_interval_seconds":5,"rules":[]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ProviderIntervalSeconds != MinProviderIntervalSeconds {
		t.Errorf("provider interval = %d, want the floor %d", cfg.ProviderIntervalSeconds, MinProviderIntervalSeconds)
	}
}

func TestAddProviderPersistsAndRejectsUnknown(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	store := NewConfigStore(cfg, p)

	if err := store.AddProvider("default", "cloudflare"); err != nil {
		t.Fatalf("AddProvider: %v", err)
	}
	if err := store.AddProvider("default", "cloudflare"); err == nil {
		t.Error("adding the same provider twice must be rejected")
	}
	if err := store.AddProvider("default", "not-a-provider"); err == nil {
		t.Error("an unknown provider id must be rejected on the way in")
	}

	reloaded, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Rules) != 1 || len(reloaded.Rules[0].Providers) != 1 ||
		reloaded.Rules[0].Providers[0] != "cloudflare" {
		t.Errorf("the provider did not survive the round trip: %+v", reloaded.Rules)
	}
}

func TestRemovingAProviderClearsItAndRemovingItAgainIsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	store := NewConfigStore(cfg, p)
	if err := store.AddProvider("default", "cloudflare"); err != nil {
		t.Fatalf("AddProvider: %v", err)
	}
	if err := store.RemoveProvider("default", "cloudflare"); err != nil {
		t.Fatalf("RemoveProvider: %v", err)
	}
	if got := store.Snapshot().Rules[0].Providers; len(got) != 0 {
		t.Errorf("providers = %v, want empty", got)
	}
	if err := store.RemoveProvider("default", "cloudflare"); err == nil {
		t.Error("removing what is not there must be an error")
	}
}

func TestSetProviderIntervalRejectsBelowTheFloorAndPersistsAValidValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	store := NewConfigStore(cfg, p)
	if err := store.SetProviderInterval(MinProviderIntervalSeconds - 1); err == nil {
		t.Error("below the floor must be rejected")
	}
	if err := store.SetProviderInterval(86400); err != nil {
		t.Fatalf("SetProviderInterval: %v", err)
	}
	if got := store.Snapshot().ProviderIntervalSeconds; got != 86400 {
		t.Errorf("provider interval = %d, want 86400", got)
	}
}

// cloneConfig backs Snapshot, which the reconcile loop reads every cycle. A
// shallow copy of Providers would let the loop mutate the stored config.
func TestCloneConfigCopiesProvidersIndependently(t *testing.T) {
	c := &Config{Rules: []RuleConfig{{RuleID: "default", Providers: []string{"cloudflare"}}}}
	clone := cloneConfig(c)
	clone.Rules[0].Providers[0] = "tampered"
	if c.Rules[0].Providers[0] != "cloudflare" {
		t.Error("cloneConfig shares the Providers slice with the original")
	}
}
