package main

import (
	"os"
	"path/filepath"
	"reflect"
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
