package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// DefaultIntervalSeconds is used when the config omits an interval. 30s is
// half the typical DDNS record TTL (60s), so a changed IP is picked up within
// one poll of becoming resolvable — the reconciler only calls the API on real
// deltas, so a short interval adds no churn when nothing changes.
const DefaultIntervalSeconds = 30

// DefaultGraceSeconds is how long the last known IPs are kept when resolution
// fails for a reason that leaves the answer unknown. One hour covers a
// prolonged outage without leaving an address authorised for a whole day.
const DefaultGraceSeconds = 3600

type RuleConfig struct {
	RuleID string   `json:"rule_id"`
	FQDNs  []string `json:"fqdns"`
}

type Config struct {
	IntervalSeconds int `json:"interval_seconds"`
	// DNSServers are queried in order; empty means the system resolver.
	DNSServers []string `json:"dns_servers,omitempty"`
	// DNSServer is the superseded single-valued form. It is only read, and
	// only when DNSServers is absent, so configs written before the list
	// existed keep working; LoadConfig migrates and clears it.
	DNSServer string `json:"dns_server,omitempty"`
	// GraceSeconds is the failure grace window. 0 means fail closed at once.
	GraceSeconds int `json:"dns_failure_grace_seconds"`
	// UnroutableCIDRs are ranges that must never be authorised. An FQDN that
	// resolves only into these is reported as offline. Note the absence of
	// omitempty: an explicitly empty list means "block nothing" and has to
	// survive a save/reload round-trip.
	UnroutableCIDRs []string     `json:"unroutable_cidrs"`
	Rules           []RuleConfig `json:"rules"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createDefaultConfig(path)
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = DefaultIntervalSeconds
	} else if cfg.IntervalSeconds < MinIntervalSeconds {
		cfg.IntervalSeconds = MinIntervalSeconds
	}
	// Migrate the superseded single-valued field, unless a list is present.
	if len(cfg.DNSServers) == 0 && cfg.DNSServer != "" {
		cfg.DNSServers = []string{cfg.DNSServer}
	}
	cfg.DNSServer = ""
	// A missing key means "default"; an explicit 0 means "no grace". Both
	// decode to 0, so distinguish them by re-reading the raw JSON.
	if !hasJSONKey(data, "dns_failure_grace_seconds") {
		cfg.GraceSeconds = DefaultGraceSeconds
	}
	if cfg.GraceSeconds < 0 {
		cfg.GraceSeconds = 0
	}
	// As with the grace window, a missing key means "default" and an explicit
	// empty list means "the operator switched this off".
	if !hasJSONKey(data, "unroutable_cidrs") {
		cfg.UnroutableCIDRs = append([]string(nil), DefaultUnroutableCIDRs...)
	}
	// Validate at load time so a hand-edited, malformed list refuses to start
	// the plugin instead of leaving Reconciler.Unroutable nil (which blocks
	// nothing) until the first successful compile in the reconcile loop.
	if _, err := NewUnroutableSet(cfg.UnroutableCIDRs); err != nil {
		return nil, fmt.Errorf("invalid unroutable_cidrs: %w", err)
	}
	return &cfg, nil
}

// createDefaultConfig writes a starting config so a plugin installed as a bare
// binary can run. The rule list is empty on purpose: with nothing to sync the
// plugin idles harmlessly until it is configured from its UI, which is safer
// than guessing at rules on someone's proxy.
func createDefaultConfig(path string) (*Config, error) {
	cfg := &Config{
		IntervalSeconds: DefaultIntervalSeconds,
		GraceSeconds:    DefaultGraceSeconds,
		UnroutableCIDRs: append([]string(nil), DefaultUnroutableCIDRs...),
		Rules:           []RuleConfig{},
	}
	if err := saveConfig(cfg, path); err != nil {
		return nil, fmt.Errorf("creating default config %q: %w", path, err)
	}
	return cfg, nil
}

// hasJSONKey reports whether the top-level object contains key.
func hasJSONKey(data []byte, key string) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	_, ok := raw[key]
	return ok
}

const MinIntervalSeconds = 15

var fqdnPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

func validateFQDN(fqdn string) error {
	f := strings.TrimSpace(fqdn)
	if f == "" {
		return fmt.Errorf("fqdn is empty")
	}
	if !fqdnPattern.MatchString(f) {
		return fmt.Errorf("invalid fqdn: %q", fqdn)
	}
	return nil
}

// validateDNSServer accepts an empty string (system resolver), a bare IP or
// hostname, or either with an explicit port.
func validateDNSServer(addr string) error {
	if addr == "" {
		return nil
	}
	host := addr
	if h, p, err := net.SplitHostPort(addr); err == nil {
		port, perr := strconv.Atoi(p)
		if perr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid dns server port: %q", p)
		}
		host = h
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if !fqdnPattern.MatchString(host) {
		return fmt.Errorf("invalid dns server: %q", addr)
	}
	return nil
}

// ParseDNSServers splits a comma-separated UI value into a server list,
// dropping blanks. A blank input means the system resolver.
func ParseDNSServers(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func cloneConfig(c *Config) *Config {
	out := &Config{IntervalSeconds: c.IntervalSeconds, GraceSeconds: c.GraceSeconds}
	out.DNSServers = append([]string(nil), c.DNSServers...)
	out.UnroutableCIDRs = append([]string(nil), c.UnroutableCIDRs...)
	for _, r := range c.Rules {
		fq := make([]string, len(r.FQDNs))
		copy(fq, r.FQDNs)
		out.Rules = append(out.Rules, RuleConfig{RuleID: r.RuleID, FQDNs: fq})
	}
	return out
}

// saveConfig writes the config atomically (temp file + rename) and durably
// (fsync before the rename). Mode 0600: the file is not a secret — the Zoraxy
// API key arrives at runtime and is never written — but it is the access
// policy in the clear.
//
// Durability is not fussiness here. If this file is lost, LoadConfig creates a
// fresh one with no rules, Reconciler.All then iterates over nothing, and the
// entries already in the whitelist are never removed, because removal only
// happens inside the rule that owns them. Losing the config leaves orphaned
// authorisations that nothing will clean up.
func saveConfig(c *Config, path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir flushes the directory entry so the rename itself survives a crash.
// Its error is deliberately ignored: on Windows a directory cannot be opened
// for sync at all, and there the rename's own semantics are what we get.
// Failing the save over it would turn a durability nicety into an outage.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	d.Sync()
	d.Close()
}

// ConfigStore is the thread-safe, persisted source of truth for the config.
type ConfigStore struct {
	mu   sync.RWMutex
	cfg  *Config
	path string
}

func NewConfigStore(cfg *Config, path string) *ConfigStore {
	return &ConfigStore{cfg: cfg, path: path}
}

// Snapshot returns a deep copy safe to read without holding the lock.
func (s *ConfigStore) Snapshot() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneConfig(s.cfg)
}

func (s *ConfigStore) SetInterval(seconds int) error {
	if seconds < MinIntervalSeconds {
		return fmt.Errorf("interval must be >= %d seconds", MinIntervalSeconds)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.cfg)
	next.IntervalSeconds = seconds
	if err := saveConfig(next, s.path); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

// SetDNSServers persists the ordered resolver list. The list is validated as a
// whole before anything is written, so an invalid entry cannot be half-applied.
func (s *ConfigStore) SetDNSServers(servers []string) error {
	cleaned := make([]string, 0, len(servers))
	for _, srv := range servers {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if err := validateDNSServer(srv); err != nil {
			return err
		}
		cleaned = append(cleaned, srv)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.cfg)
	next.DNSServers = cleaned
	if err := saveConfig(next, s.path); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

// SetGraceSeconds persists the failure grace window. 0 disables it.
func (s *ConfigStore) SetGraceSeconds(seconds int) error {
	if seconds < 0 {
		return fmt.Errorf("grace window must be >= 0 seconds")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.cfg)
	next.GraceSeconds = seconds
	if err := saveConfig(next, s.path); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func (s *ConfigStore) AddFQDN(ruleID, fqdn string) error {
	fqdn = strings.TrimSpace(fqdn)
	if err := validateFQDN(fqdn); err != nil {
		return err
	}
	if strings.TrimSpace(ruleID) == "" {
		return fmt.Errorf("rule_id is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.cfg)
	idx := -1
	for i := range next.Rules {
		if next.Rules[i].RuleID == ruleID {
			idx = i
			break
		}
	}
	if idx == -1 {
		next.Rules = append(next.Rules, RuleConfig{RuleID: ruleID, FQDNs: []string{}})
		idx = len(next.Rules) - 1
	}
	for _, existing := range next.Rules[idx].FQDNs {
		if existing == fqdn {
			return fmt.Errorf("fqdn %q already present in rule %q", fqdn, ruleID)
		}
	}
	next.Rules[idx].FQDNs = append(next.Rules[idx].FQDNs, fqdn)
	if err := saveConfig(next, s.path); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func (s *ConfigStore) RemoveFQDN(ruleID, fqdn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.cfg)
	for i := range next.Rules {
		if next.Rules[i].RuleID != ruleID {
			continue
		}
		kept := []string{}
		found := false
		for _, f := range next.Rules[i].FQDNs {
			if f == fqdn {
				found = true
				continue
			}
			kept = append(kept, f)
		}
		if !found {
			return fmt.Errorf("fqdn %q not found in rule %q", fqdn, ruleID)
		}
		next.Rules[i].FQDNs = kept
		if err := saveConfig(next, s.path); err != nil {
			return err
		}
		s.cfg = next
		return nil
	}
	return fmt.Errorf("rule %q not found", ruleID)
}

// ParseCIDRList splits a comma-separated UI value into a CIDR list,
// dropping blanks.
func ParseCIDRList(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// SetUnroutableCIDRs persists the never-authorise list. The list is compiled
// before anything is written, so a malformed entry is rejected as a whole
// instead of leaving a half-applied blocklist behind.
func (s *ConfigStore) SetUnroutableCIDRs(cidrs []string) error {
	cleaned := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if c = strings.TrimSpace(c); c != "" {
			cleaned = append(cleaned, c)
		}
	}
	if _, err := NewUnroutableSet(cleaned); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.cfg)
	next.UnroutableCIDRs = cleaned
	if err := saveConfig(next, s.path); err != nil {
		return err
	}
	s.cfg = next
	return nil
}
