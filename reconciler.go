package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const MarkerPrefix = "fqdn-sync:"

type ReconcileResult struct {
	RuleID   string
	Resolved map[string][]string // fqdn -> resolved IPs
	// Grace holds, per FQDN currently inside its grace window with IPs kept, a
	// human-readable remaining time. It exists so the UI can render "failing
	// but still authorised" as its own state instead of hiding it in Errors.
	// Like every other map here it is allocated fresh each cycle and never
	// mutated after the result is published (see StatusStore.Snapshot).
	Grace map[string]string
	// Offline holds, per FQDN, the unroutable addresses it resolved to. Such
	// an answer is the DDNS service positively reporting the device as
	// unreachable, so it is neither a success nor a failure and gets a state
	// of its own — rendering it as ok would be a lie the operator acts on.
	Offline map[string][]string
	Added   []string
	Removed []string
	Errors  []string
	// Providers holds one entry per provider configured on this rule, healthy
	// or not. Built fresh each cycle — see the doc comment on ProviderStatus.
	Providers []ProviderStatus
}

// ProviderStatus is how one provider's outcome is reported to the UI. Like
// every other field on ReconcileResult it is built fresh each cycle and never
// mutated after publication — see StatusStore.Snapshot.
type ProviderStatus struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Prefixes are the ranges currently authorised for this provider, whether
	// they came from a fresh fetch, the cache, or the entries already owned.
	Prefixes []string `json:"prefixes"`
	// LastSuccess is RFC3339, empty if a fetch has never succeeded this run.
	LastSuccess string `json:"last_success"`
	// StaleFor is a human-readable age, set only while Error is set.
	StaleFor string `json:"stale_for"`
	Error    string `json:"error"`
	// Blocked says the ranges were refused this cycle for overlapping the
	// never-authorise list, rather than a fetch having failed. The two look
	// identical through Error alone, and the panel's fetch-failure copy is
	// false three times over here — the list is fresh, nothing failed to
	// refresh, and a range was revoked instead of kept — at the exact moment
	// the operator is checking whether their edit took effect. A bool, so the
	// publish-by-reference contract on ReconcileResult is unaffected.
	Blocked bool `json:"blocked"`
}

// toCIDR turns a single address into its single-host CIDR form (/32 for IPv4,
// /128 for IPv6). Zoraxy matches a whitelist entry with either MatchIpWildcard
// or MatchIpCIDR: the former splits on "." and bails unless it sees exactly
// four octets, so it can never match an IPv6 address, and the latter needs a
// CIDR mask to parse at all. A bare IPv6 therefore matches nothing and, under
// fail-closed, would deny access silently. Writing CIDR satisfies MatchIpCIDR
// for both families.
func toCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip // not an address we can classify; store as-is
	}
	if parsed.To4() != nil {
		return ip + "/32"
	}
	return ip + "/128"
}

// canonicalEntry maps a stored whitelist entry to the form this plugin writes,
// so a bare address and its /32 (or /128) are treated as one authorisation.
// Anything that is not a plain address (a real subnet, a wildcard) is left
// untouched — it is not something we own or would ever write.
func canonicalEntry(entry string) string {
	if net.ParseIP(entry) != nil {
		return toCIDR(entry)
	}
	return entry
}

// ownedAddressIsUnroutable reports whether a canonical entry from ownedBy —
// a CIDR, either an FQDN's resolved address in host form ("a/32", "a/128") or
// a provider's own prefix such as "104.16.0.0/13" — falls in the blocklist.
// Overlaps is the test that is correct for both shapes: for a /32 or /128 it
// agrees exactly with Contains, since a single-host prefix can only ever be
// identical to or contained in a blocked range, never straddle its edge.
// For a wider provider prefix, Overlaps is the only correct test — Contains
// on the bare network address misses the case where only part of the prefix
// (not its first address) falls inside a range the operator adds later, or
// where the provider prefix is the wider one and contains the blocked range.
// A value that fails to parse as a CIDR (which should not happen for an
// owned entry) falls back to Contains rather than silently passing the
// filter.
func ownedAddressIsUnroutable(u *UnroutableSet, canonical string) bool {
	if _, _, err := net.ParseCIDR(canonical); err != nil {
		return u.Contains(canonical)
	}
	return u.Overlaps(canonical)
}

// keepableOwned returns the owned entries that may still be authorised.
//
// Grace protects against a failure that leaves the answer unknown; it must
// never protect an address that has to be refused whatever the reason it is
// there — an operator adding a range to unroutable_cidrs while a source is
// already failing, or a sentinel surviving an upgrade. Both the FQDN grace
// path and the provider fallback path go through here, which is the one piece
// the two passes genuinely share, and why it must reject on overlap rather
// than on bare membership: the fallback path is exactly where a provider
// prefix already on the whitelist gets re-evaluated against the blocklist.
func keepableOwned(u *UnroutableSet, owned []string) []string {
	if len(owned) == 0 {
		return nil
	}
	kept := make([]string, 0, len(owned))
	for _, entry := range owned {
		if ownedAddressIsUnroutable(u, entry) {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// Reconciler owns the state that must survive between cycles: how long each
// FQDN has been failing to resolve. The clock is injectable so grace-window
// tests do not sleep.
type Reconciler struct {
	Client   ZoraxyClient
	Resolver Resolver
	Grace    time.Duration
	// Unroutable filters out addresses that must never be authorised. A nil
	// set blocks nothing.
	Unroutable *UnroutableSet
	// Fetcher retrieves provider range lists. Injectable so no test reaches
	// the network.
	Fetcher ProviderFetcher
	// ProviderPeriod is how long a successful fetch is good for.
	ProviderPeriod time.Duration

	now            func() time.Time
	failingSince   map[string]time.Time
	providers      map[string]*providerState
	lastForced     time.Time
	forceThisCycle bool
}

// providerState is the in-memory schedule and cache for one provider, keyed by
// provider id and shared across rules. It is deliberately not persisted: on a
// restart it is empty, which forces a fetch on the first cycle, and the plugin
// keeps its "nothing to flush on the way out" property.
type providerState struct {
	prefixes    []string
	lastSuccess time.Time
	nextAttempt time.Time
	lastErr     string
	// lastForcedSeen is stamped with r.now() whenever a forced cycle attempts
	// this provider. It exists only so shouldAttempt can tell "already handled
	// this forced cycle" apart from "still due" — without it, forceThisCycle
	// stays true for every rule in the cycle, and a provider shared by two
	// rules (or failing, and so never advancing nextAttempt) would be fetched
	// once per rule instead of once per cycle.
	lastForcedSeen time.Time
}

func NewReconciler(client ZoraxyClient, resolver Resolver, grace time.Duration) *Reconciler {
	return &Reconciler{
		Client:       client,
		Resolver:     resolver,
		Grace:        grace,
		now:          time.Now,
		failingSince: map[string]time.Time{},
		providers:    map[string]*providerState{},
	}
}

// Rule syncs one access rule's whitelist with the resolved IPs of its
// configured FQDNs. Only entries whose comment carries MarkerPrefix are
// treated as plugin-owned and are eligible for removal.
func (r *Reconciler) Rule(rule RuleConfig) ReconcileResult {
	result := ReconcileResult{
		RuleID:    rule.RuleID,
		Resolved:  map[string][]string{},
		Grace:     map[string]string{},
		Offline:   map[string][]string{},
		Providers: []ProviderStatus{},
	}

	// 1. Read the current whitelist first: the grace path answers "what were
	// this FQDN's last known IPs?" from the entries we already own, which is
	// what keeps the plugin free of its own persistent state.
	entries, err := r.Client.ListWhitelistIP(rule.RuleID)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list %s: %v", rule.RuleID, err))
		return result
	}
	// Compare by canonical (CIDR) form so that a bare "1.2.3.4" and a
	// "1.2.3.4/32" written by an admin — or by an older version of this
	// plugin — are recognised as the same authorisation instead of being
	// duplicated.
	adminPresent := map[string]bool{} // canonical form of entries we do not own
	managed := map[string]string{}    // canonical form -> the IP string as stored
	ownedBy := map[string][]string{}  // fqdn -> canonical forms we hold for it
	for _, e := range entries {
		canonical := canonicalEntry(e.IP)
		if !strings.HasPrefix(e.Comment, MarkerPrefix) {
			adminPresent[canonical] = true
			continue
		}
		managed[canonical] = e.IP
		owner := strings.TrimPrefix(e.Comment, MarkerPrefix)
		ownedBy[owner] = append(ownedBy[owner], canonical)
	}

	// 2. Build the desired set: ip -> owning fqdn (first provenance wins).
	desired := map[string]string{}
	for _, fqdn := range rule.FQDNs {
		ips, err := r.Resolver.Resolve(fqdn)
		if err == nil {
			delete(r.failingSince, fqdn)
			// Split the answer: an unroutable address is a statement that the
			// device is down, not a location. It is dropped from the desired
			// set, so whatever the device held before is revoked on this very
			// cycle — no grace, because nothing failed.
			routable := []string{}
			for _, ip := range ips {
				if r.Unroutable.Contains(ip) {
					result.Offline[fqdn] = append(result.Offline[fqdn], ip)
					continue
				}
				routable = append(routable, ip)
			}
			result.Resolved[fqdn] = routable
			for _, ip := range routable {
				entry := toCIDR(ip)
				if _, exists := desired[entry]; !exists {
					desired[entry] = fqdn
				}
			}
			continue
		}
		if IsNameNotFound(err) {
			// An authoritative "this name does not exist": the record really
			// is gone, so fail closed at once regardless of the grace window.
			delete(r.failingSince, fqdn)
			result.Errors = append(result.Errors, fmt.Sprintf("resolve %s: %v", fqdn, err))
			continue
		}
		// The window is tracked even when there is nothing to keep, so that a
		// later cycle in which this FQDN does own entries still measures the
		// outage from its first failure.
		left, inGrace := r.graceLeft(fqdn)
		// A last known IP that now falls in the blocklist must never be kept:
		// grace protects against an unknown DNS failure, not against an
		// address that must never be authorised regardless of why it is
		// there (an operator adding a range to unroutable_cidrs while the
		// FQDN is already failing, or a sentinel entry surviving an upgrade).
		kept := keepableOwned(r.Unroutable, ownedBy[fqdn])
		// ownedBy is keyed by the single owner named in an entry's comment, so
		// an FQDN can legitimately hold no entries — including when another
		// FQDN resolved to the same address first and was recorded as its
		// owner, or when every entry it did hold was just filtered out above
		// as blocklisted. With no last known IPs there is nothing to protect,
		// and claiming otherwise would assert the opposite of what happened.
		if inGrace && len(kept) > 0 {
			for _, ip := range kept {
				if _, exists := desired[ip]; !exists {
					desired[ip] = fqdn
				}
			}
			// Report the kept IPs and the remaining window as a state of their
			// own, so the UI can distinguish "still authorised, protected" from
			// "revoked" instead of rendering both as a bare failure.
			result.Resolved[fqdn] = append([]string(nil), kept...)
			result.Grace[fqdn] = left.Round(time.Minute).String()
			result.Errors = append(result.Errors, fmt.Sprintf(
				"resolve %s: %v (keeping last known IPs, %s of grace left)", fqdn, err, left.Round(time.Minute)))
			continue
		}
		result.Errors = append(result.Errors, fmt.Sprintf("resolve %s: %v", fqdn, err))
	}

	// 2b. Provider pass. Deliberately a second explicit pass rather than a
	// shared Source interface: an FQDN has three outcomes (resolved, an
	// authoritative NXDOMAIN, an ambiguous failure) and a provider has two,
	// the unroutable test is membership for an address and overlap for a
	// prefix, and the failure policy is a grace window against
	// keep-indefinitely. Both passes feed the same `desired` map, so unifying
	// them later — when a third *kind* of source appears, not a third provider
	// — stays cheap.
	for _, id := range rule.Providers {
		st := r.providerStateFor(id)
		provider, known := LookupProvider(id)
		switch {
		case !known:
			// Reachable only from a hand-edited config or a downgraded binary.
			// Treated exactly as a failed fetch with no new information: keep
			// what is owned, say so. Revoking would take a site down over a
			// downgrade.
			st.lastErr = fmt.Sprintf("unknown provider %q", id)
		case r.Fetcher == nil:
			// Reachable today: main.go constructs the Reconciler with no
			// Fetcher, and Task 7 is what assigns one. An invariant that
			// depends on the caller having wired a field is not an
			// invariant — a hand-edited "providers" key must not panic the
			// reconcile loop, it must fail like any other fetch.
			st.lastErr = "no provider fetcher configured"
		case r.shouldAttempt(st):
			// Stamped before the fetch, not after: a forced cycle must count
			// this as "attempted" whether the fetch that follows succeeds or
			// fails, or a failing provider on N rules would be retried N
			// times under force (it already can't happen on the schedule
			// path, since nextAttempt itself blocks a same-cycle repeat).
			if r.forceThisCycle {
				st.lastForcedSeen = r.now()
			}
			prefixes, err := r.Fetcher.Fetch(provider)
			// Shape and volume are checked here, on what the seam returned,
			// rather than left to the implementation behind it. parsePrefixList
			// does check every line it reads, but a guarantee that lives inside
			// one implementation is not a guarantee of the plugin: this
			// interface decides who may reach the proxied services, so its
			// rules belong to the caller. Order matters — an entry that is not
			// a CIDR would slip past validateAgainstUnroutable, which answers
			// "no overlap" for anything it cannot parse.
			if err == nil && len(prefixes) == 0 {
				// An empty answer is a failure, never an instruction to
				// authorise nothing. HTTPProviderFetcher refuses one of its own
				// accord, but that is again a guarantee living in a single
				// implementation: without this, any other fetcher returning
				// nothing would have lastSuccess stamped and lastErr cleared,
				// and the row would go green over a provider that authorises
				// nothing at all.
				err = fmt.Errorf("the fetch returned no prefixes")
			}
			if err == nil {
				err = checkPrefixList(prefixes)
			}
			if err == nil {
				err = validateAgainstUnroutable(prefixes, r.Unroutable)
			}
			if err != nil {
				st.lastErr = err.Error()
				st.nextAttempt = r.now().Add(providerRetryInterval)
			} else {
				st.prefixes = prefixes
				st.lastSuccess = r.now()
				st.lastErr = ""
				// A zero ProviderPeriod — the field's own zero value before
				// Task 7 wires it from config each cycle — must not read as
				// "due again immediately"; that would collapse the schedule
				// into a fetch on every tick.
				period := r.ProviderPeriod
				if period <= 0 {
					period = time.Duration(DefaultProviderIntervalSeconds) * time.Second
				}
				st.nextAttempt = r.now().Add(period)
			}
		}

		// What is actually authorised: the cache when there is one, otherwise
		// the entries this provider already owns in the whitelist. That
		// fallback is why no cache has to survive a restart.
		//
		// The cache is re-tested against the never-authorise list on every
		// cycle, not only on the cycle that fetched it. unroutable_cidrs is an
		// operator control that can change at any moment, while a fetch happens
		// twice a day: with the test only at fetch time, a range added from the
		// panel would stay authorised for the rest of the interval, and the one
		// control whose entire purpose is "never authorise this" would do
		// nothing. The FQDN pass re-checks its resolved addresses on every
		// cycle for the same reason. A cache that no longer passes counts as no
		// cache, so the owned entries below are filtered per prefix instead:
		// the blocked one is revoked, the provider's others survive.
		//
		// The rejection is reported for this cycle only and st.prefixes is left
		// alone. The cache is upstream data, not an authorisation, and it is
		// tested again before every use; keeping it is what lets the prefixes
		// come back within one tick if the operator takes the range out of the
		// list again, instead of at the next scheduled fetch. When a fetch
		// error is also outstanding this message replaces it, because it is the
		// one that explains what is authorised right now.
		reported := st.lastErr
		blocked := false
		authorised := st.prefixes
		if err := validateAgainstUnroutable(authorised, r.Unroutable); err != nil {
			reported = err.Error()
			blocked = true
			authorised = nil
		}
		if len(authorised) == 0 {
			authorised = keepableOwned(r.Unroutable, ownedBy[id])
		}
		for _, prefix := range authorised {
			if _, exists := desired[prefix]; !exists {
				desired[prefix] = id
			}
		}

		status := ProviderStatus{
			ID:       id,
			Name:     provider.Name,
			Prefixes: append([]string(nil), authorised...),
			Error:    reported,
			Blocked:  blocked,
		}
		if status.Name == "" {
			status.Name = id
		}
		if !st.lastSuccess.IsZero() {
			status.LastSuccess = st.lastSuccess.Format(time.RFC3339)
		}
		if reported != "" && !st.lastSuccess.IsZero() {
			status.StaleFor = r.now().Sub(st.lastSuccess).Round(time.Minute).String()
		}
		if reported != "" {
			result.Errors = append(result.Errors, fmt.Sprintf("provider %s: %s", id, reported))
		}
		result.Providers = append(result.Providers, status)
	}

	// 3a. Add desired IPs not already authorised. An address already covered
	// by an admin entry is left alone — admin entries must never be converted
	// into plugin-owned ones by a collision.
	for ip, fqdn := range desired {
		if adminPresent[ip] || managed[ip] == ip {
			continue
		}
		if err := r.Client.AddWhitelistIP(rule.RuleID, ip, MarkerPrefix+fqdn); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("add %s: %v", ip, err))
			continue
		}
		result.Added = append(result.Added, ip)
	}

	// 3b. Remove owned entries no longer desired, plus those still stored in a
	// legacy non-CIDR form — their replacement was added above, so dropping
	// them never leaves the address unauthorised in between.
	for canonical, stored := range managed {
		_, want := desired[canonical]
		if want && stored == canonical {
			continue
		}
		if err := r.Client.RemoveWhitelistIP(rule.RuleID, stored); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("remove %s: %v", stored, err))
			continue
		}
		result.Removed = append(result.Removed, stored)
	}

	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	return result
}

// graceLeft reports how much of the grace window remains for a failing FQDN,
// starting the window on the first failure of a run. ok is false when the
// window is disabled or has expired, meaning the caller must fail closed.
func (r *Reconciler) graceLeft(fqdn string) (time.Duration, bool) {
	if r.Grace <= 0 {
		return 0, false
	}
	since, seen := r.failingSince[fqdn]
	if !seen {
		since = r.now()
		r.failingSince[fqdn] = since
	}
	left := r.Grace - r.now().Sub(since)
	if left <= 0 {
		return 0, false
	}
	return left, true
}

func (r *Reconciler) providerStateFor(id string) *providerState {
	if st, ok := r.providers[id]; ok {
		return st
	}
	st := &providerState{}
	r.providers[id] = st
	return st
}

// shouldAttempt answers "is it time to talk to this provider?". A zero
// nextAttempt means it has never been fetched, so the first cycle always does.
//
// The force branch is gated on lastForcedSeen rather than firing unconditionally:
// r.lastForced is stamped once per forced cycle (in All), before any rule
// runs, so "lastForcedSeen is before r.lastForced" is true exactly for a
// provider not yet attempted this forced cycle. Without that gate, the same
// provider configured on two rules — or one still failing, so nextAttempt
// never moves past now — would be fetched once per rule instead of once per
// cycle.
func (r *Reconciler) shouldAttempt(st *providerState) bool {
	if r.forceThisCycle && st.lastForcedSeen.Before(r.lastForced) {
		return true
	}
	return !r.now().Before(st.nextAttempt)
}

// All reconciles every rule in the config independently; an error on one rule
// does not stop the others. force comes from the UI's Refresh button and makes
// this cycle refetch provider lists regardless of their schedule — honoured at
// most once per providerForceFloor, evaluated here rather than per provider so
// several providers in one cycle share the one allowance.
func (r *Reconciler) All(cfg *Config, force bool) []ReconcileResult {
	r.forceThisCycle = force && !r.now().Before(r.lastForced.Add(providerForceFloor))
	if r.forceThisCycle {
		r.lastForced = r.now()
	}

	results := []ReconcileResult{}
	configured := map[string]bool{}
	configuredProviders := map[string]bool{}
	for _, rule := range cfg.Rules {
		results = append(results, r.Rule(rule))
		for _, fqdn := range rule.FQDNs {
			configured[fqdn] = true
		}
		for _, id := range rule.Providers {
			configuredProviders[id] = true
		}
	}
	// Forget the failure history of FQDNs that are no longer configured.
	// Without this, an FQDN removed and later re-added would be judged against
	// the timestamp of its old outage: the window would look long expired and
	// the grace protection would be silently off for it.
	for fqdn := range r.failingSince {
		if !configured[fqdn] {
			delete(r.failingSince, fqdn)
		}
	}
	// Same reasoning for providers: a stale nextAttempt would otherwise make a
	// re-added provider look recently fetched when it has not been fetched at
	// all this configuration.
	for id := range r.providers {
		if !configuredProviders[id] {
			delete(r.providers, id)
		}
	}
	return results
}
