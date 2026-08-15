package main

import (
	"strings"
	"testing"
)

// The registry and the marker share one namespace: an entry's owner is written
// as "fqdn-sync:<owner>", where the owner is either an FQDN or a provider id.
// A provider id that parsed as an FQDN would let a configured name claim that
// provider's entries. It cannot happen today only because fqdnPattern requires
// a dot — an accidental invariant, which this test makes a declared one.
func TestProviderIDsAreNotValidFQDNs(t *testing.T) {
	for _, p := range KnownProviders {
		if err := validateFQDN(p.ID); err == nil {
			t.Errorf("provider id %q parses as a valid FQDN; ids must not, or entry ownership becomes ambiguous", p.ID)
		}
		if p.Name == "" || len(p.Endpoints) == 0 {
			t.Errorf("provider %q is incomplete: name=%q endpoints=%d", p.ID, p.Name, len(p.Endpoints))
		}
	}
}

func TestLookupProvider(t *testing.T) {
	if _, ok := LookupProvider("cloudflare"); !ok {
		t.Error("cloudflare must be in the registry")
	}
	if _, ok := LookupProvider("nope"); ok {
		t.Error("an unknown id must not resolve")
	}
}

func TestParsePrefixListReadsOneCIDRPerLine(t *testing.T) {
	body := "173.245.48.0/20\n103.21.244.0/22\n\n104.16.0.0/13\n"
	got, err := parsePrefixList([]byte(body))
	if err != nil {
		t.Fatalf("parsePrefixList: %v", err)
	}
	want := []string{"173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// All-or-nothing. A partial parse of a whitelist source silently narrows the
// authorised set — it switches off access from the prefixes it dropped, with
// nothing on screen to say so.
func TestParsePrefixListRejectsTheWholeBodyOnOneBadLine(t *testing.T) {
	body := "104.16.0.0/13\nnot-a-cidr\n172.64.0.0/13\n"
	if _, err := parsePrefixList([]byte(body)); err == nil {
		t.Fatal("a malformed line must fail the whole parse")
	} else if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error should name the offending line, got %v", err)
	}
}

// An empty 200 is a failure, never an instruction to empty the whitelist.
func TestParsePrefixListRejectsAnEmptyBody(t *testing.T) {
	for _, body := range []string{"", "\n", "   \n\n  "} {
		if _, err := parsePrefixList([]byte(body)); err == nil {
			t.Errorf("body %q must be a failure, not an empty result", body)
		}
	}
}

// The catastrophic case: a list containing 0.0.0.0/0 does not add a prefix,
// it switches the whitelist off while the panel stays green. The unroutable
// filter cannot catch it — the default route is not contained in any blocked
// range, it contains them.
func TestParsePrefixListRejectsOverBroadPrefixes(t *testing.T) {
	cases := []string{"0.0.0.0/0", "0.0.0.0/4", "128.0.0.0/1", "::/0", "2000::/3"}
	for _, prefix := range cases {
		if _, err := parsePrefixList([]byte(prefix + "\n")); err == nil {
			t.Errorf("%q is broader than the floor and must be refused", prefix)
		}
	}
}

// The floor must never get in the way of a real list.
func TestParsePrefixListAcceptsTheRealCloudflareBreadth(t *testing.T) {
	for _, prefix := range []string{"104.16.0.0/13", "173.245.48.0/20", "2a06:98c0::/29", "2400:cb00::/32"} {
		if _, err := parsePrefixList([]byte(prefix + "\n")); err != nil {
			t.Errorf("%q is a real published prefix and must be accepted: %v", prefix, err)
		}
	}
}

func TestCheckPrefixCountCeiling(t *testing.T) {
	ok := make([]string, providerMaxPrefixes)
	for i := range ok {
		ok[i] = "104.16.0.0/13"
	}
	if err := checkPrefixCount(ok); err != nil {
		t.Errorf("exactly the ceiling must pass: %v", err)
	}
	if err := checkPrefixCount(append(ok, "104.16.0.0/13")); err == nil {
		t.Error("one over the ceiling must fail")
	}
}

func TestValidateAgainstUnroutable(t *testing.T) {
	set, err := NewUnroutableSet([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatalf("NewUnroutableSet: %v", err)
	}
	if err := validateAgainstUnroutable([]string{"104.16.0.0/13"}, set); err != nil {
		t.Errorf("a clean list must pass: %v", err)
	}
	if err := validateAgainstUnroutable([]string{"104.16.0.0/13", "192.0.2.128/25"}, set); err == nil {
		t.Error("one overlapping prefix must fail the whole list")
	}
}
