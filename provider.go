package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

/*
	provider.go

	Where range-shaped whitelist sources come from.

	The registry is closed on purpose. A user-supplied URL is the obvious
	generalisation and the wrong one here: on a blacklist a hostile list costs
	availability, but on a *whitelist* whoever controls the URL controls who
	can reach the services behind the proxy. With a closed registry the
	endpoints, the format and the expected volume are known at compile time.
*/

// Provider is one known publisher of IP ranges.
//
// ID must not parse as a valid FQDN. Entry ownership is recorded as
// "fqdn-sync:<owner>", where the owner is either an FQDN or a provider id;
// if a provider id could also be an FQDN, a configured name could claim that
// provider's entries. Asserted by TestProviderIDsAreNotValidFQDNs.
type Provider struct {
	ID        string
	Name      string
	Endpoints []string
}

// KnownProviders is the whole registry, and it has one member.
//
// Adding a second is not the row it looks like, which is worth saying here
// because here is where someone would try. Every other published list was
// measured on 2026-08-16 (notes/2026-08-16-provider-registry-survey.md) and
// Cloudflare turned out to be the only one publishing one CIDR per line:
// Fastly, Imperva, Google, AWS and Azure are all JSON, each with its own key
// names. parsePrefixList therefore covers exactly one provider, and a second
// needs a decoder chosen per format.
//
// A second provider also owes a per-rule bound on the prefix count — see
// providerMaxPrefixes, which counts one provider at a time.
//
// Fastly is the cheapest candidate if it is ever wanted: 21 prefixes, one
// endpoint, no authentication. AWS and Azure publish the right list for this
// plugin's purpose — the addresses their CDN uses to reach an origin,
// CLOUDFRONT_ORIGIN_FACING at 49 and AzureFrontDoor.Backend at 239 — but both
// bury it in megabytes, past the body limit below.
var KnownProviders = []Provider{
	{
		ID:   "cloudflare",
		Name: "Cloudflare",
		// Verified 2026-08-15: text/plain, one CIDR per line, 15 IPv4 and 7
		// IPv6 prefixes, 334 bytes in total. No ETag, and If-Modified-Since is
		// not honoured (200, never 304) — hence no conditional requests.
		Endpoints: []string{
			"https://www.cloudflare.com/ips-v4",
			"https://www.cloudflare.com/ips-v6",
		},
	},
}

func LookupProvider(id string) (Provider, bool) {
	for _, p := range KnownProviders {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

const (
	// Real responses are a few hundred bytes; anything slower than this is
	// broken rather than slow. The timeout also bounds how long a stalled
	// endpoint can delay the rest of the reconcile cycle, which is sequential.
	providerFetchTimeout = 10 * time.Second
	// Three orders of magnitude above reality, still bounded.
	providerBodyLimit = 1 << 20
	// Cloudflare publishes 22. This is a tripwire that turns an upstream change
	// into a readable error, and it bounds a cost paid inside Zoraxy: its
	// IsIPWhitelisted iterates every entry and re-parses each CIDR on *every
	// proxied request*. Every entry is latency on every request, so this is a
	// bound to respect, not a budget to spend.
	//
	// Note what it does not bound: checkPrefixCount runs on the union of one
	// provider's endpoints, so nothing checks what a rule accumulates across
	// several of them.
	//
	// Measured 2026-08-16 with Cloudflare's real published list, per proxied
	// request, across the hardware Zoraxy actually ships builds for. The
	// spread is the finding — 55x between fastest and slowest at today's 22
	// entries, so a number from one machine says nothing about another:
	//
	//   entries   EPYC vCPU    Pi 5     Pi 3 B+    Pi 2 B (armv7)
	//        22      9.6 µs   17.1 µs    163 µs      224 µs
	//       512      200 µs    410 µs   3.70 ms     5.14 ms
	//    16,762     8.82 ms   15.1 ms    152 ms      178 ms
	//
	// So 512 is comfortable on a server and emphatically not on a Pi, and the
	// megabyte-scale provider lists are disqualifying rather than merely large.
	// It stays at 512 all the same: it is a tripwire that today's 22 entries
	// come nowhere near, so tuning it changes nothing anyone is paying.
	//
	// The allocations are the part no short list escapes: they are per request,
	// so they scale with traffic rather than with list length, and they fall on
	// requests matching *nothing* — scanners and bots — since only a hit exits
	// early. Since this constant bounds one provider while the cost is paid on
	// the rule's total, a second provider in the registry owes a per-rule bound.
	//
	// bench/whitelist-scan in the workspace repo holds the code, its fixture
	// guards, and the radix trie zoraxy#986 asks for — worth about 2.4x end to
	// end rather than the two orders of magnitude its own timings suggest,
	// because it replaces only one of the two matchers the scan runs.
	providerMaxPrefixes = 512
	// After a failure, retry sooner than the normal interval — a transient
	// failure must not leave a provider stale for half a day — but not on every
	// tick, which would poll a failing endpoint every 30 seconds.
	providerRetryInterval = 5 * time.Minute
	// The UI's "Refresh now" bypasses the schedule, at most this often.
	providerForceFloor = 60 * time.Second

	// Breadth floor. A published CDN prefix is never anywhere near this broad:
	// Cloudflare's widest are /13 and /29.
	minIPv4PrefixLen = 8
	minIPv6PrefixLen = 16
)

// parsePrefixList reads one endpoint body: one CIDR per line, blank lines
// ignored.
//
// It is all-or-nothing, and that is the important property. With a closed
// registry of well-known providers, any anomaly is far more likely to be
// tampering or upstream breakage than a legitimate change, and accepting the
// rest of a list that has already shown an anomaly means trusting a list that
// has been altered. A partial parse would also narrow the authorised set in
// silence, which is the worst failure mode a whitelist source has.
func parsePrefixList(body []byte) ([]string, error) {
	out := []string{}
	for i, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if err := checkPrefix(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, errors.New("no prefixes in the response")
	}
	return out, nil
}

// checkPrefix refuses anything that is not a CIDR, and anything broader than
// the floor. The breadth check is the one that matters: a list containing
// 0.0.0.0/0 does not add a prefix, it authorises the entire Internet while
// every indicator still reads green.
func checkPrefix(prefix string) error {
	ip, network, err := net.ParseCIDR(prefix)
	if err != nil {
		return fmt.Errorf("not a CIDR: %q", prefix)
	}
	floor := minIPv6PrefixLen
	if ip.To4() != nil {
		floor = minIPv4PrefixLen
	}
	if ones, _ := network.Mask.Size(); ones < floor {
		return fmt.Errorf("prefix %q is broader than the /%d floor", prefix, floor)
	}
	return nil
}

// checkPrefixList applies both rules to a whole list at once, so the caller of
// a ProviderFetcher can enforce the contract in one call regardless of which
// implementation answered.
func checkPrefixList(prefixes []string) error {
	for _, prefix := range prefixes {
		if err := checkPrefix(prefix); err != nil {
			return err
		}
	}
	return checkPrefixCount(prefixes)
}

func checkPrefixCount(prefixes []string) error {
	if len(prefixes) > providerMaxPrefixes {
		return fmt.Errorf("%d prefixes exceeds the ceiling of %d", len(prefixes), providerMaxPrefixes)
	}
	return nil
}

// validateAgainstUnroutable is the last gate, kept separate because it needs
// the operator's configured list, which the fetcher has no business knowing.
// Its failure is treated exactly like a fetch failure by the caller, so the
// all-or-nothing rule holds across both halves.
func validateAgainstUnroutable(prefixes []string, u *UnroutableSet) error {
	for _, p := range prefixes {
		if u.Overlaps(p) {
			return fmt.Errorf("prefix %q overlaps a never-authorise range", p)
		}
	}
	return nil
}

// ProviderFetcher is the seam the reconciler is built against, so no test ever
// makes a network request.
//
// Contract: every returned element must be a CIDR that passes checkPrefix, and
// there must be no more than providerMaxPrefixes of them. The reconciler
// applies checkPrefixList to whatever comes back rather than trusting the
// implementation to have done it — what crosses this seam becomes network
// authorisation, and a rule enforced only inside one implementation stops
// being a rule the moment a second one exists.
type ProviderFetcher interface {
	Fetch(p Provider) ([]string, error)
}

type HTTPProviderFetcher struct {
	HTTP *http.Client
	// BaseOverride replaces an endpoint URL with another. It exists only so
	// tests can aim the real fetcher at an httptest server; nothing in
	// production sets it.
	BaseOverride map[string]string
}

// NewHTTPProviderFetcher builds the hardened client.
//
// The client deliberately uses the *system* resolver rather than the plugin's
// configured dns_servers. That setting exists so the FQDNs being synced are
// answered authoritatively, and its documented use is pointing at an internal
// split-horizon resolver; letting it also govern where the plugin downloads
// its authorisation lists from would silently widen what the operator thinks
// they configured. TLS verification is the control that matters here, and it
// is left at the default.
func NewHTTPProviderFetcher() *HTTPProviderFetcher {
	return &HTTPProviderFetcher{
		HTTP: &http.Client{
			Timeout: providerFetchTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("redirects are not followed")
			},
		},
	}
}

// Fetch reads every endpoint of a provider and returns their union. If any
// endpoint fails, or any answer fails validation, the whole fetch fails and
// the caller keeps whatever it already had.
func (f *HTTPProviderFetcher) Fetch(p Provider) ([]string, error) {
	all := []string{}
	for _, endpoint := range p.Endpoints {
		url := endpoint
		if replacement, ok := f.BaseOverride[endpoint]; ok {
			url = replacement
		}
		prefixes, err := f.fetchOne(url)
		if err != nil {
			// Not wrapped with the endpoint here: fetchOne already names it
			// wherever the underlying error does not. Doing it in both places
			// is what put the same URL in a status line twice, at the width of
			// a panel column.
			return nil, err
		}
		all = append(all, prefixes...)
	}
	// A provider with no endpoints at all would otherwise be an empty success
	// with no network involved: the caller would stamp lastSuccess, clear the
	// error and paint the row green while the provider authorises nothing.
	// parsePrefixList already refuses an empty body, so an empty union can only
	// mean the registry row is wrong — which is a failure to report, never an
	// instruction to authorise nothing.
	if len(all) == 0 {
		return nil, fmt.Errorf("provider %q has no endpoints", p.ID)
	}
	if err := checkPrefixCount(all); err != nil {
		return nil, err
	}
	return all, nil
}

// fetchOne carries the endpoint in its errors, but only where the underlying
// error does not already name it. An http.Client failure reads
// `Get "https://…": …` and repeating the address in front of that is how a
// stale row's note ended up twice as long as it needed to be, in a panel column
// narrow enough to feel it. Everything below that point loses the URL unless we
// put it back: a status code, a size, and `line 3: not a CIDR` say nothing about
// which of a provider's two endpoints they came from.
func (f *HTTPProviderFetcher) fetchOne(url string) ([]string, error) {
	resp, err := f.HTTP.Get(url)
	if err != nil {
		// Usually the client's own error already reads `Get "<url>": …` and
		// prefixing it would say the address twice. Not always: when
		// CheckRedirect refuses a redirect, Go replaces the *url.Error's URL
		// with the raw Location header, so a relative one leaves an error
		// naming neither the endpoint nor a host — on the very failure this
		// fetcher goes out of its way to produce. Add it only when missing.
		if !strings.Contains(err.Error(), url) {
			return nil, fmt.Errorf("%s: %w", url, err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: http %d", url, resp.StatusCode)
	}
	// One byte past the ceiling, so a body that reaches the limit is detected
	// as oversized instead of being silently truncated into a valid answer.
	body, err := io.ReadAll(io.LimitReader(resp.Body, providerBodyLimit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if len(body) > providerBodyLimit {
		return nil, fmt.Errorf("%s: response exceeds %d bytes", url, providerBodyLimit)
	}
	prefixes, err := parsePrefixList(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return prefixes, nil
}
