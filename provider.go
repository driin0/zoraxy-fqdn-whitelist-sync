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

// KnownProviders is the whole registry. Adding one is a row here plus an icon
// in the UI dropdown — the reconciler does not change.
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
			return nil, fmt.Errorf("%s: %w", endpoint, err)
		}
		all = append(all, prefixes...)
	}
	if err := checkPrefixCount(all); err != nil {
		return nil, err
	}
	return all, nil
}

func (f *HTTPProviderFetcher) fetchOne(url string) ([]string, error) {
	resp, err := f.HTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	// One byte past the ceiling, so a body that reaches the limit is detected
	// as oversized instead of being silently truncated into a valid answer.
	body, err := io.ReadAll(io.LimitReader(resp.Body, providerBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > providerBodyLimit {
		return nil, fmt.Errorf("response exceeds %d bytes", providerBodyLimit)
	}
	return parsePrefixList(body)
}
