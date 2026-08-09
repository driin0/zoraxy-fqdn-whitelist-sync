package main

import (
	"context"
	"errors"
	"net"
	"time"
)

type Resolver interface {
	Resolve(fqdn string) ([]string, error)
}

type NetResolver struct{}

func (NetResolver) Resolve(fqdn string) ([]string, error) {
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		return nil, err
	}
	return ipsToStrings(ips), nil
}

// DNSServerResolver queries one specific DNS server instead of the system
// resolver. This exists because the host's resolver cannot always be trusted
// to answer for the FQDNs we sync: in a split-horizon setup, a private DNS
// zone attached to the network the proxy runs in silently overrides the public
// authoritative answer, and a wildcard record there makes every name under the
// domain resolve to one unrelated address. The whitelist would then be built
// from that wrong address.
type DNSServerResolver struct {
	r *net.Resolver
}

func (d DNSServerResolver) Resolve(fqdn string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := d.r.LookupIP(ctx, "ip", fqdn)
	if err != nil {
		return nil, err
	}
	return ipsToStrings(ips), nil
}

// FallbackResolver queries resolvers in order, moving on when one fails for a
// reason that leaves the answer unknown (timeout, refused, SERVFAIL). It stops
// at the first success and, importantly, at the first authoritative
// "no such name": that is an answer, and asking another server would only
// repeat it.
type FallbackResolver struct {
	resolvers []Resolver
}

func (f FallbackResolver) Resolve(fqdn string) ([]string, error) {
	var lastErr error
	for _, r := range f.resolvers {
		ips, err := r.Resolve(fqdn)
		if err == nil {
			return ips, nil
		}
		if IsNameNotFound(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// IsNameNotFound reports whether err means the name authoritatively does not
// exist, as opposed to the resolver being unreachable. Callers use this to
// decide between "the record was deleted, drop its IPs" and "we do not know,
// keep what we have".
func IsNameNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// NewResolver returns a resolver querying the given servers in order. An empty
// list (or a list of empty strings) means the system resolver. A server may
// omit the port, in which case 53 is assumed.
func NewResolver(servers []string) Resolver {
	resolvers := make([]Resolver, 0, len(servers))
	for _, s := range servers {
		if s == "" {
			resolvers = append(resolvers, NetResolver{})
			continue
		}
		resolvers = append(resolvers, newDNSServerResolver(s))
	}
	switch len(resolvers) {
	case 0:
		return NetResolver{}
	case 1:
		return resolvers[0]
	default:
		return FallbackResolver{resolvers: resolvers}
	}
}

func newDNSServerResolver(server string) Resolver {
	addr := withDefaultDNSPort(server)
	return DNSServerResolver{r: &net.Resolver{
		// PreferGo plus a custom Dial is what actually bypasses the system
		// resolver — without it cgo may answer from the host's configuration.
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}}
}

// withDefaultDNSPort appends :53 unless the address already carries a port.
// It handles bare IPv6 literals, which must be bracketed before a port.
func withDefaultDNSPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "[" + addr + "]:53"
	}
	return addr + ":53"
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
