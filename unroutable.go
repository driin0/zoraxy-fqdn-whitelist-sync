package main

import (
	"fmt"
	"net"
)

// DefaultUnroutableCIDRs are ranges that must never be authorised: they can
// never legitimately be a client's source address, so an FQDN resolving into
// one is telling us the device is unreachable, not where it is.
//
// The DDNS service publishes 192.0.2.1 (RFC 5737 TEST-NET-1) for exactly that
// purpose. The rest of the list covers the other conventions a device or a
// half-broken resolver may produce: 0.0.0.0 as a null, loopback, and the
// link-local block a host self-assigns when DHCP does not answer.
//
// RFC 1918 private ranges are deliberately absent — they are unroutable on
// the public Internet but perfectly valid to whitelist for an internal FQDN.
var DefaultUnroutableCIDRs = []string{
	"0.0.0.0/8",       // RFC 1122 "this network"
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // RFC 3927 link-local (DHCP failure fallback)
	"192.0.2.0/24",    // RFC 5737 TEST-NET-1
	"198.51.100.0/24", // RFC 5737 TEST-NET-2
	"203.0.113.0/24",  // RFC 5737 TEST-NET-3
	"::/128",          // unspecified
	"::1/128",         // loopback
	"100::/64",        // RFC 6666 discard-only
	"2001:db8::/32",   // RFC 3849 documentation
}

// UnroutableSet answers whether an address falls in a range that must never
// be whitelisted. The zero value and a nil pointer block nothing.
type UnroutableSet struct {
	nets []*net.IPNet
}

// NewUnroutableSet compiles a list of CIDRs. A bare address is accepted and
// treated as a single host, since that is what an operator listing a sentinel
// value will usually type. The whole list is validated before anything is
// returned, so a malformed entry cannot be half-applied.
func NewUnroutableSet(cidrs []string) (*UnroutableSet, error) {
	set := &UnroutableSet{}
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(raw)
		if err == nil {
			set.nets = append(set.nets, network)
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("invalid CIDR or address: %q", raw)
		}
		bits := 128
		if ip.To4() != nil {
			ip = ip.To4()
			bits = 32
		}
		set.nets = append(set.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return set, nil
}

// Contains reports whether ip falls in any configured range. An input that is
// not an address is not unroutable — it is not an address at all, and the
// caller handles it elsewhere.
func (u *UnroutableSet) Contains(ip string) bool {
	if u == nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range u.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
