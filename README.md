# FQDN Whitelist Sync — a Zoraxy plugin

Keeps a Zoraxy access-control whitelist in sync with the IPs a set of FQDNs
resolves to. Point it at a dynamic-DNS name and the whitelist follows that
host as its address changes, without anyone editing rules by hand.

Built for the case where the people who must reach a service sit behind
dynamic residential addresses — a DDNS name per site, and the whitelist keeps
up on its own.

![The plugin's panel in Zoraxy. Three sites and an on-call laptop are synced into the Default rule's whitelist — one site resolving to two addresses, the laptop to both an IPv4 and an IPv6 — while a roaming laptop whose DDNS has fallen back to a sentinel address is reported offline and left unauthorised.](docs/panel.png)

## What it guarantees

- **It fails closed.** When a name stops resolving, its addresses lose their
  authorisation. A DNS outage narrows access, it never widens it.
- **A grace window for ambiguity.** When a lookup fails in a way that leaves
  the answer *unknown* (a timeout, a server failure) rather than *negative*,
  the last known addresses are kept for a configurable window — one hour by
  default — so a flaky resolver does not lock people out. An authoritative
  NXDOMAIN is not ambiguous and revokes immediately.
- **It only touches its own entries.** Every address it adds is tagged with a
  `fqdn-sync:<fqdn>` comment. Entries added by an administrator are never
  modified or removed.
- **It never authorises an unroutable address.** DDNS providers publish
  sentinels such as `192.0.2.1` for an offline device, and a host that failed
  DHCP self-assigns a link-local address. Whitelisting those would authorise
  the wrong thing, so an FQDN resolving only into such ranges is reported as
  offline instead. The list is configurable.

## Requirements

Zoraxy v3.3.3 or later. Verified against v3.3.3 and v3.3.4-rc2.

Builds are published for `linux/amd64`, `linux/386`, `linux/arm`,
`linux/arm64`, `linux/mipsle`, `linux/riscv64` and `windows/amd64` — the
platforms Zoraxy itself ships for. Only the two Linux builds it was developed
on, `amd64` and `arm64`, have been run against a live Zoraxy; the rest are the
same source cross-compiled, with no platform-specific code, but untested.

## Install

### From the Zoraxy plugin manager

Once the plugin is listed in the official registry, find "FQDN Whitelist Sync"
in the plugin list and install it. Zoraxy downloads the binary for your
architecture, makes it executable and places it in its own plugin folder.

### Manually

Download the binary for your architecture from the
[latest release](https://github.com/driin0/zoraxy-fqdn-whitelist-sync/releases/latest)
and put it in Zoraxy's plugin directory, inside a folder **named after the
binary** — Zoraxy runs the file whose name matches its folder:

    plugins/
    └── fqdn-whitelist-sync/
        └── fqdn-whitelist-sync

Make it executable (`chmod +x fqdn-whitelist-sync`) and restart Zoraxy. Drop
[`icon.png`](icon.png) beside it if you want the icon in the plugin manager;
the plugin manager fetches it for you.

To update, replace the binary, re-apply `chmod +x`, and restart Zoraxy.

If you installed manually and later switch to the plugin manager, remove your
folder first: the manager creates its own, and two copies of the same plugin ID
will collide.

## Configure

Enable the plugin in Zoraxy, then open its UI to add rules. Each rule pairs a
Zoraxy access-rule ID with the FQDNs whose addresses should be synced into it.

**Also enable Whitelist mode on the target access rule.** Without it, the
whitelist is maintained but does not restrict anything — the plugin's UI warns
when it detects this.

The plugin writes `config.json` next to its binary on first start:

| Key | Meaning | Default |
|---|---|---|
| `interval_seconds` | How often to re-resolve and reconcile. Minimum 15. | `30` |
| `dns_servers` | Resolvers to query, in order. Empty means the system resolver. | system |
| `dns_failure_grace_seconds` | How long to keep the last known IPs when a lookup fails ambiguously. `0` fails closed at once. | `3600` |
| `unroutable_cidrs` | Ranges that must never be authorised. An explicit empty list disables the check. | RFC 5737, loopback, link-local, and other sentinels |
| `rules[].rule_id` | Zoraxy access-rule ID. `default` is the global rule. | — |
| `rules[].fqdns` | FQDNs whose resolved IPs sync into that rule. | — |

Private RFC 1918 ranges are deliberately *not* in the unroutable defaults: an
internal FQDN resolving into private space is a case worth syncing.

## Build

```sh
go build .
```

No external dependencies.

## Licence

MIT — see [LICENSE](LICENSE).

The vendored Zoraxy plugin SDK under `mod/zoraxy_plugin/` is copied unmodified
from [Zoraxy](https://github.com/tobychui/zoraxy) and is LGPL licensed; see
`mod/zoraxy_plugin/UPSTREAM.md`.
