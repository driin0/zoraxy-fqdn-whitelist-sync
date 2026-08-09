# FQDN Whitelist Sync — a Zoraxy plugin

Keeps a Zoraxy access-control whitelist in sync with the IPs a set of FQDNs
resolves to. Point it at a dynamic-DNS name and the whitelist follows that
host as its address changes, without anyone editing rules by hand.

Built for the case where the people who must reach a service sit behind
dynamic residential addresses — a DDNS name per site, and the whitelist keeps
up on its own.

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

Zoraxy v3.3.3 or later. Verified against v3.3.3.

## Install

### From the Zoraxy plugin manager

Once the plugin is listed in the official registry, find "FQDN Whitelist Sync"
in the plugin list and install it. Zoraxy downloads the binary for your
architecture, makes it executable and places it in its own plugin folder.

### Manually

Download the `.tar.gz` for your architecture from the
[latest release](https://github.com/driin0/zoraxy-fqdn-whitelist-sync/releases/latest)
and extract it into Zoraxy's plugin directory, keeping the folder name:

    plugins/
    └── fqdn-whitelist-sync/
        ├── start.sh
        ├── fqdn-whitelist-sync.bin
        └── icon.png

Zoraxy looks for an executable named after the folder, then for `start.sh`, so
this layout starts via the script. The archive already carries the executable
bit; if your extraction tool drops it, restore it once with
`chmod +x start.sh`. Then restart Zoraxy.

Later updates only need the `.bin` replaced — `start.sh` re-applies the
executable bit on each launch.

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
