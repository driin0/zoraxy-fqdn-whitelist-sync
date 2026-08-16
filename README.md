# FQDN Whitelist Sync — a Zoraxy plugin

Keeps a Zoraxy access-control whitelist in sync with the IPs a set of FQDNs
resolves to, and with the published ranges of known CDN providers. Point it
at a dynamic-DNS name and the whitelist follows that host as its address
changes, without anyone editing rules by hand.

Built for the case where the people who must reach a service sit behind
dynamic residential addresses — a DDNS name per site, and the whitelist keeps
up on its own.

![The plugin's panel in Zoraxy. Cloudflare's twenty-two published ranges and three of four FQDNs are synced into the Default rule's whitelist — one name resolving to two addresses, another to both an IPv4 and an IPv6 — while the fourth, a roaming laptop whose DDNS has fallen back to a sentinel address, is reported offline and left unauthorised. Under the table, an expanded "How the sync works" panel lists what the plugin guarantees.](docs/panel.png)

## What it guarantees

- **It fails closed on FQDNs.** When a name stops resolving, its addresses
  lose their authorisation. A DNS outage narrows access, it never widens it.
  Provider ranges follow the opposite policy, for the reason given below.
- **A grace window for ambiguity.** When a lookup fails in a way that leaves
  the answer *unknown* (a timeout, a server failure) rather than *negative*,
  the last known addresses are kept for a configurable window — one hour by
  default — so a flaky resolver does not lock people out. An authoritative
  NXDOMAIN is not ambiguous and revokes immediately.
- **It only touches its own entries.** Every entry it adds is tagged with a
  `fqdn-sync:<owner>` comment, where the owner is the FQDN or provider id
  that authorised it. Entries added by an administrator are never modified
  or removed.
- **It never authorises an unroutable address or range.** DDNS providers
  publish sentinels such as `192.0.2.1` for an offline device, and a host that
  failed DHCP self-assigns a link-local address. Whitelisting those would
  authorise the wrong thing, so an FQDN resolving only into such ranges is
  reported as offline instead — and a published provider prefix that *overlaps*
  one is refused and removed on the next cycle, which the panel marks
  **blocked**. This is the one thing that does revoke a provider range. The list
  is configurable.
- **It converges, so nothing it owns stays wrong for long.** Each cycle it
  reads the rule's whitelist and makes it match what is configured — it does
  not apply changes and hope they stuck. An entry of its own that goes missing
  is restored on the next tick, and one it removed that comes back is removed
  again, whatever the cause: a hand edit, a restart, or a write discarded
  somewhere underneath. Its exposure to anything like that is one interval,
  thirty seconds by default. Entries it does not own are outside this, since it
  never touches them.
- **A provider list that cannot be fetched never revokes.** Published CDN
  ranges are refetched on their own slow timer; if a fetch fails, or returns
  anything anomalous, the ranges already authorised stay authorised and the
  panel marks them stale. If none were authorised yet — a first fetch failing
  after a restart — the row is marked failed and nothing is authorised for that
  provider. A whitelist source whose failure took the site down would be worse
  than one that goes briefly out of date.

## Requirements

Zoraxy v3.3.3 or later. Verified against v3.3.3 and the v3.3.4 release
candidates, most recently v3.3.4-rc3.

Builds are published for `linux/amd64`, `linux/386`, `linux/arm`,
`linux/arm64`, `linux/mipsle`, `linux/riscv64` and `windows/amd64` — the
platforms Zoraxy itself ships for. `linux/amd64` and `linux/arm64` have been
run against a live Zoraxy, the latter on a Raspberry Pi 5 and a Pi 3 among
others. The `linux/arm` and
`windows/amd64` builds have been executed on real hardware — a Raspberry Pi 2
and Windows 11 — far enough to confirm they start and introspect correctly, and
on Windows to confirm the plugin stops cleanly when asked, but neither has run
against a live Zoraxy. The remaining three are the same source cross-compiled,
with no platform-specific code, but untested.

## Install

### From the Zoraxy plugin manager

Once the plugin is listed in the official registry, find "FQDN Whitelist Sync"
in the plugin list and install it. Zoraxy downloads the binary for your
architecture, makes it executable and places it in its own plugin folder.

### Manually

Release assets are named `fqdn_whitelist_sync_<os>_<arch>` — for example
`fqdn_whitelist_sync_linux_amd64`, or `fqdn_whitelist_sync_windows_amd64.exe`.
Download the one for your platform from the
[latest release](https://github.com/driin0/zoraxy-fqdn-whitelist-sync/releases/latest),
**rename it** to `fqdn-whitelist-sync`, and put it in Zoraxy's plugin directory
inside a folder of the same name — Zoraxy runs the file whose name matches its
folder:

    plugins/
    └── fqdn-whitelist-sync/
        └── fqdn-whitelist-sync

Make it executable (`chmod +x fqdn-whitelist-sync`) and restart Zoraxy. On
Windows keep the `.exe` extension on both the folder's file and its name, and
skip the `chmod`.

If you want the icon in the plugin manager, put [`icon.png`](icon.png) in the
same folder. Installing through the plugin manager instead fetches it for you.

To update, replace the binary, re-apply `chmod +x`, and restart Zoraxy.

If you installed manually and later switch to the plugin manager, remove your
folder first: the manager creates its own, and two copies of the same plugin ID
will collide.

## Configure

Enable the plugin in Zoraxy, then open its UI to add rules. Each rule pairs a
Zoraxy access-rule ID with the FQDNs and provider ranges that should be
synced into it.

**Also enable Whitelist mode on the target access rule.** Without it, the
whitelist is maintained but does not restrict anything — the plugin's UI warns
when it detects this.

The plugin writes `config.json` next to its binary on first start:

| Key | Meaning | Default |
|---|---|---|
| `interval_seconds` | How often to re-resolve and reconcile. Minimum 15. | `30` |
| `dns_servers` | Resolvers to query, in order. Empty means the system resolver. Used for FQDN lookups only — provider lists are always fetched through the system resolver. | system |
| `dns_failure_grace_seconds` | How long to keep the last known IPs when a lookup fails ambiguously. `0` fails closed at once. | `3600` |
| `unroutable_cidrs` | Ranges that must never be authorised. An explicit empty list disables the check. | RFC 5737, loopback, link-local, and other sentinels |
| `provider_interval_seconds` | How often published provider ranges are refetched. Minimum 3600. | `43200` |
| `rules[].rule_id` | Zoraxy access-rule ID. `default` is the global rule. | — |
| `rules[].fqdns` | FQDNs whose resolved IPs sync into that rule. | — |
| `rules[].providers` | Known provider ids whose ranges sync into that rule. Currently `cloudflare`. | none |

Private RFC 1918 ranges are deliberately *not* in the unroutable defaults: an
internal FQDN resolving into private space is a case worth syncing.

## Provider ranges

Besides FQDNs, a rule can sync the published IP ranges of known CDN
providers — currently Cloudflare. Enable it per rule from the plugin's UI, or
by adding the provider id to `rules[].providers`.

The set of available providers is fixed in the plugin, not a URL the operator
supplies: on a whitelist, whoever controls the source controls who gets in,
so the list of sources is not something a config file should be able to
redirect.

Removing the plugin does not remove the entries it added. Zoraxy stops the
plugin and revokes its API key, but the whitelist entries stay in the access
rule — its provider prefixes, twenty-two for Cloudflare today. Delete them from the
Access Rules panel if you no longer want them.

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
