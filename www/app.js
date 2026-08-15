// FQDN Whitelist Sync — GUI logic.
// Native-Zoraxy look: rule selector dropdown + per-rule FQDN table.
// GETs use plain $.getJSON; POSTs use $.cjax (CSRF token from the meta tag).
// $.cjax fires the request but returns nothing, so success/error handlers go
// inside the payload. Chaining .done()/.fail() onto it throws a TypeError
// before either is registered: the write still reaches the server and the 5s
// poll repaints the panel, so only the reporting is lost — silently, which is
// worse. Guarded by TestPanelDoesNotChainOnCjax.

let rulesCache = [];   // Zoraxy access rules: [{id,name,whitelist_enabled}]
let stateCache = null; // {interval_seconds,last_run,rules,results}
let currentRule = "default";
// Two different failures, two flags. /api/state is served from the plugin's
// own memory, so it failing means the plugin is gone; /api/rules proxies to
// Zoraxy's access API and answers 502 when *that* is down (httpapi.go), with
// the plugin perfectly healthy and every write still persisting. One flag for
// both would put "changes will not be saved" on screen while they are being
// saved, and the next /api/state tick would wipe it half a second later.
let unreachable = null;      // /api/state did not answer: the plugin is gone
let rulesUnavailable = null; // /api/rules did not answer: Zoraxy's rule API is

function esc(s) {
    return String(s == null ? "" : s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function notify(msg, ok) {
    if (window.parent && window.parent.msgbox) {
        window.parent.msgbox(msg, ok !== false);
    }
}

// --- talking to the plugin ----------------------------------------------
// Everything goes through these two, so every response is read by apiError
// (api.js) instead of by its HTTP status. Guarded by
// TestPanelHasOneWayToCallTheAPI.

// The 5s poll calls these on every tick; re-render only on a change.
function setUnreachable(err) {
    if (unreachable === err) return;
    unreachable = err;
    renderCurrent();
}

function setRulesUnavailable(err) {
    if (rulesUnavailable === err) return;
    rulesUnavailable = err;
    renderCurrent();
}

// On failure the caller's handler is not run, so the panel keeps displaying
// the last values it actually received rather than blanking itself from an
// error body. onFail owns one flag, so each endpoint reports its own failure
// and cannot clear the other's.
function apiGet(url, onOk, onFail) {
    return $.getJSON(url).done(function (resp) {
        const err = apiError(resp);
        if (err) { onFail(err); return; }
        onFail(null);
        onOk(resp);
    }).fail(function (xhr, textStatus) {
        onFail(apiErrorFromXHR(xhr, textStatus));
    });
}

function apiPost(url, data, onOk, failMsg) {
    $.cjax({
        url: url, method: "POST", data: data,
        success: function (resp) {
            const err = apiError(resp);
            if (err) { notify(err, false); return; }
            onOk();
        },
        error: xhr => notify((xhr.responseJSON && xhr.responseJSON.error) || failMsg, false),
    });
}

function ruleInfo(id) { return rulesCache.find(r => r.id === id); }
function cfgRule(id) { return ((stateCache && stateCache.rules) || []).find(r => r.rule_id === id); }
function resultFor(id) { return ((stateCache && stateCache.results) || []).find(r => r.RuleID === id); }

// Match Zoraxy's native rule icons: yellow star = default, green filter = whitelist-only.
function ruleIcon(r) {
    if (r.id === "default") return '<i class="ui yellow star icon"></i>';
    if (r.whitelist_enabled) return '<i class="ui green filter icon"></i>';
    return '<i class="ui grey filter icon"></i>';
}

function populateRuleDropdown() {
    const $menu = $("#ruleMenu").empty();
    rulesCache.forEach(r => {
        $menu.append(`<div class="item" data-value="${esc(r.id)}">${ruleIcon(r)} ${esc(r.name)}</div>`);
    });
    $("#ruleSelector").dropdown({
        onChange: function (val) {
            if (val) { currentRule = val; renderCurrent(); }
        }
    });
    const ids = rulesCache.map(r => r.id);
    if (!ids.includes(currentRule)) {
        currentRule = ids.includes("default") ? "default" : (ids[0] || "default");
    }
    $("#ruleSelector").dropdown("set selected", currentRule);
}

function renderStatusMsg() {
    const $m = $("#syncStatusMsg");
    // Takes priority: while the plugin is unreachable nothing else on the
    // panel can be trusted, including the rule this message would describe.
    if (unreachable) {
        $m.attr("class", "ui negative message")
            .html('<i class="exclamation triangle icon"></i> ' + (unreachable === SESSION_EXPIRED
                ? 'Your Zoraxy session has expired — reload the page to sign in again. Nothing on this panel is being saved.'
                : 'Cannot reach the plugin (' + esc(unreachable) +
                  '). These are the last values received — changes will not be saved.')).show();
        return;
    }
    // The plugin is fine here: it is Zoraxy's own access-rule API that did not
    // answer. Syncing continues and writes persist, so this must not say the
    // things the message above says.
    if (rulesUnavailable) {
        $m.attr("class", "ui warning message")
            .html('<i class="exclamation triangle icon"></i> Zoraxy did not return its access rules (' +
                esc(rulesUnavailable) + '). The rule list may be incomplete; syncing is unaffected.').show();
        return;
    }
    const info = ruleInfo(currentRule);
    if (!info) {
        $m.attr("class", "ui warning message")
            .html('<i class="exclamation triangle icon"></i> This rule was not found in Zoraxy.').show();
        return;
    }
    if (info.whitelist_enabled) {
        $m.attr("class", "ui positive message")
            .html('<i class="check circle icon"></i> Whitelist mode is enabled on this rule.').show();
    } else {
        $m.attr("class", "ui warning message")
            .html('<i class="exclamation triangle icon"></i> Whitelist mode is <b>disabled</b> — synced IPs are not enforced until you enable it in the Access Rules panel.').show();
    }
}

// A week of staleness turns the row red. Orange says "degraded but holding",
// which is true for hours or days; past that it is an authorisation nobody has
// checked, and it should stop looking survivable.
const STALE_ALARM_MS = 7 * 24 * 60 * 60 * 1000;

// An icon and its word are one unit: the Status column is narrow enough that
// "offline" and "unresolved" were breaking between the two, leaving the icon
// stranded on its own line. Anything appended after this — the stale age — is
// free to wrap.
// icon is a Semantic class name and text a fixed label, both literals at every
// call site. text is escaped anyway: this function has no way to tell a literal
// from something a future caller derives from the API, and that is exactly how
// the escaping discipline elsewhere in this file gets quietly broken.
function statusLabel(icon, text) {
    return '<span class="statusLabel"><i class="' + icon + ' icon"></i> ' + esc(text) + "</span>";
}

// Above this many entries an address cell collapses to a count. The threshold
// is on the count, not on the kind of source: the problem is length, and the
// kind is only a proxy for it. A provider publishing three ranges should not be
// hidden, and an FQDN fronted by a CDN that resolves to fifteen addresses
// should be — Cloudflare's twenty-two happens to be the case that made this
// visible, not the case the rule is written for. Eight is two wrapped lines at
// the panel's usual width.
const COLLAPSE_ABOVE = 8;

// Which sources the operator has opened. renderTable rebuilds every row from
// scratch on the five-second poll, so without this a list opened by hand would
// snap shut a few seconds later, repeatedly, while being read.
const expandedSources = new Set();

// "How the sync works" explains what the plugin is about to do, which is worth
// a lot before anything is configured and nothing afterwards. So it opens
// itself on a rule with no sources — there is no table to read there and this
// is the only thing worth showing — and closes once sources exist, leaving the
// summary as the way back to it.
//
// The default is applied only when the rule or its emptiness actually changes,
// never on every render. Re-asserting it each cycle would slam the panel shut
// five seconds after an operator opened it, which is the same defect the
// address lists have to avoid.
// Keyed per rule, not a single last-applied value. With one scalar, switching
// to another rule and back re-applied the default to the first one and closed a
// panel the operator had opened by hand — the same defect this memo exists to
// prevent, reached by a different route.
const howtoAppliedTo = new Map();
function applyHowtoDefault(ruleID, isEmpty) {
    // loadRules() paints once before loadState() has answered, so the config is
    // not merely empty, it is unknown — and opening on that flashes the panel
    // open for one tick on every load. Same distinction renderTable already
    // draws for the table body.
    if (!stateCache) return;
    if (howtoAppliedTo.get(ruleID) === isEmpty) return;
    howtoAppliedTo.set(ruleID, isEmpty);
    const el = document.querySelector("details.howto");
    if (el) el.open = isEmpty;
}

// addressCell renders the Addresses column for one source. key identifies the
// source across re-renders; noun is what its entries are called, because a
// provider's CIDR blocks and an FQDN's resolved addresses are not the same
// thing and the summary should not pretend otherwise.
function addressCell(key, items, noun) {
    if (!items || items.length === 0) return '<span class="muted">—</span>';
    const list = '<div class="ipList">' + items.map(v => "<span>" + esc(v) + "</span>").join("") + "</div>";
    if (items.length <= COLLAPSE_ABOVE) return list;
    const open = expandedSources.has(key) ? " open" : "";
    // The invitation disappears once it is open, where it would be telling the
    // operator to do something they have already done. The chevron stays and
    // turns, so the control still reads as a control.
    return '<details class="addrs" data-key="' + esc(key) + '"' + open + ">" +
        "<summary><b>" + items.length + "</b> " + esc(noun) +
        '<span class="hint"> — click to show</span>' +
        '<i class="chevron down icon"></i></summary>' +
        list + "</details>";
}

function renderProviderRow($t, id, status) {
    const prefixes = (status && status.prefixes) || [];
    // "ranges", not "published ranges": when the provider is blocked, or its
    // first fetch after a restart failed, this list is what the whitelist
    // already held rather than anything the provider is currently known to
    // publish. The row's note says which case it is.
    const listText = addressCell("provider:" + id, prefixes, "ranges");

    let statusCls, statusTxt, note = "";
    if (!status) {
        // handleProviderAdd only triggers a reconcile, it does not wait for
        // one, so the render right after clicking Add lands before any cycle
        // has looked at this provider — there is no ProviderStatus for it
        // yet. Grey and "pending", the FQDN table's own never-run state:
        // falling into the ok branch below would paint ranges as authorised
        // before anything has actually been fetched.
        statusCls = "status-pending";
        statusTxt = statusLabel("clock outline", "pending");
    } else if (status.blocked) {
        // The reconciler refused these ranges because they overlap the
        // never-authorise list, and revoked the ones already whitelisted. The
        // stale branch below would be false three times over here — the list
        // is fresh, nothing failed to refresh, and a range was revoked rather
        // than kept — and false at the exact moment the operator is looking to
        // see whether their edit took effect.
        statusCls = "status-blocked";
        statusTxt = statusLabel("ban", "blocked");
        note = '<div class="graceNote">Ranges overlapping your never-authorise list were revoked (' +
               esc(status.error) + ') — ' +
               (prefixes.length
                   ? "the ranges listed stay authorised."
                   : "nothing is authorised for this provider.") +
               "</div>";
    } else if (!status.error) {
        statusCls = "status-ok";
        statusTxt = statusLabel("check circle", "ok");
    } else if (prefixes.length > 0) {
        // last_success empty is not "just refreshed" (age zero) — the
        // provider cache is not persisted across restarts (reconciler.go),
        // so after a restart whose first fetch fails these prefixes are
        // carried forward from what the whitelist already owned, never
        // confirmed by this run at all. That is the most stale a provider
        // can be, so it reads as maximally aged (red) and says so, rather
        // than showing the same orange and a blank age as a fetch that
        // merely failed five minutes ago.
        const confirmed = !!status.last_success;
        const age = confirmed ? Date.now() - new Date(status.last_success).getTime() : Infinity;
        statusCls = age > STALE_ALARM_MS ? "status-stale-long" : "status-stale";
        const ageText = confirmed
            ? (status.stale_for ? " — " + esc(status.stale_for) : "")
            : " — not confirmed since the plugin started";
        statusTxt = statusLabel("hourglass half", "stale") + ageText;
        // "the ranges it holds", not "below": above the collapse threshold the
        // list is behind a summary rather than printed underneath.
        note = '<div class="graceNote">Cannot refresh the list (' + esc(status.error) +
               ') — the ranges it holds stay authorised.</div>';
    } else {
        statusCls = "status-error";
        statusTxt = statusLabel("times circle", "failed");
        note = '<div class="graceNote">' + esc(status.error) + ' — nothing is authorised for this provider.</div>';
    }

    $t.append(`
        <tr>
            <td><i class="cloud icon"></i> ${esc((status && status.name) || id)}${note}</td>
            <td>${listText}</td>
            <td class="${statusCls}">${statusTxt}</td>
            <td><button class="ui icon basic mini red button removeProviderBtn" data-provider="${esc(id)}"><i class="trash alternate icon"></i></button></td>
        </tr>`);
}

function renderTable() {
    const cfg = cfgRule(currentRule);
    const res = resultFor(currentRule) || {};
    const resolved = res.Resolved || {};
    const grace = res.Grace || {};
    const offline = res.Offline || {};
    const providers = res.Providers || [];
    const $t = $("#fqdnTable").empty();
    const fqdns = (cfg && cfg.fqdns) || [];
    const configuredProviders = (cfg && cfg.providers) || [];

    applyHowtoDefault(currentRule, fqdns.length === 0 && configuredProviders.length === 0);

    if (fqdns.length === 0 && configuredProviders.length === 0) {
        // "Nothing configured" and "we cannot ask" look identical from here,
        // and only one of them is a green tick.
        $t.append(unreachable
            ? '<tr><td colspan="4"><i class="exclamation triangle icon"></i> Cannot reach the plugin — this list is unknown, not empty.</td></tr>'
            : '<tr><td colspan="4"><i class="green check circle icon"></i> Nothing synced for this rule yet. Add an FQDN or a provider above.</td></tr>');
        return;
    }

    configuredProviders.forEach(id => renderProviderRow($t, id, providers.find(p => p.id === id)));

    fqdns.forEach(fqdn => {
        const ips = resolved[fqdn];
        const ok = ips && ips.length > 0;
        const ipText = ok ? addressCell("fqdn:" + fqdn, ips, "addresses") : '<span class="muted">—</span>';
        const graceLeft = grace[fqdn];
        const offlineIPs = offline[fqdn];
        let statusCls, statusTxt;
        if (graceLeft) {
            // DNS is failing but the last known IPs are still whitelisted:
            // neither ok nor revoked. Show it, so the operator can tell that
            // access is preserved and for how long.
            statusCls = "status-grace";
            statusTxt = statusLabel("hourglass half", "grace") + " — " + esc(graceLeft) + " left";
        } else if (offlineIPs && offlineIPs.length > 0 && !ok) {
            // The DDNS positively reports the device unreachable (sentinel-only
            // answer): checked before ok, so no routable address left never
            // renders green.
            statusCls = "status-offline";
            statusTxt = statusLabel("power off", "offline");
        } else if (ok) {
            statusCls = "status-ok"; statusTxt = statusLabel("check circle", "ok");
        } else if (stateCache && stateCache.last_run) {
            statusCls = "status-error"; statusTxt = statusLabel("times circle", "unresolved");
        } else {
            statusCls = "status-pending"; statusTxt = statusLabel("clock outline", "pending");
        }
        $t.append(`
            <tr>
                <td><i class="globe icon"></i> ${esc(fqdn)}${graceLeft ? '<div class="graceNote">DNS failing — last known IPs kept until the window closes.</div>' : ""}${(offlineIPs && offlineIPs.length > 0 && !ok) ? '<div class="graceNote">DDNS reports the device unreachable (' + esc(offlineIPs.join(", ")) + ') — not authorised.</div>' : ""}</td>
                <td>${ipText}</td>
                <td class="${statusCls}">${statusTxt}</td>
                <td><button class="ui icon basic mini red button removeBtn" data-fqdn="${esc(fqdn)}"><i class="trash alternate icon"></i></button></td>
            </tr>`);
    });
}

function renderCurrent() {
    const info = ruleInfo(currentRule);
    $("#ruleTitle").text(info ? info.name : currentRule);
    renderStatusMsg();
    renderTable();
}

function loadRules() {
    return apiGet("./api/rules", function (rules) {
        rulesCache = Array.isArray(rules) ? rules : [];
        populateRuleDropdown();
        renderCurrent();
    }, setRulesUnavailable);
}

function loadState() {
    return apiGet("./api/state", function (state) {
        stateCache = state;
        if (!$("#intervalInput").is(":focus")) {
            $("#intervalInput").val(state.interval_seconds);
        }
        if (!$("#dnsServersInput").is(":focus")) {
            $("#dnsServersInput").val((state.dns_servers || []).join(", "));
        }
        if (!$("#graceInput").is(":focus")) {
            $("#graceInput").val(state.grace_seconds);
        }
        if (!$("#unroutableInput").is(":focus")) {
            $("#unroutableInput").val((state.unroutable_cidrs || []).join(", "));
        }
        if (!$("#providerIntervalInput").is(":focus")) {
            $("#providerIntervalInput").val(state.provider_interval_seconds);
        }
        populateProviderDropdown(state.available_providers || []);
        $("#lastRun").text(state.last_run ? "Last sync: " + new Date(state.last_run).toLocaleString() : "No sync yet");
        renderTable();
    }, setUnreachable);
}

// The registry comes from /api/state, so the panel knows no provider by name
// of its own and adding one never means editing this file.
//
// Unlike populateRuleDropdown, this runs on every 5s poll (loadState), not
// once at startup, so it cannot unconditionally tear the control down and
// rebuild it the way that one does: KnownProviders is a compile-time
// constant, so in practice the id list never changes while the plugin is
// running, and the guard below turns every poll after the first into a
// no-op comparison instead of an init call that would fight the operator
// for a menu they currently have open or a value they just picked.
let providerDropdownIds = [];
let providerDropdownReady = false;

function populateProviderDropdown(available) {
    const ids = available.map(p => p.id);
    if (providerDropdownReady && ids.length === providerDropdownIds.length &&
        ids.every((id, i) => id === providerDropdownIds[i])) {
        return; // the registry has not changed since the last draw
    }
    providerDropdownIds = ids;

    const current = providerDropdownReady ? $("#providerSelect").dropdown("get value") : null;
    const $menu = $("#providerMenu").empty();
    available.forEach(p => {
        $menu.append(`<div class="item" data-value="${esc(p.id)}">${esc(p.name)}</div>`);
    });

    if (!providerDropdownReady) {
        $("#providerSelect").dropdown();
        providerDropdownReady = true;
    } else {
        // The menu items changed under an already-initialised dropdown:
        // resync Semantic's internal item list instead of reinitialising,
        // which would reset any menu the operator has open right now.
        $("#providerSelect").dropdown("refresh");
    }
    if (current && ids.includes(current)) {
        $("#providerSelect").dropdown("set selected", current);
    }
}

$(function () {
    $("#addFqdnBtn").on("click", function () {
        const fqdn = $("#fqdnInput").val().trim();
        if (!currentRule || !fqdn) { notify("Enter a FQDN", false); return; }
        apiPost("./api/fqdn/add", { rule_id: currentRule, fqdn: fqdn },
            () => { $("#fqdnInput").val(""); notify("FQDN added", true); loadState(); }, "Add failed");
    });

    $("#fqdnTable").on("click", ".removeBtn", function () {
        const fqdn = $(this).attr("data-fqdn");
        apiPost("./api/fqdn/remove", { rule_id: currentRule, fqdn: fqdn },
            () => { notify("FQDN removed", true); loadState(); }, "Remove failed");
    });

    $("#saveIntervalBtn").on("click", function () {
        apiPost("./api/interval", { seconds: $("#intervalInput").val() },
            () => notify("Interval saved", true), "Save failed");
    });

    $("#saveDnsServersBtn").on("click", function () {
        apiPost("./api/dns-servers", { servers: $("#dnsServersInput").val() },
            () => { notify("DNS servers saved", true); loadState(); }, "Save failed");
    });

    $("#saveGraceBtn").on("click", function () {
        apiPost("./api/grace", { seconds: $("#graceInput").val() },
            () => { notify("Grace window saved", true); loadState(); }, "Save failed");
    });

    $("#saveUnroutableBtn").on("click", function () {
        const cidrs = $("#unroutableInput").val();
        const stored = (stateCache && stateCache.unroutable_cidrs) || [];
        // Mirrors ParseCIDRList (config.go): split on commas, trim, drop
        // blanks. A trim()==="" check alone misses separator-only input like
        // "," — that also parses down to an empty list server-side, so it
        // would clear the blocklist with no confirmation.
        const willBeEmpty = cidrs.split(",").every(part => part.trim() === "");
        // Blanking this field is the only one-click control on this panel that
        // can turn off an access-control protection: it authorises every
        // resolved address, sentinels included. Only confirm the case that
        // actually changes something — clearing a list that was non-empty.
        if (willBeEmpty && stored.length > 0 &&
            !confirm("This clears the never-authorise list. Every resolved address, including sentinel addresses like 192.0.2.1, will be authorised. Continue?")) {
            return;
        }
        apiPost("./api/unroutable", { cidrs: cidrs },
            () => { notify("Never-authorise list saved", true); loadState(); }, "Save failed");
    });

    // Fill the field with the built-in list, keeping any custom range the
    // operator already typed. It deliberately does not save: an access-control
    // change stays reviewed before it takes effect.
    $("#restoreUnroutableBtn").on("click", function () {
        const defaults = (stateCache && stateCache.unroutable_defaults) || [];
        if (defaults.length === 0) {
            notify("Built-in list not available yet — wait for the next refresh", false);
            return;
        }
        const current = $("#unroutableInput").val().split(",")
            .map(s => s.trim()).filter(s => s !== "");
        const merged = current.concat(defaults.filter(d => !current.includes(d)));
        $("#unroutableInput").val(merged.join(", "));
        notify(merged.length === current.length
            ? "The built-in ranges were already in the list"
            : "Built-in ranges filled in — review, then Save", true);
    });

    $("#addProviderBtn").on("click", function () {
        // A native <select> reads with .val(); this control is the same
        // selection-dropdown markup as #ruleSelector, so its value comes
        // from Semantic's own API instead.
        const provider = $("#providerSelect").dropdown("get value");
        if (!currentRule || !provider) { notify("Choose a provider", false); return; }
        apiPost("./api/provider/add", { rule_id: currentRule, provider: provider },
            () => { notify("Provider added", true); loadState(); }, "Add failed");
    });

    // Remember which address lists are open, so the next repaint restores them.
    // Delegated because renderTable replaces every row on the five-second poll,
    // which would otherwise close a list the operator is in the middle of
    // reading. "toggle" does not bubble, hence the capture phase.
    document.getElementById("fqdnTable").addEventListener("toggle", function (ev) {
        const el = ev.target;
        if (!el.classList || !el.classList.contains("addrs")) return;
        const key = el.getAttribute("data-key");
        if (el.open) { expandedSources.add(key); } else { expandedSources.delete(key); }
    }, true);

    $("#fqdnTable").on("click", ".removeProviderBtn", function () {
        const provider = $(this).attr("data-provider");
        apiPost("./api/provider/remove", { rule_id: currentRule, provider: provider },
            () => { notify("Provider removed", true); loadState(); }, "Remove failed");
    });

    $("#saveProviderIntervalBtn").on("click", function () {
        apiPost("./api/provider-interval", { seconds: $("#providerIntervalInput").val() },
            () => { notify("Provider refresh interval saved", true); loadState(); }, "Save failed");
    });

    $("#refreshBtn").on("click", function () {
        // /api/refresh has no application error path of its own — it always
        // answers 200. What it can still hit is an unreachable plugin or an
        // expired session, and apiPost is what notices those.
        apiPost("./api/refresh", {},
            () => { notify("Refresh triggered", true); loadRules(); setTimeout(loadState, 600); }, "Refresh failed");
    });

    loadRules().always(loadState);
    setInterval(loadState, 5000);
    startFrameHeightSync();
});

// --- iframe height ------------------------------------------------------
//
// Zoraxy sizes the plugin iframe from the viewport, not from its content, and
// never recomputes it when the content grows. A plugin taller than that box
// scrolls inside the panel, unlike Zoraxy's own pages, which sit in the normal
// document flow and simply extend the window.
//
// The formula in components/plugincontext.html has changed once, and this code
// is deliberately indifferent to which one is running:
//
//   up to v3.3.3     height = mainMenuHeight (the sidebar), falling back to
//                    innerHeight - 198 when the sidebar measures 0
//   from v3.3.4-rc1  height = max(mainMenuHeight, innerHeight - 198)
//                    (upstream PR #1211)
//
// Both derive the height from the viewport or the surrounding chrome, never
// from the content, so both leave the same problem. We assume neither: the
// height Zoraxy last set is read back and used as a floor, so a change of
// formula can only raise that floor.
//
// Production runs the official image, so the fix has to come from inside: the
// plugin measures itself and grows the frame that holds it. This is a guest
// writing into its host's layout, acceptable only because this is a
// first-party plugin -- and written so the worst case is the scrollbar we
// have today, never a broken page.
//
// Four upstream details are load-bearing. Re-verified against v3.3.3, main and
// the v3.3.4 branch on 2026-08-09:
//
//   1. the iframe is sandboxed "allow-scripts allow-same-origin", so
//      window.frameElement is readable at all. Losing this one breaks the
//      mechanism outright rather than degrading it.
//   2. resizeIframe() writes iframe.style.height directly.
//   3. inactive tabs are hidden with display:none (.functiontab in main.css).
//   4. no ancestor of the iframe is position:fixed.
//
// If a future release changes any of them, re-verify -- the likely outcome is
// that this quietly stops working.
//
// Measured end to end on 2026-08-09 with the plugin installed in the official
// Docker image, on both v3.3.3 and v3.3.4-rc2, this panel needing 940px:
//
//   sidebar expanded   the floor is 1122px, the panel already fits and this
//                      code changes nothing.
//   sidebar collapsed  the floor drops to 642px, and 298px of the panel would
//                      be cut off. The frame was grown to exactly 940px, with
//                      no inner scrollbar.
//
// The floor tracks how the operator left the sidebar, not the Zoraxy version:
// collapsing the menu groups is enough to trigger it on any version. That is
// the case this exists for, and it is why the code reads back the height
// Zoraxy set instead of reimplementing the formula above.
//
// Two deliberate restrictions keep this simple enough to reason about:
//
//   It never fights Zoraxy for the frame. Whenever the frame is a size we
//   did not set, that size is Zoraxy's own choice and becomes the floor; we
//   only ever extend past it, and we compare against the height we actually
//   observed after writing, so rounding cannot make us mistake our own value
//   for a new one.
//
//   It polls instead of listening. Reacting to resize events meant recovering
//   from a tab switch that may not fire an event at all in a hidden frame.
//   Re-asserting on a timer needs no events, and lets the frame follow the
//   content back down when a rule's FQDNs are removed.

const FRAME_HEIGHT_SLACK = 12;   // absorbs sub-pixel rounding at the bottom edge
const FRAME_SYNC_INTERVAL_MS = 1000;

let appliedFrameHeight = null;   // height observed right after our own write
let hostFrameHeight = 0;         // the height Zoraxy last chose, used as a floor

function syncFrameHeight() {
    let frame;
    try {
        frame = window.frameElement; // null, or throws, if not embedded
    } catch (e) {
        return;
    }
    if (!frame || !frame.style) return;
    // Zoraxy hides the plugin tab with CSS rather than unloading the iframe.
    // Measuring a hidden element yields zeroes, which would poison the floor.
    if (!frame.offsetParent) return;

    if (frame.clientHeight !== appliedFrameHeight) {
        hostFrameHeight = frame.clientHeight;
    }

    // Measure the container, not document.body: the rule selector's Semantic
    // dropdown is an absolutely-positioned overlay, which the root scrolling
    // area counts but an ancestor's border box does not. Measuring the body
    // would inflate the whole admin page whenever that menu is opened.
    const content = document.querySelector(".standardContainer");
    if (!content) return;

    const needed = Math.ceil(content.getBoundingClientRect().bottom + window.scrollY)
        + FRAME_HEIGHT_SLACK;
    const wanted = Math.max(needed, hostFrameHeight);
    if (wanted !== frame.clientHeight) {
        frame.style.height = wanted + "px";
        appliedFrameHeight = frame.clientHeight;
    }
}

function startFrameHeightSync() {
    syncFrameHeight();
    setInterval(syncFrameHeight, FRAME_SYNC_INTERVAL_MS);
}
