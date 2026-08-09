// FQDN Whitelist Sync — GUI logic.
// Native-Zoraxy look: rule selector dropdown + per-rule FQDN table.
// GETs use plain $.getJSON; POSTs use $.cjax (CSRF token from the meta tag).

let rulesCache = [];   // Zoraxy access rules: [{id,name,whitelist_enabled}]
let stateCache = null; // {interval_seconds,last_run,rules,results}
let currentRule = "default";

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
    const info = ruleInfo(currentRule);
    const $m = $("#syncStatusMsg");
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

function renderTable() {
    const cfg = cfgRule(currentRule);
    const res = resultFor(currentRule) || {};
    const resolved = res.Resolved || {};
    const grace = res.Grace || {};
    const offline = res.Offline || {};
    const $t = $("#fqdnTable").empty();
    const fqdns = (cfg && cfg.fqdns) || [];

    if (fqdns.length === 0) {
        $t.append('<tr><td colspan="4"><i class="green check circle icon"></i> No FQDNs synced for this rule yet. Add one above.</td></tr>');
        return;
    }
    fqdns.forEach(fqdn => {
        const ips = resolved[fqdn];
        const ok = ips && ips.length > 0;
        const ipText = ok ? '<div class="ipList">' + ips.map(esc).join("<br>") + "</div>" : '<span class="muted">—</span>';
        const graceLeft = grace[fqdn];
        const offlineIPs = offline[fqdn];
        let statusCls, statusTxt;
        if (graceLeft) {
            // DNS is failing but the last known IPs are still whitelisted:
            // neither ok nor revoked. Show it, so the operator can tell that
            // access is preserved and for how long.
            statusCls = "status-grace";
            statusTxt = '<i class="hourglass half icon"></i> grace — ' + esc(graceLeft) + " left";
        } else if (offlineIPs && offlineIPs.length > 0 && !ok) {
            // The DDNS positively reports the device unreachable (sentinel-only
            // answer): checked before ok, so no routable address left never
            // renders green.
            statusCls = "status-offline";
            statusTxt = '<i class="power off icon"></i> offline';
        } else if (ok) {
            statusCls = "status-ok"; statusTxt = '<i class="check circle icon"></i> ok';
        } else if (stateCache && stateCache.last_run) {
            statusCls = "status-error"; statusTxt = '<i class="times circle icon"></i> unresolved';
        } else {
            statusCls = "status-pending"; statusTxt = "pending";
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
    return $.getJSON("./api/rules").done(function (rules) {
        rulesCache = Array.isArray(rules) ? rules : [];
        populateRuleDropdown();
        renderCurrent();
    }).fail(function () {
        // dropdown stays as-is; the table still renders from config
    });
}

function loadState() {
    return $.getJSON("./api/state").done(function (state) {
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
        $("#lastRun").text(state.last_run ? "Last sync: " + new Date(state.last_run).toLocaleString() : "No sync yet");
        renderTable();
    });
}

$(function () {
    $("#addFqdnBtn").on("click", function () {
        const fqdn = $("#fqdnInput").val().trim();
        if (!currentRule || !fqdn) { notify("Enter a FQDN", false); return; }
        $.cjax({ url: "./api/fqdn/add", method: "POST", data: { rule_id: currentRule, fqdn: fqdn } })
            .done(() => { $("#fqdnInput").val(""); notify("FQDN added", true); loadState(); })
            .fail(xhr => notify((xhr.responseJSON && xhr.responseJSON.error) || "Add failed", false));
    });

    $("#fqdnTable").on("click", ".removeBtn", function () {
        const fqdn = $(this).attr("data-fqdn");
        $.cjax({ url: "./api/fqdn/remove", method: "POST", data: { rule_id: currentRule, fqdn: fqdn } })
            .done(() => { notify("FQDN removed", true); loadState(); })
            .fail(xhr => notify((xhr.responseJSON && xhr.responseJSON.error) || "Remove failed", false));
    });

    $("#saveIntervalBtn").on("click", function () {
        $.cjax({ url: "./api/interval", method: "POST", data: { seconds: $("#intervalInput").val() } })
            .done(() => notify("Interval saved", true))
            .fail(xhr => notify((xhr.responseJSON && xhr.responseJSON.error) || "Save failed", false));
    });

    $("#saveDnsServersBtn").on("click", function () {
        $.cjax({ url: "./api/dns-servers", method: "POST", data: { servers: $("#dnsServersInput").val() } })
            .done(() => { notify("DNS servers saved", true); loadState(); })
            .fail(xhr => notify((xhr.responseJSON && xhr.responseJSON.error) || "Save failed", false));
    });

    $("#saveGraceBtn").on("click", function () {
        $.cjax({ url: "./api/grace", method: "POST", data: { seconds: $("#graceInput").val() } })
            .done(() => { notify("Grace window saved", true); loadState(); })
            .fail(xhr => notify((xhr.responseJSON && xhr.responseJSON.error) || "Save failed", false));
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
        $.cjax({ url: "./api/unroutable", method: "POST", data: { cidrs: cidrs } })
            .done(() => { notify("Never-authorise list saved", true); loadState(); })
            .fail(xhr => notify((xhr.responseJSON && xhr.responseJSON.error) || "Save failed", false));
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

    $("#refreshBtn").on("click", function () {
        $.cjax({ url: "./api/refresh", method: "POST" })
            .done(() => { notify("Refresh triggered", true); loadRules(); setTimeout(loadState, 600); });
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
