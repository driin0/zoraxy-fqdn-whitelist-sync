// FQDN Whitelist Sync — how a response from the plugin's API is read.
//
// Zoraxy's plugin proxy answers **200** with {"error": "..."} when it cannot
// reach the plugin process, so the HTTP status alone cannot tell a delivered
// request from an undelivered one. Trusting the status makes the panel report
// "FQDN added" when nothing was added, and repaint itself from an error body
// as though the configuration had become empty. Every response goes through
// here instead.
//
// A successful body never carries `error`: writes answer {"ok": true}, /api/rules
// answers an array, /api/state answers the state object, and the plugin's own
// rejections carry both `error` and a 4xx status.

const SESSION_EXPIRED = "the session has expired — reload the page";

function apiError(resp) {
    // A session that expired while the panel sat open is answered with 200,
    // text/html and the login page, so jQuery hands the callback a string.
    // Nothing this API returns is anything but an object or an array, so any
    // other shape means the answer did not come from the plugin.
    if (resp === null || typeof resp !== "object") return SESSION_EXPIRED;
    if (Array.isArray(resp)) return null;
    return typeof resp.error === "string" && resp.error !== "" ? resp.error : null;
}

// The same question for a request jQuery treated as failed. "parsererror" is
// a 2xx whose body would not parse — the login page again, on the GET path,
// where the body never reaches apiError. Naming it "cannot reach the plugin"
// would send the operator to look at a plugin that is running perfectly.
function apiErrorFromXHR(xhr, textStatus) {
    if (textStatus === "parsererror") return SESSION_EXPIRED;
    return (xhr && xhr.responseJSON && xhr.responseJSON.error) || "no answer from the plugin";
}

// The browser just gets the global. node requires this file directly in
// TestAPIErrorDetectsAnErrorBody, which is why the logic lives in its own file
// and touches no browser API.
if (typeof module !== "undefined" && module.exports) {
    module.exports = { apiError, apiErrorFromXHR, SESSION_EXPIRED };
}
