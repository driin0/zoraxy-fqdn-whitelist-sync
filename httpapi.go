package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// RuleLister is the subset of the Zoraxy client the UI needs (ISP-narrow).
type RuleLister interface {
	ListAccessRules() ([]AccessRuleInfo, error)
}

type APIServer struct {
	Store   *ConfigStore
	Status  *StatusStore
	Rules   RuleLister
	Trigger chan struct{}
	// ForceProviders is raised by the Refresh button and lowered by the
	// reconcile loop, which is the only reader.
	ForceProviders *atomic.Bool
}

func (a *APIServer) trigger() {
	select {
	case a.Trigger <- struct{}{}:
	default:
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (a *APIServer) handleState(w http.ResponseWriter, r *http.Request) {
	cfg := a.Store.Snapshot()
	lastRun, results := a.Status.Snapshot()
	var lr *string
	if !lastRun.IsZero() {
		s := lastRun.Format(time.RFC3339)
		lr = &s
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"interval_seconds": cfg.IntervalSeconds,
		"dns_servers":      cfg.DNSServers,
		"grace_seconds":    cfg.GraceSeconds,
		"unroutable_cidrs": cfg.UnroutableCIDRs,
		// The built-in list is exposed separately so the UI can offer a way
		// back after the operator has cleared the configured one. Without it
		// an empty list is a one-way door: the stored value is [] and the
		// defaults would have to be retyped by hand.
		"unroutable_defaults": append([]string(nil), DefaultUnroutableCIDRs...),
		"last_run":            lr,
		"rules":               cfg.Rules,
		"results":             results,
	})
}

func (a *APIServer) handleRules(w http.ResponseWriter, r *http.Request) {
	rules, err := a.Rules.ListAccessRules()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rules))
	for _, ru := range rules {
		out = append(out, map[string]any{
			"id":                ru.ID,
			"name":              ru.Name,
			"whitelist_enabled": ru.WhitelistEnabled,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *APIServer) handleFQDNAdd(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.AddFQDN(r.FormValue("rule_id"), r.FormValue("fqdn")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.trigger()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *APIServer) handleFQDNRemove(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.RemoveFQDN(r.FormValue("rule_id"), r.FormValue("fqdn")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.trigger()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *APIServer) handleInterval(w http.ResponseWriter, r *http.Request) {
	seconds, err := strconv.Atoi(r.FormValue("seconds"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "seconds must be an integer")
		return
	}
	if err := a.Store.SetInterval(seconds); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.trigger()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *APIServer) handleDNSServers(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.SetDNSServers(ParseDNSServers(r.FormValue("servers"))); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.trigger()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *APIServer) handleGrace(w http.ResponseWriter, r *http.Request) {
	seconds, err := strconv.Atoi(r.FormValue("seconds"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "seconds must be an integer")
		return
	}
	if err := a.Store.SetGraceSeconds(seconds); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.trigger()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *APIServer) handleUnroutable(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.SetUnroutableCIDRs(ParseCIDRList(r.FormValue("cidrs"))); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.trigger()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *APIServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if a.ForceProviders != nil {
		a.ForceProviders.Store(true)
	}
	a.trigger()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// postOnly rejects any request whose method is not POST, preventing
// state-changing handlers from being reachable via a lured GET navigation
// (which bypasses gorilla/csrf and the SameSite=Lax admin cookie).
func postOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h(w, r)
	}
}

// Register wires the API handlers under uiPath+"/api/..." on the default mux.
func (a *APIServer) Register(uiPath string) {
	http.HandleFunc(uiPath+"/api/state", a.handleState)
	http.HandleFunc(uiPath+"/api/rules", a.handleRules)
	http.HandleFunc(uiPath+"/api/fqdn/add", postOnly(a.handleFQDNAdd))
	http.HandleFunc(uiPath+"/api/fqdn/remove", postOnly(a.handleFQDNRemove))
	http.HandleFunc(uiPath+"/api/interval", postOnly(a.handleInterval))
	http.HandleFunc(uiPath+"/api/dns-servers", postOnly(a.handleDNSServers))
	http.HandleFunc(uiPath+"/api/grace", postOnly(a.handleGrace))
	http.HandleFunc(uiPath+"/api/unroutable", postOnly(a.handleUnroutable))
	http.HandleFunc(uiPath+"/api/refresh", postOnly(a.handleRefresh))
}
