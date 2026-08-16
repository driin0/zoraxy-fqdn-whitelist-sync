package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeLister struct {
	rules []AccessRuleInfo
	err   error
}

func (f *fakeLister) ListAccessRules() ([]AccessRuleInfo, error) {
	return f.rules, f.err
}

func newAPIServer(t *testing.T, cfgJSON string, lister RuleLister) (*APIServer, *ConfigStore) {
	t.Helper()
	store := loadStore(t, cfgJSON)
	api := &APIServer{
		Store:   store,
		Status:  &StatusStore{},
		Rules:   lister,
		Trigger: make(chan struct{}, 1),
	}
	return api, store
}

func drained(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestHandleStateReturnsConfigAndStatus(t *testing.T) {
	api, _ := newAPIServer(t, `{"interval_seconds":120,"rules":[{"rule_id":"default","fqdns":["a.example.com"]}]}`, &fakeLister{})
	api.Status.Set([]ReconcileResult{{RuleID: "default", Added: []string{"203.0.113.7"}}}, time.Unix(1700000000, 0))

	rec := httptest.NewRecorder()
	api.handleState(rec, httptest.NewRequest(http.MethodGet, "/ui/api/state", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var body struct {
		IntervalSeconds int               `json:"interval_seconds"`
		LastRun         *string           `json:"last_run"`
		Rules           []RuleConfig      `json:"rules"`
		Results         []ReconcileResult `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.IntervalSeconds != 120 || len(body.Rules) != 1 || body.Rules[0].RuleID != "default" {
		t.Errorf("state = %+v, unexpected", body)
	}
	if body.LastRun == nil || len(body.Results) != 1 || body.Results[0].RuleID != "default" {
		t.Errorf("status not surfaced: %+v", body)
	}
}

func TestHandleRulesNormalizesKeys(t *testing.T) {
	api, _ := newAPIServer(t, `{"interval_seconds":300,"rules":[]}`, &fakeLister{rules: []AccessRuleInfo{{ID: "default", Name: "Default", WhitelistEnabled: false}}})
	rec := httptest.NewRecorder()
	api.handleRules(rec, httptest.NewRequest(http.MethodGet, "/ui/api/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0]["id"] != "default" || out[0]["name"] != "Default" || out[0]["whitelist_enabled"] != false {
		t.Errorf("rules out = %+v, unexpected keys/values", out)
	}
}

func TestHandleRulesUpstreamErrorReturns502(t *testing.T) {
	api, _ := newAPIServer(t, `{"interval_seconds":300,"rules":[]}`, &fakeLister{err: fmt.Errorf("boom")})
	rec := httptest.NewRecorder()
	api.handleRules(rec, httptest.NewRequest(http.MethodGet, "/ui/api/rules", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rec.Code)
	}
}

func postForm(api *APIServer, h http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ui/api/x", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestHandleFQDNAddValidTriggersAndPersists(t *testing.T) {
	api, store := newAPIServer(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":[]}]}`, &fakeLister{})
	rec := postForm(api, api.handleFQDNAdd, url.Values{"rule_id": {"default"}, "fqdn": {"casa.example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body %s", rec.Code, rec.Body.String())
	}
	if len(store.Snapshot().Rules[0].FQDNs) != 1 {
		t.Errorf("fqdn not added: %+v", store.Snapshot().Rules)
	}
	if !drained(api.Trigger) {
		t.Error("expected a trigger to be sent")
	}
}

func TestHandleFQDNAddInvalidReturns400(t *testing.T) {
	api, _ := newAPIServer(t, `{"interval_seconds":300,"rules":[]}`, &fakeLister{})
	rec := postForm(api, api.handleFQDNAdd, url.Values{"rule_id": {"default"}, "fqdn": {"bad host"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	if drained(api.Trigger) {
		t.Error("no trigger expected on validation failure")
	}
}

func TestHandleFQDNRemoveValidTriggersAndPersists(t *testing.T) {
	api, store := newAPIServer(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":["a.example.com"]}]}`, &fakeLister{})
	rec := postForm(api, api.handleFQDNRemove, url.Values{"rule_id": {"default"}, "fqdn": {"a.example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body %s", rec.Code, rec.Body.String())
	}
	if len(store.Snapshot().Rules[0].FQDNs) != 0 {
		t.Errorf("fqdn not removed: %+v", store.Snapshot().Rules)
	}
	if !drained(api.Trigger) {
		t.Error("expected a trigger to be sent")
	}
}

func TestHandleFQDNRemoveNotFoundReturns400(t *testing.T) {
	api, _ := newAPIServer(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":["a.example.com"]}]}`, &fakeLister{})
	rec := postForm(api, api.handleFQDNRemove, url.Values{"rule_id": {"default"}, "fqdn": {"missing.example.com"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	if drained(api.Trigger) {
		t.Error("no trigger expected on failure")
	}
}

func TestHandleIntervalSuccessPersistsAndTriggers(t *testing.T) {
	api, store := newAPIServer(t, `{"interval_seconds":300,"rules":[]}`, &fakeLister{})
	rec := postForm(api, api.handleInterval, url.Values{"seconds": {"60"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body %s", rec.Code, rec.Body.String())
	}
	if store.Snapshot().IntervalSeconds != 60 {
		t.Errorf("interval = %d, want 60", store.Snapshot().IntervalSeconds)
	}
	if !drained(api.Trigger) {
		t.Error("expected a trigger to be sent")
	}
}

func TestHandleIntervalBelowFloorReturns400(t *testing.T) {
	api, _ := newAPIServer(t, `{"interval_seconds":300,"rules":[]}`, &fakeLister{})
	rec := postForm(api, api.handleInterval, url.Values{"seconds": {"5"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	rec = postForm(api, api.handleInterval, url.Values{"seconds": {"60"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestHandleRefreshTriggers(t *testing.T) {
	api, _ := newAPIServer(t, `{"interval_seconds":300,"rules":[]}`, &fakeLister{})
	rec := postForm(api, api.handleRefresh, url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if !drained(api.Trigger) {
		t.Error("expected a trigger")
	}
}

// The GET guard, tested through Register rather than around it.
//
// The previous version of this test wrapped each handler by hand —
// `postOnly(api.handleProviderAdd)` — which tests postOnly and nothing else.
// Register is where the wrapping actually happens and where it can be lost, and
// removing postOnly from six registrations left that test green. This drives
// the real mux, so a bare registration fails here.
//
// What it still cannot catch is a *new* handler added to Register without
// postOnly and without a line below. Keeping the list complete is a review
// obligation, not something the test enforces.
func TestRegisterWrapsEveryMutatingHandlerInPostOnly(t *testing.T) {
	api, store := newAPIServer(t, `{"interval_seconds":300,"rules":[{"rule_id":"default","fqdns":[]}]}`, &fakeLister{})
	// Register uses http.HandleFunc, so this may run only once per process.
	const base = "/testui"
	api.Register(base)

	mutating := []string{
		"/api/fqdn/add", "/api/fqdn/remove", "/api/interval", "/api/dns-servers",
		"/api/grace", "/api/unroutable", "/api/refresh",
		"/api/provider/add", "/api/provider/remove", "/api/provider-interval",
	}
	for _, path := range mutating {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, base+path+"?rule_id=default&fqdn=evil.example.com&seconds=60&provider=cloudflare", nil)
		http.DefaultServeMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: code = %d, want 405 — is it registered without postOnly?", path, rec.Code)
		}
	}

	// The two read endpoints must NOT be behind it, or the panel cannot load.
	for _, path := range []string{"/api/state", "/api/rules"} {
		rec := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, base+path, nil))
		if rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("GET %s: 405, but this one must answer GET", path)
		}
	}

	if len(store.Snapshot().Rules[0].FQDNs) != 0 {
		t.Errorf("a rejected GET mutated the store: %+v", store.Snapshot().Rules)
	}
	if drained(api.Trigger) {
		t.Error("a rejected GET triggered a reconcile")
	}
}

func TestHandleStateIncludesDNSServersAndGrace(t *testing.T) {
	api, _ := newAPIServer(t, `{"dns_servers":["1.1.1.1","8.8.8.8"],"dns_failure_grace_seconds":900,"rules":[]}`, &fakeLister{})

	rec := httptest.NewRecorder()
	api.handleState(rec, httptest.NewRequest(http.MethodGet, "/ui/api/state", nil))

	var body struct {
		DNSServers   []string `json:"dns_servers"`
		GraceSeconds int      `json:"grace_seconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(body.DNSServers, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("dns_servers = %v, want [1.1.1.1 8.8.8.8]", body.DNSServers)
	}
	if body.GraceSeconds != 900 {
		t.Errorf("grace_seconds = %d, want 900", body.GraceSeconds)
	}
}

func TestHandleDNSServersSetsListAndTriggers(t *testing.T) {
	api, store := newAPIServer(t, `{"rules":[]}`, &fakeLister{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/dns-servers",
		strings.NewReader(url.Values{"servers": {"1.1.1.1, 8.8.8.8"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	api.handleDNSServers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := store.Snapshot().DNSServers; !reflect.DeepEqual(got, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("dns_servers = %v, want [1.1.1.1 8.8.8.8]", got)
	}
	if !drained(api.Trigger) {
		t.Error("expected a reconcile to be triggered")
	}
}

func TestHandleDNSServersRejectsInvalid(t *testing.T) {
	api, store := newAPIServer(t, `{"rules":[]}`, &fakeLister{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/dns-servers",
		strings.NewReader(url.Values{"servers": {"1.1.1.1, http://nope"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	api.handleDNSServers(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", rec.Code)
	}
	if len(store.Snapshot().DNSServers) != 0 {
		t.Error("an invalid list must not be partially applied")
	}
}

func TestHandleUnroutablePersistsTheList(t *testing.T) {
	p := writeTempConfig(t, `{"rules": []}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)
	api := &APIServer{Store: store, Status: &StatusStore{}, Trigger: make(chan struct{}, 1)}

	req := httptest.NewRequest(http.MethodPost, "/ui/api/unroutable",
		strings.NewReader("cidrs=198.18.0.0/15, 192.0.2.0/24"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	api.handleUnroutable(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	want := []string{"198.18.0.0/15", "192.0.2.0/24"}
	if !reflect.DeepEqual(store.Snapshot().UnroutableCIDRs, want) {
		t.Errorf("stored = %v, want %v", store.Snapshot().UnroutableCIDRs, want)
	}
}

func TestHandleUnroutableRejectsMalformed(t *testing.T) {
	p := writeTempConfig(t, `{"rules": []}`)
	cfg, _ := LoadConfig(p)
	store := NewConfigStore(cfg, p)
	api := &APIServer{Store: store, Status: &StatusStore{}, Trigger: make(chan struct{}, 1)}

	req := httptest.NewRequest(http.MethodPost, "/ui/api/unroutable",
		strings.NewReader("cidrs=nonsense"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	api.handleUnroutable(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !reflect.DeepEqual(store.Snapshot().UnroutableCIDRs, DefaultUnroutableCIDRs) {
		t.Error("a rejected list must leave the stored one untouched")
	}
}

func TestStateExposesUnroutableCIDRs(t *testing.T) {
	p := writeTempConfig(t, `{"unroutable_cidrs": ["192.0.2.0/24"], "rules": []}`)
	cfg, _ := LoadConfig(p)
	api := &APIServer{Store: NewConfigStore(cfg, p), Status: &StatusStore{}}

	w := httptest.NewRecorder()
	api.handleState(w, httptest.NewRequest(http.MethodGet, "/ui/api/state", nil))

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	list, ok := got["unroutable_cidrs"].([]any)
	if !ok || len(list) != 1 || list[0] != "192.0.2.0/24" {
		t.Errorf("unroutable_cidrs = %v, want [192.0.2.0/24]", got["unroutable_cidrs"])
	}
}

// Clearing the list must not be a one-way door: the built-in defaults have to
// stay reachable from the UI even when the stored list is empty, or the only
// way back would be retyping ten ranges by hand.
func TestStateExposesTheBuiltInDefaultsEvenWhenTheListIsEmpty(t *testing.T) {
	p := writeTempConfig(t, `{"unroutable_cidrs": [], "rules": []}`)
	cfg, _ := LoadConfig(p)
	api := &APIServer{Store: NewConfigStore(cfg, p), Status: &StatusStore{}}

	w := httptest.NewRecorder()
	api.handleState(w, httptest.NewRequest(http.MethodGet, "/ui/api/state", nil))

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stored, _ := got["unroutable_cidrs"].([]any); len(stored) != 0 {
		t.Errorf("unroutable_cidrs = %v, want the empty stored list", got["unroutable_cidrs"])
	}
	defaults, ok := got["unroutable_defaults"].([]any)
	if !ok || len(defaults) != len(DefaultUnroutableCIDRs) {
		t.Fatalf("unroutable_defaults = %v, want all %d built-in ranges", got["unroutable_defaults"], len(DefaultUnroutableCIDRs))
	}
	for i, want := range DefaultUnroutableCIDRs {
		if defaults[i] != want {
			t.Errorf("unroutable_defaults[%d] = %v, want %s", i, defaults[i], want)
		}
	}
}

func TestHandleGraceSetsAndRejectsNegative(t *testing.T) {
	api, store := newAPIServer(t, `{"rules":[]}`, &fakeLister{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/grace",
		strings.NewReader(url.Values{"seconds": {"900"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	api.handleGrace(rec, req)
	if rec.Code != http.StatusOK || store.Snapshot().GraceSeconds != 900 {
		t.Fatalf("code = %d, grace = %d, want 200 and 900", rec.Code, store.Snapshot().GraceSeconds)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/ui/api/grace",
		strings.NewReader(url.Values{"seconds": {"-5"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	api.handleGrace(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 for a negative window", rec.Code)
	}
}

func TestHandleProviderAddPersistsAndTriggers(t *testing.T) {
	api, store := newAPIServer(t, `{"rules":[]}`, &fakeLister{})
	rec := postForm(api, api.handleProviderAdd, url.Values{"rule_id": {"default"}, "provider": {"cloudflare"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := store.Snapshot().Rules[0].Providers; len(got) != 1 || got[0] != "cloudflare" {
		t.Errorf("providers = %v, want [cloudflare]", got)
	}
	if !drained(api.Trigger) {
		t.Error("the write must trigger a reconcile")
	}
}

func TestHandleProviderAddRejectsUnknown(t *testing.T) {
	api, _ := newAPIServer(t, `{"rules":[]}`, &fakeLister{})
	rec := postForm(api, api.handleProviderAdd, url.Values{"rule_id": {"default"}, "provider": {"nope"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 for an unknown provider", rec.Code)
	}
	if drained(api.Trigger) {
		t.Error("a rejected write must not trigger a reconcile")
	}
}

func TestHandleProviderRemove(t *testing.T) {
	api, store := newAPIServer(t, `{"rules":[{"rule_id":"default","fqdns":[],"providers":["cloudflare"]}]}`, &fakeLister{})
	rec := postForm(api, api.handleProviderRemove, url.Values{"rule_id": {"default"}, "provider": {"cloudflare"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := store.Snapshot().Rules[0].Providers; len(got) != 0 {
		t.Errorf("providers = %v, want empty", got)
	}
}

func TestHandleProviderRemoveNotFoundReturns400(t *testing.T) {
	api, _ := newAPIServer(t, `{"rules":[{"rule_id":"default","fqdns":[]}]}`, &fakeLister{})
	rec := postForm(api, api.handleProviderRemove, url.Values{"rule_id": {"default"}, "provider": {"cloudflare"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", rec.Code)
	}
}

func TestHandleProviderIntervalFloor(t *testing.T) {
	api, store := newAPIServer(t, `{"rules":[]}`, &fakeLister{})
	if rec := postForm(api, api.handleProviderInterval, url.Values{"seconds": {"60"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 below the floor", rec.Code)
	}
	if rec := postForm(api, api.handleProviderInterval, url.Values{"seconds": {"86400"}}); rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200 above the floor", rec.Code)
	}
	if got := store.Snapshot().ProviderIntervalSeconds; got != 86400 {
		t.Errorf("provider interval = %d, want 86400", got)
	}
}

// The panel must not know any provider by name of its own: the registry is the
// single source, so adding one never means editing JavaScript.
func TestStateExposesTheProviderRegistry(t *testing.T) {
	api, _ := newAPIServer(t, `{"rules":[]}`, &fakeLister{})

	rec := httptest.NewRecorder()
	api.handleState(rec, httptest.NewRequest(http.MethodGet, "/ui/api/state", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var body struct {
		ProviderIntervalSeconds int `json:"provider_interval_seconds"`
		AvailableProviders      []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"available_providers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the state: %v", err)
	}
	if body.ProviderIntervalSeconds != DefaultProviderIntervalSeconds {
		t.Errorf("provider_interval_seconds = %d, want %d", body.ProviderIntervalSeconds, DefaultProviderIntervalSeconds)
	}
	if len(body.AvailableProviders) != len(KnownProviders) {
		t.Fatalf("available_providers has %d entries, want %d", len(body.AvailableProviders), len(KnownProviders))
	}
	if body.AvailableProviders[0].ID == "" || body.AvailableProviders[0].Name == "" {
		t.Errorf("a registry entry came through incomplete: %+v", body.AvailableProviders[0])
	}
}
