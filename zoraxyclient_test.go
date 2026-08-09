package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(srv *httptest.Server) *HTTPZoraxyClient {
	return &HTTPZoraxyClient{BaseURL: srv.URL, APIKey: "test-key", HTTP: srv.Client()}
}

func TestListWhitelistIPParsesAndSendsAuthAndType(t *testing.T) {
	var gotAuth, gotType, gotID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotType = r.URL.Query().Get("type")
		gotID = r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"EntryType":1,"CC":"","IP":"203.0.113.7","Comment":"fqdn-sync:a.example.com"}]`))
	}))
	defer srv.Close()

	entries, err := newTestClient(srv).ListWhitelistIP("default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("auth = %q, want Bearer test-key", gotAuth)
	}
	if gotType != "ip" {
		t.Errorf("type = %q, want ip", gotType)
	}
	if gotID != "default" {
		t.Errorf("id = %q, want default", gotID)
	}
	if len(entries) != 1 || entries[0].IP != "203.0.113.7" || entries[0].Comment != "fqdn-sync:a.example.com" {
		t.Errorf("entries = %+v, unexpected", entries)
	}
}

func TestAddWhitelistIPPostsFormAndSucceedsOnOK(t *testing.T) {
	var gotIP, gotID, gotComment, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotIP = r.Form.Get("ip")
		gotID = r.Form.Get("id")
		gotComment = r.Form.Get("comment")
		gotCT = r.Header.Get("Content-Type")
		w.Write([]byte(`"OK"`))
	}))
	defer srv.Close()

	err := newTestClient(srv).AddWhitelistIP("default", "203.0.113.9", "fqdn-sync:a.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotIP != "203.0.113.9" || gotID != "default" || gotComment != "fqdn-sync:a.example.com" {
		t.Errorf("form = ip:%q id:%q comment:%q, unexpected", gotIP, gotID, gotComment)
	}
	if !strings.HasPrefix(gotCT, "application/x-www-form-urlencoded") {
		t.Errorf("content-type = %q, want form-urlencoded", gotCT)
	}
}

func TestAddWhitelistIPReturnsErrorOnErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":"invalid or empty ip address"}`))
	}))
	defer srv.Close()

	err := newTestClient(srv).AddWhitelistIP("default", "", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid or empty ip address") {
		t.Errorf("error = %v, want to contain api message", err)
	}
}

func TestRemoveWhitelistIPPostsForm(t *testing.T) {
	var gotIP, gotID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotIP = r.Form.Get("ip")
		gotID = r.Form.Get("id")
		w.Write([]byte(`"OK"`))
	}))
	defer srv.Close()

	err := newTestClient(srv).RemoveWhitelistIP("admin", "203.0.113.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotIP != "203.0.113.7" || gotID != "admin" {
		t.Errorf("form = ip:%q id:%q, unexpected", gotIP, gotID)
	}
}

func TestListAccessRulesParsesAndSendsAuth(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Write([]byte(`[{"ID":"default","Name":"Default","WhitelistEnabled":false,"Desc":"x"},{"ID":"admin","Name":"Admin","WhitelistEnabled":true}]`))
	}))
	defer srv.Close()

	rules, err := newTestClient(srv).ListAccessRules()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotPath != "/plugin/api/access/list" {
		t.Errorf("path = %q", gotPath)
	}
	if len(rules) != 2 || rules[0].ID != "default" || rules[0].WhitelistEnabled != false ||
		rules[1].ID != "admin" || rules[1].WhitelistEnabled != true {
		t.Errorf("rules = %+v, unexpected", rules)
	}
}
