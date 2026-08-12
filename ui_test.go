package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Zoraxy's plugin proxy answers **200** with {"error": "..."} when it cannot
// reach the plugin process, so an HTTP success is not proof that the request
// arrived. Reading only the status code makes the panel report "FQDN added"
// when nothing was added, and repaint itself from an error body as though the
// configuration were empty. apiError is the single place that decides, so it
// is tested for real — run through node — rather than asserted by matching
// strings in the source.
//
// node is available wherever this runs: the workflow's actions/checkout is
// itself a JavaScript action, so a runner without node could not check the
// repository out to begin with.
// What apiError must say when the body did not come from the plugin's API at
// all. Kept here so the test and www/api.js cannot drift apart silently.
const sessionGone = "the session has expired — reload the page"

func TestAPIErrorDetectsAnErrorBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // "" means apiError must return null
	}{
		{"proxy cannot reach the plugin", `{"error":"dial tcp 127.0.0.1:5808: connect: connection refused"}`,
			"dial tcp 127.0.0.1:5808: connect: connection refused"},
		{"a write that succeeded", `{"ok":true}`, ""},
		{"the rules array", `[{"id":"default","name":"Default"}]`, ""},
		{"a state object", `{"interval_seconds":30,"rules":[]}`, ""},
		{"an empty error string reports nothing", `{"error":""}`, ""},

		// An expired session is answered by Zoraxy with 200, text/html and the
		// login page, so jQuery hands the callback a string. Reading only the
		// status, or only an `error` field, reports "Interval saved" for a
		// write that never happened.
		{"the login page instead of JSON", `"<!DOCTYPE HTML><html><body>login</body></html>"`, sessionGone},
		{"an empty body", `""`, sessionGone},
		{"no body at all", `null`, sessionGone},
	}

	bodies := make([]json.RawMessage, len(cases))
	for i, c := range cases {
		bodies[i] = json.RawMessage(c.body)
	}
	encoded, err := json.Marshal(bodies)
	if err != nil {
		t.Fatalf("encoding the cases: %v", err)
	}

	script := fmt.Sprintf(`const { apiError } = require("./www/api.js");
console.log(JSON.stringify(%s.map(apiError)));`, encoded)

	if _, err := exec.LookPath("node"); err != nil {
		// CI always has node — actions/checkout is itself a JavaScript action,
		// so a runner without it could not check the repository out. Anywhere
		// else a missing node is the environment's business, not a failure of
		// this code.
		if os.Getenv("CI") != "" {
			t.Fatalf("node not found in CI: %v", err)
		}
		t.Skipf("node not installed: %v", err)
	}

	// Only stdout carries the result: node writes deprecation and experimental
	// warnings to stderr, and merging the two would fail the parse below over
	// a notice that says nothing about apiError.
	cmd := exec.Command("node", "-e", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running node: %v\n%s", err, stderr.String())
	}

	var got []*string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("parsing node output %q: %v", out, err)
	}
	if len(got) != len(cases) {
		t.Fatalf("got %d results for %d cases", len(got), len(cases))
	}
	for i, c := range cases {
		switch {
		case c.want == "" && got[i] != nil:
			t.Errorf("%s: apiError returned %q, want null", c.name, *got[i])
		case c.want != "" && got[i] == nil:
			t.Errorf("%s: apiError returned null, want %q", c.name, c.want)
		case c.want != "" && *got[i] != c.want:
			t.Errorf("%s: apiError returned %q, want %q", c.name, *got[i], c.want)
		}
	}
}

// The same question on the failure side. jQuery reports "parsererror" when a
// 2xx body will not parse as JSON, which for this panel means Zoraxy served
// the login page: the plugin is fine and saying "cannot reach the plugin"
// sends the operator after the wrong thing.
func TestAPIErrorFromXHRNamesTheRightFailure(t *testing.T) {
	cases := []struct {
		name       string
		xhr        string
		textStatus string
		want       string
	}{
		{"a 2xx body that will not parse", `{}`, "parsererror", sessionGone},
		{"the plugin's own error", `{"responseJSON":{"error":"dial tcp: connection refused"}}`, "error",
			"dial tcp: connection refused"},
		{"an error with no body", `{}`, "error", "no answer from the plugin"},
	}

	if _, err := exec.LookPath("node"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("node not found in CI: %v", err)
		}
		t.Skipf("node not installed: %v", err)
	}

	calls := make([]string, len(cases))
	for i, c := range cases {
		calls[i] = fmt.Sprintf("apiErrorFromXHR(%s, %q)", c.xhr, c.textStatus)
	}
	script := fmt.Sprintf(`const { apiErrorFromXHR } = require("./www/api.js");
console.log(JSON.stringify([%s]));`, strings.Join(calls, ","))

	cmd := exec.Command("node", "-e", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running node: %v\n%s", err, stderr.String())
	}

	var got []string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("parsing node output %q: %v", out, err)
	}
	for i, c := range cases {
		if got[i] != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got[i], c.want)
		}
	}
}

// index.html loading a script that is not in the embed produces a panel that
// dies on its first line, with a binary that built and started perfectly. The
// files are embedded by a wildcard, so nothing else notices one going missing.
func TestPanelScriptsAreEmbedded(t *testing.T) {
	b, err := content.ReadFile("www/index.html")
	if err != nil {
		t.Fatalf("reading embedded index.html: %v", err)
	}

	// Only the plugin's own assets: paths starting with / are served by Zoraxy.
	srcs := regexp.MustCompile(`src="\./([^"]+)"`).FindAllStringSubmatch(string(b), -1)
	if len(srcs) == 0 {
		t.Fatal("index.html loads none of its own scripts — the pattern no longer matches anything")
	}
	for _, s := range srcs {
		if _, err := content.ReadFile("www/" + s[1]); err != nil {
			t.Errorf("index.html loads ./%s, which is not in the embedded www/: %v", s[1], err)
		}
	}
}

// Every call to the plugin's API must go through the two helpers that consult
// apiError, so a new endpoint cannot quietly reintroduce the "200 means it
// worked" assumption. One $.cjax and one $.getJSON in the whole panel is what
// that looks like from here.
func TestPanelHasOneWayToCallTheAPI(t *testing.T) {
	b, err := content.ReadFile("www/app.js")
	if err != nil {
		t.Fatalf("reading embedded app.js: %v", err)
	}
	src := string(b)

	for _, call := range []string{"$.cjax(", "$.getJSON("} {
		if n := strings.Count(src, call); n != 1 {
			t.Errorf("%s appears %d times, want 1 — route it through the apiGet/apiPost helpers", call, n)
		}
	}
}

// Zoraxy's $.cjax (script/utils.js) fires the request but does not return the
// jqXHR, so anything chained onto it throws a TypeError before the callbacks
// are ever registered. The request still reaches the server and a 5s poll
// repaints the panel, so the success path looks fine — what is silently lost
// is .fail(), leaving a rejected write with no report to the operator at all.
// Callbacks must therefore be passed inside the payload, not chained.
func TestPanelDoesNotChainOnCjax(t *testing.T) {
	b, err := content.ReadFile("www/app.js")
	if err != nil {
		t.Fatalf("reading embedded app.js: %v", err)
	}
	src := string(b)

	const call = "$.cjax("
	calls := 0
	for i := 0; ; {
		start := strings.Index(src[i:], call)
		if start < 0 {
			break
		}
		start += i
		calls++

		// Walk to the parenthesis closing this call. The payloads in this file
		// hold no parenthesis inside a string literal, so counting depth is
		// enough; if that ever changes this test fails loudly, which is the
		// safe direction for a guard.
		depth, end := 0, -1
		for j := start + len(call) - 1; j < len(src); j++ {
			switch src[j] {
			case '(':
				depth++
			case ')':
				if depth--; depth == 0 {
					end = j
					break
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			t.Fatalf("unbalanced parentheses in the $.cjax call at offset %d", start)
		}

		rest := strings.TrimLeft(src[end+1:], " \t\r\n")
		if strings.HasPrefix(rest, ".done") || strings.HasPrefix(rest, ".fail") {
			t.Errorf("line %d: callback chained onto $.cjax, which returns undefined — "+
				"pass success/error inside the payload instead",
				strings.Count(src[:start], "\n")+1)
		}
		i = end + 1
	}

	if calls == 0 {
		t.Fatal("no $.cjax call found in app.js — the panel's write path was renamed and this guard no longer guards anything")
	}
}

func TestStatusStoreRoundTrip(t *testing.T) {
	s := &StatusStore{}
	when := time.Unix(1_700_000_000, 0)
	s.Set([]ReconcileResult{{RuleID: "default", Added: []string{"203.0.113.7"}}}, when)

	got, results := s.Snapshot()
	if !got.Equal(when) {
		t.Errorf("lastRun = %v, want %v", got, when)
	}
	if len(results) != 1 || results[0].RuleID != "default" {
		t.Errorf("results = %+v, unexpected", results)
	}
}
