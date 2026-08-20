package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The release assets are bare binaries — Zoraxy's registry indexer builds
// direct download URLs, so nothing can be wrapped in an archive carrying a
// LICENSE beside it. The binary is therefore the whole of what a recipient
// gets, and AGPL §4, reached through §6, requires a copy of the License to
// reach them with it. Embedding is what satisfies that; these routes are what
// make the embedded copy retrievable by someone holding only the binary.
//
// The obligation arrives with mod/zoraxy_plugin/, copied verbatim from Zoraxy's
// AGPL tree. A build that quietly dropped the embed would still run and still
// pass every other test in this package.
func TestPanelServesTheLicenceTexts(t *testing.T) {
	for _, tc := range []struct {
		file, route, mustContain string
	}{
		{"LICENSE", "/ui/license", "GNU AFFERO GENERAL PUBLIC LICENSE"},
		{"NOTICE", "/ui/notice", "Copyright (C)"},
	} {
		rec := httptest.NewRecorder()
		licenceHandler(tc.file)(rec, httptest.NewRequest(http.MethodGet, tc.route, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200 — the licence text is not being served", tc.file, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("%s: Content-Type %q, want text/plain", tc.file, ct)
		}
		if body := rec.Body.String(); !strings.Contains(body, tc.mustContain) {
			t.Errorf("%s: served %d bytes not containing %q — what is embedded is not the file at the repository root", tc.file, len(body), tc.mustContain)
		}
	}
}

// §13 — Remote Network Interaction — is the obligation that applies to a plugin
// nobody ever downloads: whoever uses it over a network must be offered the
// Corresponding Source. That offer is Zoraxy's plugin list, which renders
// Spec.url as a working link (components/plugins.html), and Spec.url is this
// plugin's own declaration rather than anything Zoraxy invents. Losing it would
// withdraw the offer without breaking a single visible thing.
//
// .introspect is asserted rather than the struct literal in main() because CI
// already pins the two together — `go run . -introspect | diff -u .introspect -`
// — so the file cannot disagree with what the binary reports.
func TestThePluginDeclaresWhereItsSourceIs(t *testing.T) {
	b, err := os.ReadFile(".introspect")
	if err != nil {
		t.Fatalf("reading .introspect: %v", err)
	}
	var spec struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatalf("parsing .introspect: %v", err)
	}
	if !strings.HasPrefix(spec.URL, "https://") {
		t.Errorf("the plugin declares url %q — Zoraxy's plugin list is where the offer of Corresponding Source is made, and it makes it from this field", spec.URL)
	}
}

// Nothing in the panel may link out, because nothing that links out can work.
// Zoraxy sandboxes the plugin iframe "allow-scripts allow-same-origin": a link
// with target="_blank" is blocked for want of allow-popups — the click does
// nothing at all, no tab and no navigation — and navigating the frame itself to
// an external site is blocked by that site's own frame-ancestors, as GitHub's
// is. Both were tried against a replica of this panel.
//
// So the way to point somewhere from here is a URL the reader can copy, or
// Zoraxy's own plugin list. This guards the tidy-up that would turn one of
// those into a link that looks right and silently does nothing.
func TestThePanelHasNoLinkThatCannotWork(t *testing.T) {
	b, err := content.ReadFile("www/index.html")
	if err != nil {
		t.Fatalf("reading embedded index.html: %v", err)
	}
	if strings.Contains(string(b), `target="_blank"`) {
		t.Error(`target="_blank" in the panel: Zoraxy's iframe sandbox has no allow-popups, so that link does nothing whatsoever when clicked`)
	}
}
