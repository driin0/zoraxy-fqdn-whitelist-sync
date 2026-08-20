package main

import "net/http"

// Serving the licence texts is a compliance requirement, not a courtesy.
//
// AGPL §6 conveys object code under the conditions of §4, and §4 requires that
// whoever receives that object code receives a copy of the License along with
// it. The release assets here are bare binaries: Zoraxy's registry indexer
// builds direct download URLs, so they cannot be wrapped in an archive carrying
// a LICENSE beside them. The binary is therefore the whole of what a recipient
// gets, and the only place the text can travel is inside it.
//
// §13 is the half that applies to something like this even when nobody
// downloads anything: a user interacting with the program remotely over a
// network must be offered the Corresponding Source. The panel's footer links to
// the repository, and that link is the offer.
//
// The obligation arrives with mod/zoraxy_plugin/, which is copied verbatim from
// Zoraxy's AGPL source tree. It is inherited rather than chosen, and it is not
// ours to waive on tobychui's behalf.
func licenceHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := content.ReadFile(name)
		if err != nil {
			// Unreachable while the go:embed directive in main.go names this
			// file — a build that lost it does not compile. Answering 500
			// rather than 404 keeps a licence that failed to ship from reading
			// like a mistyped URL.
			http.Error(w, "licence text unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	}
}

// RegisterLicenceRoutes publishes the licence texts under the plugin's UI path.
// They sit beside the panel rather than inside www/ so that the files served
// are the repository's own LICENSE and NOTICE, with no second copy to drift.
func RegisterLicenceRoutes(uiPath string) {
	http.HandleFunc(uiPath+"/license", licenceHandler("LICENSE"))
	http.HandleFunc(uiPath+"/notice", licenceHandler("NOTICE"))
}
