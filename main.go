package main

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"time"

	plugin "github.com/driin0/zoraxy-fqdn-whitelist-sync/mod/zoraxy_plugin"
)

const (
	PLUGIN_ID   = "io.github.driin0.zoraxy.fqdn_whitelist_sync"
	UI_PATH     = "/ui"
	WEB_ROOT    = "/www"
	CONFIG_PATH = "config.json"
)

//go:embed www/*
var content embed.FS

func main() {
	runtimeCfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            PLUGIN_ID,
		Name:          "FQDN Whitelist Sync",
		Author:        "driin0",
		AuthorContact: "driin0@users.noreply.github.com",
		URL:           "https://github.com/driin0/zoraxy-fqdn-whitelist-sync",
		Description:   "Keeps access-control whitelists in sync with the resolved IPs of configured FQDNs",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  1,
		VersionMinor:  0,
		VersionPatch:  0,
		UIPath:        UI_PATH,
		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{
			{Method: http.MethodGet, Endpoint: "/plugin/api/access/list", Reason: "List access rules for the UI dropdown and whitelist-mode warning"},
			{Method: http.MethodGet, Endpoint: "/plugin/api/whitelist/list", Reason: "Read the current whitelist to reconcile"},
			{Method: http.MethodPost, Endpoint: "/plugin/api/whitelist/ip/add", Reason: "Add resolved FQDN IPs to the whitelist"},
			{Method: http.MethodPost, Endpoint: "/plugin/api/whitelist/ip/remove", Reason: "Remove stale FQDN IPs from the whitelist"},
		},
	})
	if err != nil {
		fmt.Printf("failed to init plugin: %v\n", err)
		os.Exit(1)
	}

	cfg, err := LoadConfig(CONFIG_PATH)
	if err != nil {
		fmt.Printf("failed to load config %q: %v\n", CONFIG_PATH, err)
		os.Exit(1)
	}

	store := NewConfigStore(cfg, CONFIG_PATH)
	client := NewHTTPZoraxyClient(runtimeCfg.ZoraxyPort, runtimeCfg.APIKey)
	status := &StatusStore{}
	trigger := make(chan struct{}, 1)

	api := &APIServer{Store: store, Status: status, Rules: client, Trigger: trigger}
	api.Register(UI_PATH)

	uiRouter := plugin.NewPluginEmbedUIRouter(PLUGIN_ID, &content, WEB_ROOT, UI_PATH)
	uiRouter.AttachHandlerToMux(nil)

	go runReconcileLoop(client, NewResolver, store, status, trigger)

	addr := fmt.Sprintf("127.0.0.1:%d", runtimeCfg.Port)
	fmt.Printf("FQDN Whitelist Sync running on %s\n", addr)
	http.ListenAndServe(addr, nil)
}

// runReconcileLoop runs an immediate first reconcile, then repeats every
// interval (re-read from the store each cycle so UI edits take effect) and
// whenever a trigger arrives. It blocks; run it in a goroutine.
//
// One Reconciler is kept for the whole run and updated in place: rebuilding it
// each cycle would reset the per-FQDN failure clocks and the grace window
// would never expire.
func runReconcileLoop(client ZoraxyClient, newResolver func(servers []string) Resolver, store *ConfigStore, status *StatusStore, trigger <-chan struct{}) {
	reconciler := NewReconciler(client, nil, 0)
	runOnce := func() {
		cfg := store.Snapshot()
		reconciler.Resolver = newResolver(cfg.DNSServers)
		reconciler.Grace = time.Duration(cfg.GraceSeconds) * time.Second
		// cfg.UnroutableCIDRs should always be valid by the time it gets here:
		// LoadConfig validates it and is fatal at startup if it is not, the UI
		// path (SetUnroutableCIDRs) validates before persisting, and
		// store.Snapshot() only ever returns that already-validated in-memory
		// config — it never re-reads the file. This branch is defence in
		// depth against that invariant being broken by a future change, not a
		// scenario reachable today; keeping the previous set rather than
		// silently blocking nothing is still the fail-closed choice if it ever
		// does trigger.
		if set, err := NewUnroutableSet(cfg.UnroutableCIDRs); err == nil {
			reconciler.Unroutable = set
		} else {
			fmt.Printf("invalid unroutable_cidrs, keeping the previous list: %v\n", err)
		}
		status.Set(reconciler.All(cfg), time.Now())
	}
	runOnce() // immediate first run
	ticker := time.NewTicker(time.Duration(store.Snapshot().IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			runOnce()
		case <-trigger:
			runOnce()
		}
		ticker.Reset(time.Duration(store.Snapshot().IntervalSeconds) * time.Second)
	}
}
