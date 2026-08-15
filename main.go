package main

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
		VersionMinor:  1,
		VersionPatch:  3,
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

	// Shutting down quietly takes both halves of this.
	//
	// Zoraxy stops a plugin by GETting <UIPath>/term, and without a handler
	// there it logs "does not support termination request". The SDK's handler
	// answers 200 and then exits 100ms later, once the response is on the wire.
	uiRouter.RegisterTerminateHandler(func() {
		fmt.Println("FQDN Whitelist Sync terminating")
	}, nil)

	// That alone is not enough: Zoraxy sends SIGTERM immediately after the GET
	// returns, without waiting (see StopPlugin in mod/plugins/lifecycle.go), so
	// the signal always wins the race against that 100ms timer. Go's default
	// for an unhandled SIGTERM is to die by signal, which Zoraxy reports as
	// "encounted a fatal error ... Disabling plugin" and then, five seconds
	// later, "failed to stop gracefully, killing it".
	//
	// Exiting 0 on the signal turns that into an ordinary stop. Nothing needs
	// flushing on the way out: config.json is written atomically on every
	// change, never held in memory pending a save.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		fmt.Println("FQDN Whitelist Sync stopping")
		os.Exit(0)
	}()

	go runReconcileLoop(client, NewResolver, store, status, trigger)

	addr := fmt.Sprintf("127.0.0.1:%d", runtimeCfg.Port)
	fmt.Printf("FQDN Whitelist Sync running on %s\n", addr)
	http.ListenAndServe(addr, nil)
}

// waitForZoraxyAPI blocks until Zoraxy's plugin API answers, or timeout
// expires. It probes the default access rule, which always exists.
//
// The timeout is a bound on the damage, not an expectation: on a healthy start
// this returns in well under a second. If Zoraxy really is unreachable the loop
// proceeds anyway and reports the failure like any other, rather than idling
// forever in a state the UI cannot explain.
func waitForZoraxyAPI(client ZoraxyClient, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	delay := 100 * time.Millisecond
	for {
		if _, err := client.ListWhitelistIP("default"); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(delay)
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

// runReconcileLoop runs an immediate first reconcile, then repeats every
// interval (re-read from the store each cycle so UI edits take effect) and
// whenever a trigger arrives. It blocks; run it in a goroutine.
//
// One Reconciler is kept for the whole run and updated in place: rebuilding it
// each cycle would reset the per-FQDN failure clocks and the grace window
// would never expire.
func runReconcileLoop(client ZoraxyClient, newResolver func(servers []string) Resolver, store *ConfigStore, status *StatusStore, trigger <-chan struct{}) {
	// Zoraxy launches its plugins while it is still starting up, before its own
	// API port is listening, so reconciling immediately fails with "connection
	// refused" — and that error then sits in the UI until the next tick, which
	// is a whole interval away and five minutes on a slow poll. Nothing is
	// actually wrong, so publishing it would be noise the operator has to learn
	// to ignore.
	waitForZoraxyAPI(client, 30*time.Second)

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
