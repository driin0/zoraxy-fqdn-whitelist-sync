package main

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
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
		Description:   "Keeps access-control whitelists in sync with resolved FQDNs and published CDN provider ranges",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  1,
		VersionMinor:  2,
		VersionPatch:  0,
		UIPath:        UI_PATH,
		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{
			{Method: http.MethodGet, Endpoint: "/plugin/api/access/list", Reason: "List access rules for the UI dropdown and whitelist-mode warning"},
			{Method: http.MethodGet, Endpoint: "/plugin/api/whitelist/list", Reason: "Read the current whitelist to reconcile, and to recover the last authorised addresses and ranges after a restart"},
			{Method: http.MethodPost, Endpoint: "/plugin/api/whitelist/ip/add", Reason: "Add resolved FQDN addresses and published CDN provider ranges to the whitelist"},
			{Method: http.MethodPost, Endpoint: "/plugin/api/whitelist/ip/remove", Reason: "Remove addresses and ranges that are no longer authorised, and entries left in a legacy format"},
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
	force := &atomic.Bool{}

	api := &APIServer{Store: store, Status: status, Rules: client, Trigger: trigger, ForceProviders: force}
	api.Register(UI_PATH)

	uiRouter := plugin.NewPluginEmbedUIRouter(PLUGIN_ID, &content, WEB_ROOT, UI_PATH)
	uiRouter.AttachHandlerToMux(nil)

	// Shutting down quietly takes both halves of this.
	//
	// Zoraxy stops a plugin by GETting <UIPath>/term, and without a handler
	// there it logs "does not support termination request". The SDK's handler
	// answers 200 and then exits 100ms later, once the response is on the wire.
	//
	// This one only prints, and that is the design rather than an omission:
	// there is nothing to flush. config.json is written atomically on every
	// change (saveConfig: temp file, fsync, rename) and never held in memory
	// pending a save; there is no database, no open connection, and no cache
	// that survives the process. "No new persistent state" is an acceptance
	// criterion of this plugin, not an accident of it.
	//
	// If that ever stops being true, the cleanup belongs *here* and not in the
	// signal handler below, and on every platform. termFunc runs synchronously,
	// before the 200 goes on the wire, and Zoraxy's GET carries a 3s client
	// timeout — so that is the window for slow work, and it is the same on POSIX
	// and Windows because only what happens *after* the response differs.
	//
	// After the response there is far less room than the POSIX path suggests.
	// POSIX: SIGTERM, then five seconds of polling before Zoraxy kills. Windows:
	// no signal at all, 300ms, then Kill — against the SDK's own self-exit.
	//
	// Measured on Windows 11 (build 26200) rather than deduced: /term answered
	// 200 in 48ms, the process exited by itself 88ms later, and the signal
	// handler below never printed — only the /term handler did. So the clean
	// stop on Windows comes entirely from the SDK's timer, leaving about
	// **212ms of margin** before Zoraxy's kill and nothing to catch if it is
	// missed. Any cleanup that does not fit before the response has no home
	// there.
	//
	// Make it callable from both paths (a sync.Once), because a SIGTERM can also
	// arrive without this handler running at all: at machine shutdown, or if the
	// GET times out.
	//
	// What it must not do is call os.Exit itself, despite the review on PR #17
	// asking for exactly that. Exiting here happens before the response is
	// written, so Zoraxy's GET fails and it logs "termination request failed.
	// Force shutting down" — a worse outcome than today, and one the SDK already
	// avoids by owning the exit after the response.
	uiRouter.RegisterTerminateHandler(func() {
		fmt.Println("FQDN Whitelist Sync terminating")
	}, nil)

	// That alone is not enough: on POSIX, Zoraxy sends SIGTERM immediately after
	// the GET returns, without waiting (see StopPlugin in
	// mod/plugins/lifecycle.go), so the signal wins the race against that 100ms
	// timer. On Windows there is no SIGTERM at all — StopPlugin sleeps 300ms and
	// calls Process.Kill(), so the SDK's timer gets there first and this handler
	// never runs. Zoraxy ships windows/amd64, so both paths are real. Go's default
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

	go runReconcileLoop(client, NewResolver, NewHTTPProviderFetcher(), store, status, trigger, force)

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
func runReconcileLoop(client ZoraxyClient, newResolver func(servers []string) Resolver, fetcher ProviderFetcher, store *ConfigStore, status *StatusStore, trigger <-chan struct{}, force *atomic.Bool) {
	// Zoraxy launches its plugins while it is still starting up, before its own
	// API port is listening, so reconciling immediately fails with "connection
	// refused" — and that error then sits in the UI until the next tick, which
	// is a whole interval away and five minutes on a slow poll. Nothing is
	// actually wrong, so publishing it would be noise the operator has to learn
	// to ignore.
	waitForZoraxyAPI(client, 30*time.Second)

	reconciler := NewReconciler(client, nil, 0)
	reconciler.Fetcher = fetcher
	runOnce := func() {
		cfg := store.Snapshot()
		reconciler.Resolver = newResolver(cfg.DNSServers)
		reconciler.Grace = time.Duration(cfg.GraceSeconds) * time.Second
		reconciler.ProviderPeriod = time.Duration(cfg.ProviderIntervalSeconds) * time.Second
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
		// Read and clear in one operation: a press arriving while a cycle is
		// already running is honoured by the next one rather than lost.
		status.Set(reconciler.All(cfg, force.Swap(false)), time.Now())
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
