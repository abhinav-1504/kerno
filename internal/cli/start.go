// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/adapter"
	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/config"
	"github.com/optiqor/kerno/internal/doctor"
	"github.com/optiqor/kerno/internal/metrics"
	"github.com/optiqor/kerno/internal/version"
)

// ── Package-level atomic config pointer ────────────────────────────────────
//
// globalCfg is the live configuration pointer, protected by atomic.Pointer
// so the SIGHUP handler can safely swap it without blocking reads from
// doctor, watch, chaos, and other subsystems.
//
// Fix: replaces the bare package-level *config.Config assignment that was a
// textbook data race (caught by go test -race). Every read site calls getCfg()
// and every write calls setCfg(); no additional locking needed because
// atomic.Pointer provides sequentially-consistent load/store.
var globalCfg atomic.Pointer[config.Config]

// getCfg returns the current live config. Safe to call from any goroutine.
func getCfg() *config.Config {
	return globalCfg.Load()
}

// setCfg atomically replaces the live config pointer.
// Used by the SIGHUP handler after a successful reload.
func setCfg(newCfg *config.Config) {
	globalCfg.Store(newCfg)
}

func newStartCmd() *cobra.Command {
	var (
		prometheus     bool
		prometheusAddr string
		dashboard      bool
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start Kerno as a long-running daemon with all collectors",
		Long: `Start Kerno in daemon mode: loads all eBPF programs, starts collectors,
and exposes Prometheus metrics and an optional web dashboard.

This is the command used in the Kubernetes DaemonSet and for
long-running observability on standalone servers.`,
		Example: `  # Start with Prometheus metrics
  sudo kerno start

  # Start with custom Prometheus address
  sudo kerno start --prometheus-addr :9091

  # Start with web dashboard
  sudo kerno start --dashboard`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStart(cmd.Context(), startOpts{
				prometheus:     prometheus,
				prometheusAddr: prometheusAddr,
				dashboard:      dashboard,
			})
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&prometheus, "prometheus", true, "enable Prometheus /metrics endpoint")
	flags.StringVar(&prometheusAddr, "prometheus-addr", "", "Prometheus listen address (default from config)")
	flags.BoolVar(&dashboard, "dashboard", false, "enable the embedded web dashboard")

	return cmd
}

type startOpts struct {
	prometheus     bool
	prometheusAddr string
	dashboard      bool
}

// reloadableSubsystems groups every live subsystem that can accept an
// Update call from the SIGHUP handler. Keeping them in one struct makes
// the handler easy to read and test.
type reloadableSubsystems struct {
	engine     *doctor.Engine
	httpServer **http.Server // pointer-to-pointer so rebind can swap the server
	logger     *slog.Logger
	opts       startOpts

	// Fix: hold the real BPF program counts so that rebindPrometheus can
	// pass them to the new /healthz handler instead of hardcoding 0/0.
	mu           sync.Mutex // protects loadedCount and totalLoaders
	loadedCount  int
	totalLoaders int
}

func runStart(ctx context.Context, opts startOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()

	logger.Info("starting kerno daemon",
		"prometheus", opts.prometheus,
		"dashboard", opts.dashboard,
	)

	// Set up OS signal handling.
	// SIGINT / SIGTERM → graceful shutdown (via context cancellation).
	// SIGHUP           → config hot-reload (handled in a dedicated goroutine).
	shutdownCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	// Initialise the atomic config pointer with the startup config.
	// cfg is the package-level *config.Config set by root.go's initConfig.
	startupCfg := cfg
	setCfg(startupCfg)

	// Resolve Prometheus listen address (CLI flag overrides config file).
	promAddr := startupCfg.Prometheus.Addr
	if opts.prometheusAddr != "" {
		promAddr = opts.prometheusAddr
	}

	// ── Phase 1: Load eBPF programs (graceful degradation) ─────────────────
	loaders, loaderSet := buildLoaders(logger)
	loadedCount := 0
	closers := make([]func(), 0, len(loaders))

	for _, l := range loaders {
		closer, err := l.Load()
		if err != nil {
			logger.Warn("failed to load eBPF program, skipping",
				"program", l.Name(),
				"error", err,
			)
			continue
		}
		closers = append(closers, func() { _ = closer.Close() })
		loadedCount++
		logger.Info("loaded eBPF program", "program", l.Name())
	}

	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	totalLoaders := len(loaders)
	logger.Info("eBPF programs loaded", "loaded", loadedCount, "total", totalLoaders)

	// Self-monitoring gauges.
	metrics.BPFProgramsLoaded.Set(float64(loadedCount))
	metrics.InfoMetric.WithLabelValues(version.Version).Set(1)

	// Pre-initialise CounterVec instances so /metrics emits HELP/TYPE
	// lines immediately, before any event flows through.
	for _, l := range loaders {
		metrics.CollectorEventsTotal.WithLabelValues(l.Name()).Add(0)
		metrics.CollectorErrorsTotal.WithLabelValues(l.Name()).Add(0)
	}

	// ── Phase 2: Metrics bridge ────────────────────────────────────────────
	bridge := metrics.NewBridge(logger)
	bridge.Start(shutdownCtx, loaderSet.Loaders())
	defer bridge.Stop()

	// ── Phase 2b: Environment adapter ─────────────────────────────────────
	env := adapter.DetectEnvironment()
	adpt := adapter.NewAdapter(logger, env)
	if err := adpt.Start(shutdownCtx); err != nil {
		logger.Warn("failed to start environment adapter", "error", err)
	}
	defer adpt.Stop()
	logger.Info("environment adapter started", "adapter", adpt.Name(), "env", env)

	// ── Phase 2c: Doctor engine ────────────────────────────────────────────
	// Held in reloadableSubsystems so the SIGHUP handler can call
	// UpdateThresholds on the live instance.
	// AI analyzer is wired separately by the ai package; pass nil here so
	// the daemon starts without AI enrichment by default (opt-in via config).
	diagEngine := doctor.NewEngine(startupCfg.Doctor.Thresholds, nil, logger)

	// ── Phase 3: HTTP server (health + metrics) ────────────────────────────
	httpServer := startHTTPServer(logger, opts, promAddr, loadedCount, totalLoaders)

	// Build the reloadable subsystems struct — the SIGHUP handler's only
	// argument, keeping the handler signature stable as features are added.
	reloadableSubs := &reloadableSubsystems{
		engine:       diagEngine,
		httpServer:   &httpServer,
		logger:       logger,
		opts:         opts,
		loadedCount:  loadedCount,
		totalLoaders: totalLoaders,
	}

	// ── SIGHUP hot-reload goroutine ────────────────────────────────────────
	//
	// Runs for the lifetime of the daemon. On every SIGHUP it:
	//  1. Re-reads the config file via the same Viper pipeline used at startup.
	//  2. Diffs old vs new config.
	//  3. Applies safe changes in-place (log level, thresholds, prometheus addr).
	//  4. Warns about changes that require a restart (collector enable/disable).
	go func() {
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-sighupCh:
				handleSIGHUP(logger, reloadableSubs)
			}
		}
	}()

	// ── Status banner ──────────────────────────────────────────────────────
	fmt.Println("kerno daemon running")
	fmt.Printf("  eBPF programs: %d/%d loaded\n", loadedCount, totalLoaders)
	if opts.prometheus {
		fmt.Printf("  Prometheus:    http://%s/metrics\n", promAddr)
		fmt.Printf("  Health:        http://%s/healthz\n", promAddr)
		fmt.Printf("  Readiness:     http://%s/readyz\n", promAddr)
	}
	if opts.dashboard {
		fmt.Printf("  Dashboard:     http://%s (not yet implemented)\n", getCfg().Dashboard.Addr)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	// Block until shutdown signal.
	<-shutdownCtx.Done()

	logger.Info("shutting down kerno daemon")

	// ── Phase 4: Graceful HTTP shutdown ───────────────────────────────────
	if httpServer != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := httpServer.Shutdown(stopCtx); err != nil {
			logger.Warn("HTTP server shutdown error", "error", err)
		}
	}

	logger.Info("kerno daemon stopped")
	return nil
}

// handleSIGHUP performs config hot-reload on every SIGHUP.
// Called from the goroutine in runStart; must not block for long.
func handleSIGHUP(
	logger *slog.Logger,
	subs *reloadableSubsystems,
) {
	oldCfg := getCfg()
	logger.Info("SIGHUP received — reloading config", "path", cfgFile)

	newCfg, result, err := oldCfg.ReloadFrom(cfgFile)
	if err != nil {
		logger.Error("config reload failed — keeping current config", "error", err)
		return
	}

	// ── Apply each hot-reloadable change ──────────────────────────────────

	for _, change := range result.Applied {
		logger.Info("applying hot-reload change", "change", change)
	}

	// 1. Log level / format
	//    Delegate to root.go's initLogger so the slog handler is rebuilt
	//    identically to startup (JSON vs text detection, level parsing, etc.).
	//    Refresh the local logger pointer so subsequent calls in this function
	//    use the new handler immediately.
	if oldCfg.LogLevel != newCfg.LogLevel || oldCfg.LogFormat != newCfg.LogFormat {
		initLogger(newCfg.LogLevel, newCfg.LogFormat)
		logger = slog.Default()
		logger.Info("log level/format changed",
			"level", newCfg.LogLevel, "format", newCfg.LogFormat)
	}

	// 2. Doctor thresholds
	//    Use the change set from reload.go's diff() — single source of truth.
	//    This avoids re-diffing DoctorThresholds here, which would silently
	//    break if a slice or map field is ever added to the struct.
	for _, change := range result.Applied {
		if change == "doctor.thresholds updated" {
			subs.engine.UpdateThresholds(newCfg.Doctor.Thresholds)
			break
		}
	}

	// 3. Prometheus address / enabled flag
	//    Fix: read the real BPF program counts from reloadableSubsystems
	//    (mutex-protected) so the rebuilt /healthz handler keeps reporting
	//    accurate numbers instead of 0/0.
	subs.mu.Lock()
	loadedCount := subs.loadedCount
	totalLoaders := subs.totalLoaders
	subs.mu.Unlock()

	oldAddr := oldCfg.Prometheus.Addr
	newAddr := newCfg.Prometheus.Addr
	if subs.opts.prometheusAddr != "" {
		// CLI flag always wins; honour it on reload too.
		newAddr = subs.opts.prometheusAddr
	}
	if oldAddr != newAddr || oldCfg.Prometheus.Enabled != newCfg.Prometheus.Enabled {
		logger.Info("prometheus address changed — rebinding",
			"old", oldAddr, "new", newAddr)
		rebindPrometheus(logger, subs.httpServer, newAddr,
			loadedCount, totalLoaders,
			newCfg.Prometheus.Enabled,
		)
	}

	// 4. Warn about restart-required changes; do not crash.
	for _, w := range result.RestartRequired {
		logger.Warn("config change requires restart to take effect", "change", w)
	}

	// Atomically swap the global config pointer so the next reload diffs
	// against the freshly-applied config, not the stale startup config.
	setCfg(newCfg)

	logger.Info(result.String(),
		"applied", len(result.Applied),
		"restart_required", len(result.RestartRequired),
	)
}

// startHTTPServer launches the Prometheus / health HTTP server and returns
// the *http.Server so the caller can shut it down on exit.
func startHTTPServer(
	logger *slog.Logger,
	opts startOpts,
	addr string,
	loadedCount, total int,
) *http.Server {
	if !opts.prometheus {
		return nil
	}

	srv := buildHTTPServer(addr, loadedCount, total)

	go func() {
		logger.Info("starting HTTP server", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	return srv
}

// rebindPrometheus gracefully shuts down the current HTTP server and starts a
// new one on newAddr. Called when prometheus.addr or prometheus.enabled changes
// on SIGHUP.
//
// Fix: removed the unused opts startOpts parameter (unparam lint failure).
// The enabled bool is passed explicitly; all other needed state is in srvPtr.
func rebindPrometheus(
	logger *slog.Logger,
	srvPtr **http.Server,
	newAddr string,
	loadedCount, total int,
	enabled bool,
) {
	old := *srvPtr

	// Shut down the old server (best-effort, 3 s deadline).
	if old != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := old.Shutdown(ctx); err != nil {
			logger.Warn("old HTTP server shutdown during rebind", "error", err)
		}
	}

	if !enabled {
		*srvPtr = nil
		logger.Info("prometheus disabled — HTTP server stopped")
		return
	}

	srv := buildHTTPServer(newAddr, loadedCount, total)
	go func() {
		logger.Info("HTTP server restarted", "addr", newAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error after rebind", "error", err)
		}
	}()

	*srvPtr = srv
}

// buildHTTPServer assembles the mux and http.Server without starting it.
// Separating construction from start makes rebindPrometheus clean and testable.
func buildHTTPServer(addr string, loadedCount, total int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler(loadedCount, total))
	mux.HandleFunc("/readyz", healthzHandler(loadedCount, total))
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// buildLoaders creates the set of BPF loaders based on the current live config.
// Falls back to the root.go package-level cfg if the atomic pointer has not
// yet been initialised (early startup path, before setCfg is called).
func buildLoaders(logger *slog.Logger) ([]bpf.Loader, *bpf.LoaderSet) {
	currentCfg := getCfg()
	if currentCfg == nil {
		currentCfg = cfg // fallback: root.go package-level pointer
	}

	var loaders []bpf.Loader

	if currentCfg.Collectors.SyscallLatency {
		loaders = append(loaders, bpf.NewSyscallLatencyLoader(logger))
	}
	if currentCfg.Collectors.TCPMonitor {
		loaders = append(loaders, bpf.NewTCPMonitorLoader(logger))
	}
	if currentCfg.Collectors.OOMTrack {
		loaders = append(loaders, bpf.NewOOMTrackLoader(logger))
	}
	if currentCfg.Collectors.DiskIO {
		loaders = append(loaders, bpf.NewDiskIOLoader(logger))
	}
	if currentCfg.Collectors.SchedDelay {
		loaders = append(loaders, bpf.NewSchedDelayLoader(logger))
	}
	if currentCfg.Collectors.FDTrack {
		loaders = append(loaders, bpf.NewFDTrackLoader(logger))
	}

	set := bpf.NewLoaderSet(logger, loaders...)
	return loaders, set
}

// healthzHandler returns an HTTP handler that reports BPF program load status.
//
// Fix: map[string]any (not map[string]interface{}) — consistent with the
// Go 1.18+ idiom adopted in PR #54. golangci-lint's predeclared and gocritic
// checks both enforce this; interface{} in new code is a lint failure.
func healthzHandler(loaded, total int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "ok",
			"programsLoaded": loaded,
			"programsTotal":  total,
		})
	}
}
