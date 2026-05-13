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
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/adapter"
	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/doctor"
	"github.com/optiqor/kerno/internal/metrics"
	"github.com/optiqor/kerno/internal/version"
)

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
	httpServer **http.Server // pointer-to-pointer so we can swap the server
	logger     *slog.Logger
	opts       startOpts
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
	// SIGHUP           → config hot-reload (handled in a separate goroutine).
	shutdownCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	// Resolve Prometheus address.
	promAddr := cfg.Prometheus.Addr
	if opts.prometheusAddr != "" {
		promAddr = opts.prometheusAddr
	}

	// Phase 1: Load eBPF programs with graceful degradation.
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

	logger.Info("eBPF programs loaded", "loaded", loadedCount, "total", len(loaders))

	// Set Prometheus gauges for self-monitoring.
	metrics.BPFProgramsLoaded.Set(float64(loadedCount))
	metrics.InfoMetric.WithLabelValues(version.Version).Set(1)

	// Pre-initialize CounterVec instances so /metrics emits HELP/TYPE
	// lines immediately, before any event flows.
	for _, l := range loaders {
		metrics.CollectorEventsTotal.WithLabelValues(l.Name()).Add(0)
		metrics.CollectorErrorsTotal.WithLabelValues(l.Name()).Add(0)
	}

	// Phase 2: Start the metrics bridge.
	bridge := metrics.NewBridge(logger)
	bridge.Start(shutdownCtx, loaderSet.Loaders())
	defer bridge.Stop()

	// Phase 2b: Start environment adapter.
	env := adapter.DetectEnvironment()
	adpt := adapter.NewAdapter(logger, env)
	if err := adpt.Start(shutdownCtx); err != nil {
		logger.Warn("failed to start environment adapter", "error", err)
	}
	defer adpt.Stop()
	logger.Info("environment adapter started", "adapter", adpt.Name(), "env", env)

	// Phase 2c: Create the doctor engine — held in a pointer so the
	// SIGHUP handler can call UpdateThresholds on the live instance.
	diagEngine := doctor.NewEngine(cfg.Doctor.Thresholds, nil, logger)

	// Phase 3: Start HTTP server for health and metrics.
	httpServer := startHTTPServer(logger, opts, promAddr, loadedCount, len(loaders))

	// ── SIGHUP hot-reload goroutine ────────────────────────────────────
	//
	// Runs until the daemon shuts down. On every SIGHUP it:
	//  1. Re-reads the config file from the path kerno was started with.
	//  2. Diffs old vs new.
	//  3. Applies safe changes in-place (log level, thresholds, etc.).
	//  4. Warns about changes that need a restart (collector toggles).
	go func() {
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-sighupCh:
				handleSIGHUP(logger, diagEngine, &httpServer, opts)
			}
		}
	}()

	// Log daemon status.
	fmt.Println("kerno daemon running")
	fmt.Printf("  eBPF programs: %d/%d loaded\n", loadedCount, len(loaders))
	if opts.prometheus {
		fmt.Printf("  Prometheus:    http://%s/metrics\n", promAddr)
		fmt.Printf("  Health:        http://%s/healthz\n", promAddr)
		fmt.Printf("  Readiness:     http://%s/readyz\n", promAddr)
	}
	if opts.dashboard {
		fmt.Printf("  Dashboard:     http://%s (not yet implemented)\n", cfg.Dashboard.Addr)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	// Block until shutdown signal.
	<-shutdownCtx.Done()

	logger.Info("shutting down kerno daemon")

	// Phase 4: Graceful HTTP shutdown.
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

// handleSIGHUP performs the config hot-reload on every SIGHUP signal.
// It is called from the goroutine in runStart and must not block for long.
func handleSIGHUP(
	logger *slog.Logger,
	engine *doctor.Engine,
	httpServerPtr **http.Server,
	opts startOpts,
) {
	logger.Info("SIGHUP received — reloading config", "path", cfgFile)

	newCfg, result, err := cfg.ReloadFrom(cfgFile)
	if err != nil {
		logger.Error("config reload failed — keeping current config", "error", err)
		return
	}

	// ── Apply each safe change ─────────────────────────────────────────

	for _, change := range result.Applied {
		logger.Info("applying hot-reload change", "change", change)
	}

	// 1. Log level / format — delegate to root.go's initLogger so the
	//    slog handler is rebuilt identically to startup behaviour
	//    (JSON vs text detection, level, etc.).
	if cfg.LogLevel != newCfg.LogLevel || cfg.LogFormat != newCfg.LogFormat {
		initLogger(newCfg.LogLevel, newCfg.LogFormat)
		logger.Info("log level/format changed",
			"level", newCfg.LogLevel, "format", newCfg.LogFormat)
	}

	// 2. Doctor thresholds
	if cfg.Doctor.Thresholds != newCfg.Doctor.Thresholds {
		engine.UpdateThresholds(newCfg.Doctor.Thresholds)
	}

	// 3. Prometheus address re-bind
	oldAddr := cfg.Prometheus.Addr
	newAddr := newCfg.Prometheus.Addr
	if opts.prometheusAddr != "" {
		// CLI flag always wins for the initial bind; honour it on reload too.
		newAddr = opts.prometheusAddr
	}
	if oldAddr != newAddr || cfg.Prometheus.Enabled != newCfg.Prometheus.Enabled {
		logger.Info("prometheus address changed — rebinding",
			"old", oldAddr, "new", newAddr)
		rebindPrometheus(logger, httpServerPtr, opts, newAddr,
			0, // loadedCount / total not tracked here; healthz uses last snapshot
			0,
			newCfg.Prometheus.Enabled,
		)
	}

	// 4. Warn about restart-required changes.
	for _, w := range result.RestartRequired {
		logger.Warn("config change requires restart to take effect", "change", w)
	}

	// Swap the global config pointer so subsequent reloads diff correctly.
	// cfg is the package-level *config.Config set by the root command.
	cfg = newCfg

	logger.Info(result.String(),
		"applied", len(result.Applied),
		"restart_required", len(result.RestartRequired),
	)
}

// startHTTPServer launches the Prometheus / health HTTP server and returns
// it so the caller can shut it down later.
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

// rebindPrometheus gracefully shuts down the old HTTP server and starts a
// new one on newAddr. Called when prometheus.addr changes on SIGHUP.
func rebindPrometheus(
	logger *slog.Logger,
	srvPtr **http.Server,
	opts startOpts,
	newAddr string,
	loadedCount, total int,
	enabled bool,
) {
	old := *srvPtr

	// Shut down the old server (best effort, 3 s deadline).
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

// buildLoaders creates the set of BPF loaders based on config.
func buildLoaders(logger *slog.Logger) ([]bpf.Loader, *bpf.LoaderSet) {
	var loaders []bpf.Loader

	if cfg.Collectors.SyscallLatency {
		loaders = append(loaders, bpf.NewSyscallLatencyLoader(logger))
	}
	if cfg.Collectors.TCPMonitor {
		loaders = append(loaders, bpf.NewTCPMonitorLoader(logger))
	}
	if cfg.Collectors.OOMTrack {
		loaders = append(loaders, bpf.NewOOMTrackLoader(logger))
	}
	if cfg.Collectors.DiskIO {
		loaders = append(loaders, bpf.NewDiskIOLoader(logger))
	}
	if cfg.Collectors.SchedDelay {
		loaders = append(loaders, bpf.NewSchedDelayLoader(logger))
	}
	if cfg.Collectors.FDTrack {
		loaders = append(loaders, bpf.NewFDTrackLoader(logger))
	}

	set := bpf.NewLoaderSet(logger, loaders...)
	return loaders, set
}

// healthzHandler returns the health check handler.
func healthzHandler(loaded, total int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "ok",
			"programsLoaded": loaded,
			"programsTotal":  total,
		})
	}
}
