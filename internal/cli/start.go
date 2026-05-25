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
	"os/user"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/adapter"
	"github.com/optiqor/kerno/internal/audit"
	"github.com/optiqor/kerno/internal/bpf"
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
and exposes Prometheus metrics and an optional web dashboard.`,
		Example: `  sudo kerno start
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

func runStart(ctx context.Context, opts startOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()

	// Phase 0: Audit logger
	auditLog, err := audit.New(audit.Config{
		FilePath:   cfg.Audit.FilePath,
		MaxSizeMB:  cfg.Audit.MaxSizeMB,
		MaxBackups: cfg.Audit.MaxBackups,
		Stderr:     cfg.Audit.Stderr,
	})
	if err != nil {
		logger.Error("failed to initialise audit logger; audit events will be lost", "error", err)
		auditLog = audit.Noop()
	}

	// daemon.panic recovery — stack digest audit log mein, full trace stderr mein.
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			logger.Error("daemon panic recovered", "panic", r, "stack", string(stack))
			auditLog.RecordPanic(version.Version, stack)
			panic(r) // re-panic — process must exit non-zero
		}
	}()

	// daemon.start — pehli auditable event.
	auditLog.Record("kerno/start", audit.EventDaemonStart, audit.DaemonDetails{
		Version: version.Version,
	})

	// daemon.stop — hamesha last auditable event hogi.
	defer auditLog.Record("kerno/start", audit.EventDaemonStop, audit.DaemonDetails{
		Version: version.Version,
	})

	logger.Info("starting kerno daemon",
		"prometheus", opts.prometheus,
		"dashboard", opts.dashboard,
		"version", version.Version,
	)

	// Set up OS signal handling for graceful shutdown.
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// SIGHUP → config.reload audit event.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			uid := currentUID()
			auditLog.RecordConfigReload(
				cfgFile,
				"SIGHUP",
				[]string{},
				0,
				uid,
			)
			logger.Info("SIGHUP received; config reload not yet implemented — audited only")
		}
	}()

	promAddr := cfg.Prometheus.Addr
	if opts.prometheusAddr != "" {
		promAddr = opts.prometheusAddr
	}

	// Phase 1: Load eBPF programs with graceful degradation.
	loaders := buildLoaders(logger)
	loadedCount := 0
	closers := make([]func(), 0, len(loaders))

	for _, l := range loaders {
		closer, err := l.Load()
		if err != nil {
			auditLog.RecordBPFLoad(l.Name(), false, err)
			logger.Warn("failed to load eBPF program, skipping", "program", l.Name(), "error", err)
			continue
		}
		auditLog.RecordBPFLoad(l.Name(), true, nil)
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
	// lines immediately, before any event flows. Without this,
	// CounterVec metrics with no observations don't show up — making
	// /metrics look empty for the first few seconds and breaking
	// scrapers that auto-discover metric names from a single fetch.
	for _, l := range loaders {
		metrics.CollectorEventsTotal.WithLabelValues(l.Name()).Add(0)
		metrics.CollectorErrorsTotal.WithLabelValues(l.Name()).Add(0)
	}

	//  Phase 2: Metrics bridge
	bridge := metrics.NewBridge(logger)
	bridge.Start(ctx, loaders)
	defer bridge.Stop()

	//  Phase 2b: Environment adapter
	env := adapter.DetectEnvironment()
	adpt := adapter.NewAdapter(logger, env)
	if err := adpt.Start(ctx); err != nil {
		logger.Warn("failed to start environment adapter", "error", err)
	}
	defer adpt.Stop()
	logger.Info("environment adapter started", "adapter", adpt.Name(), "env", env)

	//  Phase 3: HTTP server
	var httpServer *http.Server
	if opts.prometheus {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", healthzHandler(loadedCount, len(loaders)))
		mux.HandleFunc("/readyz", readyzHandler(loadedCount, len(loaders)))
		mux.Handle("/metrics", auditedMetricsHandler(
			promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}),
			cfg.Prometheus.BearerToken,
			auditLog,
		))

		httpServer = &http.Server{
			Addr:              promAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			logger.Info("starting HTTP server", "addr", promAddr)
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("HTTP server error", "error", err)
			}
		}()
	}

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
	<-ctx.Done()

	logger.Info("shutting down kerno daemon")

	//  Phase 4: Graceful HTTP shutdown
	if httpServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("HTTP server shutdown error", "error", err)
		}
	}

	logger.Info("kerno daemon stopped")
	return nil
}

// auditedMetricsHandler wraps the Prometheus handler with optional
// bearer-token authentication. Token mismatches are recorded as
// auth.failure audit events.
func auditedMetricsHandler(next http.Handler, bearerToken string, auditLog *audit.Logger) http.Handler {
	if bearerToken == "" {
		return next
	}
	expected := "Bearer " + bearerToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != expected {
			remoteIP := audit.RedactRemoteAddr(r.RemoteAddr)
			auditLog.RecordAuthFailure("/metrics", "token_mismatch", remoteIP)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// buildLoaders creates the set of BPF loaders based on config.
func buildLoaders(logger *slog.Logger) []bpf.Loader {
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

	return loaders
}

// healthzHandler returns the liveness probe handler.
func healthzHandler(loaded, total int) http.HandlerFunc {
	startTime := time.Now()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "ok",
			"version":         version.Version,
			"uptime":          time.Since(startTime).Seconds(),
			"programs_loaded": loaded,
			"programs_total":  total,
		})
	}
}

// readyzHandler returns the readiness probe handler.
func readyzHandler(loaded, total int) http.HandlerFunc {
	startTime := time.Now()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Ready with atleast one BPF program is loaded
		// Partial loads are acceptable due to graceful degradation
		if loaded == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"status":          "not_ready",
				"programs_loaded": loaded,
				"programs_total":  total,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "ready",
			"programs_loaded": loaded,
			"programs_total":  total,
			"uptime":          time.Since(startTime).Seconds(),
		})
	}
}

func currentUID() int {
	u, err := user.Current()
	if err != nil {
		return 0
	}
	uid, _ := strconv.Atoi(u.Uid)
	return uid
}
