// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

// ReloadResult holds the outcome of a config reload attempt.
type ReloadResult struct {
	// Applied is the list of fields that were updated live.
	Applied []string

	// RestartRequired is the list of fields that changed but need a
	// daemon restart to take effect (e.g. collector toggles tied to
	// already-loaded BPF programs).
	RestartRequired []string
}

// String returns a human-readable summary of the reload result.
func (r ReloadResult) String() string {
	return fmt.Sprintf(
		"config reloaded; %d changes applied; %d changes require restart",
		len(r.Applied), len(r.RestartRequired),
	)
}

// ReloadFrom reads a new config from path (using the same Viper
// pipeline as root.go's initConfig), diffs it against the receiver,
// and returns which fields changed.
//
// The caller (start.go's SIGHUP handler) is responsible for actually
// applying the changes to live subsystems.  This function only does
// the parse + diff and returns two lists:
//
//   - result.Applied         — safe to hot-apply right now
//   - result.RestartRequired — changed but needs a full daemon restart
//
// The receiver *c is NOT mutated.
func (c *Config) ReloadFrom(path string) (*Config, ReloadResult, error) {
	next, err := parseConfig(path)
	if err != nil {
		return nil, ReloadResult{}, fmt.Errorf("reload: %w", err)
	}
	if err := next.Validate(); err != nil {
		return nil, ReloadResult{}, fmt.Errorf("reload: invalid config: %w", err)
	}
	result := diff(c, next)
	return next, result, nil
}

// parseConfig mirrors the Viper pipeline in root.go's initConfig so
// that hot-reload honours the same precedence rules:
// env vars > config file > defaults.
//
// It intentionally does NOT bind CLI flags (they are one-shot at
// startup) and does NOT call initLogger (the caller does that).
func parseConfig(path string) (*Config, error) {
	v := viper.New()

	// Config file discovery — same logic as initConfig in root.go.
	resolved := path
	if resolved == "" {
		resolved = os.Getenv("KERNO_CONFIG")
	}
	if resolved != "" {
		v.SetConfigFile(resolved)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/kerno")
		v.AddConfigPath("$HOME/.kerno")
		v.AddConfigPath(".")
	}

	// Environment variable support — same prefix/replacer as root.go.
	v.SetEnvPrefix("KERNO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			if resolved != "" {
				return nil, fmt.Errorf("reading config %q: %w", resolved, err)
			}
		}
	}

	next := Default()
	if err := v.Unmarshal(next); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return next, nil
}

// diff compares two configs and classifies every changed field into
// "can hot-apply" vs "needs restart".
func diff(old, new *Config) ReloadResult {
	var r ReloadResult

	// ── Always reloadable ──────────────────────────────────────────────

	if old.LogLevel != new.LogLevel {
		r.Applied = append(r.Applied, fmt.Sprintf("log_level: %q → %q", old.LogLevel, new.LogLevel))
	}
	if old.LogFormat != new.LogFormat {
		r.Applied = append(r.Applied, fmt.Sprintf("log_format: %q → %q", old.LogFormat, new.LogFormat))
	}
	if old.Prometheus.Addr != new.Prometheus.Addr {
		r.Applied = append(r.Applied, fmt.Sprintf("prometheus.addr: %q → %q", old.Prometheus.Addr, new.Prometheus.Addr))
	}
	if old.Prometheus.Enabled != new.Prometheus.Enabled {
		r.Applied = append(r.Applied, fmt.Sprintf("prometheus.enabled: %v → %v", old.Prometheus.Enabled, new.Prometheus.Enabled))
	}
	if !reflect.DeepEqual(old.Doctor.Thresholds, new.Doctor.Thresholds) {
		r.Applied = append(r.Applied, "doctor.thresholds updated")
	}
	if old.Doctor.Duration != new.Doctor.Duration {
		r.Applied = append(r.Applied, fmt.Sprintf("doctor.duration: %s → %s", old.Doctor.Duration, new.Doctor.Duration))
	}
	if !reflect.DeepEqual(old.AI, new.AI) {
		r.Applied = append(r.Applied, "ai config updated")
	}
	if !reflect.DeepEqual(old.Dashboard, new.Dashboard) {
		r.Applied = append(r.Applied, "dashboard config updated")
	}
	if !reflect.DeepEqual(old.Kubernetes, new.Kubernetes) {
		r.Applied = append(r.Applied, "kubernetes config updated")
	}

	// ── Requires restart (BPF programs already loaded) ─────────────────

	if old.Collectors.SyscallLatency != new.Collectors.SyscallLatency {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.syscall_latency: %v → %v", old.Collectors.SyscallLatency, new.Collectors.SyscallLatency))
	}
	if old.Collectors.TCPMonitor != new.Collectors.TCPMonitor {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.tcp_monitor: %v → %v", old.Collectors.TCPMonitor, new.Collectors.TCPMonitor))
	}
	if old.Collectors.OOMTrack != new.Collectors.OOMTrack {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.oom_track: %v → %v", old.Collectors.OOMTrack, new.Collectors.OOMTrack))
	}
	if old.Collectors.DiskIO != new.Collectors.DiskIO {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.disk_io: %v → %v", old.Collectors.DiskIO, new.Collectors.DiskIO))
	}
	if old.Collectors.SchedDelay != new.Collectors.SchedDelay {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.sched_delay: %v → %v", old.Collectors.SchedDelay, new.Collectors.SchedDelay))
	}
	if old.Collectors.FDTrack != new.Collectors.FDTrack {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.fd_track: %v → %v", old.Collectors.FDTrack, new.Collectors.FDTrack))
	}
	if old.Collectors.FileAudit != new.Collectors.FileAudit {
		r.RestartRequired = append(r.RestartRequired,
			fmt.Sprintf("collectors.file_audit: %v → %v", old.Collectors.FileAudit, new.Collectors.FileAudit))
	}

	return r
}