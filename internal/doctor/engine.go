// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
)

// Analyzer is the optional AI analysis interface. When non-nil, the engine
// calls it after rule evaluation to enrich findings with natural language
// diagnosis, cross-signal correlation, and root cause analysis.
//
// This interface lives here (not in the ai package) to avoid import cycles.
// The ai package implements it.
type Analyzer interface {
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error)
}

// AnalysisRequest contains the data sent to the AI analyzer.
type AnalysisRequest struct {
	Signals  *collector.Signals
	Findings []Finding
	History  []*collector.Signals
}

// AnalysisResponse contains AI-generated insights.
type AnalysisResponse struct {
	// Summary is a plain-English diagnosis paragraph.
	Summary string `json:"summary"`

	// Correlations are cross-signal patterns detected by AI.
	Correlations []Correlation `json:"correlations,omitempty"`

	// RootCauses are prioritized explanations with fix suggestions.
	RootCauses []RootCause `json:"rootCauses,omitempty"`

	// Anomalies are deviations from baseline behavior.
	Anomalies []Anomaly `json:"anomalies,omitempty"`

	// TrendSummary describes what's changing over time (continuous mode).
	TrendSummary string `json:"trendSummary,omitempty"`

	// TokensUsed tracks LLM token consumption for cost monitoring.
	TokensUsed int `json:"tokensUsed"`
}

// Correlation describes a cross-signal pattern.
type Correlation struct {
	Signals     []string `json:"signals"`
	Description string   `json:"description"`
	Confidence  float64  `json:"confidence"`
}

// RootCause is a prioritized explanation with a fix suggestion.
type RootCause struct {
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Fix         string   `json:"fix"`
	Confidence  float64  `json:"confidence"`
}

// Anomaly describes a deviation from baseline behavior.
type Anomaly struct {
	Signal      string `json:"signal"`
	Metric      string `json:"metric"`
	CurrentVal  string `json:"currentVal"`
	BaselineVal string `json:"baselineVal"`
	Description string `json:"description"`
}

// Engine orchestrates the full doctor diagnostic pipeline:
//
//	collect signals → evaluate rules → (optional AI enrichment) → render report
type Engine struct {
	// mu protects thresholds so UpdateThresholds (called from the SIGHUP
	// goroutine) and Diagnose (called from the doctor command goroutine) never
	// race. RWMutex is used because reads vastly outnumber writes.
	mu         sync.RWMutex
	thresholds config.DoctorThresholds

	analyzer   Analyzer
	logger     *slog.Logger
	history    []*collector.Signals
	maxHistory int
}

// NewEngine creates a new diagnostic engine.
// Pass nil for analyzer to run without AI enrichment.
func NewEngine(thresholds config.DoctorThresholds, analyzer Analyzer, logger *slog.Logger) *Engine {
	return &Engine{
		thresholds: thresholds,
		analyzer:   analyzer,
		logger:     logger,
		maxHistory: 10,
	}
}

// UpdateThresholds hot-swaps the diagnostic thresholds without restarting the
// engine. Safe to call from any goroutine (e.g. a SIGHUP handler). The next
// call to Diagnose picks up the new values automatically.
func (e *Engine) UpdateThresholds(t config.DoctorThresholds) {
	e.mu.Lock()
	e.thresholds = t
	e.mu.Unlock()
	e.logger.Info("doctor thresholds updated via hot-reload")
}

// Diagnose runs the full diagnostic pipeline against the supplied signals.
func (e *Engine) Diagnose(ctx context.Context, signals *collector.Signals) (*Report, error) {
	start := time.Now()

	// Take a consistent snapshot of thresholds for this diagnostic run.
	// Using RLock means concurrent Diagnose calls never block each other;
	// only a concurrent UpdateThresholds call causes a brief wait.
	e.mu.RLock()
	thresholds := e.thresholds
	e.mu.RUnlock()

	// Phase 1: Evaluate deterministic rules.
	findings := Evaluate(signals, thresholds)
	e.logger.Debug("rules evaluated",
		"findings", len(findings),
		"duration_ms", time.Since(start).Milliseconds(),
	)

	// Phase 2: Optional AI enrichment (non-fatal on failure).
	var analysis *AnalysisResponse
	if e.analyzer != nil && hasActionableFindings(findings) {
		e.logger.Info("running AI analysis")
		var err error
		analysis, err = e.analyzer.Analyze(ctx, AnalysisRequest{
			Signals:  signals,
			Findings: findings,
			History:  e.history,
		})
		if err != nil {
			e.logger.Warn("AI analysis failed, continuing with rule-based results", "error", err)
		}
	}

	// Phase 3: Build the report.
	hostname, _ := os.Hostname()
	report := &Report{
		Hostname:  hostname,
		KernelVer: signals.Host.KernelVer,
		Arch:      runtime.GOARCH,
		StartTime: signals.Timestamp.Add(-signals.Duration),
		EndTime:   signals.Timestamp,
		Duration:  signals.Duration,
		Findings:  findings,
		Analysis:  analysis,
		// Raw signals are carried through for the JSON renderer; the
		// pretty renderer ignores this field.
		Signals: signals,
	}

	// Track event counts for the report summary.
	if signals.Syscall != nil {
		report.EventsCollected += signals.Syscall.TotalCount
	}
	if signals.Sched != nil {
		report.EventsCollected += signals.Sched.TotalCount
	}

	// Phase 4: Append to the history ring buffer.
	e.appendHistory(signals)

	return report, nil
}

func (e *Engine) appendHistory(signals *collector.Signals) {
	e.history = append(e.history, signals)
	if len(e.history) > e.maxHistory {
		e.history = e.history[1:]
	}
}

// hasActionableFindings returns true if there is at least one WARNING or
// CRITICAL finding — the threshold below which AI enrichment is not worthwhile.
func hasActionableFindings(findings []Finding) bool {
	for i := range findings {
		if findings[i].Severity >= SeverityWarning {
			return true
		}
	}
	return false
}

// FilterCriticalFindings returns only critical severity findings from the list
func FilterCriticalFindings(findings []Finding) []Finding {
	filtered := make([]Finding, 0, len(findings))
	for i := range findings {
		if findings[i].Severity == SeverityCritical {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}
