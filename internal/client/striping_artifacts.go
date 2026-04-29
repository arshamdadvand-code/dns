package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PersistStripingArtifacts writes the required evidence artifacts for the current iteration.
// This is intentionally minimal and evidence-backed by live counters (not inferred theory).
func (c *Client) PersistStripingArtifacts(outDir string) (stripingPath string, laneHealthPath string, reassemblyPath string, _ error) {
	if c == nil {
		return "", "", "", nil
	}
	if outDir == "" {
		outDir = c.cfg.ConfigDir
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", "", err
	}

	domain := ""
	if len(c.cfg.Domains) > 0 {
		domain = c.cfg.Domains[0]
	}
	safeDomain := strings.NewReplacer(".", "_", ":", "_", "/", "_", "\\", "_").Replace(domain)
	if safeDomain != "" {
		safeDomain = "_" + safeDomain
	}
	ts := time.Now().Format("20060102_150405")

	// 1) striping_metrics_*.json
	stripingPath = filepath.Join(outDir, "striping_metrics"+safeDomain+"_"+ts+".json")
	if c.balancer != nil {
		b, _ := json.MarshalIndent(c.balancer.StripingSnapshot(), "", "  ")
		_ = os.WriteFile(stripingPath, b, 0o644)
	}

	// 2) lane_health_summary_*.json (telemetry + controller snapshot)
	laneHealthPath = filepath.Join(outDir, "lane_health_summary"+safeDomain+"_"+ts+".json")
	laneHealth := map[string]any{
		"generated_at": time.Now().Format(time.RFC3339Nano),
		"domain":       domain,
		"telemetry":    func() any { if c.telemetry != nil { return c.telemetry.Snapshot() }; return nil }(),
		"adaptation":   c.runtimeControllerSnapshot(),
	}
	if b, _ := json.MarshalIndent(laneHealth, "", "  "); len(b) > 0 {
		_ = os.WriteFile(laneHealthPath, b, 0o644)
	}

	// 3) reassembly_integrity_*.json
	// Note: true reassembly integrity (out-of-order/gap counters) should be sourced
	// from ARQ-level instrumentation. For now we persist a minimal placeholder tied
	// to delivered bytes counters so runs still produce a stable artifact.
	reassemblyPath = filepath.Join(outDir, "reassembly_integrity"+safeDomain+"_"+ts+".json")
	reassembly := map[string]any{
		"generated_at": time.Now().Format(time.RFC3339Nano),
		"domain":       domain,
		"useful_delivered_rx": func() uint64 {
			if c.telemetry == nil {
				return 0
			}
			return c.telemetry.Snapshot().UsefulDeliveredRX
		}(),
		"note": "placeholder until ARQ reorder/gap counters are instrumented",
	}
	if b, _ := json.MarshalIndent(reassembly, "", "  "); len(b) > 0 {
		_ = os.WriteFile(reassemblyPath, b, 0o644)
	}

	return stripingPath, laneHealthPath, reassemblyPath, nil
}

