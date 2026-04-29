package client

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type persistedTelemetrySummary struct {
	GeneratedAt string `json:"generated_at"`
	Domain      string `json:"domain"`

	// Runtime knobs at the time of persistence.
	UploadMTU      int     `json:"synced_upload_mtu"`
	DownloadMTU    int     `json:"synced_download_mtu"`
	PacketDup      int     `json:"packet_duplication_count"`
	SetupPacketDup int     `json:"setup_packet_duplication_count"`
	FailoverThr    int     `json:"failover_resend_threshold"`
	FailoverCoolS  float64 `json:"failover_cooldown_seconds"`

	Active  []string `json:"active_resolvers"`
	Reserve []string `json:"reserve_resolvers"`

	Telemetry  any                       `json:"telemetry"`
	Adaptation runtimeControllerSnapshot `json:"runtime_adaptation"`
	Striping   any                      `json:"striping_metrics,omitempty"`
}

func (c *Client) PersistTelemetrySummary(outPath string) (string, error) {
	if c == nil || c.telemetry == nil {
		return "", nil
	}
	domain := ""
	if len(c.cfg.Domains) > 0 {
		domain = c.cfg.Domains[0]
	}
	safeDomain := strings.NewReplacer(".", "_", ":", "_", "/", "_", "\\", "_").Replace(domain)
	if outPath == "" {
		suffix := ""
		if safeDomain != "" {
			suffix = "_" + safeDomain
		}
		outPath = filepath.Join(c.cfg.ConfigDir, "telemetry_summary"+suffix+"_"+time.Now().Format("20060102_150405")+".json")
	}

	active := c.balancer.ActiveConnections()
	inactive := c.balancer.InactiveConnections()
	activeKeys := make([]string, 0, len(active))
	reserveKeys := make([]string, 0, len(inactive))
	for _, a := range active {
		if a.Key != "" {
			activeKeys = append(activeKeys, a.Key)
		}
	}
	for _, r := range inactive {
		if r.Key != "" {
			reserveKeys = append(reserveKeys, r.Key)
		}
	}

	sum := persistedTelemetrySummary{
		GeneratedAt: time.Now().Format(time.RFC3339Nano),
		Domain:      domain,
		UploadMTU:      c.syncedUploadMTU,
		DownloadMTU:    c.syncedDownloadMTU,
		PacketDup:      c.cfg.PacketDuplicationCount,
		SetupPacketDup: c.cfg.SetupPacketDuplicationCount,
		FailoverThr:    c.streamResolverFailoverResendThreshold,
		FailoverCoolS:  c.streamResolverFailoverCooldown.Seconds(),
		Active:         activeKeys,
		Reserve:        reserveKeys,
		Telemetry:      c.telemetry.Snapshot(),
		Adaptation:     c.runtimeControllerSnapshot(),
		Striping:       func() any {
			if c.balancer == nil {
				return nil
			}
			return c.balancer.StripingSnapshot()
		}(),
	}

	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		return "", err
	}
	return outPath, nil
}

func (c *Client) runTelemetryPersistLoop(ctx context.Context) {
	if c == nil {
		return
	}
	// Keep this low-frequency and bounded. It's a safety net so we always have an
	// evidence artifact even if the process is terminated ungracefully.
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	domain := ""
	if len(c.cfg.Domains) > 0 {
		domain = c.cfg.Domains[0]
	}
	safeDomain := strings.NewReplacer(".", "_", ":", "_", "/", "_", "\\", "_").Replace(domain)
	liveName := "telemetry_live.json"
	if safeDomain != "" {
		liveName = "telemetry_live_" + safeDomain + ".json"
	}
	livePath := filepath.Join(c.cfg.ConfigDir, liveName)

	stripingLive := "striping_metrics_live.json"
	laneHealthLive := "lane_health_live.json"
	reassemblyLive := "reassembly_integrity_live.json"
	if safeDomain != "" {
		stripingLive = "striping_metrics_live_" + safeDomain + ".json"
		laneHealthLive = "lane_health_live_" + safeDomain + ".json"
		reassemblyLive = "reassembly_integrity_live_" + safeDomain + ".json"
	}
	stripingPath := filepath.Join(c.cfg.ConfigDir, stripingLive)
	laneHealthPath := filepath.Join(c.cfg.ConfigDir, laneHealthLive)
	reassemblyPath := filepath.Join(c.cfg.ConfigDir, reassemblyLive)

	for {
		select {
		case <-ctx.Done():
			_, _ = c.PersistTelemetrySummary(livePath)
			_ = c.persistEvidenceLive(stripingPath, laneHealthPath, reassemblyPath)
			return
		case <-t.C:
			_, _ = c.PersistTelemetrySummary(livePath)
			_ = c.persistEvidenceLive(stripingPath, laneHealthPath, reassemblyPath)
		}
	}
}

func (c *Client) persistEvidenceLive(stripingPath string, laneHealthPath string, reassemblyPath string) error {
	if c == nil {
		return nil
	}

	writeJSON := func(path string, v any) error {
		if path == "" || v == nil {
			return nil
		}
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}

	_ = writeJSON(stripingPath, func() any {
		if c.balancer == nil {
			return nil
		}
		return c.balancer.StripingSnapshot()
	}())

	_ = writeJSON(laneHealthPath, map[string]any{
		"generated_at": time.Now().Format(time.RFC3339Nano),
		"domain":       func() string { if len(c.cfg.Domains) > 0 { return c.cfg.Domains[0] }; return "" }(),
		"telemetry":    func() any { if c.telemetry != nil { return c.telemetry.Snapshot() }; return nil }(),
		"adaptation":   c.runtimeControllerSnapshot(),
	})

	_ = writeJSON(reassemblyPath, map[string]any{
		"generated_at": time.Now().Format(time.RFC3339Nano),
		"domain":       func() string { if len(c.cfg.Domains) > 0 { return c.cfg.Domains[0] }; return "" }(),
		"useful_delivered_rx": func() uint64 {
			if c.telemetry == nil {
				return 0
			}
			return c.telemetry.Snapshot().UsefulDeliveredRX
		}(),
		"note": "placeholder until ARQ reorder/gap counters are instrumented",
	})

	return nil
}
