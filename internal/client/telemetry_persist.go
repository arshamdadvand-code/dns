package client

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
}

func (c *Client) PersistTelemetrySummary(outPath string) (string, error) {
	if c == nil || c.telemetry == nil {
		return "", nil
	}
	if outPath == "" {
		outPath = filepath.Join(c.cfg.ConfigDir, "telemetry_summary_"+time.Now().Format("20060102_150405")+".json")
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
		Domain: func() string {
			if len(c.cfg.Domains) > 0 {
				return c.cfg.Domains[0]
			}
			return ""
		}(),
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

	livePath := filepath.Join(c.cfg.ConfigDir, "telemetry_live.json")

	for {
		select {
		case <-ctx.Done():
			_, _ = c.PersistTelemetrySummary(livePath)
			return
		case <-t.C:
			_, _ = c.PersistTelemetrySummary(livePath)
		}
	}
}
