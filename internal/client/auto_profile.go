// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/profiling"
)

var ErrAutoProfileNoViableResolvers = errors.New("auto-profile: no viable resolvers")

type probeOutcome uint8

const (
	probeSuccess probeOutcome = iota
	probeTimeout
	probeMalformed
)

type probeSample struct {
	outcome probeOutcome
	rtt     time.Duration
}

func (c *Client) autoProfileRegistryPath() string {
	if c == nil {
		return ""
	}
	if c.cfg.ResolverRegistryFile != "" {
		if filepath.IsAbs(c.cfg.ResolverRegistryFile) {
			return filepath.Clean(c.cfg.ResolverRegistryFile)
		}
		return filepath.Clean(filepath.Join(c.cfg.ConfigDir, c.cfg.ResolverRegistryFile))
	}
	if c.cfg.ConfigDir != "" {
		return filepath.Join(c.cfg.ConfigDir, "resolver_registry.json")
	}
	return "resolver_registry.json"
}

func (c *Client) autoProfileDerivedRuntimePath() string {
	if c == nil {
		return ""
	}
	if c.cfg.ConfigDir != "" {
		return filepath.Join(c.cfg.ConfigDir, "derived_runtime.json")
	}
	return "derived_runtime.json"
}

type autoProfileSource string

const (
	autoProfileWarm autoProfileSource = "warm"
	autoProfileCold autoProfileSource = "cold"
)

// AutoProfileBootstrapAndApply enforces the Phase-1 authority rule:
// - warm start from registry when fresh and sufficient
// - otherwise neutral profiling from resolver input file
// - derived runtime state is then applied and becomes authoritative
func (c *Client) AutoProfileBootstrapAndApply(ctx context.Context) error {
	if c == nil || c.balancer == nil {
		return ErrNoValidConnections
	}
	if len(c.cfg.Domains) == 0 {
		return fmt.Errorf("auto-profile: no domains configured")
	}

	regPath := c.autoProfileRegistryPath()
	reg, err := profiling.LoadRegistry(regPath)
	if err != nil {
		return err
	}

	if c.tryWarmStartApply(reg, regPath) == nil {
		return nil
	}

	// Cold path: neutral profiling of the given resolver input file.
	if err := c.profileAllResolversAndApply(ctx, reg, regPath); err != nil {
		return err
	}
	return nil
}

func (c *Client) tryWarmStartApply(reg *profiling.Registry, regPath string) error {
	if c == nil {
		return ErrNoValidConnections
	}
	if reg == nil || len(reg.Resolvers) == 0 {
		return ErrAutoProfileNoViableResolvers
	}

	now := c.now()
	maxAge := time.Duration(c.cfg.AutoProfileWarmMaxAgeSeconds * float64(time.Second))
	if maxAge <= 0 {
		maxAge = 15 * time.Minute
	}
	minViable := c.cfg.AutoProfileWarmMinViable
	if minViable < 1 {
		minViable = 3
	}

	// Keep only fresh viable resolvers from registry.
	fresh := &profiling.Registry{Resolvers: map[string]*profiling.ResolverProfile{}}
	for addr, p := range reg.Resolvers {
		if p == nil {
			continue
		}
		if p.Viability.Status != profiling.ViabilityViable {
			continue
		}
		if p.Identity.LastProfiledAt.IsZero() || now.Sub(p.Identity.LastProfiledAt) > maxAge {
			continue
		}
		if p.Upload.RecommendedBytes <= 0 || p.Download.RecommendedBytes <= 0 {
			continue
		}
		fresh.Resolvers[addr] = p
	}
	if len(fresh.Resolvers) < minViable {
		return ErrAutoProfileNoViableResolvers
	}

	derived, err := deriveRuntimeFromRegistry(fresh, now)
	if err != nil {
		return err
	}
	if err := c.applyDerivedRuntime(derived, regPath, autoProfileWarm); err != nil {
		return err
	}

	_ = c.saveDerivedRuntimeEvidence(derived, regPath, autoProfileWarm)
	if c.log != nil {
		c.log.Infof(
			"\U0001F525 <green>AutoProfile Warm Start Applied</green> <gray>|</gray> registry=<cyan>%s</cyan> viable=<cyan>%d</cyan> active=<cyan>%d</cyan> reserve=<cyan>%d</cyan> up=<cyan>%d</cyan> down=<cyan>%d</cyan>",
			regPath,
			len(fresh.Resolvers),
			len(derived.ActiveResolvers),
			len(derived.ReserveResolvers),
			derived.UploadTargetBytes,
			derived.DownloadTargetBytes,
		)
	}
	return nil
}

func (c *Client) profileAllResolversAndApply(ctx context.Context, reg *profiling.Registry, regPath string) error {
	if c == nil || c.balancer == nil {
		return ErrNoValidConnections
	}
	if len(c.cfg.Domains) == 0 {
		return fmt.Errorf("auto-profile: no domains configured")
	}

	domain := c.cfg.Domains[0]
	now := c.now()
	stats := newAutoProfileRunStats(domain, c.cfg.ResolverFileStats, len(c.cfg.Resolvers))

	// Full-screen TUI dashboard during profiling. Route logger console output into a
	// small event pane (no scrolling main view).
	// If full-lifecycle TUI is enabled, attach stats to it and avoid any ANSI pseudo-dashboard.
	if c.ui != nil {
		c.ui.AttachAutoProfileStats(stats)
	}

	// Build a unique resolver list from the loaded resolver file.
	type resolverAddr struct {
		ip   string
		port int
	}
	resolvers := make([]resolverAddr, 0, len(c.cfg.Resolvers))
	seen := make(map[string]struct{}, len(c.cfg.Resolvers))
	for _, r := range c.cfg.Resolvers {
		if r.IP == "" || r.Port < 1 {
			continue
		}
		addr := fmt.Sprintf("%s:%d", r.IP, r.Port)
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		resolvers = append(resolvers, resolverAddr{ip: r.IP, port: r.Port})
	}
	if len(resolvers) == 0 {
		return fmt.Errorf("auto-profile: resolver list is empty")
	}

	parallelism := c.cfg.EffectiveMTUTestParallelism()
	if parallelism < 1 {
		parallelism = 16
	}
	// AutoProfile does staged probing. Stage0/Stage1 are intentionally light, but
	// parallelism can still self-collapse the local host/stack in sparse-hit environments.
	// Cap parallelism to avoid "everything looks dead" due to local overload.
	if parallelism > 128 {
		parallelism = 128
	}
	if parallelism > len(resolvers) {
		parallelism = len(resolvers)
	}

	type result struct {
		key     string
		profile *profiling.ResolverProfile
	}
	jobs := make(chan resolverAddr, len(resolvers))
	results := make(chan result, len(resolvers))

	var wg sync.WaitGroup
	for range parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				if ctx.Err() != nil {
					return
				}
				key := fmt.Sprintf("%s:%d", r.ip, r.port)
				old := reg.Resolvers[key]
				profile := c.profileOneResolver(ctx, stats, domain, r.ip, r.port, old, now)
				results <- result{key: key, profile: profile}
			}
		}()
	}
	for _, r := range resolvers {
		jobs <- r
	}
	close(jobs)
	wg.Wait()
	close(results)

	for r := range results {
		reg.Resolvers[r.key] = r.profile
	}

	// Persist profiles even if derivation fails. This is the Phase-1 minimal registry.
	_ = profiling.SaveRegistryAtomic(regPath, reg)
	// Keep dashboard's stage summary in sync for the final screen.
	if stats != nil {
		// scan input already includes duplicates/invalid accounted in resolver file stats
		stats.mu.Lock()
		// stage0Attempted was incremented per resolver
		stats.mu.Unlock()
	}

	// Minimal progress snapshot for Phase-1 observability.
	// (We intentionally keep history/analytics for later phases.)
	if c.log != nil && c.log.Enabled(logger.LevelInfo) {
		total := len(reg.Resolvers)
		viable := 0
		for _, p := range reg.Resolvers {
			if p != nil && p.Viability.Status == profiling.ViabilityViable {
				viable++
			}
		}
		c.log.Infof("<cyan>AutoProfile scan finished</cyan> <gray>|</gray> total=<cyan>%d</cyan> viable=<cyan>%d</cyan>", total, viable)
	}

	derived, err := deriveRuntimeFromRegistry(reg, now)
	if err != nil {
		return err
	}

	// Record derived snapshot for the dashboard (first-class visibility).
	stats.setDerivedSnapshot(
		derived.UploadTargetBytes,
		derived.DownloadTargetBytes,
		derived.ActiveResolvers,
		derived.ReserveResolvers,
		derived.SetupDuplicationCount,
		derived.PacketDuplicationCount,
		derived.FailoverResendThreshold,
		derived.FailoverCooldownSeconds,
		derived.Confidence,
		derived.Fragile,
	)

	if err := c.applyDerivedRuntime(derived, regPath, autoProfileCold); err != nil {
		return err
	}

	// Freeze + persist a final summary for this run (Phase 1 closure).
	if stats != nil {
		snap := stats.snapshot()
		out := filepath.Join(c.cfg.ConfigDir, "autoprofile_summary_"+time.Now().Format("20060102_150405")+".json")
		path, perr := persistAutoProfileSummary(c.cfg, snap, derived, out)
		if perr == nil {
			stats.markCompleted(path)
		} else {
			stats.markCompleted("")
		}
	}
	_ = c.saveDerivedRuntimeEvidence(derived, regPath, autoProfileCold)
	if c.log != nil {
		c.log.Infof(
			"\U0001F9EA <green>AutoProfile Cold Start Applied</green> <gray>|</gray> registry=<cyan>%s</cyan> profiles=<cyan>%d</cyan> active=<cyan>%d</cyan> reserve=<cyan>%d</cyan> up=<cyan>%d</cyan> down=<cyan>%d</cyan>",
			regPath,
			len(reg.Resolvers),
			len(derived.ActiveResolvers),
			len(derived.ReserveResolvers),
			derived.UploadTargetBytes,
			derived.DownloadTargetBytes,
		)
	}
	return nil
}

func (c *Client) applyDerivedRuntime(derived derivedRuntimeConfig, regPath string, source autoProfileSource) error {
	if c == nil || c.balancer == nil {
		return ErrNoValidConnections
	}
	if len(c.cfg.Domains) == 0 {
		return fmt.Errorf("auto-profile: no domains configured")
	}
	domain := c.cfg.Domains[0]

	uploadTarget := derived.UploadTargetBytes
	downloadTarget := derived.DownloadTargetBytes
	if uploadTarget <= 0 || downloadTarget <= 0 {
		return ErrAutoProfileNoViableResolvers
	}

	// Apply derived runtime knobs (authoritative).
	c.cfg.PacketDuplicationCount = derived.PacketDuplicationCount
	c.cfg.SetupPacketDuplicationCount = derived.SetupDuplicationCount
	c.cfg.StreamResolverFailoverResendThreshold = derived.FailoverResendThreshold
	c.cfg.StreamResolverFailoverCooldownSec = derived.FailoverCooldownSeconds
	c.streamResolverFailoverResendThreshold = derived.FailoverResendThreshold
	c.streamResolverFailoverCooldown = time.Duration(derived.FailoverCooldownSeconds * float64(time.Second))
	c.balancer.SetStreamFailoverConfig(c.streamResolverFailoverResendThreshold, c.streamResolverFailoverCooldown)

	uploadChars := c.encodedCharsForPayload(uploadTarget)
	c.applySyncedMTUState(uploadTarget, downloadTarget, uploadChars)

	activeKeys := make(map[string]struct{}, len(derived.ActiveResolvers))
	for _, addr := range derived.ActiveResolvers {
		activeKeys[addr] = struct{}{}
	}

	for _, conn := range c.balancer.AllConnections() {
		if conn.Domain != domain {
			_ = c.balancer.SetConnectionValidityWithLog(conn.Key, false, false)
			continue
		}

		_, ok := activeKeys[conn.ResolverLabel]
		if !ok {
			// Reserve set stays inactive; it can be rechecked later by the existing health loop.
			_ = c.balancer.SetConnectionValidityWithLog(conn.Key, false, false)
			continue
		}

		_ = c.balancer.SetConnectionMTU(conn.Key, uploadTarget, uploadChars, downloadTarget)
		_ = c.balancer.SetConnectionValidityWithLog(conn.Key, true, false)
		c.balancer.SeedConservativeStats(conn.Key)
	}

	c.successMTUChecks = true
	if c.log != nil {
		c.log.Infof(
			"\U0001F9ED <green>Derived Runtime Applied</green> <gray>|</gray> source=<cyan>%s</cyan> up=<cyan>%d</cyan> down=<cyan>%d</cyan> active=<cyan>%d</cyan> reserve=<cyan>%d</cyan> dup=<cyan>%d</cyan> setupdup=<cyan>%d</cyan> failover(thr=<cyan>%d</cyan>,cool=<cyan>%.1fs</cyan>)",
			string(source),
			uploadTarget,
			downloadTarget,
			len(derived.ActiveResolvers),
			len(derived.ReserveResolvers),
			derived.PacketDuplicationCount,
			derived.SetupDuplicationCount,
			derived.FailoverResendThreshold,
			derived.FailoverCooldownSeconds,
		)
		c.log.Infof("\U0001F4C4 <green>Registry:</green> <cyan>%s</cyan>", regPath)
	}
	return nil
}

func (c *Client) saveDerivedRuntimeEvidence(derived derivedRuntimeConfig, regPath string, source autoProfileSource) error {
	if c == nil {
		return nil
	}
	type evidence struct {
		GeneratedAt time.Time            `json:"generated_at"`
		Source      string               `json:"source"`
		Registry    string               `json:"registry"`
		Derived     derivedRuntimeConfig `json:"derived"`
		Applied     struct {
			SyncedUploadMTU   int     `json:"synced_upload_mtu"`
			SyncedDownloadMTU int     `json:"synced_download_mtu"`
			Duplication       int     `json:"duplication"`
			SetupDuplication  int     `json:"setup_duplication"`
			FailoverThreshold int     `json:"failover_threshold"`
			FailoverCooldown  float64 `json:"failover_cooldown_seconds"`
		} `json:"applied"`
	}

	ev := evidence{
		GeneratedAt: c.now(),
		Source:      string(source),
		Registry:    regPath,
		Derived:     derived,
	}
	ev.Applied.SyncedUploadMTU = c.syncedUploadMTU
	ev.Applied.SyncedDownloadMTU = c.syncedDownloadMTU
	ev.Applied.Duplication = c.cfg.PacketDuplicationCount
	ev.Applied.SetupDuplication = c.cfg.SetupPacketDuplicationCount
	ev.Applied.FailoverThreshold = c.streamResolverFailoverResendThreshold
	ev.Applied.FailoverCooldown = c.streamResolverFailoverCooldown.Seconds()

	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	path := c.autoProfileDerivedRuntimePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *Client) profileOneResolver(ctx context.Context, stats *autoProfileRunStats, domain string, ip string, port int, old *profiling.ResolverProfile, now time.Time) *profiling.ResolverProfile {
	key := fmt.Sprintf("%s:%d", ip, port)
	conn := Connection{
		Domain:        domain,
		Resolver:      ip,
		ResolverPort:  port,
		ResolverLabel: key,
		Key:           key,
	}

	profile := &profiling.ResolverProfile{}
	if old != nil {
		*profile = *old
	}

	if profile.Identity.IP == "" {
		profile.Identity.IP = ip
	}
	if profile.Identity.Port == 0 {
		profile.Identity.Port = port
	}
	if profile.Identity.FirstSeenAt.IsZero() {
		profile.Identity.FirstSeenAt = now
	}
	profile.Identity.LastSeenAt = now

	prevStatus := profile.Viability.Status
	profile.Viability.Status = profiling.ViabilityUnknown
	profile.Viability.FailReason = ""
	profile.Viability.TestCount++

	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		profile.Viability.Status = profiling.ViabilityNotViable
		profile.Viability.FailReason = "UDP_DIAL"
		return finalizeProfile(profile, prevStatus, now)
	}
	defer transport.conn.Close()

	timeout := time.Duration(c.cfg.MTUTestTimeout * float64(time.Second))
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	// Stage 0: ultra-light viability admission (tunnel-compatible sanity only).
	// IMPORTANT: No policy-driven MinUpload/MinDownload gating here.
	if stats != nil {
		stats.incStage0Attempted()
	}
	s0 := c.stage0ViabilityProbe(ctx, conn, transport, timeout)
	if !s0.ok {
		profile.Viability.Status = profiling.ViabilityNotViable
		profile.Viability.FailReason = s0.failReason
		// Keep minimal timing/reliability from Stage0 for debugging, but do not treat
		// this as a full profile.
		profile.Timing = timingFromSamples(s0.samples)
		profile.Reliability = reliabilityFromSamples(s0.samples)
		if stats != nil {
			stats.recordStage0Result(false, s0.failReason, s0.subReason)
		}
		return finalizeProfile(profile, prevStatus, now)
	}
	if stats != nil {
		stats.recordStage0Result(true, "", "")
	}

	// Stage 0 passed. Mark as viable (admitted). Further stages may still fail to
	// derive a useful envelope, but viability is not policy-driven.
	profile.Viability.Status = profiling.ViabilityViable

	// Stage 1: coarse, directional region profiling (cheap grid, no binary search).
	upEnv, upRegions, upFail := c.stage1CoarseUploadRegions(ctx, conn, transport, timeout)
	if upFail != "" {
		// Keep admitted viability, but mark why envelope is missing (it will be skipped by derivation).
		profile.Viability.FailReason = upFail
		profile.Upload = profiling.Envelope{}
		profile.UploadRegions = upRegions
		if stats != nil {
			stats.recordStage1Upload(false, upFail)
			stats.upsertSurvivor(autoProfileResolverMini{addr: key, stage0OK: true, failStage: upFail})
		}
		profile.Identity.LastProfiledAt = now
		return finalizeProfile(profile, prevStatus, now)
	}
	if stats != nil {
		stats.recordStage1Upload(true, "")
	}

	downEnv, downRegions, downFail := c.stage1CoarseDownloadRegions(ctx, conn, transport, upEnv.RecommendedBytes, timeout)
	if downFail != "" {
		profile.Viability.FailReason = downFail
		profile.Upload = upEnv
		profile.UploadRegions = upRegions
		profile.Download = profiling.Envelope{}
		profile.DownloadRegions = downRegions
		if stats != nil {
			stats.recordStage1Download(false, downFail)
			stats.upsertSurvivor(autoProfileResolverMini{addr: key, stage0OK: true, upRec: upEnv.RecommendedBytes, upMax: upEnv.WorkingMaxBytes, failStage: downFail})
		}
		profile.Identity.LastProfiledAt = now
		return finalizeProfile(profile, prevStatus, now)
	}
	if stats != nil {
		stats.recordStage1Download(true, "")
	}

	profile.Upload = upEnv
	profile.UploadRegions = upRegions
	profile.Download = downEnv
	profile.DownloadRegions = downRegions

	// Stage 2: lightweight sampling at recommended points for timing/reliability only.
	// (No burst in Phase-1 admission; burst is refinement-only and can be added later.)
	samples := make([]probeSample, 0, 12)
	samples = append(samples, c.sampleUpload(ctx, conn, transport, upEnv.RecommendedBytes, timeout, 3)...)
	// Keep download probe request size small/neutral.
	samples = append(samples, c.sampleDownload(ctx, conn, transport, downEnv.RecommendedBytes, autoProfileStage0UploadProbeBytes, timeout, 3)...)
	profile.Timing = timingFromSamples(samples)
	profile.Reliability = reliabilityFromSamples(samples)
	profile.Burst = profiling.BurstStats{}
	if stats != nil {
		stats.recordStage2Refined()
		stats.recordProfileComplete()
		stats.upsertSurvivor(autoProfileResolverMini{addr: key, stage0OK: true, upRec: upEnv.RecommendedBytes, downRec: downEnv.RecommendedBytes, upMax: upEnv.WorkingMaxBytes, downMax: downEnv.WorkingMaxBytes})
	}
	profile.Identity.LastProfiledAt = now
	return finalizeProfile(profile, prevStatus, now)
}

type envelopeProfileResult struct {
	recommendedSamples []probeSample
	failReason         string
}

func (c *Client) profileUploadEnvelope(ctx context.Context, conn Connection, transport *udpQueryTransport, maxPayload int, timeout time.Duration) (profiling.Envelope, envelopeProfileResult) {
	env := profiling.Envelope{}
	res := envelopeProfileResult{}

	// Align the floor with the official MTU scan. Some servers/resolvers may not
	// respond reliably to extremely small probes even if they are theoretically valid.
	floor := max(minUploadMTUFloor, c.cfg.MinUploadMTU)
	floorOK := c.checkUpload(ctx, conn, transport, floor, timeout)
	if !floorOK {
		res.failReason = "UPLOAD_FLOOR"
		return env, res
	}

	ceiling := c.findUploadCeiling(ctx, conn, transport, floor, maxPayload, timeout)
	if ceiling <= 0 {
		res.failReason = "UPLOAD_CEILING"
		return env, res
	}

	recommended := ceiling - max(4, ceiling/10)
	if recommended < floor {
		recommended = floor
	}

	res.recommendedSamples = c.sampleUpload(ctx, conn, transport, recommended, timeout, 6)

	env.FloorBytes = floor
	env.WorkingMinBytes = floor
	env.WorkingMaxBytes = ceiling
	env.RecommendedBytes = recommended
	env.CeilingBytes = ceiling
	env.RecommendedProbeRtt = p50MsFromSamples(res.recommendedSamples)
	return env, res
}

func (c *Client) profileDownloadEnvelope(ctx context.Context, conn Connection, transport *udpQueryTransport, uploadMTU int, timeout time.Duration) (profiling.Envelope, envelopeProfileResult) {
	env := profiling.Envelope{}
	res := envelopeProfileResult{}

	if uploadMTU <= 0 {
		uploadMTU = 32
	}

	// Align the floor with the official MTU scan.
	floor := max(minDownloadMTUFloor, c.cfg.MinDownloadMTU)
	if !c.checkDownload(ctx, conn, transport, floor, uploadMTU, timeout) {
		res.failReason = "DOWNLOAD_FLOOR"
		return env, res
	}

	maxProbe := c.cfg.MaxDownloadMTU
	if maxProbe <= 0 {
		maxProbe = EDnsSafeUDPSize
	}
	ceiling := c.findDownloadCeiling(ctx, conn, transport, floor, maxProbe, uploadMTU, timeout)
	if ceiling <= 0 {
		res.failReason = "DOWNLOAD_CEILING"
		return env, res
	}

	recommended := ceiling - max(8, ceiling/10)
	if recommended < floor {
		recommended = floor
	}

	res.recommendedSamples = c.sampleDownload(ctx, conn, transport, recommended, uploadMTU, timeout, 6)

	env.FloorBytes = floor
	env.WorkingMinBytes = floor
	env.WorkingMaxBytes = ceiling
	env.RecommendedBytes = recommended
	env.CeilingBytes = ceiling
	env.RecommendedProbeRtt = p50MsFromSamples(res.recommendedSamples)
	return env, res
}

func (c *Client) checkUpload(ctx context.Context, conn Connection, transport *udpQueryTransport, size int, timeout time.Duration) bool {
	for attempt := 0; attempt < max(1, c.mtuTestRetries); attempt++ {
		outcome, _ := c.probeUploadOnce(ctx, conn, transport, size, timeout)
		if outcome == probeSuccess {
			return true
		}
	}
	return false
}

func (c *Client) checkDownload(ctx context.Context, conn Connection, transport *udpQueryTransport, size int, uploadMTU int, timeout time.Duration) bool {
	for attempt := 0; attempt < max(1, c.mtuTestRetries); attempt++ {
		outcome, _ := c.probeDownloadOnce(ctx, conn, transport, size, uploadMTU, timeout)
		if outcome == probeSuccess {
			return true
		}
	}
	return false
}

func (c *Client) findUploadCeiling(ctx context.Context, conn Connection, transport *udpQueryTransport, floor int, maxPayload int, timeout time.Duration) int {
	lastGood := 0
	firstBad := 0

	candidate := floor
	for candidate <= maxPayload {
		if ctx.Err() != nil {
			return 0
		}
		// Match the official MTU scan semantics: treat a probe point as "good"
		// only when it succeeds across retries, not just a single lucky packet.
		if c.checkUpload(ctx, conn, transport, candidate, timeout) {
			lastGood = candidate
			if candidate == maxPayload {
				break
			}
			next := candidate * 2
			if next <= candidate {
				break
			}
			if next > maxPayload {
				next = maxPayload
			}
			candidate = next
			continue
		}
		firstBad = candidate
		break
	}

	if lastGood <= 0 {
		return 0
	}
	if firstBad <= 0 || firstBad <= lastGood+1 {
		return lastGood
	}

	low := lastGood + 1
	high := firstBad - 1
	best := lastGood
	for low <= high {
		mid := (low + high) / 2
		if c.checkUpload(ctx, conn, transport, mid, timeout) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func (c *Client) findDownloadCeiling(ctx context.Context, conn Connection, transport *udpQueryTransport, floor int, maxProbe int, uploadMTU int, timeout time.Duration) int {
	lastGood := 0
	firstBad := 0

	candidate := floor
	for candidate <= maxProbe {
		if ctx.Err() != nil {
			return 0
		}
		// Match the official MTU scan semantics: treat a probe point as "good"
		// only when it succeeds across retries, not just a single lucky packet.
		if c.checkDownload(ctx, conn, transport, candidate, uploadMTU, timeout) {
			lastGood = candidate
			if candidate == maxProbe {
				break
			}
			next := candidate * 2
			if next <= candidate {
				break
			}
			if next > maxProbe {
				next = maxProbe
			}
			candidate = next
			continue
		}
		firstBad = candidate
		break
	}

	if lastGood <= 0 {
		return 0
	}
	if firstBad <= 0 || firstBad <= lastGood+1 {
		return lastGood
	}

	low := lastGood + 1
	high := firstBad - 1
	best := lastGood
	for low <= high {
		mid := (low + high) / 2
		if c.checkDownload(ctx, conn, transport, mid, uploadMTU, timeout) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func (c *Client) sampleUpload(ctx context.Context, conn Connection, transport *udpQueryTransport, size int, timeout time.Duration, n int) []probeSample {
	samples := make([]probeSample, 0, n)
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		outcome, rtt := c.probeUploadOnce(ctx, conn, transport, size, timeout)
		samples = append(samples, probeSample{outcome: outcome, rtt: rtt})
	}
	return samples
}

func (c *Client) sampleDownload(ctx context.Context, conn Connection, transport *udpQueryTransport, size int, uploadMTU int, timeout time.Duration, n int) []probeSample {
	samples := make([]probeSample, 0, n)
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		outcome, rtt := c.probeDownloadOnce(ctx, conn, transport, size, uploadMTU, timeout)
		samples = append(samples, probeSample{outcome: outcome, rtt: rtt})
	}
	return samples
}

func (c *Client) probeUploadOnce(ctx context.Context, conn Connection, transport *udpQueryTransport, mtuSize int, timeout time.Duration) (probeOutcome, time.Duration) {
	if mtuSize < 1+mtuProbeCodeLength {
		return probeMalformed, 0
	}
	if ctx.Err() != nil {
		return probeTimeout, 0
	}

	payload, code, useBase64, err := c.buildMTUProbePayload(mtuSize)
	if err != nil {
		return probeMalformed, 0
	}
	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_UP_REQ, payload)
	if err != nil {
		return probeMalformed, 0
	}

	startedAt := time.Now()
	response, err := c.exchangeUDPQuery(transport, query, timeout)
	if err != nil {
		return probeTimeout, 0
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		return probeMalformed, rtt
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		return probeMalformed, rtt
	}
	if len(packet.Payload) != 6 {
		return probeMalformed, rtt
	}
	if binaryBigEndianU32(packet.Payload[:mtuProbeCodeLength]) != code {
		return probeMalformed, rtt
	}
	if binaryBigEndianU16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2]) != uint16(mtuSize) {
		return probeMalformed, rtt
	}
	return probeSuccess, rtt
}

func (c *Client) probeDownloadOnce(ctx context.Context, conn Connection, transport *udpQueryTransport, mtuSize int, uploadMTU int, timeout time.Duration) (probeOutcome, time.Duration) {
	if mtuSize < minDownloadMTUFloor {
		return probeMalformed, 0
	}
	if ctx.Err() != nil {
		return probeTimeout, 0
	}
	effectiveDownloadSize := effectiveDownloadMTUProbeSize(mtuSize)
	if effectiveDownloadSize < minDownloadMTUFloor {
		return probeMalformed, 0
	}

	requestLen := max(1+mtuProbeCodeLength+2, uploadMTU)
	payload, code, useBase64, err := c.buildMTUProbePayload(requestLen)
	if err != nil {
		return probeMalformed, 0
	}
	putU16(payload[1+mtuProbeCodeLength:1+mtuProbeCodeLength+2], uint16(effectiveDownloadSize))
	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_DOWN_REQ, payload)
	if err != nil {
		return probeMalformed, 0
	}

	startedAt := time.Now()
	response, err := c.exchangeUDPQuery(transport, query, timeout)
	if err != nil {
		return probeTimeout, 0
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		return probeMalformed, rtt
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		return probeMalformed, rtt
	}
	if len(packet.Payload) != effectiveDownloadSize {
		return probeMalformed, rtt
	}
	// Mirror the official MTU scan semantics: the payload starts with the 4-byte probe code,
	// followed by the 2-byte echoed size. (No leading mode byte in the MTU_DOWN_RES payload.)
	if len(packet.Payload) < mtuProbeCodeLength+2 {
		return probeMalformed, rtt
	}
	if binaryBigEndianU32(packet.Payload[:mtuProbeCodeLength]) != code {
		return probeMalformed, rtt
	}
	if binaryBigEndianU16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2]) != uint16(effectiveDownloadSize) {
		return probeMalformed, rtt
	}
	return probeSuccess, rtt
}

func finalizeProfile(p *profiling.ResolverProfile, previous profiling.ViabilityStatus, now time.Time) *profiling.ResolverProfile {
	if p == nil {
		return p
	}

	if previous != "" && previous != profiling.ViabilityUnknown && p.Viability.Status != previous {
		p.Persistence.FlapCount++
	}

	first := p.Identity.FirstSeenAt
	if !first.IsZero() {
		days := int(now.Sub(first).Hours()/24) + 1
		if days < 1 {
			days = 1
		}
		p.Persistence.DaysSeen = days
	}

	if p.Viability.Status != profiling.ViabilityViable {
		p.Persistence.RecentFailureCount++
	}

	p.Persistence.PersistenceScore = computePersistenceScore(p.Persistence.DaysSeen, p.Persistence.RecentFailureCount, p.Persistence.FlapCount)
	p.Identity.LastProfiledAt = now
	return p
}

func computePersistenceScore(daysSeen int, recentFailures int, flapCount int) float64 {
	score := 0.0
	score += float64(min(daysSeen, 30)) / 30.0
	score -= float64(min(recentFailures, 20)) / 20.0
	score -= float64(min(flapCount, 20)) / 20.0
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func timingFromSamples(samples []probeSample) profiling.TimingStats {
	rtts := make([]int, 0, len(samples))
	for _, s := range samples {
		if s.outcome == probeSuccess && s.rtt > 0 {
			rtts = append(rtts, int(s.rtt.Milliseconds()))
		}
	}
	sort.Ints(rtts)
	p50 := percentileInt(rtts, 0.50)
	p90 := percentileInt(rtts, 0.90)

	jitters := make([]int, 0, max(0, len(rtts)-1))
	for i := 1; i < len(rtts); i++ {
		jitters = append(jitters, absInt(rtts[i]-rtts[i-1]))
	}
	sort.Ints(jitters)

	return profiling.TimingStats{
		RttP50Ms:    p50,
		RttP90Ms:    p90,
		JitterP50Ms: percentileInt(jitters, 0.50),
		JitterP90Ms: percentileInt(jitters, 0.90),
	}
}

func reliabilityFromSamples(samples []probeSample) profiling.ReliabilityStats {
	total := float64(len(samples))
	if total <= 0 {
		return profiling.ReliabilityStats{}
	}
	success := 0.0
	timeout := 0.0
	malformed := 0.0
	for _, s := range samples {
		switch s.outcome {
		case probeSuccess:
			success++
		case probeTimeout:
			timeout++
		case probeMalformed:
			malformed++
		}
	}
	return profiling.ReliabilityStats{
		SuccessRatio:   success / total,
		TimeoutRatio:   timeout / total,
		MalformedRatio: malformed / total,
		// Phase 1: we don't yet implement a late-success window.
		LateSuccessRatio: 0,
	}
}

func p50MsFromSamples(samples []probeSample) int {
	rtts := make([]int, 0, len(samples))
	for _, s := range samples {
		if s.outcome == probeSuccess && s.rtt > 0 {
			rtts = append(rtts, int(s.rtt.Milliseconds()))
		}
	}
	sort.Ints(rtts)
	return percentileInt(rtts, 0.50)
}

func percentileInt(sorted []int, q float64) int {
	if len(sorted) == 0 {
		return 0
	}
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[len(sorted)-1]
	}
	pos := q * float64(len(sorted)-1)
	idx := int(pos)
	if idx < 0 {
		return sorted[0]
	}
	if idx >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	frac := pos - float64(idx)
	a := float64(sorted[idx])
	b := float64(sorted[idx+1])
	return int(a + (b-a)*frac)
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// Small helpers to avoid pulling binary.BigEndian into this file in multiple places.
func binaryBigEndianU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func binaryBigEndianU16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func putU16(b []byte, v uint16)          { b[0] = byte(v >> 8); b[1] = byte(v) }
