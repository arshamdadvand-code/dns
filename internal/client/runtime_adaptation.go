package client

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"masterdnsvpn-go/internal/telemetry"
)

type runtimeAdaptState string

const (
	runtimeStateStable     runtimeAdaptState = "STABLE"
	runtimeStateCautious   runtimeAdaptState = "CAUTIOUS"
	runtimeStateDegraded   runtimeAdaptState = "DEGRADED"
	runtimeStateRecovering runtimeAdaptState = "RECOVERING"
)

type runtimeActionKind string

const (
	runtimeActionNone           runtimeActionKind = "NONE"
	runtimeActionDemote         runtimeActionKind = "DEMOTE"
	runtimeActionPromote        runtimeActionKind = "PROMOTE"
	runtimeActionProbeReserve   runtimeActionKind = "PROBE_RESERVE"
	runtimeActionTarget         runtimeActionKind = "TARGET_ADJUST"
	runtimeActionTargetValidate runtimeActionKind = "TARGET_VALIDATE"
	runtimeActionDuplication    runtimeActionKind = "DUPLICATION_ADJUST"
	runtimeActionFailover       runtimeActionKind = "FAILOVER_ADJUST"
)

const (
	runtimeEvalCadence       = 5 * time.Second
	runtimeFastWindow        = 10 * time.Second
	runtimeControlWindow     = 60 * time.Second
	runtimeBaselineWindow    = 6 * time.Minute
	runtimeDefaultCooldown   = 18 * time.Second
	runtimeRecoverObserve    = 20 * time.Second
	runtimeStepUpFreeze      = 45 * time.Second
	runtimeProbeCooldown     = 30 * time.Second
	runtimeResolverCooldown  = 45 * time.Second
	runtimeCarrierQuarantine = 4 * time.Minute
	runtimeMinResolverObs    = 4
)

type runtimeControllerEvent struct {
	At      string `json:"at"`
	Action  string `json:"action"`
	Reason  string `json:"reason"`
	Details string `json:"details"`
}

type runtimeControllerSnapshot struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`

	LastAction       string  `json:"last_action"`
	LastReason       string  `json:"last_reason"`
	LastActionAt     string  `json:"last_action_at,omitempty"`
	CooldownRemainS  float64 `json:"cooldown_remaining_seconds"`
	StepUpFreezeS    float64 `json:"stepup_freeze_remaining_seconds"`
	RecoverRemainS   float64 `json:"recovering_remaining_seconds"`
	ActiveCount      int     `json:"active_count"`
	ReserveCount     int     `json:"reserve_count"`
	UploadTarget     int     `json:"upload_target"`
	DownloadTarget   int     `json:"download_target"`
	DuplicationData  int     `json:"duplication_data"`
	DuplicationSetup int     `json:"duplication_setup"`
	FailoverThr      int     `json:"failover_threshold"`
	FailoverCoolS    float64 `json:"failover_cooldown_seconds"`

	ActiveSetHealth      float64 `json:"active_set_health"`
	ThroughputEfficiency float64 `json:"throughput_efficiency"`
	TargetPressureDown   bool    `json:"target_pressure_down"`
	TargetPressureUp     bool    `json:"target_pressure_up"`
	DuplicationGain      float64 `json:"duplication_gain"`
	ReserveReadiness     float64 `json:"reserve_readiness"`
	CarrierPressure      float64 `json:"carrier_pressure"`
	QualityPressure      float64 `json:"quality_pressure"`
	TailInflation        float64 `json:"tail_inflation"`

	RecentEvents []runtimeControllerEvent `json:"recent_events,omitempty"`
}

type runtimeController struct {
	client *Client

	mu      sync.RWMutex
	running bool
	everRan bool
	state   runtimeAdaptState

	startedAt         time.Time
	nextActionAt      time.Time
	recoveringUntil   time.Time
	stepUpFreezeUntil time.Time
	failoverHoldUntil time.Time
	failoverTightenV  int
	failoverRelaxV    int

	lastActionKind   runtimeActionKind
	lastActionReason string
	lastActionAt     time.Time

	// Rolling telemetry deltas.
	prevAt    time.Time
	prevSnap  telemetry.Snapshot
	prevByKey map[string]telemetry.ResolverSnapshot
	havePrev  bool
	history   []runtimeTelemetrySample

	// Signal history for relative thresholds.
	signalHistory []runtimeSignalPoint

	// Resolver-level guardrails.
	resolverCooldownUntil map[string]time.Time
	quarantineUntil       map[string]time.Time // carrier-incompatible
	reserveProbeAfter     map[string]time.Time
	demoteVotes           map[string]int
	demoteTimes           []time.Time
	probeBudget           int
	probeBudgetResetAt    time.Time

	// Runtime baselines.
	baseUpload       int
	baseDownload     int
	baseDupData      int
	baseDupSetup     int
	baseFailoverThr  int
	baseFailoverCool time.Duration

	rollingBestTxEff float64
	rollingBestRxEff float64
	dupEwmaByLevel   map[int]float64
	dupSeenByLevel   map[int]int

	stableVotes   int
	cautiousVotes int
	degradedVotes int

	lastSignal runtimeSignals

	events []runtimeControllerEvent

	pendingTarget        *pendingTargetChange
	lastFailoverChangeAt time.Time

	// Test hooks (nil in production).
	dialTransport func(resolverLabel string) (*udpQueryTransport, error)
	stage0Probe   func(ctx context.Context, conn Connection, transport *udpQueryTransport, timeout time.Duration) stage0Outcome
}

type pendingTargetChange struct {
	Direction string // "up" | "down"
	OldUp     int
	OldDown   int
	NewUp     int
	NewDown   int
	AppliedAt time.Time
	DueAt     time.Time

	PreEffMin float64
	PreAckBps float64
	PreDelBps float64
}

type runtimeTelemetrySample struct {
	At time.Time
	Dt time.Duration

	WireTX uint64
	WireRX uint64

	UsefulIngressTX   uint64
	UsefulAckedTX     uint64
	UsefulDeliveredRX uint64

	LogicalPackets   uint64
	TargetsRequested uint64
	TargetsSelected  uint64

	Resolvers map[string]runtimeResolverDelta
}

type runtimeResolverDelta struct {
	OK       uint64
	Timeout  uint64
	Refused  uint64
	Servfail uint64
	NoTunnel uint64
	Other    uint64

	ConsecutiveFail    int32
	ConsecutiveTimeout int32
	RTTP50ms           float64
	RTTP90ms           float64
}

type runtimeResolverSignal struct {
	Key string

	Total        float64
	OKRatio      float64
	QualityRatio float64 // timeout + no-tunnel + other
	CarrierRatio float64 // refused + servfail
	TimeoutRatio float64

	ConsecutiveFail    int32
	ConsecutiveTimeout int32
	RTTP90             float64
	Score              float64
}

type runtimeWindowAgg struct {
	DurationSec float64

	WireTX uint64
	WireRX uint64

	UsefulIngressTX   uint64
	UsefulAckedTX     uint64
	UsefulDeliveredRX uint64

	LogicalPackets   uint64
	TargetsRequested uint64
	TargetsSelected  uint64

	Resolvers map[string]*runtimeResolverDelta
}

type runtimeSignals struct {
	ActiveCount  int
	ReserveCount int

	ActiveSetHealth  float64
	ReserveReadiness float64

	TxEff  float64
	RxEff  float64
	EffMin float64

	TxEffRel float64
	RxEffRel float64

	ControlAckBps float64
	ControlDelBps float64

	QualityPressure float64
	CarrierPressure float64
	TailInflation   float64
	DuplicationGain float64

	TargetPressureDown bool
	TargetPressureUp   bool

	ActiveSignals  []runtimeResolverSignal
	ReserveSignals []runtimeResolverSignal
	WeakActive     *runtimeResolverSignal
	BestReserve    *runtimeResolverSignal

	// Fast window view (anti-spike gating + early warning).
	FastEffMin          float64
	FastQualityPressure float64
	FastCarrierPressure float64
	FastTailInflation   float64
	FastAckBps          float64
	FastDelBps          float64
	FastByKey           map[string]runtimeResolverSignal
}

type runtimeSignalPoint struct {
	At              time.Time
	ActiveSetHealth float64
	EffMin          float64
	QualityPressure float64
	TailInflation   float64
}

type runtimeActionDecision struct {
	Kind    runtimeActionKind
	Reason  string
	Details string
	Key     string
}

func newRuntimeController(c *Client) *runtimeController {
	if c == nil {
		return nil
	}
	baseCool := c.streamResolverFailoverCooldown
	if baseCool <= 0 {
		baseCool = time.Second
	}
	return &runtimeController{
		client:                c,
		state:                 runtimeStateRecovering,
		baseUpload:            max(c.syncedUploadMTU, minUploadMTUFloor),
		baseDownload:          max(c.syncedDownloadMTU, minDownloadMTUFloor),
		baseDupData:           max(c.cfg.PacketDuplicationCount, 1),
		baseDupSetup:          max(c.cfg.SetupPacketDuplicationCount, max(c.cfg.PacketDuplicationCount, 1)),
		baseFailoverThr:       max(c.streamResolverFailoverResendThreshold, 1),
		baseFailoverCool:      baseCool,
		prevByKey:             make(map[string]telemetry.ResolverSnapshot),
		history:               make([]runtimeTelemetrySample, 0, 128),
		signalHistory:         make([]runtimeSignalPoint, 0, 128),
		resolverCooldownUntil: make(map[string]time.Time),
		quarantineUntil:       make(map[string]time.Time),
		reserveProbeAfter:     make(map[string]time.Time),
		demoteVotes:           make(map[string]int),
		demoteTimes:           make([]time.Time, 0, 16),
		probeBudget:           2,
		probeBudgetResetAt:    time.Now().Add(60 * time.Second),
		dupEwmaByLevel:        make(map[int]float64),
		dupSeenByLevel:        make(map[int]int),
		events:                make([]runtimeControllerEvent, 0, 24),
		dialTransport:         newUDPQueryTransport,
		stage0Probe:           c.stage0ViabilityProbe,
	}
}

func (c *Client) runtimeControllerEnabled() bool {
	if c == nil || c.runtimeController == nil {
		return false
	}
	return c.runtimeController.IsRunning()
}

func (c *Client) runtimeControllerPlanned() bool {
	return c != nil && c.runtimeController != nil
}

func (c *Client) runtimeControllerSnapshot() runtimeControllerSnapshot {
	if c == nil || c.runtimeController == nil {
		return runtimeControllerSnapshot{}
	}
	return c.runtimeController.Snapshot()
}

func (rc *runtimeController) IsRunning() bool {
	if rc == nil {
		return false
	}
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.running
}

func (rc *runtimeController) Snapshot() runtimeControllerSnapshot {
	if rc == nil || rc.client == nil {
		return runtimeControllerSnapshot{}
	}

	now := rc.client.now()
	c := rc.client

	activeCount := len(c.balancer.ActiveConnections())
	reserveCount := len(c.balancer.InactiveConnections())

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	snap := runtimeControllerSnapshot{
		Enabled:              rc.everRan,
		State:                string(rc.state),
		LastAction:           string(rc.lastActionKind),
		LastReason:           rc.lastActionReason,
		ActiveCount:          activeCount,
		ReserveCount:         reserveCount,
		UploadTarget:         c.syncedUploadMTU,
		DownloadTarget:       c.syncedDownloadMTU,
		DuplicationData:      c.cfg.PacketDuplicationCount,
		DuplicationSetup:     c.cfg.SetupPacketDuplicationCount,
		FailoverThr:          c.streamResolverFailoverResendThreshold,
		FailoverCoolS:        c.streamResolverFailoverCooldown.Seconds(),
		ActiveSetHealth:      rc.lastSignal.ActiveSetHealth,
		ThroughputEfficiency: rc.lastSignal.EffMin,
		TargetPressureDown:   rc.lastSignal.TargetPressureDown,
		TargetPressureUp:     rc.lastSignal.TargetPressureUp,
		DuplicationGain:      rc.lastSignal.DuplicationGain,
		ReserveReadiness:     rc.lastSignal.ReserveReadiness,
		CarrierPressure:      rc.lastSignal.CarrierPressure,
		QualityPressure:      rc.lastSignal.QualityPressure,
		TailInflation:        rc.lastSignal.TailInflation,
	}

	if !rc.lastActionAt.IsZero() {
		snap.LastActionAt = rc.lastActionAt.Format(time.RFC3339Nano)
	}
	if now.Before(rc.nextActionAt) {
		snap.CooldownRemainS = rc.nextActionAt.Sub(now).Seconds()
	}
	if now.Before(rc.stepUpFreezeUntil) {
		snap.StepUpFreezeS = rc.stepUpFreezeUntil.Sub(now).Seconds()
	}
	if now.Before(rc.recoveringUntil) {
		snap.RecoverRemainS = rc.recoveringUntil.Sub(now).Seconds()
	}

	if len(rc.events) > 0 {
		snap.RecentEvents = append([]runtimeControllerEvent(nil), rc.events...)
	}
	return snap
}

func (rc *runtimeController) Run(ctx context.Context) {
	if rc == nil || rc.client == nil || rc.client.telemetry == nil {
		return
	}

	rc.mu.Lock()
	if rc.running {
		rc.mu.Unlock()
		return
	}
	rc.running = true
	rc.everRan = true
	rc.startedAt = rc.client.now()
	rc.state = runtimeStateRecovering
	rc.recoveringUntil = rc.startedAt.Add(runtimeRecoverObserve)
	rc.mu.Unlock()

	t := time.NewTicker(runtimeEvalCadence)
	defer t.Stop()
	defer func() {
		rc.mu.Lock()
		rc.running = false
		rc.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			rc.evaluate(ctx, now)
		}
	}
}

func (rc *runtimeController) evaluate(ctx context.Context, now time.Time) {
	if rc == nil || rc.client == nil || rc.client.telemetry == nil {
		return
	}
	if !rc.collectTelemetrySample(now) {
		return
	}

	controlAgg := rc.aggregateWindow(now, runtimeControlWindow)
	fastAgg := rc.aggregateWindow(now, runtimeFastWindow)
	baselineAgg := rc.aggregateWindow(now, runtimeBaselineWindow)
	signals := rc.deriveSignals(now, controlAgg, fastAgg, baselineAgg)
	rc.updateSignalHistory(now, signals)
	rc.updateState(now, signals)

	rc.mu.Lock()
	rc.lastSignal = signals
	nextActionAt := rc.nextActionAt
	rc.mu.Unlock()

	// Decisions only when session/runtime is actually active.
	if !rc.client.sessionReady {
		return
	}
	if now.Before(nextActionAt) {
		return
	}

	action := rc.decideAction(ctx, now, signals, controlAgg, fastAgg)
	if action.Kind == runtimeActionNone {
		return
	}
	rc.applyAction(ctx, now, action, signals)
}

func (rc *runtimeController) collectTelemetrySample(now time.Time) bool {
	c := rc.client
	snap := c.telemetry.Snapshot()

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if !rc.havePrev {
		rc.havePrev = true
		rc.prevAt = now
		rc.prevSnap = snap
		rc.prevByKey = snapshotResolverMap(snap.Resolvers)
		return false
	}

	dt := now.Sub(rc.prevAt)
	if dt <= 0 {
		dt = runtimeEvalCadence
	}

	sample := runtimeTelemetrySample{
		At:                now,
		Dt:                dt,
		WireTX:            diffU64(snap.WireTX, rc.prevSnap.WireTX),
		WireRX:            diffU64(snap.WireRX, rc.prevSnap.WireRX),
		UsefulIngressTX:   diffU64(snap.UsefulIngressTX, rc.prevSnap.UsefulIngressTX),
		UsefulAckedTX:     diffU64(snap.UsefulAckedTX, rc.prevSnap.UsefulAckedTX),
		UsefulDeliveredRX: diffU64(snap.UsefulDeliveredRX, rc.prevSnap.UsefulDeliveredRX),
		LogicalPackets:    diffU64(snap.LogicalPackets, rc.prevSnap.LogicalPackets),
		TargetsRequested:  diffU64(snap.TargetsRequested, rc.prevSnap.TargetsRequested),
		TargetsSelected:   diffU64(snap.TargetsSelected, rc.prevSnap.TargetsSelected),
		Resolvers:         make(map[string]runtimeResolverDelta, len(snap.Resolvers)),
	}

	currByKey := snapshotResolverMap(snap.Resolvers)
	for key, curr := range currByKey {
		prev := rc.prevByKey[key]
		d := runtimeResolverDelta{
			OK:                 diffU64(curr.OK, prev.OK),
			Timeout:            diffU64(curr.Timeout, prev.Timeout),
			Refused:            diffU64(curr.Refused, prev.Refused),
			Servfail:           diffU64(curr.Servfail, prev.Servfail),
			NoTunnel:           diffU64(curr.NoTunnel, prev.NoTunnel),
			Other:              diffU64(curr.OtherFailures, prev.OtherFailures),
			ConsecutiveFail:    curr.ConsecutiveFail,
			ConsecutiveTimeout: curr.ConsecutiveTimeout,
			RTTP50ms:           curr.RTTP50ms,
			RTTP90ms:           curr.RTTP90ms,
		}
		if d.OK+d.Timeout+d.Refused+d.Servfail+d.NoTunnel+d.Other == 0 &&
			d.ConsecutiveFail == 0 && d.ConsecutiveTimeout == 0 &&
			d.RTTP90ms <= 0 {
			continue
		}
		sample.Resolvers[key] = d
	}

	rc.history = append(rc.history, sample)
	const maxHistorySamples = 150 // ~12.5 min at 5s cadence.
	if len(rc.history) > maxHistorySamples {
		rc.history = rc.history[len(rc.history)-maxHistorySamples:]
	}

	rc.prevAt = now
	rc.prevSnap = snap
	rc.prevByKey = currByKey
	return true
}

func (rc *runtimeController) aggregateWindow(now time.Time, window time.Duration) runtimeWindowAgg {
	rc.mu.RLock()
	history := append([]runtimeTelemetrySample(nil), rc.history...)
	rc.mu.RUnlock()

	cut := now.Add(-window)
	agg := runtimeWindowAgg{
		Resolvers: make(map[string]*runtimeResolverDelta),
	}
	for _, s := range history {
		if s.At.Before(cut) {
			continue
		}
		agg.DurationSec += s.Dt.Seconds()
		agg.WireTX += s.WireTX
		agg.WireRX += s.WireRX
		agg.UsefulIngressTX += s.UsefulIngressTX
		agg.UsefulAckedTX += s.UsefulAckedTX
		agg.UsefulDeliveredRX += s.UsefulDeliveredRX
		agg.LogicalPackets += s.LogicalPackets
		agg.TargetsRequested += s.TargetsRequested
		agg.TargetsSelected += s.TargetsSelected

		for key, rd := range s.Resolvers {
			dst := agg.Resolvers[key]
			if dst == nil {
				v := rd
				agg.Resolvers[key] = &v
				continue
			}
			dst.OK += rd.OK
			dst.Timeout += rd.Timeout
			dst.Refused += rd.Refused
			dst.Servfail += rd.Servfail
			dst.NoTunnel += rd.NoTunnel
			dst.Other += rd.Other
			dst.ConsecutiveFail = rd.ConsecutiveFail
			dst.ConsecutiveTimeout = rd.ConsecutiveTimeout
			if rd.RTTP50ms > 0 {
				dst.RTTP50ms = rd.RTTP50ms
			}
			if rd.RTTP90ms > 0 {
				dst.RTTP90ms = rd.RTTP90ms
			}
		}
	}
	return agg
}

func (rc *runtimeController) deriveSignals(now time.Time, control runtimeWindowAgg, fast runtimeWindowAgg, baseline runtimeWindowAgg) runtimeSignals {
	c := rc.client
	activeConns := c.balancer.ActiveConnections()
	reserveConns := c.balancer.InactiveConnections()

	active := make([]runtimeResolverSignal, 0, len(activeConns))
	reserve := make([]runtimeResolverSignal, 0, len(reserveConns))

	// Baseline RTT for inflation signal.
	baseRttList := make([]float64, 0, len(activeConns))
	for _, conn := range activeConns {
		if r := baseline.Resolvers[conn.Key]; r != nil && r.RTTP90ms > 0 {
			baseRttList = append(baseRttList, r.RTTP90ms)
		}
	}
	baseRttMedian := quantile(baseRttList, 0.5)
	if baseRttMedian <= 0 {
		baseRttMedian = 1
	}

	qualityRatios := make([]float64, 0, len(activeConns))
	carrierRatios := make([]float64, 0, len(activeConns))
	timeoutStreaks := make([]float64, 0, len(activeConns))
	activeHealthParts := make([]float64, 0, len(activeConns))

	for _, conn := range activeConns {
		rs := toResolverSignal(conn.Key, control.Resolvers[conn.Key], baseRttMedian)
		active = append(active, rs)
		qualityRatios = append(qualityRatios, rs.QualityRatio)
		carrierRatios = append(carrierRatios, rs.CarrierRatio)
		timeoutStreaks = append(timeoutStreaks, float64(rs.ConsecutiveTimeout))
		activeHealthParts = append(activeHealthParts, clamp01(0.5+0.5*rs.Score))
	}

	qualityQ75 := quantile(qualityRatios, 0.75)
	carrierQ75 := quantile(carrierRatios, 0.75)
	streakQ75 := quantile(timeoutStreaks, 0.75)

	for _, conn := range reserveConns {
		rs := toResolverSignal(conn.Key, control.Resolvers[conn.Key], baseRttMedian)
		reserve = append(reserve, rs)
	}

	// Fast window per-resolver view for spike gating.
	fastByKey := make(map[string]runtimeResolverSignal, len(activeConns))
	fastQualityRatios := make([]float64, 0, len(activeConns))
	fastCarrierRatios := make([]float64, 0, len(activeConns))
	fastRtt := make([]float64, 0, len(activeConns))
	for _, conn := range activeConns {
		rs := toResolverSignal(conn.Key, fast.Resolvers[conn.Key], baseRttMedian)
		fastByKey[conn.Key] = rs
		fastQualityRatios = append(fastQualityRatios, rs.QualityRatio)
		fastCarrierRatios = append(fastCarrierRatios, rs.CarrierRatio)
		if rs.RTTP90 > 0 {
			fastRtt = append(fastRtt, rs.RTTP90)
		}
	}

	txEff := ratioU64(control.UsefulAckedTX, control.WireTX)
	rxEff := ratioU64(control.UsefulDeliveredRX, control.WireRX)
	effMin := minFloat(txEff, rxEff)
	controlAckBps := 0.0
	controlDelBps := 0.0
	if control.DurationSec > 0 {
		controlAckBps = float64(control.UsefulAckedTX) / control.DurationSec
		controlDelBps = float64(control.UsefulDeliveredRX) / control.DurationSec
	}

	rc.mu.Lock()
	if txEff > 0 {
		if txEff > rc.rollingBestTxEff {
			rc.rollingBestTxEff = txEff
		} else {
			rc.rollingBestTxEff = maxFloat(txEff, rc.rollingBestTxEff*0.998)
		}
	}
	if rxEff > 0 {
		if rxEff > rc.rollingBestRxEff {
			rc.rollingBestRxEff = rxEff
		} else {
			rc.rollingBestRxEff = maxFloat(rxEff, rc.rollingBestRxEff*0.998)
		}
	}
	if rc.rollingBestTxEff <= 0 {
		rc.rollingBestTxEff = maxFloat(txEff, 0.01)
	}
	if rc.rollingBestRxEff <= 0 {
		rc.rollingBestRxEff = maxFloat(rxEff, 0.01)
	}
	bestTx := rc.rollingBestTxEff
	bestRx := rc.rollingBestRxEff
	rc.mu.Unlock()

	txRel := txEff / maxFloat(bestTx, 1e-6)
	rxRel := rxEff / maxFloat(bestRx, 1e-6)

	activeHealth := mean(activeHealthParts)
	qualityPressure := mean(qualityRatios)
	carrierPressure := mean(carrierRatios)

	// Tail inflation is relative to baseline median.
	currRtt := make([]float64, 0, len(active))
	for _, s := range active {
		if s.RTTP90 > 0 {
			currRtt = append(currRtt, s.RTTP90)
		}
	}
	currRttMedian := quantile(currRtt, 0.5)
	tailInflation := 1.0
	if currRttMedian > 0 && baseRttMedian > 0 {
		tailInflation = currRttMedian / baseRttMedian
	}

	dupLevel := max(c.cfg.PacketDuplicationCount, 1)
	dupGain := rc.duplicationGain(dupLevel, effMin)

	reserveReadiness := rc.computeReserveReadiness(now, reserveConns)
	weakActive := pickWeakActive(active, qualityQ75, carrierQ75, streakQ75)
	bestReserve := pickBestReserve(reserve)

	// Relative target pressure signals.
	effHistory := rc.effHistory()
	relQ25 := quantile(effHistory, 0.25)
	relQ75 := quantile(effHistory, 0.75)
	if relQ25 <= 0 {
		relQ25 = 0.75
	}
	if relQ75 <= 0 {
		relQ75 = 0.92
	}

	targetDown := minFloat(txRel, rxRel) <= relQ25 &&
		(qualityPressure >= quantile(qualityRatios, 0.5) || tailInflation > 1.10)
	targetUp := minFloat(txRel, rxRel) >= relQ75 &&
		qualityPressure <= quantile(qualityRatios, 0.5) &&
		carrierPressure <= quantile(carrierRatios, 0.75)

	// Fast window aggregates.
	fastTxEff := ratioU64(fast.UsefulAckedTX, fast.WireTX)
	fastRxEff := ratioU64(fast.UsefulDeliveredRX, fast.WireRX)
	fastEffMin := minFloat(fastTxEff, fastRxEff)
	fastAckBps := 0.0
	fastDelBps := 0.0
	if fast.DurationSec > 0 {
		fastAckBps = float64(fast.UsefulAckedTX) / fast.DurationSec
		fastDelBps = float64(fast.UsefulDeliveredRX) / fast.DurationSec
	}
	fastQuality := mean(fastQualityRatios)
	fastCarrier := mean(fastCarrierRatios)
	fastRttMedian := quantile(fastRtt, 0.5)
	fastTailInfl := 1.0
	if fastRttMedian > 0 && baseRttMedian > 0 {
		fastTailInfl = fastRttMedian / baseRttMedian
	}

	return runtimeSignals{
		ActiveCount:         len(activeConns),
		ReserveCount:        len(reserveConns),
		ActiveSetHealth:     activeHealth,
		ReserveReadiness:    reserveReadiness,
		TxEff:               txEff,
		RxEff:               rxEff,
		EffMin:              effMin,
		TxEffRel:            txRel,
		RxEffRel:            rxRel,
		ControlAckBps:       controlAckBps,
		ControlDelBps:       controlDelBps,
		QualityPressure:     qualityPressure,
		CarrierPressure:     carrierPressure,
		TailInflation:       tailInflation,
		DuplicationGain:     dupGain,
		TargetPressureDown:  targetDown,
		TargetPressureUp:    targetUp,
		ActiveSignals:       active,
		ReserveSignals:      reserve,
		WeakActive:          weakActive,
		BestReserve:         bestReserve,
		FastEffMin:          fastEffMin,
		FastQualityPressure: fastQuality,
		FastCarrierPressure: fastCarrier,
		FastTailInflation:   fastTailInfl,
		FastAckBps:          fastAckBps,
		FastDelBps:          fastDelBps,
		FastByKey:           fastByKey,
	}
}

func (rc *runtimeController) updateSignalHistory(now time.Time, s runtimeSignals) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.signalHistory = append(rc.signalHistory, runtimeSignalPoint{
		At:              now,
		ActiveSetHealth: s.ActiveSetHealth,
		EffMin:          s.EffMin,
		QualityPressure: s.QualityPressure,
		TailInflation:   s.TailInflation,
	})
	const maxSignalHistory = 140
	if len(rc.signalHistory) > maxSignalHistory {
		rc.signalHistory = rc.signalHistory[len(rc.signalHistory)-maxSignalHistory:]
	}

	dupLevel := max(rc.client.cfg.PacketDuplicationCount, 1)
	prev := rc.dupEwmaByLevel[dupLevel]
	seen := rc.dupSeenByLevel[dupLevel]
	alpha := 0.20
	if seen < 5 {
		alpha = 0.35
	}
	if seen == 0 {
		rc.dupEwmaByLevel[dupLevel] = s.EffMin
	} else {
		rc.dupEwmaByLevel[dupLevel] = (1-alpha)*prev + alpha*s.EffMin
	}
	rc.dupSeenByLevel[dupLevel] = seen + 1
}

func (rc *runtimeController) updateState(now time.Time, s runtimeSignals) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	healthHist := make([]float64, 0, len(rc.signalHistory))
	effHist := make([]float64, 0, len(rc.signalHistory))
	tailHist := make([]float64, 0, len(rc.signalHistory))
	for _, p := range rc.signalHistory {
		healthHist = append(healthHist, p.ActiveSetHealth)
		effHist = append(effHist, p.EffMin)
		tailHist = append(tailHist, p.TailInflation)
	}

	healthQ25 := quantile(healthHist, 0.25)
	healthQ60 := quantile(healthHist, 0.60)
	effQ25 := quantile(effHist, 0.25)
	effQ60 := quantile(effHist, 0.60)
	tailQ75 := quantile(tailHist, 0.75)

	if healthQ25 <= 0 {
		healthQ25 = 0.40
	}
	if healthQ60 <= 0 {
		healthQ60 = 0.62
	}
	if effQ25 <= 0 {
		effQ25 = 0.45
	}
	if effQ60 <= 0 {
		effQ60 = 0.65
	}
	if tailQ75 <= 0 {
		tailQ75 = 1.10
	}

	severe := (s.ActiveSetHealth <= healthQ25 && s.EffMin <= effQ25) ||
		(s.ActiveCount <= 2 && s.ReserveCount > 0)
	caution := s.ActiveSetHealth <= healthQ60 ||
		s.EffMin <= effQ60 ||
		s.TailInflation >= tailQ75 ||
		s.TargetPressureDown
	stableCandidate := s.ActiveSetHealth >= healthQ60 &&
		s.EffMin >= effQ60 &&
		!s.TargetPressureDown

	if severe {
		rc.degradedVotes++
	} else {
		rc.degradedVotes = 0
	}
	if caution {
		rc.cautiousVotes++
	} else {
		rc.cautiousVotes = 0
	}
	if stableCandidate {
		rc.stableVotes++
	} else {
		rc.stableVotes = 0
	}

	switch rc.state {
	case runtimeStateRecovering:
		if severe && rc.degradedVotes >= 2 {
			rc.state = runtimeStateDegraded
		} else if now.After(rc.recoveringUntil) {
			if rc.stableVotes >= 2 {
				rc.state = runtimeStateStable
			} else if rc.cautiousVotes >= 2 {
				rc.state = runtimeStateCautious
			}
		}
	case runtimeStateStable:
		if rc.degradedVotes >= 2 {
			rc.state = runtimeStateDegraded
		} else if rc.cautiousVotes >= 2 {
			rc.state = runtimeStateCautious
		}
	case runtimeStateCautious:
		if rc.degradedVotes >= 2 {
			rc.state = runtimeStateDegraded
		} else if rc.stableVotes >= 3 {
			rc.state = runtimeStateStable
		}
	case runtimeStateDegraded:
		if rc.stableVotes >= 3 {
			rc.state = runtimeStateRecovering
			rc.recoveringUntil = now.Add(runtimeRecoverObserve)
		} else if rc.cautiousVotes >= 3 {
			rc.state = runtimeStateCautious
		}
	default:
		rc.state = runtimeStateCautious
	}
}

func (rc *runtimeController) decideAction(ctx context.Context, now time.Time, s runtimeSignals, control runtimeWindowAgg, fast runtimeWindowAgg) runtimeActionDecision {
	_ = ctx
	_ = fast
	if s.ActiveCount == 0 {
		return runtimeActionDecision{}
	}

	// If a target change is pending validation, it owns the loop: no other actions until validated.
	rc.mu.RLock()
	pending := rc.pendingTarget
	rc.mu.RUnlock()
	if pending != nil {
		if now.Before(pending.DueAt) {
			return runtimeActionDecision{}
		}
		preEff := pending.PreEffMin
		preAck := pending.PreAckBps
		preDel := pending.PreDelBps
		postEff := s.FastEffMin
		postAck := s.FastAckBps
		postDel := s.FastDelBps

		// Relative (no absolute thresholds): evaluate effect vs the pre-change baseline.
		//
		// Direction-aware:
		// - Step-up: revert on moderate sustained regression (we were trying to increase capacity).
		// - Step-down: revert only on large regression (step-down is protective).
		effDropUp := preEff > 0 && postEff > 0 && postEff < preEff*0.94
		ackDropUp := preAck > 0 && postAck > 0 && postAck < preAck*0.94
		delDropUp := preDel > 0 && postDel > 0 && postDel < preDel*0.94
		effDropDown := preEff > 0 && postEff > 0 && postEff < preEff*0.88
		delDropDown := preDel > 0 && postDel > 0 && postDel < preDel*0.88

		revert := false
		reason := "target_validate_keep"
		if pending.Direction == "up" {
			revert = (effDropUp && delDropUp) || (ackDropUp && delDropUp)
			if revert {
				reason = "target_validate_revert"
			}
		} else { // "down"
			revert = effDropDown && delDropDown
			if revert {
				reason = "target_validate_revert"
			}
		}
		return runtimeActionDecision{
			Kind:    runtimeActionTargetValidate,
			Reason:  reason,
			Details: fmt.Sprintf("dir=%s pre_eff=%.4f post_eff=%.4f pre_ack=%.1f post_ack=%.1f pre_del=%.1f post_del=%.1f", pending.Direction, preEff, postEff, preAck, postAck, preDel, postDel),
		}
	}

	// Priority 1: protect active path.
	if act := rc.decideDemote(now, s); act.Kind != runtimeActionNone {
		return act
	}
	if act := rc.decideFailover(now, s); act.Kind != runtimeActionNone {
		return act
	}

	// Priority 2: restore capacity.
	if act := rc.decidePromoteOrProbe(now, s); act.Kind != runtimeActionNone {
		return act
	}

	// Priority 3: adjust operating point.
	if act := rc.decideTargetAdjust(now, s); act.Kind != runtimeActionNone {
		return act
	}

	// Priority 4: adjust redundancy.
	if act := rc.decideDuplicationAdjust(now, s, control); act.Kind != runtimeActionNone {
		return act
	}

	return runtimeActionDecision{}
}

func (rc *runtimeController) decideDemote(now time.Time, s runtimeSignals) runtimeActionDecision {
	if s.WeakActive == nil {
		return runtimeActionDecision{}
	}
	if s.ActiveCount <= 2 {
		return runtimeActionDecision{}
	}

	rc.mu.RLock()
	state := rc.state
	rc.mu.RUnlock()

	// In STABLE/RECOVERING avoid aggressive churn; only carrier-incompatible candidates can be removed.
	if state == runtimeStateStable || state == runtimeStateRecovering {
		// continue, but will be gated below
	}

	key := s.WeakActive.Key
	if key == "" {
		return runtimeActionDecision{}
	}
	if until := rc.cooldownFor(key); now.Before(until) {
		return runtimeActionDecision{}
	}

	fastSig, hasFast := s.FastByKey[key]
	if !hasFast {
		return runtimeActionDecision{}
	}

	// REFUSED/SERVFAIL are carrier-incompatible class; do not treat as quality decay.
	minCarrierCtrlTotal := float64(8)
	minCarrierFastTotal := float64(2)
	minQualityCtrlTotal := float64(16)
	minQualityFastTotal := float64(2)
	if s.ActiveCount <= 6 {
		minCarrierCtrlTotal = 16
		minCarrierFastTotal = 3
		minQualityCtrlTotal = 24
		minQualityFastTotal = 4
	}
	if s.ActiveCount <= 4 {
		minCarrierCtrlTotal = 24
		minCarrierFastTotal = 4
		minQualityCtrlTotal = 32
		minQualityFastTotal = 5
	}

	carrierDominantCtrl := s.WeakActive.CarrierRatio > s.WeakActive.QualityRatio &&
		s.WeakActive.CarrierRatio > 0 &&
		s.WeakActive.Total >= minCarrierCtrlTotal
	carrierDominantFast := fastSig.CarrierRatio > fastSig.QualityRatio &&
		fastSig.CarrierRatio > 0 &&
		fastSig.Total >= minCarrierFastTotal

	carrierDominant := carrierDominantCtrl && carrierDominantFast
	if carrierDominant {
		if state != runtimeStateDegraded && state != runtimeStateCautious {
			// Still require sustained evidence in other states.
			carrierDominant = false
		}
	}

	qualityRatios := extractQuality(s.ActiveSignals)
	streaks := extractTimeoutStreak(s.ActiveSignals)
	qualityQ90 := quantile(qualityRatios, 0.90)
	streakQ90 := quantile(streaks, 0.90)
	if qualityQ90 <= 0 {
		qualityQ90 = 0.60
	}
	if streakQ90 <= 0 {
		streakQ90 = 3
	}

	qualityDominantCtrl := s.WeakActive.QualityRatio >= qualityQ90 &&
		float64(s.WeakActive.ConsecutiveTimeout) >= maxFloat(2, streakQ90) &&
		s.WeakActive.Total >= minQualityCtrlTotal
	qualityDominantFast := fastSig.QualityRatio >= quantile(extractQualityFromMap(s.FastByKey), 0.75) &&
		fastSig.Total >= minQualityFastTotal

	qualityDominant := qualityDominantCtrl && qualityDominantFast && (state == runtimeStateDegraded || state == runtimeStateCautious)

	// Voting: avoid single-cycle demotion in sparse environments.
	rc.mu.Lock()
	if carrierDominant || qualityDominant {
		rc.demoteVotes[key] = rc.demoteVotes[key] + 1
	} else {
		if rc.demoteVotes[key] > 0 {
			rc.demoteVotes[key] = rc.demoteVotes[key] - 1
		}
	}
	votes := rc.demoteVotes[key]
	rc.mu.Unlock()

	// Sparse pools: require more sustained evidence to avoid over-demotion.
	minVotes := 2
	if s.ActiveCount <= 6 {
		minVotes = 3
	}
	if s.ActiveCount <= 4 {
		minVotes = 4
	}
	if votes < minVotes {
		return runtimeActionDecision{}
	}

	// Reset votes on decision to prevent repeat firing.
	rc.mu.Lock()
	rc.demoteVotes[key] = 0
	rc.mu.Unlock()

	if carrierDominant {
		return runtimeActionDecision{
			Kind:    runtimeActionDemote,
			Reason:  "carrier_incompatible_refused_servfail",
			Details: fmt.Sprintf("key=%s carrier_ratio=%.3f quality_ratio=%.3f", key, s.WeakActive.CarrierRatio, s.WeakActive.QualityRatio),
			Key:     key,
		}
	}

	if qualityDominant {
		return runtimeActionDecision{
			Kind:    runtimeActionDemote,
			Reason:  "quality_decay_timeout_tail",
			Details: fmt.Sprintf("key=%s quality_ratio=%.3f timeout_streak=%d", key, s.WeakActive.QualityRatio, s.WeakActive.ConsecutiveTimeout),
			Key:     key,
		}
	}

	return runtimeActionDecision{}
}

func (rc *runtimeController) decideFailover(now time.Time, s runtimeSignals) runtimeActionDecision {
	c := rc.client
	if c == nil {
		return runtimeActionDecision{}
	}

	rc.mu.RLock()
	state := rc.state
	holdUntil := rc.failoverHoldUntil
	degradedVotes := rc.degradedVotes
	stableVotes := rc.stableVotes
	tightenV := rc.failoverTightenV
	relaxV := rc.failoverRelaxV
	lastChangeAt := rc.lastFailoverChangeAt
	rc.mu.RUnlock()
	if !holdUntil.IsZero() && now.Before(holdUntil) {
		return runtimeActionDecision{}
	}

	thr := c.streamResolverFailoverResendThreshold
	cool := c.streamResolverFailoverCooldown

	desiredThr := rc.baseFailoverThr
	desiredCool := rc.baseFailoverCool

	if state == runtimeStateDegraded {
		// Require sustained degraded state and fast-window confirmation to avoid thrash on spikes.
		if degradedVotes < 3 {
			return runtimeActionDecision{}
		}
		tailHist := rc.tailHistory()
		tailQ75 := quantile(tailHist, 0.75)
		if tailQ75 <= 0 {
			tailQ75 = 1.10
		}
		confirm := s.FastTailInflation >= tailQ75 || s.FastQualityPressure >= s.QualityPressure || s.TargetPressureDown
		rc.mu.Lock()
		rc.failoverRelaxV = 0
		if confirm {
			rc.failoverTightenV++
		} else if rc.failoverTightenV > 0 {
			rc.failoverTightenV--
		}
		tightenV = rc.failoverTightenV
		rc.mu.Unlock()
		if tightenV < 2 {
			return runtimeActionDecision{}
		}
		desiredThr = max(1, rc.baseFailoverThr-1)
		desiredCool = maxDuration(600*time.Millisecond, time.Duration(float64(rc.baseFailoverCool)*0.75))
		if s.ActiveCount <= 4 && s.ReserveReadiness > 0 {
			desiredThr = 1
			desiredCool = maxDuration(450*time.Millisecond, time.Duration(float64(rc.baseFailoverCool)*0.60))
		}
	} else if state == runtimeStateStable && stableVotes >= 4 && s.ActiveSetHealth >= quantile(rc.healthHistory(), 0.60) {
		// Relax only after sustained stability.
		if !lastChangeAt.IsZero() && now.Sub(lastChangeAt) < 3*time.Minute {
			return runtimeActionDecision{}
		}
		rc.mu.Lock()
		rc.failoverTightenV = 0
		if stableVotes >= 6 && s.FastTailInflation <= quantile(rc.tailHistory(), 0.60) && !s.TargetPressureDown {
			rc.failoverRelaxV++
		} else if rc.failoverRelaxV > 0 {
			rc.failoverRelaxV--
		}
		relaxV = rc.failoverRelaxV
		rc.mu.Unlock()
		if relaxV < 3 {
			return runtimeActionDecision{}
		}
		desiredThr = max(rc.baseFailoverThr, thr)
		desiredCool = maxDuration(rc.baseFailoverCool, cool)
	}

	if thr != desiredThr || math.Abs(cool.Seconds()-desiredCool.Seconds()) > 0.15 {
		return runtimeActionDecision{
			Kind:    runtimeActionFailover,
			Reason:  "state_driven_failover_sensitivity",
			Details: fmt.Sprintf("thr:%d->%d cool:%.2fs->%.2fs", thr, desiredThr, cool.Seconds(), desiredCool.Seconds()),
		}
	}

	return runtimeActionDecision{}
}

func (rc *runtimeController) decidePromoteOrProbe(now time.Time, s runtimeSignals) runtimeActionDecision {
	if s.ReserveCount == 0 {
		return runtimeActionDecision{}
	}
	rc.mu.RLock()
	state := rc.state
	rc.mu.RUnlock()

	rc.mu.RLock()
	demotions := len(pruneTimes(append([]time.Time(nil), rc.demoteTimes...), now.Add(-90*time.Second)))
	rc.mu.RUnlock()

	needCapacity := state == runtimeStateDegraded || state == runtimeStateCautious ||
		s.ActiveCount <= 3 ||
		s.ActiveSetHealth <= quantile(rc.healthHistory(), 0.25) ||
		demotions >= 2
	if !needCapacity {
		return runtimeActionDecision{}
	}

	// Budget-limited reserve probing.
	if !rc.canSpendProbe(now) {
		return runtimeActionDecision{}
	}

	candidate := rc.pickReserveCandidate(now, s)
	if candidate == "" {
		return runtimeActionDecision{}
	}
	return runtimeActionDecision{
		Kind:    runtimeActionProbeReserve,
		Reason:  "restore_capacity_with_conditional_probe",
		Details: fmt.Sprintf("candidate=%s", candidate),
		Key:     candidate,
	}
}

func (rc *runtimeController) decideTargetAdjust(now time.Time, s runtimeSignals) runtimeActionDecision {
	c := rc.client
	if c == nil {
		return runtimeActionDecision{}
	}

	rc.mu.RLock()
	hasPending := rc.pendingTarget != nil
	rc.mu.RUnlock()
	if hasPending {
		return runtimeActionDecision{}
	}
	rc.mu.RLock()
	stepUpFrozen := now.Before(rc.stepUpFreezeUntil)
	state := rc.state
	rc.mu.RUnlock()

	// Fast-window confirmation: avoid acting on a single control-window artifact.
	downConfirmed := s.FastEffMin > 0 && s.EffMin > 0 && s.FastEffMin <= s.EffMin*0.995
	upConfirmed := s.FastEffMin > 0 && s.EffMin > 0 && s.FastEffMin >= s.EffMin*0.995

	if s.TargetPressureDown && downConfirmed {
		return runtimeActionDecision{
			Kind:    runtimeActionTarget,
			Reason:  "relative_efficiency_drop_with_quality_pressure",
			Details: fmt.Sprintf("tx_rel=%.3f rx_rel=%.3f quality=%.3f tail=%.2f", s.TxEffRel, s.RxEffRel, s.QualityPressure, s.TailInflation),
		}
	}

	if !stepUpFrozen && s.TargetPressureUp && upConfirmed && (state == runtimeStateStable || state == runtimeStateRecovering) {
		return runtimeActionDecision{
			Kind:    runtimeActionTarget,
			Reason:  "sustained_high_relative_efficiency",
			Details: fmt.Sprintf("tx_rel=%.3f rx_rel=%.3f", s.TxEffRel, s.RxEffRel),
		}
	}
	return runtimeActionDecision{}
}

func (rc *runtimeController) decideDuplicationAdjust(now time.Time, s runtimeSignals, control runtimeWindowAgg) runtimeActionDecision {
	c := rc.client
	if c == nil || control.LogicalPackets == 0 {
		return runtimeActionDecision{}
	}
	rc.mu.RLock()
	state := rc.state
	rc.mu.RUnlock()

	currentDup := max(c.cfg.PacketDuplicationCount, 1)
	maxDup := 5
	if c.cfg.SetupPacketDuplicationCount > maxDup {
		maxDup = c.cfg.SetupPacketDuplicationCount
	}

	// Fast-window confirmation prevents duplication thrash on transient loss spikes.
	fastConfirmsLoss := s.FastQualityPressure > 0 && s.FastQualityPressure >= s.QualityPressure*0.95

	if state == runtimeStateDegraded && fastConfirmsLoss &&
		s.QualityPressure >= quantile(extractQuality(s.ActiveSignals), 0.50) &&
		s.CarrierPressure <= quantile(extractCarrier(s.ActiveSignals), 0.75) &&
		currentDup < maxDup &&
		(s.DuplicationGain >= -0.01 || rc.dupSeenByLevel[currentDup-1] == 0) {
		return runtimeActionDecision{
			Kind:    runtimeActionDuplication,
			Reason:  "degraded_quality_with_non_carrier_loss",
			Details: fmt.Sprintf("dup=%d gain=%.4f quality=%.3f", currentDup, s.DuplicationGain, s.QualityPressure),
		}
	}

	if currentDup > 1 && state != runtimeStateDegraded && s.DuplicationGain < -0.01 {
		return runtimeActionDecision{
			Kind:    runtimeActionDuplication,
			Reason:  "negative_duplication_gain",
			Details: fmt.Sprintf("dup=%d gain=%.4f", currentDup, s.DuplicationGain),
		}
	}
	return runtimeActionDecision{}
}

func (rc *runtimeController) applyAction(ctx context.Context, now time.Time, action runtimeActionDecision, s runtimeSignals) {
	c := rc.client
	if c == nil {
		return
	}

	var applied bool
	switch action.Kind {
	case runtimeActionDemote:
		applied = rc.applyDemote(now, action, s)
	case runtimeActionFailover:
		applied = rc.applyFailover(now, action, s)
	case runtimeActionProbeReserve:
		applied = rc.applyProbeAndMaybePromote(ctx, now, action)
	case runtimeActionTarget:
		applied = rc.applyTargetAdjust(now, action, s)
	case runtimeActionTargetValidate:
		applied = rc.applyTargetValidation(now, action)
	case runtimeActionDuplication:
		applied = rc.applyDuplicationAdjust(now, action, s)
	default:
		return
	}
	if !applied {
		return
	}

	rc.mu.Lock()
	rc.lastActionKind = action.Kind
	rc.lastActionReason = action.Reason
	rc.lastActionAt = now
	rc.nextActionAt = now.Add(actionCooldownFor(action.Kind))
	rc.state = runtimeStateRecovering
	rc.recoveringUntil = now.Add(runtimeRecoverObserve)
	rc.mu.Unlock()

	rc.emitEvent(action.Kind, action.Reason, action.Details)
}

func (rc *runtimeController) applyDemote(now time.Time, action runtimeActionDecision, s runtimeSignals) bool {
	c := rc.client
	key := action.Key
	if key == "" {
		return false
	}

	ok := c.balancer.SetConnectionValidityWithLog(key, false, false)
	if !ok {
		return false
	}

	rc.mu.Lock()
	rc.resolverCooldownUntil[key] = now.Add(runtimeResolverCooldown)
	// Record demotions as an event-driven trigger for reserve probing.
	rc.demoteTimes = append(rc.demoteTimes, now)
	rc.demoteTimes = pruneTimes(rc.demoteTimes, now.Add(-90*time.Second))
	// Small budget bump on demote (bounded by later refill).
	if rc.probeBudget < 3 {
		rc.probeBudget++
	}
	if strings.Contains(action.Reason, "carrier_incompatible") {
		rc.quarantineUntil[key] = now.Add(runtimeCarrierQuarantine)
	}
	rc.mu.Unlock()

	c.log.Warnf("ADAPT action=%s reason=%s %s", action.Kind, action.Reason, action.Details)
	return true
}

func (rc *runtimeController) applyFailover(now time.Time, action runtimeActionDecision, s runtimeSignals) bool {
	c := rc.client
	if c == nil {
		return false
	}
	_ = now
	_ = s

	thr := c.streamResolverFailoverResendThreshold
	cool := c.streamResolverFailoverCooldown

	rc.mu.RLock()
	state := rc.state
	rc.mu.RUnlock()

	desiredThr := rc.baseFailoverThr
	desiredCool := rc.baseFailoverCool
	if state == runtimeStateDegraded {
		desiredThr = max(1, rc.baseFailoverThr-1)
		desiredCool = maxDuration(600*time.Millisecond, time.Duration(float64(rc.baseFailoverCool)*0.75))
		if s.ActiveCount <= 4 && s.ReserveReadiness > 0 {
			desiredThr = 1
			desiredCool = maxDuration(450*time.Millisecond, time.Duration(float64(rc.baseFailoverCool)*0.60))
		}
	}

	if thr == desiredThr && math.Abs(cool.Seconds()-desiredCool.Seconds()) <= 0.15 {
		return false
	}

	c.streamResolverFailoverResendThreshold = desiredThr
	c.streamResolverFailoverCooldown = desiredCool
	c.balancer.SetStreamFailoverConfig(desiredThr, desiredCool)
	rc.mu.Lock()
	rc.failoverHoldUntil = now.Add(90 * time.Second)
	rc.lastFailoverChangeAt = now
	rc.failoverTightenV = 0
	rc.failoverRelaxV = 0
	rc.mu.Unlock()
	c.log.Warnf("ADAPT action=%s reason=%s %s", action.Kind, action.Reason, action.Details)
	return true
}

func (rc *runtimeController) applyProbeAndMaybePromote(ctx context.Context, now time.Time, action runtimeActionDecision) bool {
	c := rc.client
	key := action.Key
	if key == "" {
		return false
	}

	rc.mu.Lock()
	rc.refillProbeBudgetLocked(now)
	if rc.probeBudget <= 0 {
		rc.mu.Unlock()
		return false
	}
	rc.probeBudget--
	rc.mu.Unlock()

	conn, ok := c.balancer.GetConnectionByKey(key)
	if !ok || conn.Key == "" {
		return false
	}

	rc.mu.RLock()
	if until := rc.quarantineUntil[key]; now.Before(until) {
		rc.mu.RUnlock()
		return false
	}
	if until := rc.reserveProbeAfter[key]; now.Before(until) {
		rc.mu.RUnlock()
		return false
	}
	rc.mu.RUnlock()

	dial := rc.dialTransport
	probe := rc.stage0Probe
	if dial == nil || probe == nil {
		return false
	}

	transport, err := dial(conn.ResolverLabel)
	if err != nil {
		return false
	}
	defer transport.conn.Close()

	timeout := 1500 * time.Millisecond
	if c.tunnelPacketTimeout > 0 && c.tunnelPacketTimeout < timeout {
		timeout = c.tunnelPacketTimeout
	}
	out := probe(ctx, conn, transport, timeout)

	rc.mu.Lock()
	rc.reserveProbeAfter[key] = now.Add(runtimeProbeCooldown)
	rc.mu.Unlock()

	if !out.ok {
		carrierBlocked := strings.Contains(strings.ToUpper(out.subReason), "REFUSED") ||
			strings.Contains(strings.ToUpper(out.subReason), "SERVFAIL")
		if carrierBlocked {
			rc.mu.Lock()
			rc.quarantineUntil[key] = now.Add(runtimeCarrierQuarantine)
			rc.mu.Unlock()
		}
		reason := "reserve_probe_failed"
		if carrierBlocked {
			reason = "reserve_probe_carrier_incompatible"
		}
		rc.emitEvent(runtimeActionProbeReserve, reason, fmt.Sprintf("candidate=%s fail=%s sub=%s", key, out.failReason, out.subReason))
		c.log.Warnf("ADAPT action=%s reason=%s candidate=%s fail=%s sub=%s", runtimeActionProbeReserve, reason, key, out.failReason, out.subReason)
		return true
	}

	upload := max(c.syncedUploadMTU, minUploadMTUFloor)
	download := max(c.syncedDownloadMTU, minDownloadMTUFloor)
	uploadChars := c.encodedCharsForPayload(upload)

	_ = c.balancer.SetConnectionMTU(key, upload, uploadChars, download)
	if !c.balancer.SetConnectionValidityWithLog(key, true, true) {
		return false
	}
	c.balancer.SeedConservativeStats(key)

	rc.mu.Lock()
	rc.resolverCooldownUntil[key] = now.Add(runtimeResolverCooldown)
	delete(rc.quarantineUntil, key)
	rc.mu.Unlock()

	c.log.Warnf("ADAPT action=%s reason=reserve_probe_pass_promoted key=%s", runtimeActionPromote, key)
	rc.emitEvent(runtimeActionPromote, "reserve_probe_pass_promoted", fmt.Sprintf("key=%s", key))
	return true
}

func (rc *runtimeController) applyTargetAdjust(now time.Time, action runtimeActionDecision, s runtimeSignals) bool {
	c := rc.client
	if c == nil {
		return false
	}

	currentUp := max(c.syncedUploadMTU, minUploadMTUFloor)
	currentDown := max(c.syncedDownloadMTU, minDownloadMTUFloor)

	minUp := max(minUploadMTUFloor, 16)
	minDown := max(minDownloadMTUFloor, 64)

	maxUp := c.cfg.MaxUploadMTU
	if maxUp <= 0 {
		maxUp = max(512, currentUp+160)
	}
	maxDown := c.cfg.MaxDownloadMTU
	if maxDown <= 0 {
		maxDown = max(1800, currentDown+320)
	}

	up := currentUp
	down := currentDown
	changed := false

	rc.mu.RLock()
	stepUpFrozen := now.Before(rc.stepUpFreezeUntil)
	rc.mu.RUnlock()

	if s.TargetPressureDown {
		upStep := max(1, int(math.Ceil(float64(currentUp)*0.12)))
		downStep := max(2, int(math.Ceil(float64(currentDown)*0.15)))
		up = clampInt(currentUp-upStep, minUp, maxUp)
		down = clampInt(currentDown-downStep, minDown, maxDown)
		changed = up != currentUp || down != currentDown
		if changed {
			rc.mu.Lock()
			rc.stepUpFreezeUntil = now.Add(runtimeStepUpFreeze)
			rc.mu.Unlock()
		}
	} else if s.TargetPressureUp && !stepUpFrozen {
		upStep := max(1, int(math.Ceil(float64(currentUp)*0.04)))
		downStep := max(2, int(math.Ceil(float64(currentDown)*0.06)))
		up = clampInt(currentUp+upStep, minUp, maxUp)
		down = clampInt(currentDown+downStep, minDown, maxDown)
		changed = up != currentUp || down != currentDown
	}

	if !changed {
		return false
	}

	c.applySyncedMTUState(up, down, c.encodedCharsForPayload(up))
	rc.mu.Lock()
	dir := "up"
	if s.TargetPressureDown {
		dir = "down"
	}
	rc.pendingTarget = &pendingTargetChange{
		Direction: dir,
		OldUp:     currentUp,
		OldDown:   currentDown,
		NewUp:     up,
		NewDown:   down,
		AppliedAt: now,
		DueAt:     now.Add(20 * time.Second),
		PreEffMin: s.EffMin,
		PreAckBps: s.ControlAckBps,
		PreDelBps: s.ControlDelBps,
	}
	rc.mu.Unlock()
	c.log.Warnf("ADAPT action=%s reason=%s up:%d->%d down:%d->%d", action.Kind, action.Reason, currentUp, up, currentDown, down)
	return true
}

func (rc *runtimeController) applyTargetValidation(now time.Time, action runtimeActionDecision) bool {
	c := rc.client
	if c == nil {
		return false
	}

	rc.mu.Lock()
	p := rc.pendingTarget
	rc.pendingTarget = nil
	rc.mu.Unlock()
	if p == nil {
		return false
	}

	if action.Reason == "target_validate_revert" {
		c.applySyncedMTUState(p.OldUp, p.OldDown, c.encodedCharsForPayload(p.OldUp))
		rc.mu.Lock()
		rc.stepUpFreezeUntil = now.Add(2 * runtimeStepUpFreeze)
		rc.mu.Unlock()
		c.log.Warnf("ADAPT action=%s reason=%s revert up:%d->%d down:%d->%d %s", action.Kind, action.Reason, p.NewUp, p.OldUp, p.NewDown, p.OldDown, action.Details)
		return true
	}

	// Keep: no further action, but validation counts as a controller action (cooldown/observe).
	c.log.Warnf("ADAPT action=%s reason=%s keep up=%d down=%d %s", action.Kind, action.Reason, p.NewUp, p.NewDown, action.Details)
	return true
}

func (rc *runtimeController) applyDuplicationAdjust(now time.Time, action runtimeActionDecision, s runtimeSignals) bool {
	c := rc.client
	if c == nil {
		return false
	}
	_ = now

	curData := max(c.cfg.PacketDuplicationCount, 1)
	curSetup := max(c.cfg.SetupPacketDuplicationCount, curData)
	maxDup := 5
	if curSetup > maxDup {
		maxDup = curSetup
	}
	newData := curData

	if strings.Contains(action.Reason, "negative_duplication_gain") && curData > 1 {
		newData = curData - 1
	} else if strings.Contains(action.Reason, "degraded_quality") && curData < maxDup && s.CarrierPressure <= quantile(extractCarrier(s.ActiveSignals), 0.75) {
		newData = curData + 1
	}

	if newData == curData {
		return false
	}
	newSetup := max(curSetup, newData)
	if newSetup > 5 {
		newSetup = 5
	}

	c.cfg.PacketDuplicationCount = newData
	c.cfg.SetupPacketDuplicationCount = newSetup
	c.log.Warnf("ADAPT action=%s reason=%s data_dup:%d->%d setup_dup:%d->%d", action.Kind, action.Reason, curData, newData, curSetup, newSetup)
	return true
}

func (rc *runtimeController) pickReserveCandidate(now time.Time, s runtimeSignals) string {
	if len(s.ReserveSignals) == 0 {
		return ""
	}
	weakScore := -1.0
	if s.WeakActive != nil {
		weakScore = s.WeakActive.Score
	}
	bestKey := ""
	bestScore := -100.0

	for _, cand := range s.ReserveSignals {
		if cand.Key == "" {
			continue
		}
		rc.mu.RLock()
		quUntil := rc.quarantineUntil[cand.Key]
		probeAfter := rc.reserveProbeAfter[cand.Key]
		cooldown := rc.resolverCooldownUntil[cand.Key]
		rc.mu.RUnlock()
		if now.Before(quUntil) || now.Before(probeAfter) || now.Before(cooldown) {
			continue
		}

		score := cand.Score
		if cand.Total < 1 {
			// Unknown reserve gets neutral-but-low priority.
			score = -0.10
		}
		if score > bestScore {
			bestScore = score
			bestKey = cand.Key
		}
	}

	if bestKey == "" {
		return ""
	}
	// Promote only if it is meaningfully better than current weakest active or active pool is sparse.
	if s.ActiveCount <= 3 || weakScore < -0.05 || bestScore >= weakScore+0.05 {
		return bestKey
	}
	return ""
}

func (rc *runtimeController) computeReserveReadiness(now time.Time, reserve []Connection) float64 {
	if len(reserve) == 0 {
		return 0
	}
	ready := 0
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	for _, r := range reserve {
		if r.Key == "" {
			continue
		}
		if until := rc.quarantineUntil[r.Key]; now.Before(until) {
			continue
		}
		if until := rc.reserveProbeAfter[r.Key]; now.Before(until) {
			continue
		}
		ready++
	}
	return float64(ready) / float64(len(reserve))
}

func (rc *runtimeController) emitEvent(kind runtimeActionKind, reason string, details string) {
	if rc == nil {
		return
	}
	ev := runtimeControllerEvent{
		At:      time.Now().Format("15:04:05"),
		Action:  string(kind),
		Reason:  reason,
		Details: details,
	}

	rc.mu.Lock()
	rc.events = append(rc.events, ev)
	if len(rc.events) > 16 {
		rc.events = rc.events[len(rc.events)-16:]
	}
	rc.mu.Unlock()

	if rc.client != nil && rc.client.ui != nil {
		rc.client.ui.AddRuntimeEvent(ev)
	}
}

func (rc *runtimeController) cooldownFor(key string) time.Time {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.resolverCooldownUntil[key]
}

func (rc *runtimeController) healthHistory() []float64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	out := make([]float64, 0, len(rc.signalHistory))
	for _, p := range rc.signalHistory {
		out = append(out, p.ActiveSetHealth)
	}
	return out
}

func (rc *runtimeController) effHistory() []float64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	out := make([]float64, 0, len(rc.signalHistory))
	for _, p := range rc.signalHistory {
		out = append(out, p.EffMin)
	}
	return out
}

func (rc *runtimeController) tailHistory() []float64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	out := make([]float64, 0, len(rc.signalHistory))
	for _, p := range rc.signalHistory {
		out = append(out, p.TailInflation)
	}
	return out
}

func (rc *runtimeController) duplicationGain(level int, currentEff float64) float64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	if level <= 1 {
		return 0
	}
	current, okCur := rc.dupEwmaByLevel[level]
	lower, okLower := rc.dupEwmaByLevel[level-1]
	if !okCur && !okLower {
		return 0
	}
	if !okCur {
		current = currentEff
	}
	if !okLower {
		return 0
	}
	return current - lower
}

func actionCooldownFor(kind runtimeActionKind) time.Duration {
	switch kind {
	case runtimeActionProbeReserve, runtimeActionPromote, runtimeActionDemote:
		return 12 * time.Second
	case runtimeActionTarget, runtimeActionDuplication, runtimeActionFailover:
		return 20 * time.Second
	default:
		return runtimeDefaultCooldown
	}
}

func toResolverSignal(key string, rd *runtimeResolverDelta, baselineRtt90 float64) runtimeResolverSignal {
	s := runtimeResolverSignal{Key: key}
	if rd == nil {
		s.Score = -0.10
		return s
	}
	total := float64(rd.OK + rd.Timeout + rd.Refused + rd.Servfail + rd.NoTunnel + rd.Other)
	s.Total = total
	if total <= 0 {
		s.ConsecutiveFail = rd.ConsecutiveFail
		s.ConsecutiveTimeout = rd.ConsecutiveTimeout
		s.RTTP90 = rd.RTTP90ms
		s.Score = -0.10
		return s
	}

	s.OKRatio = float64(rd.OK) / total
	s.TimeoutRatio = float64(rd.Timeout) / total
	s.QualityRatio = float64(rd.Timeout+rd.NoTunnel+rd.Other) / total
	s.CarrierRatio = float64(rd.Refused+rd.Servfail) / total
	s.ConsecutiveFail = rd.ConsecutiveFail
	s.ConsecutiveTimeout = rd.ConsecutiveTimeout
	s.RTTP90 = rd.RTTP90ms

	score := s.OKRatio - s.QualityRatio - 0.70*s.CarrierRatio
	if rd.ConsecutiveTimeout > 0 {
		score -= minFloat(0.25, float64(rd.ConsecutiveTimeout)/12.0)
	}
	if rd.RTTP90ms > 0 && baselineRtt90 > 0 {
		infl := rd.RTTP90ms / baselineRtt90
		if infl > 1 {
			score -= minFloat(0.20, (infl-1.0)*0.08)
		}
	}
	s.Score = clamp(score, -1.0, 1.0)
	return s
}

func pickWeakActive(active []runtimeResolverSignal, qualityQ75, carrierQ75, streakQ75 float64) *runtimeResolverSignal {
	if len(active) == 0 {
		return nil
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].Score < active[j].Score
	})
	for i := range active {
		a := active[i]
		if a.Total < runtimeMinResolverObs {
			continue
		}
		if a.CarrierRatio >= carrierQ75 || a.QualityRatio >= qualityQ75 || float64(a.ConsecutiveTimeout) >= streakQ75 {
			v := a
			return &v
		}
	}
	v := active[0]
	if v.Total >= runtimeMinResolverObs {
		return &v
	}
	return nil
}

func pickBestReserve(reserve []runtimeResolverSignal) *runtimeResolverSignal {
	if len(reserve) == 0 {
		return nil
	}
	sort.Slice(reserve, func(i, j int) bool {
		return reserve[i].Score > reserve[j].Score
	})
	v := reserve[0]
	return &v
}

func snapshotResolverMap(in []telemetry.ResolverSnapshot) map[string]telemetry.ResolverSnapshot {
	out := make(map[string]telemetry.ResolverSnapshot, len(in))
	for _, r := range in {
		out[r.Key] = r
	}
	return out
}

func diffU64(curr, prev uint64) uint64 {
	if curr >= prev {
		return curr - prev
	}
	return 0
}

func ratioU64(num, den uint64) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func extractQuality(in []runtimeResolverSignal) []float64 {
	out := make([]float64, 0, len(in))
	for _, v := range in {
		out = append(out, v.QualityRatio)
	}
	return out
}

func extractCarrier(in []runtimeResolverSignal) []float64 {
	out := make([]float64, 0, len(in))
	for _, v := range in {
		out = append(out, v.CarrierRatio)
	}
	return out
}

func extractTimeoutStreak(in []runtimeResolverSignal) []float64 {
	out := make([]float64, 0, len(in))
	for _, v := range in {
		out = append(out, float64(v.ConsecutiveTimeout))
	}
	return out
}

func extractQualityFromMap(in map[string]runtimeResolverSignal) []float64 {
	if len(in) == 0 {
		return nil
	}
	out := make([]float64, 0, len(in))
	for _, v := range in {
		out = append(out, v.QualityRatio)
	}
	return out
}

func quantile(vals []float64, q float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	if q <= 0 {
		q = 0
	}
	if q >= 1 {
		q = 1
	}
	cp := append([]float64(nil), vals...)
	sort.Float64s(cp)
	if len(cp) == 1 {
		return cp[0]
	}
	pos := q * float64(len(cp)-1)
	i := int(math.Floor(pos))
	j := int(math.Ceil(pos))
	if i == j {
		return cp[i]
	}
	frac := pos - float64(i)
	return cp[i]*(1-frac) + cp[j]*frac
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func clamp(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func clampInt(v, minV, maxV int) int {
	if maxV < minV {
		maxV = minV
	}
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func pruneTimes(in []time.Time, cutoff time.Time) []time.Time {
	if len(in) == 0 {
		return in
	}
	out := in[:0]
	for _, t := range in {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func (rc *runtimeController) refillProbeBudgetLocked(now time.Time) {
	if rc.probeBudgetResetAt.IsZero() {
		rc.probeBudgetResetAt = now.Add(60 * time.Second)
	}
	if now.Before(rc.probeBudgetResetAt) {
		return
	}
	rc.probeBudget = 2
	rc.probeBudgetResetAt = now.Add(60 * time.Second)
}

func (rc *runtimeController) canSpendProbe(now time.Time) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.refillProbeBudgetLocked(now)
	return rc.probeBudget > 0
}
