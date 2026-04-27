package client

import (
	"context"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

func newTestController() (*runtimeController, *Client) {
	c := &Client{
		cfg: config.ClientConfig{
			PacketDuplicationCount:      2,
			SetupPacketDuplicationCount: 2,
			MaxUploadMTU:                200,
			MaxDownloadMTU:              2000,
		},
		syncedUploadMTU:     80,
		syncedDownloadMTU:   400,
		mtuCryptoOverhead:   0,
		uploadCompression:   0,
		downloadCompression: 0,
	}
	c.log = logger.New("test", "error")
	c.balancer = NewBalancer(BalancingRoundRobinDefault, c.log)
	c.udpBufferPool.New = func() any { return make([]byte, RuntimeUDPReadBufferSize) }
	codec, _ := security.NewCodec(1, "testkey")
	c.codec = codec
	// Defaults (copied from runtime path expectations)
	c.streamResolverFailoverResendThreshold = 5
	c.streamResolverFailoverCooldown = 10 * time.Second

	rc := newRuntimeController(c)
	return rc, c
}

func TestPromoteProbeTriggeredOnMultiDemotion(t *testing.T) {
	rc, _ := newTestController()
	now := time.Now()
	rc.mu.Lock()
	rc.state = runtimeStateCautious
	rc.demoteTimes = []time.Time{now.Add(-30 * time.Second), now.Add(-10 * time.Second)}
	rc.probeBudget = 1
	rc.probeBudgetResetAt = now.Add(60 * time.Second)
	rc.mu.Unlock()

	s := runtimeSignals{
		ActiveCount:      6,
		ReserveCount:     10,
		ActiveSetHealth:  0.40,
		ReserveReadiness: 0.90,
		ReserveSignals: []runtimeResolverSignal{
			{Key: "r1", Score: 0.20, Total: 3},
		},
	}

	act := rc.decidePromoteOrProbe(now, s)
	if act.Kind != runtimeActionProbeReserve {
		t.Fatalf("expected PROBE_RESERVE, got %s", act.Kind)
	}
}

func TestApplyProbePromotesOnSuccess(t *testing.T) {
	rc, c := newTestController()
	now := time.Now()

	conn := &Connection{
		Domain:        "example.com",
		ResolverLabel: "127.0.0.1:53",
		Key:           "r1",
		IsValid:       false,
	}
	c.balancer.SetConnections([]*Connection{conn})

	rc.mu.Lock()
	rc.state = runtimeStateCautious
	rc.probeBudget = 1
	rc.probeBudgetResetAt = now.Add(60 * time.Second)
	rc.mu.Unlock()

	rc.dialTransport = func(_ string) (*udpQueryTransport, error) {
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return nil, err
		}
		return &udpQueryTransport{conn: u}, nil
	}
	rc.stage0Probe = func(_ context.Context, _ Connection, _ *udpQueryTransport, _ time.Duration) stage0Outcome {
		return stage0Outcome{ok: true}
	}

	ok := rc.applyProbeAndMaybePromote(context.Background(), now, runtimeActionDecision{Kind: runtimeActionProbeReserve, Key: "r1"})
	if !ok {
		t.Fatalf("expected applyProbeAndMaybePromote to return true")
	}
	if got := len(c.balancer.ActiveConnections()); got != 1 {
		t.Fatalf("expected 1 active connection after promotion, got %d", got)
	}
}

func TestTargetValidationEmitsValidateAction(t *testing.T) {
	rc, _ := newTestController()
	now := time.Now()
	rc.mu.Lock()
	rc.pendingTarget = &pendingTargetChange{
		Direction: "down",
		PreEffMin: 0.50,
		PreAckBps: 1000,
		PreDelBps: 1000,
		DueAt:     now.Add(-time.Second),
	}
	rc.mu.Unlock()

	s := runtimeSignals{
		ActiveCount:   5,
		FastEffMin:    0.30,
		FastAckBps:    800,
		FastDelBps:    800, // 20% drop -> revert
		FastByKey:     map[string]runtimeResolverSignal{},
		ActiveSignals: []runtimeResolverSignal{},
	}

	act := rc.decideAction(nil, now, s, runtimeWindowAgg{}, runtimeWindowAgg{})
	if act.Kind != runtimeActionTargetValidate {
		t.Fatalf("expected TARGET_VALIDATE, got %s", act.Kind)
	}
	if act.Reason != "target_validate_revert" {
		t.Fatalf("expected revert, got %s", act.Reason)
	}
}

func TestFailoverAdjustRequiresSustainedDegraded(t *testing.T) {
	rc, c := newTestController()
	now := time.Now()
	rc.mu.Lock()
	rc.state = runtimeStateDegraded
	rc.degradedVotes = 3
	rc.failoverHoldUntil = now.Add(-time.Second)
	rc.mu.Unlock()

	s := runtimeSignals{
		ActiveCount:         4,
		ReserveReadiness:    0.8,
		FastTailInflation:   2.0,
		FastQualityPressure: 0.7,
		QualityPressure:     0.3,
		TargetPressureDown:  true,
	}

	// First call builds hysteresis votes; second call should trigger.
	_ = rc.decideFailover(now, s)
	act := rc.decideFailover(now.Add(5*time.Second), s)
	if act.Kind != runtimeActionFailover {
		t.Fatalf("expected FAILOVER_ADJUST, got %s", act.Kind)
	}

	// Ensure action would change something in client state.
	if c.streamResolverFailoverResendThreshold <= 0 {
		t.Fatalf("unexpected failover threshold")
	}
}

func TestDuplicationAdjustTriggersInDegradedWithNonCarrierLoss(t *testing.T) {
	rc, c := newTestController()
	now := time.Now()
	rc.mu.Lock()
	rc.state = runtimeStateDegraded
	rc.mu.Unlock()

	c.cfg.PacketDuplicationCount = 1
	c.cfg.SetupPacketDuplicationCount = 2

	s := runtimeSignals{
		ActiveCount:         6,
		QualityPressure:     0.6,
		CarrierPressure:     0.0,
		DuplicationGain:     0.00,
		FastQualityPressure: 0.6,
		ActiveSignals:       []runtimeResolverSignal{{QualityRatio: 0.6, CarrierRatio: 0.0}},
		ReserveReadiness:    0.8,
	}

	control := runtimeWindowAgg{LogicalPackets: 10}
	act := rc.decideDuplicationAdjust(now, s, control)
	if act.Kind != runtimeActionDuplication {
		t.Fatalf("expected DUPLICATION_ADJUST, got %s", act.Kind)
	}
}

func TestTargetAdjustRequiresFastConfirmation(t *testing.T) {
	rc, _ := newTestController()
	now := time.Now()
	rc.mu.Lock()
	rc.state = runtimeStateStable
	rc.mu.Unlock()

	s := runtimeSignals{
		ActiveCount:        6,
		TargetPressureDown: true,
		EffMin:             0.50,
		FastEffMin:         0.60, // no down-confirmation
	}
	act := rc.decideTargetAdjust(now, s)
	if act.Kind != "" && act.Kind != runtimeActionNone {
		t.Fatalf("expected NONE when fast window does not confirm, got %s", act.Kind)
	}
}

func TestDemoteIsLessTriggerHappyInSparsePools(t *testing.T) {
	rc, _ := newTestController()
	now := time.Now()
	rc.mu.Lock()
	rc.state = runtimeStateDegraded
	rc.mu.Unlock()

	key := "k1"
	weak := &runtimeResolverSignal{
		Key:                key,
		Total:              30,
		CarrierRatio:       0.90,
		QualityRatio:       0.05,
		ConsecutiveTimeout: 0,
	}
	fastByKey := map[string]runtimeResolverSignal{
		key: {Key: key, Total: 5, CarrierRatio: 0.90, QualityRatio: 0.05},
	}

	s := runtimeSignals{
		ActiveCount: 4, // sparse => minVotes=4
		WeakActive:  weak,
		FastByKey:   fastByKey,
		ActiveSignals: []runtimeResolverSignal{
			{QualityRatio: 0.01, CarrierRatio: 0.0},
			{QualityRatio: 0.02, CarrierRatio: 0.0},
			{QualityRatio: 0.03, CarrierRatio: 0.0},
			{QualityRatio: 0.04, CarrierRatio: 0.0},
		},
	}

	for i := 0; i < 3; i++ {
		act := rc.decideDemote(now.Add(time.Duration(i)*5*time.Second), s)
		if act.Kind != "" && act.Kind != runtimeActionNone {
			t.Fatalf("expected NONE before enough votes in sparse pool, got %s", act.Kind)
		}
	}
	act := rc.decideDemote(now.Add(20*time.Second), s)
	if act.Kind != runtimeActionDemote {
		t.Fatalf("expected DEMOTE on 4th sustained vote in sparse pool, got %s", act.Kind)
	}
}
