package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Sink is the minimal interface used by ARQ to report useful byte movement.
// It is intentionally aggregate-only for v0.1 to keep attribution complexity out of ARQ.
type Sink interface {
	AddUsefulIngressTX(n int)
	AddUsefulAckedTX(n int)
	AddUsefulDeliveredRX(n int)
	NoteReassemblyOutOfOrder(gap int)
	NoteReassemblyDuplicate()
	NoteReassemblyDeliveredChunks(n int)
}

type RuntimeTelemetry struct {
	startedAt time.Time

	// Aggregate bytes (since start).
	wireTX atomic.Uint64
	wireRX atomic.Uint64

	usefulIngressTX  atomic.Uint64 // bytes read from local app socket into ARQ
	usefulAckedTX    atomic.Uint64 // bytes ACKed by peer (STREAM_DATA_ACK)
	usefulDeliveredRX atomic.Uint64 // bytes written to local app socket

	reassemblyOutOfOrder   atomic.Uint64
	reassemblyDuplicates   atomic.Uint64
	reassemblyDeliveredOps atomic.Uint64
	reassemblyMaxGap       atomic.Uint64

	// Duplication overhead baseline inputs (since start).
	logicalPackets atomic.Uint64 // planner tasks processed
	targetsRequested atomic.Uint64
	targetsSelected  atomic.Uint64

	// Per-resolver stats keyed by "serverKey" (usually ip:port label).
	resolvers sync.Map // map[string]*resolverStats
}

type resolverStats struct {
	// Outcome mix (since start).
	ok      atomic.Uint64
	timeout atomic.Uint64
	refused atomic.Uint64
	servfail atomic.Uint64
	otherFail atomic.Uint64
	noTunnelAnswer atomic.Uint64

	// Streaks (instantaneous).
	consecutiveFail    atomic.Int32
	consecutiveTimeout atomic.Int32

	// RTT quantiles for tunnel OK responses.
	rtt50 *p2Quantile
	rtt90 *p2Quantile
}

func NewRuntimeTelemetry() *RuntimeTelemetry {
	return &RuntimeTelemetry{startedAt: time.Now()}
}

func (t *RuntimeTelemetry) ensureResolver(key string) *resolverStats {
	if key == "" {
		key = "unknown"
	}
	if v, ok := t.resolvers.Load(key); ok {
		return v.(*resolverStats)
	}
	s := &resolverStats{
		rtt50: newP2Quantile(0.50),
		rtt90: newP2Quantile(0.90),
	}
	if v, loaded := t.resolvers.LoadOrStore(key, s); loaded {
		return v.(*resolverStats)
	}
	return s
}

func (t *RuntimeTelemetry) AddWireTX(n int) {
	if n > 0 {
		t.wireTX.Add(uint64(n))
	}
}

func (t *RuntimeTelemetry) AddWireRX(n int) {
	if n > 0 {
		t.wireRX.Add(uint64(n))
	}
}

func (t *RuntimeTelemetry) AddWireTXForResolver(key string, n int) {
	if n <= 0 {
		return
	}
	t.AddWireTX(n)
	s := t.ensureResolver(key)
	_ = s // reserved for future per-resolver wire accounting if needed
}

func (t *RuntimeTelemetry) AddWireRXForResolver(key string, n int) {
	if n <= 0 {
		return
	}
	t.AddWireRX(n)
}

func (t *RuntimeTelemetry) AddUsefulIngressTX(n int) {
	if n > 0 {
		t.usefulIngressTX.Add(uint64(n))
	}
}

func (t *RuntimeTelemetry) AddUsefulAckedTX(n int) {
	if n > 0 {
		t.usefulAckedTX.Add(uint64(n))
	}
}

func (t *RuntimeTelemetry) AddUsefulDeliveredRX(n int) {
	if n > 0 {
		t.usefulDeliveredRX.Add(uint64(n))
	}
}

func (t *RuntimeTelemetry) NoteReassemblyOutOfOrder(gap int) {
	if t == nil || gap <= 0 {
		return
	}
	t.reassemblyOutOfOrder.Add(1)
	for {
		prev := t.reassemblyMaxGap.Load()
		if uint64(gap) <= prev {
			return
		}
		if t.reassemblyMaxGap.CompareAndSwap(prev, uint64(gap)) {
			return
		}
	}
}

func (t *RuntimeTelemetry) NoteReassemblyDuplicate() {
	if t == nil {
		return
	}
	t.reassemblyDuplicates.Add(1)
}

func (t *RuntimeTelemetry) NoteReassemblyDeliveredChunks(n int) {
	if t == nil || n <= 0 {
		return
	}
	t.reassemblyDeliveredOps.Add(uint64(n))
}

func (t *RuntimeTelemetry) NoteTunnelOK(key string, rtt time.Duration) {
	s := t.ensureResolver(key)
	s.ok.Add(1)
	s.consecutiveFail.Store(0)
	s.consecutiveTimeout.Store(0)
	if rtt > 0 {
		ms := float64(rtt.Microseconds()) / 1000.0
		s.rtt50.Add(ms)
		s.rtt90.Add(ms)
	}
}

func (t *RuntimeTelemetry) NoteTimeout(key string) {
	s := t.ensureResolver(key)
	s.timeout.Add(1)
	s.consecutiveFail.Add(1)
	s.consecutiveTimeout.Add(1)
}

func (t *RuntimeTelemetry) NoteRcodeFailure(key string, rcode uint8) {
	s := t.ensureResolver(key)
	// DNS RCODE: 5=REFUSED, 2=SERVFAIL.
	switch rcode {
	case 5:
		s.refused.Add(1)
	case 2:
		s.servfail.Add(1)
	default:
		s.otherFail.Add(1)
	}
	s.consecutiveFail.Add(1)
	// Not a timeout; keep timeout streak unchanged.
}

func (t *RuntimeTelemetry) NoteNoTunnelAnswer(key string) {
	s := t.ensureResolver(key)
	s.noTunnelAnswer.Add(1)
	s.consecutiveFail.Add(1)
}

func (t *RuntimeTelemetry) NoteOtherFailure(key string) {
	s := t.ensureResolver(key)
	s.otherFail.Add(1)
	s.consecutiveFail.Add(1)
}

func (t *RuntimeTelemetry) NoteDuplicationSelection(requested int, selected int) {
	t.logicalPackets.Add(1)
	if requested > 0 {
		t.targetsRequested.Add(uint64(requested))
	}
	if selected > 0 {
		t.targetsSelected.Add(uint64(selected))
	}
}

type ResolverSnapshot struct {
	Key string `json:"key"`

	OK            uint64 `json:"ok"`
	Timeout       uint64 `json:"timeout"`
	Refused       uint64 `json:"refused"`
	Servfail      uint64 `json:"servfail"`
	NoTunnel      uint64 `json:"no_tunnel_answer"`
	OtherFailures uint64 `json:"other_failures"`

	ConsecutiveFail    int32 `json:"consecutive_fail"`
	ConsecutiveTimeout int32 `json:"consecutive_timeout"`

	RTTP50ms float64 `json:"rtt_p50_ms"`
	RTTP90ms float64 `json:"rtt_p90_ms"`
}

type Snapshot struct {
	GeneratedAt string `json:"generated_at"`
	ElapsedSec  float64 `json:"elapsed_seconds"`

	WireTX uint64 `json:"wire_bytes_tx"`
	WireRX uint64 `json:"wire_bytes_rx"`

	UsefulIngressTX   uint64 `json:"useful_ingress_tx"`
	UsefulAckedTX     uint64 `json:"useful_acked_tx"`
	UsefulDeliveredRX uint64 `json:"useful_delivered_rx"`
	ReassemblyOutOfOrder uint64 `json:"reassembly_out_of_order"`
	ReassemblyDuplicates uint64 `json:"reassembly_duplicates"`
	ReassemblyDeliveredOps uint64 `json:"reassembly_delivered_ops"`
	ReassemblyMaxGap uint64 `json:"reassembly_max_gap"`

	LogicalPackets    uint64 `json:"logical_packets"`
	TargetsRequested  uint64 `json:"targets_requested"`
	TargetsSelected   uint64 `json:"targets_selected"`

	Resolvers []ResolverSnapshot `json:"resolvers"`
}

func (t *RuntimeTelemetry) Snapshot() Snapshot {
	now := time.Now()
	snap := Snapshot{
		GeneratedAt: now.Format(time.RFC3339Nano),
		ElapsedSec:  now.Sub(t.startedAt).Seconds(),
		WireTX:      t.wireTX.Load(),
		WireRX:      t.wireRX.Load(),
		UsefulIngressTX:   t.usefulIngressTX.Load(),
		UsefulAckedTX:     t.usefulAckedTX.Load(),
		UsefulDeliveredRX: t.usefulDeliveredRX.Load(),
		ReassemblyOutOfOrder: t.reassemblyOutOfOrder.Load(),
		ReassemblyDuplicates: t.reassemblyDuplicates.Load(),
		ReassemblyDeliveredOps: t.reassemblyDeliveredOps.Load(),
		ReassemblyMaxGap: t.reassemblyMaxGap.Load(),
		LogicalPackets:    t.logicalPackets.Load(),
		TargetsRequested:  t.targetsRequested.Load(),
		TargetsSelected:   t.targetsSelected.Load(),
	}

	var resolvers []ResolverSnapshot
	t.resolvers.Range(func(k, v any) bool {
		key := k.(string)
		rs := v.(*resolverStats)
		p50, _ := rs.rtt50.Value()
		p90, _ := rs.rtt90.Value()
		resolvers = append(resolvers, ResolverSnapshot{
			Key: key,
			OK: rs.ok.Load(),
			Timeout: rs.timeout.Load(),
			Refused: rs.refused.Load(),
			Servfail: rs.servfail.Load(),
			NoTunnel: rs.noTunnelAnswer.Load(),
			OtherFailures: rs.otherFail.Load(),
			ConsecutiveFail: rs.consecutiveFail.Load(),
			ConsecutiveTimeout: rs.consecutiveTimeout.Load(),
			RTTP50ms: p50,
			RTTP90ms: p90,
		})
		return true
	})
	sort.Slice(resolvers, func(i, j int) bool {
		// Show most OK first.
		if resolvers[i].OK != resolvers[j].OK {
			return resolvers[i].OK > resolvers[j].OK
		}
		return resolvers[i].Key < resolvers[j].Key
	})
	snap.Resolvers = resolvers
	return snap
}

func (t *RuntimeTelemetry) PersistJSON(outPath string) (string, error) {
	if outPath == "" {
		return "", nil
	}
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	snap := t.Snapshot()
	b, err := json.MarshalIndent(snap, "", "  ")
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
