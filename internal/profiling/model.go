// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package profiling

import "time"

type ViabilityStatus string

const (
	ViabilityUnknown   ViabilityStatus = "unknown"
	ViabilityViable    ViabilityStatus = "viable"
	ViabilityNotViable ViabilityStatus = "not_viable"
)

type ResolverIdentity struct {
	IP             string    `json:"ip"`
	Port           int       `json:"port"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	LastProfiledAt time.Time `json:"last_profiled_at"`
}

type ResolverViability struct {
	Status     ViabilityStatus `json:"viability_status"`
	FailReason string          `json:"viability_fail_reason"`
	TestCount  int             `json:"viability_test_count"`
}

type Envelope struct {
 	FloorBytes          int `json:"floor_bytes"`
 	WorkingMinBytes     int `json:"working_min_bytes"`
 	WorkingMaxBytes     int `json:"working_max_bytes"`
 	RecommendedBytes    int `json:"recommended_bytes"`
 	CeilingBytes        int `json:"ceiling_bytes"`
 	RecommendedProbeRtt int `json:"recommended_probe_rtt_ms"`
}

type RegionClass string

const (
	RegionFail     RegionClass = "fail"
	RegionUnstable RegionClass = "unstable"
	RegionWorking  RegionClass = "working"
)

// RegionInterval is a coarse, persisted view of probe outcomes for an MTU range.
// Phase 1 stores only a lightweight interval list (fail/unstable/working) so the
// client can warm-start and re-derive runtime parameters without re-probing everything.
type RegionInterval struct {
	MinBytes      int        `json:"min_bytes"`
	MaxBytes      int        `json:"max_bytes"`
	Class         RegionClass`json:"class"`
	SuccessRatio  float64    `json:"success_ratio"`
	SampleCount   int        `json:"sample_count"`
}

type TimingStats struct {
 	RttP50Ms    int `json:"rtt_p50_ms"`
 	RttP90Ms    int `json:"rtt_p90_ms"`
 	JitterP50Ms int `json:"jitter_p50_ms"`
 	JitterP90Ms int `json:"jitter_p90_ms"`
}

type ReliabilityStats struct {
	SuccessRatio     float64 `json:"success_ratio"`
	TimeoutRatio     float64 `json:"timeout_ratio"`
	MalformedRatio   float64 `json:"malformed_ratio"`
	LateSuccessRatio float64 `json:"late_success_ratio"`
}

type BurstStats struct {
	MaxStableParallelProbeDepth int     `json:"max_stable_parallel_probe_depth"`
	BurstSuccessRatio           float64 `json:"burst_success_ratio"`
	BurstCollapseIndicator      float64 `json:"burst_collapse_indicator"`
}

type PersistenceStats struct {
	PersistenceScore   float64 `json:"persistence_score"`
	DaysSeen           int     `json:"days_seen"`
	RecentFailureCount int     `json:"recent_failure_count"`
	FlapCount          int     `json:"flap_count"`
}

type Classification struct {
	TxPreferenceScore float64 `json:"tx_preference_score"`
	RxPreferenceScore float64 `json:"rx_preference_score"`
	StabilityScore    float64 `json:"stability_score"`
}

type ResolverProfile struct {
	Identity       ResolverIdentity  `json:"identity"`
	Viability      ResolverViability `json:"viability"`
	Upload         Envelope          `json:"upload_envelope"`
	UploadRegions  []RegionInterval  `json:"upload_regions,omitempty"`
	Download       Envelope          `json:"download_envelope"`
	DownloadRegions []RegionInterval `json:"download_regions,omitempty"`
	Timing         TimingStats       `json:"timing"`
	Reliability    ReliabilityStats  `json:"reliability"`
	Burst          BurstStats        `json:"burst"`
	Persistence    PersistenceStats  `json:"persistence"`
	Classification Classification    `json:"classification"`
}
