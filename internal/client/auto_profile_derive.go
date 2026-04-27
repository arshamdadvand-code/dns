// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"sort"
	"time"

	"masterdnsvpn-go/internal/profiling"
)

type derivedRuntimeConfig struct {
	UploadTargetBytes       int
	DownloadTargetBytes     int
	ActiveResolvers         []string
	ReserveResolvers        []string
	PacketDuplicationCount  int
	SetupDuplicationCount   int
	FailoverResendThreshold int
	FailoverCooldownSeconds float64
	Confidence              string
	Fragile                 bool
}

func deriveRuntimeFromRegistry(reg *profiling.Registry, now time.Time) (derivedRuntimeConfig, error) {
	if reg == nil || len(reg.Resolvers) == 0 {
		return derivedRuntimeConfig{}, ErrAutoProfileNoViableResolvers
	}

	type scored struct {
		addr    string
		profile *profiling.ResolverProfile
		score   float64
	}

	scoredList := make([]scored, 0, len(reg.Resolvers))
	for addr, p := range reg.Resolvers {
		if p == nil {
			continue
		}
		if p.Viability.Status != profiling.ViabilityViable {
			continue
		}
		if p.Upload.RecommendedBytes <= 0 || p.Download.RecommendedBytes <= 0 {
			continue
		}

		// Phase-1: derive a relative stability score from current batch distribution.
		score := 0.0
		score += p.Reliability.SuccessRatio
		score -= p.Reliability.TimeoutRatio * 1.1
		score -= p.Reliability.MalformedRatio * 1.2
		score -= float64(p.Timing.RttP50Ms) / 5000.0
		score -= float64(p.Timing.JitterP90Ms) / 5000.0
		score -= p.Burst.BurstCollapseIndicator * 0.6
		score += p.Persistence.PersistenceScore * 0.2

		scoredList = append(scoredList, scored{addr: addr, profile: p, score: score})
	}

	if len(scoredList) == 0 {
		return derivedRuntimeConfig{}, ErrAutoProfileNoViableResolvers
	}

	sort.Slice(scoredList, func(i, j int) bool {
		return scoredList[i].score > scoredList[j].score
	})

	// Active set is the top tier in this batch (relative, not absolute).
	activeCount := min(32, max(3, len(scoredList)/5))
	if activeCount > len(scoredList) {
		activeCount = len(scoredList)
	}
	active := scoredList[:activeCount]

	uploads := make([]int, 0, len(active))
	downloads := make([]int, 0, len(active))
	for _, s := range active {
		uploads = append(uploads, s.profile.Upload.RecommendedBytes)
		downloads = append(downloads, s.profile.Download.RecommendedBytes)
	}
	sort.Ints(uploads)
	sort.Ints(downloads)

	uploadTarget := percentileInt(uploads, 0.25)
	downloadTarget := percentileInt(downloads, 0.25)
	if uploadTarget <= 0 || downloadTarget <= 0 {
		return derivedRuntimeConfig{}, ErrAutoProfileNoViableResolvers
	}

	activeResolvers := make([]string, 0, len(active))
	reserveResolvers := make([]string, 0, len(scoredList)-len(active))

	for _, s := range active {
		if s.profile.Upload.WorkingMaxBytes >= uploadTarget && s.profile.Download.WorkingMaxBytes >= downloadTarget {
			activeResolvers = append(activeResolvers, s.addr)
		} else {
			reserveResolvers = append(reserveResolvers, s.addr)
		}
	}
	for _, s := range scoredList[activeCount:] {
		reserveResolvers = append(reserveResolvers, s.addr)
	}

	if len(activeResolvers) == 0 {
		// Fallback: keep at least one best resolver.
		activeResolvers = append(activeResolvers, scoredList[0].addr)
		uploadTarget = scoredList[0].profile.Upload.RecommendedBytes
		downloadTarget = scoredList[0].profile.Download.RecommendedBytes
	}

	confidence := "low"
	switch {
	case len(activeResolvers) >= 10 && len(scoredList) >= 40:
		confidence = "high"
	case len(activeResolvers) >= 6 && len(scoredList) >= 20:
		confidence = "medium"
	}
	fragile := len(activeResolvers) <= 3 || len(scoredList) < 10

	timeoutRatios := make([]int, 0, len(active))
	jitterP90 := make([]int, 0, len(active))
	for _, s := range active {
		timeoutRatios = append(timeoutRatios, int(s.profile.Reliability.TimeoutRatio*1000))
		jitterP90 = append(jitterP90, s.profile.Timing.JitterP90Ms)
	}
	sort.Ints(timeoutRatios)
	sort.Ints(jitterP90)
	timeoutP50 := float64(percentileInt(timeoutRatios, 0.50)) / 1000.0
	jitterP50 := percentileInt(jitterP90, 0.50)

	packetDup := 1
	switch {
	case timeoutP50 >= 0.50:
		packetDup = 4
	case timeoutP50 >= 0.25:
		packetDup = 3
	case timeoutP50 >= 0.10:
		packetDup = 2
	}
	setupDup := min(4, packetDup+1)

	failoverThreshold := 2
	failoverCooldown := 2.5
	switch {
	case len(activeResolvers) <= 3:
		failoverThreshold = 6
		failoverCooldown = 15
	case timeoutP50 >= 0.20 || jitterP50 >= 200:
		failoverThreshold = 5
		failoverCooldown = 10
	}

	// Store back derived classification scores (relative to the current batch).
	// This is not used by the runtime yet, but it is part of the minimal DB.
	minScore := scoredList[len(scoredList)-1].score
	maxScore := scoredList[0].score
	span := maxScore - minScore
	if span <= 0 {
		span = 1
	}
	for _, s := range scoredList {
		n := (s.score - minScore) / span
		if n < 0 {
			n = 0
		}
		if n > 1 {
			n = 1
		}
		s.profile.Classification.StabilityScore = n
		s.profile.Classification.TxPreferenceScore = float64(s.profile.Upload.RecommendedBytes)
		s.profile.Classification.RxPreferenceScore = float64(s.profile.Download.RecommendedBytes)
	}

	return derivedRuntimeConfig{
		UploadTargetBytes:       uploadTarget,
		DownloadTargetBytes:     downloadTarget,
		ActiveResolvers:         activeResolvers,
		ReserveResolvers:        reserveResolvers,
		PacketDuplicationCount:  packetDup,
		SetupDuplicationCount:   setupDup,
		FailoverResendThreshold: failoverThreshold,
		FailoverCooldownSeconds: failoverCooldown,
		Confidence:              confidence,
		Fragile:                 fragile,
	}, nil
}
