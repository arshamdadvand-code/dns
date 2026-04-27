// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"time"
)

// Phase-1 Stage0 must stay ultra-light:
// - tunnel-compatible sanity only
// - no policy-driven floors (no MinUploadMTU/MinDownloadMTU gating)
// - no ceiling search, no sampling, no burst
//
// We use a tiny MTU upload probe because it:
// - proves the resolver can carry a tunnel-shaped query/response
// - proves the client/server keying is correct (otherwise decode/type checks fail)
const (
	autoProfileStage0UploadProbeBytes = 32
	autoProfileStage0UploadAttempts   = 2
)

type stage0Outcome struct {
	ok         bool
	failReason string
	subReason  string
	samples    []probeSample
}

func (c *Client) stage0ViabilityProbe(ctx context.Context, conn Connection, transport *udpQueryTransport, timeout time.Duration) stage0Outcome {
	out := stage0Outcome{}
	if c == nil {
		out.failReason = "CLIENT_NIL"
		return out
	}
	if transport == nil {
		out.failReason = "UDP_DIAL"
		return out
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	malformed := 0
	success := 0
	subCounts := map[string]int{}
	samples := make([]probeSample, 0, autoProfileStage0UploadAttempts)
	for i := 0; i < autoProfileStage0UploadAttempts; i++ {
		if ctx.Err() != nil {
			out.failReason = "CANCELLED"
			out.samples = samples
			return out
		}
		o, rtt, sub := c.probeUploadOnceDetailed(ctx, conn, transport, autoProfileStage0UploadProbeBytes, timeout)
		samples = append(samples, probeSample{outcome: o, rtt: rtt})
		switch o {
		case probeSuccess:
			success++
		case probeMalformed:
			malformed++
			if sub == "" {
				sub = "(unknown)"
			}
			subCounts[sub] = subCounts[sub] + 1
		}
	}

	out.samples = samples
	if success > 0 {
		out.ok = true
		return out
	}
	if malformed > 0 {
		out.failReason = "STAGE0_MALFORMED"
		best := ""
		bestN := 0
		for k, v := range subCounts {
			if v > bestN {
				bestN = v
				best = k
			}
		}
		out.subReason = best
	} else {
		out.failReason = "STAGE0_TIMEOUT"
	}
	return out
}
