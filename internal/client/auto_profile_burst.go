// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"sync"
	"time"

	"masterdnsvpn-go/internal/profiling"
)

func (c *Client) profileBurst(ctx context.Context, conn Connection, mtuSize int, timeout time.Duration) profiling.BurstStats {
	if mtuSize <= 0 {
		return profiling.BurstStats{}
	}

	depths := []int{1, 2, 4, 8, 16}
	base := c.runBurst(ctx, conn, mtuSize, timeout, 1)
	if base <= 0 {
		return profiling.BurstStats{
			MaxStableParallelProbeDepth: 0,
			BurstSuccessRatio:           0,
			BurstCollapseIndicator:      1,
		}
	}

	maxStable := 1
	lastRatio := base
	for _, d := range depths[1:] {
		if ctx.Err() != nil {
			break
		}
		ratio := c.runBurst(ctx, conn, mtuSize, timeout, d)
		lastRatio = ratio

		// Stability is evaluated relatively to the single-probe baseline.
		if ratio >= base*0.80 {
			maxStable = d
		} else {
			break
		}
	}

	collapse := 0.0
	if base > 0 && lastRatio > 0 {
		collapse = 1.0 - (lastRatio / base)
	}
	if collapse < 0 {
		collapse = 0
	}
	if collapse > 1 {
		collapse = 1
	}

	return profiling.BurstStats{
		MaxStableParallelProbeDepth: maxStable,
		BurstSuccessRatio:           lastRatio,
		BurstCollapseIndicator:      collapse,
	}
}

func (c *Client) runBurst(ctx context.Context, conn Connection, mtuSize int, timeout time.Duration, depth int) float64 {
	if depth < 1 {
		depth = 1
	}

	success := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(depth)
	for i := 0; i < depth; i++ {
		go func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			transport, err := newUDPQueryTransport(conn.ResolverLabel)
			if err != nil {
				return
			}
			defer transport.conn.Close()
			outcome, _ := c.probeUploadOnce(ctx, conn, transport, mtuSize, timeout)
			if outcome == probeSuccess {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return float64(success) / float64(depth)
}
