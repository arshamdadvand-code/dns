// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"sort"
	"time"

	"masterdnsvpn-go/internal/profiling"
)

// Stage1 is coarse and directional:
// - run only on Stage0 survivors
// - grid-based probes (cheap)
// - produce interval regions (fail/unstable/working)
// - pick a best working region and a conservative recommended point inside it
const (
	stage1PointAttempts = 2
)

func (c *Client) stage1CoarseUploadRegions(ctx context.Context, conn Connection, transport *udpQueryTransport, timeout time.Duration) (profiling.Envelope, []profiling.RegionInterval, string) {
	if c == nil || transport == nil {
		return profiling.Envelope{}, nil, "UDP_DIAL"
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	maxPayload := c.maxUploadMTUPayload(conn.Domain)
	if maxPayload <= 0 {
		maxPayload = defaultUploadMaxCap
	}
	// Neutral cap: avoid unbounded work, but do not use MinUpload/MaxUpload policy gates.
	if maxPayload > defaultUploadMaxCap {
		maxPayload = defaultUploadMaxCap
	}

	grid := stage1UploadGrid(maxPayload)
	regions, best := c.probeGridUpload(ctx, conn, transport, grid, timeout)
	if best.MaxBytes <= 0 {
		return profiling.Envelope{}, regions, "STAGE1_NO_UPLOAD_REGION"
	}

	rec := stage1RecommendedInside(best)
	env := profiling.Envelope{
		FloorBytes:          best.MinBytes,
		WorkingMinBytes:     best.MinBytes,
		WorkingMaxBytes:     best.MaxBytes,
		RecommendedBytes:    rec,
		CeilingBytes:        best.MaxBytes,
		RecommendedProbeRtt: 0,
	}
	return env, regions, ""
}

func (c *Client) stage1CoarseDownloadRegions(ctx context.Context, conn Connection, transport *udpQueryTransport, uploadMTU int, timeout time.Duration) (profiling.Envelope, []profiling.RegionInterval, string) {
	if c == nil || transport == nil {
		return profiling.Envelope{}, nil, "UDP_DIAL"
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	// IMPORTANT: keep the request side of download probes small/neutral.
	// probeDownloadOnce() sizes the request as max(headerMin, uploadMTU), so using
	// a large upload MTU here would incorrectly make downloads look worse.
	uploadMTU = autoProfileStage0UploadProbeBytes

	// Neutral cap: avoid unbounded work, but do not use MinDownload/MaxDownload policy gates.
	maxProbe := EDnsSafeUDPSize
	if maxProbe > 2048 {
		maxProbe = 2048
	}

	grid := stage1DownloadGrid(maxProbe)
	regions, best := c.probeGridDownload(ctx, conn, transport, grid, uploadMTU, timeout)
	if best.MaxBytes <= 0 {
		return profiling.Envelope{}, regions, "STAGE1_NO_DOWNLOAD_REGION"
	}

	rec := stage1RecommendedInside(best)
	env := profiling.Envelope{
		FloorBytes:          best.MinBytes,
		WorkingMinBytes:     best.MinBytes,
		WorkingMaxBytes:     best.MaxBytes,
		RecommendedBytes:    rec,
		CeilingBytes:        best.MaxBytes,
		RecommendedProbeRtt: 0,
	}
	return env, regions, ""
}

func stage1UploadGrid(maxPayload int) []int {
	// Include small sizes so Stage1 doesn't miss Stage0-successful resolvers.
	candidates := []int{16, 24, 32, 40, 48, 64, 80, 96, 128, 160, 192, 256, 320, 384, 448, 512}
	out := make([]int, 0, len(candidates))
	seen := map[int]struct{}{}
	for _, v := range candidates {
		if v < 1+mtuProbeCodeLength {
			continue
		}
		if v > maxPayload {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func stage1DownloadGrid(maxProbe int) []int {
	// Download values are "requested download MTU"; effective payload will be larger by reserve.
	// We probe a moderate range because some environments only support small-ish DNS responses.
	candidates := []int{32, 48, 64, 80, 96, 128, 160, 192, 256, 320, 384, 512, 768, 1024, 1536, 2048}
	out := make([]int, 0, len(candidates))
	seen := map[int]struct{}{}
	for _, v := range candidates {
		if v < minDownloadMTUFloor {
			continue
		}
		if v > maxProbe {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func (c *Client) probeGridUpload(ctx context.Context, conn Connection, transport *udpQueryTransport, grid []int, timeout time.Duration) ([]profiling.RegionInterval, profiling.RegionInterval) {
	points := c.probeUploadPoints(ctx, conn, transport, grid, timeout)
	return stage1MergeBuckets(points), stage1PickBestWorking(stage1MergeBuckets(points))
}

func (c *Client) probeGridDownload(ctx context.Context, conn Connection, transport *udpQueryTransport, grid []int, uploadMTU int, timeout time.Duration) ([]profiling.RegionInterval, profiling.RegionInterval) {
	points := c.probeDownloadPoints(ctx, conn, transport, grid, uploadMTU, timeout)
	return stage1MergeBuckets(points), stage1PickBestWorking(stage1MergeBuckets(points))
}

type stage1Point struct {
	minBytes     int
	maxBytes     int
	class        profiling.RegionClass
	successRatio float64
	sampleCount  int
}

func (c *Client) probeUploadPoints(ctx context.Context, conn Connection, transport *udpQueryTransport, grid []int, timeout time.Duration) []stage1Point {
	return c.probeGrid(ctx, grid, func(size int) probeOutcome {
		o, _ := c.probeUploadOnce(ctx, conn, transport, size, timeout)
		return o
	})
}

func (c *Client) probeDownloadPoints(ctx context.Context, conn Connection, transport *udpQueryTransport, grid []int, uploadMTU int, timeout time.Duration) []stage1Point {
	return c.probeGrid(ctx, grid, func(size int) probeOutcome {
		o, _ := c.probeDownloadOnce(ctx, conn, transport, size, uploadMTU, timeout)
		return o
	})
}

func (c *Client) probeGrid(ctx context.Context, grid []int, probe func(size int) probeOutcome) []stage1Point {
	if len(grid) == 0 {
		return nil
	}
	sizes := append([]int(nil), grid...)
	sort.Ints(sizes)

	// Build contiguous bucket bounds between adjacent grid points.
	bounds := make([][2]int, 0, len(sizes))
	for i := 0; i < len(sizes); i++ {
		var minB, maxB int
		if i == 0 {
			minB = sizes[i]
			if len(sizes) == 1 {
				maxB = sizes[i]
			} else {
				maxB = (sizes[i] + sizes[i+1]) / 2
			}
		} else if i == len(sizes)-1 {
			minB = (sizes[i-1]+sizes[i])/2 + 1
			maxB = sizes[i]
		} else {
			minB = (sizes[i-1]+sizes[i])/2 + 1
			maxB = (sizes[i]+sizes[i+1])/2
		}
		if minB > maxB {
			minB = sizes[i]
			maxB = sizes[i]
		}
		bounds = append(bounds, [2]int{minB, maxB})
	}

	out := make([]stage1Point, 0, len(sizes))
	for i, size := range sizes {
		if ctx.Err() != nil {
			break
		}
		success := 0
		total := 0
		for a := 0; a < stage1PointAttempts; a++ {
			if ctx.Err() != nil {
				break
			}
			total++
			if probe(size) == probeSuccess {
				success++
			}
		}

		ratio := 0.0
		if total > 0 {
			ratio = float64(success) / float64(total)
		}

		class := profiling.RegionFail
		switch {
		case ratio <= 0.001:
			class = profiling.RegionFail
		case ratio >= 0.50:
			// With only 2 attempts per point, require only "at least one" success.
			// Stage1 is coarse discovery, not final quality gating.
			class = profiling.RegionWorking
		default:
			class = profiling.RegionUnstable
		}

		out = append(out, stage1Point{
			minBytes:     bounds[i][0],
			maxBytes:     bounds[i][1],
			class:        class,
			successRatio: ratio,
			sampleCount:  total,
		})
	}
	return out
}

func stage1MergeBuckets(points []stage1Point) []profiling.RegionInterval {
	if len(points) == 0 {
		return nil
	}

	merged := make([]profiling.RegionInterval, 0, len(points))
	cur := profiling.RegionInterval{
		MinBytes:     points[0].minBytes,
		MaxBytes:     points[0].maxBytes,
		Class:        points[0].class,
		SuccessRatio: points[0].successRatio,
		SampleCount:  points[0].sampleCount,
	}

	weightedSum := cur.SuccessRatio * float64(max(1, cur.SampleCount))
	weightedCount := float64(max(1, cur.SampleCount))

	for i := 1; i < len(points); i++ {
		p := points[i]
		if p.class == cur.Class && p.minBytes <= cur.MaxBytes+1 {
			if p.maxBytes > cur.MaxBytes {
				cur.MaxBytes = p.maxBytes
			}
			w := float64(max(1, p.sampleCount))
			weightedSum += p.successRatio * w
			weightedCount += w
			cur.SampleCount += p.sampleCount
			cur.SuccessRatio = weightedSum / weightedCount
			continue
		}

		merged = append(merged, cur)
		cur = profiling.RegionInterval{
			MinBytes:     p.minBytes,
			MaxBytes:     p.maxBytes,
			Class:        p.class,
			SuccessRatio: p.successRatio,
			SampleCount:  p.sampleCount,
		}
		weightedSum = cur.SuccessRatio * float64(max(1, cur.SampleCount))
		weightedCount = float64(max(1, cur.SampleCount))
	}
	merged = append(merged, cur)
	return merged
}

func stage1PickBestWorking(regions []profiling.RegionInterval) profiling.RegionInterval {
	best := profiling.RegionInterval{}
	bestUnstable := profiling.RegionInterval{}
	for _, r := range regions {
		switch r.Class {
		case profiling.RegionWorking:
			if best.MaxBytes == 0 {
				best = r
				continue
			}
			bestWidth := best.MaxBytes - best.MinBytes
			rWidth := r.MaxBytes - r.MinBytes
			// Prefer higher success ratio first, then higher operating points, then width.
			if r.SuccessRatio > best.SuccessRatio ||
				(r.SuccessRatio == best.SuccessRatio && (r.MaxBytes > best.MaxBytes || (r.MaxBytes == best.MaxBytes && rWidth > bestWidth))) {
				best = r
			}
		case profiling.RegionUnstable:
			// Keep a fallback so Stage1 can still yield an operating point in sparse-hit environments.
			if bestUnstable.MaxBytes == 0 ||
				r.SuccessRatio > bestUnstable.SuccessRatio ||
				(r.SuccessRatio == bestUnstable.SuccessRatio && r.MaxBytes > bestUnstable.MaxBytes) {
				bestUnstable = r
			}
		}
	}
	if best.MaxBytes > 0 {
		return best
	}
	return bestUnstable
}

func stage1RecommendedInside(best profiling.RegionInterval) int {
	if best.MaxBytes <= 0 {
		return 0
	}
	width := best.MaxBytes - best.MinBytes
	// Slightly conservative inside best region: stay below the top edge.
	backoff := 8
	if width > 0 {
		backoff = max(8, width/8) // 12.5% below the top, minimum 8 bytes.
	}
	rec := best.MaxBytes - backoff
	if rec < best.MinBytes {
		rec = best.MinBytes
	}
	return rec
}
