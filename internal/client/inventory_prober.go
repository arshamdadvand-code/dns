package client

import (
	"context"
	"fmt"
	"time"

	"masterdnsvpn-go/internal/profiling"
	"masterdnsvpn-go/internal/security"
)

// InventoryProber reuses the optimized in-client profiling path for a single
// resolver endpoint. This keeps scanner separation architectural, not behavioral.
type InventoryProber struct {
	domain string
	c      *Client
	s0     *Stage0Prober
}

func NewInventoryProber(domain string, encryptionMethod int, rawKey string) (*InventoryProber, error) {
	codec, err := security.NewCodec(encryptionMethod, rawKey)
	if err != nil {
		return nil, err
	}

	c := &Client{}
	c.cfg.BaseEncodeData = false
	c.cfg.DataEncryptionMethod = encryptionMethod
	c.cfg.MTUTestTimeout = 2.0
	c.cfg.MinUploadMTU = 35
	c.cfg.MinDownloadMTU = 100
	c.cfg.MaxDownloadMTU = 2048
	c.codec = codec
	c.udpBufferPool.New = func() any { return make([]byte, RuntimeUDPReadBufferSize) }

	s0, err := NewStage0Prober(domain, encryptionMethod, rawKey)
	if err != nil {
		return nil, err
	}

	return &InventoryProber{
		domain: domain,
		c:      c,
		s0:     s0,
	}, nil
}

func (p *InventoryProber) Profile(ctx context.Context, ip string, port int, timeout time.Duration) (*profiling.ResolverProfile, error) {
	if p == nil || p.c == nil {
		return nil, nil
	}
	if ip == "" || port < 1 || port > 65535 {
		return nil, nil
	}
	if timeout > 0 {
		p.c.cfg.MTUTestTimeout = timeout.Seconds()
	}
	return p.c.profileOneResolver(ctx, nil, p.domain, ip, port, nil, time.Now()), nil
}

func (p *InventoryProber) ProfileResult(ctx context.Context, ip string, port int, timeout time.Duration) (Stage0ProbeResult, *profiling.ResolverProfile, error) {
	// Preserve Stage0 diagnostic detail. This is especially important for the
	// scanner service so it can classify failures (NXDOMAIN/SERVFAIL/shape).
	if p != nil && p.s0 != nil {
		s0, _ := p.s0.Probe(ctx, ip, port, timeout)
		if !s0.OK {
			return s0, nil, nil
		}
	}

	profile, err := p.Profile(ctx, ip, port, timeout)
	if err != nil {
		return Stage0ProbeResult{OK: false, FailReason: "PROFILE_ERR"}, nil, err
	}
	if profile == nil {
		return Stage0ProbeResult{OK: false, FailReason: "PROFILE_NIL"}, nil, nil
	}
	rtt := float64(profile.Timing.RttP50Ms)
	if rtt <= 0 {
		rtt = float64(profile.Upload.RecommendedProbeRtt)
	}
	res := Stage0ProbeResult{
		OK:         profile.Viability.Status == profiling.ViabilityViable && profile.Upload.RecommendedBytes > 0 && profile.Download.RecommendedBytes > 0,
		FailReason: profile.Viability.FailReason,
		RTTms:      rtt,
	}
	if res.FailReason == "" && !res.OK {
		switch {
		case profile.Upload.RecommendedBytes <= 0:
			res.FailReason = "STAGE1_NO_UPLOAD_REGION"
		case profile.Download.RecommendedBytes <= 0:
			res.FailReason = "STAGE1_NO_DOWNLOAD_REGION"
		default:
			res.FailReason = "PROFILE_INCOMPLETE"
		}
	}
	if !res.OK && profile.Viability.Status == profiling.ViabilityNotViable && profile.Viability.FailReason == "" {
		res.FailReason = "NOT_VIABLE"
	}
	if !res.OK && res.FailReason == "" {
		res.FailReason = fmt.Sprintf("PROFILE_FAIL_%s", profile.Viability.Status)
	}
	return res, profile, nil
}
