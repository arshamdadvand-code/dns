package client

import (
	"context"
	"fmt"
	"time"

	"masterdnsvpn-go/internal/security"
)

type Stage0ProbeResult struct {
	OK         bool    `json:"ok"`
	FailReason string  `json:"fail_reason"`
	SubReason  string  `json:"sub_reason,omitempty"`
	RTTms      float64 `json:"rtt_ms,omitempty"`
}

// Stage0Prober is a minimal probe harness for scanner/inventory work.
// It performs an ultra-light tunnel-shaped MTU upload probe to detect instance-specific
// carrier compatibility (domain+key+method).
type Stage0Prober struct {
	domain string
	c      *Client
}

func NewStage0Prober(domain string, encryptionMethod int, rawKey string) (*Stage0Prober, error) {
	codec, err := security.NewCodec(encryptionMethod, rawKey)
	if err != nil {
		return nil, err
	}
	c := &Client{}
	c.cfg.BaseEncodeData = false
	c.cfg.DataEncryptionMethod = encryptionMethod
	c.codec = codec
	c.udpBufferPool.New = func() any { return make([]byte, RuntimeUDPReadBufferSize) }
	return &Stage0Prober{
		domain: domain,
		c:      c,
	}, nil
}

func (p *Stage0Prober) Probe(ctx context.Context, ip string, port int, timeout time.Duration) (Stage0ProbeResult, error) {
	if p == nil || p.c == nil {
		return Stage0ProbeResult{OK: false, FailReason: "PROBER_NIL"}, nil
	}
	if ip == "" || port < 1 || port > 65535 {
		return Stage0ProbeResult{OK: false, FailReason: "INVALID_ENDPOINT"}, nil
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	conn := Connection{
		Domain:        p.domain,
		ResolverLabel: fmt.Sprintf("%s:%d", ip, port),
	}
	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		return Stage0ProbeResult{OK: false, FailReason: "UDP_DIAL"}, err
	}
	defer transport.conn.Close()

	out := p.c.stage0ViabilityProbe(ctx, conn, transport, timeout)
	rtt := 0.0
	for _, s := range out.samples {
		if s.outcome == probeSuccess && s.rtt > 0 {
			rtt = s.rtt.Seconds() * 1000.0
			break
		}
	}
	return Stage0ProbeResult{
		OK:         out.ok,
		FailReason: out.failReason,
		SubReason:  out.subReason,
		RTTms:      rtt,
	}, nil
}
