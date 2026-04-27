// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

func (c *Client) probeUploadOnceDetailed(ctx context.Context, conn Connection, transport *udpQueryTransport, mtuSize int, timeout time.Duration) (probeOutcome, time.Duration, string) {
	if mtuSize < 1+mtuProbeCodeLength {
		return probeMalformed, 0, "upload_mtu_too_small"
	}
	if ctx.Err() != nil {
		return probeTimeout, 0, "cancelled"
	}

	payload, code, useBase64, err := c.buildMTUProbePayload(mtuSize)
	if err != nil {
		return probeMalformed, 0, "build_payload_failed"
	}
	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_UP_REQ, payload)
	if err != nil {
		return probeMalformed, 0, "build_query_failed"
	}

	startedAt := time.Now()
	response, err := c.exchangeUDPQuery(transport, query, timeout)
	if err != nil {
		return probeTimeout, 0, "exchange_timeout"
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		return probeMalformed, rtt, classifyDNSOrExtractFailure(response, "extract_vpn_failed")
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		return probeMalformed, rtt, fmt.Sprintf("packet_type_mismatch_%d", packet.PacketType)
	}
	if len(packet.Payload) != 6 {
		return probeMalformed, rtt, fmt.Sprintf("payload_len_mismatch_%d", len(packet.Payload))
	}
	if binaryBigEndianU32(packet.Payload[:mtuProbeCodeLength]) != code {
		return probeMalformed, rtt, "code_mismatch"
	}
	if binaryBigEndianU16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2]) != uint16(mtuSize) {
		return probeMalformed, rtt, "echo_mtu_mismatch"
	}
	return probeSuccess, rtt, ""
}

func classifyDNSOrExtractFailure(response []byte, fallback string) string {
	if len(response) == 0 {
		return fallback
	}
	p, err := DnsParser.ParsePacketLite(response)
	if err != nil {
		return "dns_parse_failed"
	}
	// rcode 0 with no tunnel payload is still a meaningful subreason:
	// it usually means NXDOMAIN/SERVFAIL aren't the issue, but the answer isn't tunnel-shaped.
	if p.Header.RCode != 0 {
		return "dns_rcode_" + dnsRcodeName(p.Header.RCode)
	}
	if p.Header.ANCount == 0 {
		return "dns_no_answers_rcode0"
	}
	return fallback
}

func dnsRcodeName(rc uint8) string {
	switch rc {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("%d", rc)
	}
}

