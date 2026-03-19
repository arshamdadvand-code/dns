// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"errors"
	"io"
	"net"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const maxClientStreamFollowUps = 16

var ErrClientStreamClosed = errors.New("client stream closed")

func (c *Client) createStream(streamID uint16, conn net.Conn) *clientStream {
	stream := &clientStream{
		ID:             streamID,
		Conn:           conn,
		NextSequence:   2,
		LastActivityAt: time.Now(),
	}
	c.storeStream(stream)
	if c.stream0Runtime != nil {
		c.stream0Runtime.NotifyDNSActivity()
	}
	return stream
}

func (c *Client) nextClientStreamSequence(stream *clientStream) uint16 {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.NextSequence++
	if stream.NextSequence == 0 {
		stream.NextSequence = 1
	}
	stream.LastActivityAt = time.Now()
	return stream.NextSequence
}

func (c *Client) sendStreamData(stream *clientStream, payload []byte, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	packet, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_DATA,
		stream.ID,
		c.nextClientStreamSequence(stream),
		payload,
		timeout,
	)
	if err != nil {
		return err
	}
	return c.handleFollowUpServerPacket(packet, timeout)
}

func (c *Client) sendStreamFIN(stream *clientStream, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	if stream.LocalFinSent || stream.Closed {
		stream.mu.Unlock()
		return nil
	}
	stream.LocalFinSent = true
	stream.mu.Unlock()

	packet, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_FIN,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
	if err != nil {
		return err
	}
	return c.handleFollowUpServerPacket(packet, timeout)
}

func (c *Client) sendStreamRST(stream *clientStream, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	if stream.ResetSent || stream.Closed {
		stream.mu.Unlock()
		return nil
	}
	stream.ResetSent = true
	stream.mu.Unlock()

	packet, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_RST,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
	if err != nil {
		return err
	}
	return c.handleFollowUpServerPacket(packet, timeout)
}

func (c *Client) handleFollowUpServerPacket(packet VpnProto.Packet, timeout time.Duration) error {
	current := packet
	for range maxClientStreamFollowUps {
		switch current.PacketType {
		case 0, Enums.PACKET_PONG, Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK, Enums.PACKET_SOCKS5_SYN_ACK:
			return nil
		case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_FIN, Enums.PACKET_STREAM_RST:
			nextPacket, err := c.handleInboundStreamPacket(current, timeout)
			if err != nil {
				return err
			}
			current = nextPacket
		default:
			if isSOCKS5ErrorPacket(current.PacketType) {
				return errors.New(Enums.PacketTypeName(current.PacketType))
			}
			return nil
		}
	}
	return nil
}

func (c *Client) handleInboundStreamPacket(packet VpnProto.Packet, timeout time.Duration) (VpnProto.Packet, error) {
	stream, ok := c.getStream(packet.StreamID)
	if !ok || stream == nil {
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_RST, packet.StreamID, packet.SequenceNum, nil, timeout)
	}

	stream.mu.Lock()
	stream.LastActivityAt = time.Now()
	stream.mu.Unlock()

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA:
		stream.mu.Lock()
		if stream.InboundDataSet && sequenceSeenOrOlder(stream.InboundDataSeq, packet.SequenceNum) {
			stream.mu.Unlock()
			return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum, nil, timeout)
		}
		stream.InboundDataSeq = packet.SequenceNum
		stream.InboundDataSet = true
		stream.mu.Unlock()
		if len(packet.Payload) != 0 {
			if _, err := stream.Conn.Write(packet.Payload); err != nil {
				stream.mu.Lock()
				stream.Closed = true
				stream.mu.Unlock()
				c.deleteStream(stream.ID)
				return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_RST, stream.ID, packet.SequenceNum, nil, timeout)
			}
		}
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum, nil, timeout)
	case Enums.PACKET_STREAM_FIN:
		stream.mu.Lock()
		if stream.RemoteFinSet && stream.RemoteFinSeq == packet.SequenceNum {
			stream.mu.Unlock()
			return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum, nil, timeout)
		}
		stream.RemoteFinSeq = packet.SequenceNum
		stream.RemoteFinSet = true
		stream.RemoteFinRecv = true
		stream.mu.Unlock()
		closeWriteConn(stream.Conn)
		if streamFinished(stream) {
			c.deleteStream(stream.ID)
		}
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum, nil, timeout)
	case Enums.PACKET_STREAM_RST:
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		c.deleteStream(stream.ID)
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_RST_ACK, stream.ID, packet.SequenceNum, nil, timeout)
	default:
		return VpnProto.Packet{}, nil
	}
}

func (c *Client) runLocalStreamReadLoop(stream *clientStream, timeout time.Duration) {
	defer func() {
		stream.mu.Lock()
		closed := stream.Closed
		stream.mu.Unlock()
		if !closed {
			_ = c.sendStreamFIN(stream, timeout)
		}
		if streamFinished(stream) {
			c.deleteStream(stream.ID)
		}
	}()

	readSize := c.maxMainStreamFragmentPayload(c.cfg.Domains[0], Enums.PACKET_STREAM_DATA)
	if readSize < 256 {
		readSize = 256
	}
	buffer := make([]byte, readSize)
	for {
		n, err := stream.Conn.Read(buffer)
		if n > 0 {
			if sendErr := c.sendStreamData(stream, append([]byte(nil), buffer[:n]...), timeout); sendErr != nil {
				_ = c.sendStreamRST(stream, timeout)
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return
		}
		_ = c.sendStreamRST(stream, timeout)
		return
	}
}

func streamFinished(stream *clientStream) bool {
	if stream == nil {
		return true
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.Closed || (stream.LocalFinSent && stream.RemoteFinRecv)
}

func closeWriteConn(conn net.Conn) {
	if conn == nil {
		return
	}
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := conn.(closeWriter); ok {
		_ = writer.CloseWrite()
		return
	}
	_ = conn.Close()
}

func sequenceSeenOrOlder(last uint16, current uint16) bool {
	diff := uint16(current - last)
	return diff == 0 || diff >= 0x8000
}
