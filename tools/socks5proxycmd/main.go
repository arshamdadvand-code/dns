package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

// Minimal SOCKS5 "proxy command" for PuTTY/plink -proxycmd.
//
// Hardcoded proxy: 127.0.0.1:10808 (per project instructions).
// Usage (PuTTY will substitute %host %port):
//   plink -proxycmd "C:\dns\socks5proxycmd.exe %host %port" user@server
func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: socks5proxycmd <dest-host> <dest-port>")
		os.Exit(2)
	}

	destHost := os.Args[1]
	destPort, err := strconv.Atoi(os.Args[2])
	if err != nil || destPort < 1 || destPort > 65535 {
		_, _ = fmt.Fprintln(os.Stderr, "invalid dest-port")
		os.Exit(2)
	}

	proxyAddr := "127.0.0.1:10808"
	dialer := net.Dialer{Timeout: 8 * time.Second}
	c, err := dialer.Dial("tcp", proxyAddr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "dial proxy failed: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	if err := socks5Handshake(c); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "socks handshake failed: %v\n", err)
		os.Exit(1)
	}

	if err := socks5Connect(c, destHost, uint16(destPort)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "socks connect failed: %v\n", err)
		os.Exit(1)
	}

	// Bridge stdin/stdout for plink.
	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(c, os.Stdin)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(os.Stdout, c)
		errCh <- e
	}()

	// Exit when one side closes.
	_ = <-errCh
}

func socks5Handshake(c net.Conn) error {
	// VER=5, NMETHODS=1, METHODS[0]=0 (no auth)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("bad version %d", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("proxy requires auth method %d", resp[1])
	}
	return nil
}

func socks5Connect(c net.Conn, host string, port uint16) error {
	// CONNECT request: VER=5 CMD=1 RSV=0 ATYP=3 (domain) LEN host PORT
	if len(host) < 1 || len(host) > 255 {
		return fmt.Errorf("bad host length")
	}

	req := make([]byte, 0, 6+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, []byte(host)...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	req = append(req, p[:]...)

	if _, err := c.Write(req); err != nil {
		return err
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("bad version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("connect refused rep=%d", hdr[1])
	}

	// Drain BND.ADDR based on ATYP.
	switch hdr[3] {
	case 0x01: // IPv4
		var b [4 + 2]byte
		_, err := io.ReadFull(c, b[:])
		return err
	case 0x04: // IPv6
		var b [16 + 2]byte
		_, err := io.ReadFull(c, b[:])
		return err
	case 0x03: // domain
		var ln [1]byte
		if _, err := io.ReadFull(c, ln[:]); err != nil {
			return err
		}
		n := int(ln[0])
		buf := make([]byte, n+2)
		_, err := io.ReadFull(c, buf)
		return err
	default:
		return fmt.Errorf("unknown atyp=%d", hdr[3])
	}
}

