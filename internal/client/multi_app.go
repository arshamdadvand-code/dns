package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

// MultiApp runs multiple logical client instances (domain+key) inside one process
// and exposes a single front SOCKS listener that sticky-routes each inbound TCP
// connection to one backend instance. This increases total concurrency capacity
// without implementing stream striping/reassembly yet.
type MultiApp struct {
	log *LoggerFacade

	frontListenIP   string
	frontListenPort int

	backends     []*Client
	backendAddrs []string
	nextPick     atomic.Uint32

	ln      net.Listener
	stopCh  chan struct{}
	stopOnce sync.Once
	wg      sync.WaitGroup

	ui *multiTUI
}

// LoggerFacade is a tiny adapter so MultiApp can log without taking a hard dep
// on the internal logger package here (Client already has it).
type LoggerFacade struct {
	Infof  func(string, ...any)
	Warnf  func(string, ...any)
	Errorf func(string, ...any)
}

type MultiAppConfig struct {
	FrontIP   string
	FrontPort int
	BackendPorts []int
}

func NewMultiApp(cfg MultiAppConfig, backends []*Client) (*MultiApp, error) {
	if cfg.FrontIP == "" || cfg.FrontPort <= 0 {
		return nil, fmt.Errorf("invalid front listen config")
	}
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends")
	}
	if len(cfg.BackendPorts) != len(backends) {
		return nil, fmt.Errorf("backend ports mismatch")
	}
	addrs := make([]string, 0, len(cfg.BackendPorts))
	for _, p := range cfg.BackendPorts {
		addrs = append(addrs, net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", p)))
	}
	return &MultiApp{
		frontListenIP:   cfg.FrontIP,
		frontListenPort: cfg.FrontPort,
		backends:        backends,
		backendAddrs:    addrs,
		stopCh:          make(chan struct{}),
	}, nil
}

func (m *MultiApp) SetLogger(l *LoggerFacade) {
	m.log = l
}

func (m *MultiApp) Run(ctx context.Context) error {
	if m == nil {
		return nil
	}

	m.startTUIIfInteractive()

	// Start backends.
	for _, b := range m.backends {
		if b == nil {
			continue
		}
		m.wg.Add(1)
		go func(c *Client) {
			defer m.wg.Done()
			_ = c.Run(ctx)
		}(b)
	}

	// Front listener.
	addr := net.JoinHostPort(m.frontListenIP, fmt.Sprintf("%d", m.frontListenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	m.ln = ln

	if m.log != nil && m.log.Infof != nil {
		m.log.Infof("SOCKS mux listening on %s", addr)
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-ctx.Done()
		m.Stop()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			select {
			case <-ctx.Done():
				break
			default:
				continue
			}
		}

		m.wg.Add(1)
		go func(c net.Conn) {
			defer m.wg.Done()
			m.handleConn(ctx, c)
		}(conn)
	}

	m.wg.Wait()
	return nil
}

func (m *MultiApp) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
		if m.ln != nil {
			_ = m.ln.Close()
		}

		// Evidence artifacts: persist per-backend snapshots on shutdown.
		for _, b := range m.backends {
			if b == nil {
				continue
			}
			_, _ = b.PersistTelemetrySummary("")
			_, _, _, _ = b.PersistStripingArtifacts("")
		}

		if m.ui != nil {
			m.ui.Stop()
		}
	})
}

func (m *MultiApp) pickBackend() (addr string, idx int) {
	n := len(m.backendAddrs)
	if n == 0 {
		return "", -1
	}
	i := int(m.nextPick.Add(1)) % n
	return m.backendAddrs[i], i
}

func (m *MultiApp) handleConn(ctx context.Context, in net.Conn) {
	defer func() { _ = in.Close() }()

	backendAddr, idx := m.pickBackend()
	if backendAddr == "" {
		return
	}

	out, err := net.DialTimeout("tcp", backendAddr, 3*time.Second)
	if err != nil {
		if m.log != nil && m.log.Warnf != nil {
			m.log.Warnf("mux: backend dial failed idx=%d addr=%s err=%v", idx, backendAddr, err)
		}
		if m.ui != nil {
			m.ui.AddEvent("mux", fmt.Sprintf("backend dial failed idx=%d err=%v", idx, err))
		}
		return
	}
	defer func() { _ = out.Close() }()

	// Bidirectional pipe.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(out, in)
		_ = out.SetDeadline(time.Now())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(in, out)
		_ = in.SetDeadline(time.Now())
	}()
	wg.Wait()
}

func (m *MultiApp) startTUIIfInteractive() {
	if m == nil || m.ui != nil {
		return
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	scannerAddr := ""
	if len(m.backends) > 0 && m.backends[0] != nil {
		scannerAddr = m.backends[0].cfg.ScannerAddr
	}
	ui := newMultiTUI(m.backends, scannerAddr)
	m.ui = ui
	ui.Start()
	ui.AddEvent("system", "multi-instance mux started")
}
