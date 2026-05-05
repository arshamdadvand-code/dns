// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic and initialization for the MasterDnsVPN client.
// This file (client.go) defines the main Client struct and bootstrapping process.
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	Enums "masterdnsvpn-go/internal/enums"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/mlq"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/telemetry"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	EDnsSafeUDPSize = 4096
)

type Client struct {
	cfg           config.ClientConfig
	log           *logger.Logger
	codec         *security.Codec
	codecByDomain map[string]*security.Codec
	balancer      *Balancer
	telemetry     *telemetry.RuntimeTelemetry

	successMTUChecks  bool
	udpBufferPool     sync.Pool
	resolverConnsMu   sync.Mutex
	resolverConns     map[string]chan pooledUDPConn
	resolverAddrMu    sync.RWMutex
	resolverAddrCache map[string]*net.UDPAddr
	nowFn             func() time.Time

	// MTU States
	syncedUploadMTU                       int
	syncedDownloadMTU                     int
	syncedUploadChars                     int
	safeUploadMTU                         int
	maxPackedBlocks                       int
	uploadCompression                     uint8
	downloadCompression                   uint8
	mtuCryptoOverhead                     int
	mtuProbeCounter                       atomic.Uint32
	mtuTestRetries                        int
	mtuTestTimeout                        time.Duration
	mtuSaveToFile                         bool
	mtuServersFileName                    string
	mtuServersFileFormat                  string
	mtuSuccessOutputPath                  string
	mtuOutputMu                           sync.Mutex
	mtuUsageSeparatorWritten              bool
	mtuUsingSeparatorText                 string
	mtuRemovedServerLogFormat             string
	mtuAddedServerLogFormat               string
	mtuReactiveAddedServerLogFormat       string
	streamResolverFailoverResendThreshold int
	streamResolverFailoverCooldown        time.Duration

	// Session States
	sessionID             uint8
	sessionCookie         uint8
	responseMode          uint8
	sessionReady          bool
	initStateMu           sync.Mutex
	sessionInitReady      bool
	sessionInitBase64     bool
	sessionInitPayload    []byte
	sessionInitVerify     [4]byte
	sessionInitCursor     int
	sessionInitBusyUnix   atomic.Int64
	sessionResetPending   atomic.Bool
	runtimeResetPending   atomic.Bool
	resolverHealthStarted atomic.Bool
	sessionResetSignal    chan struct{}
	rxDroppedPackets      atomic.Uint64
	lastRXDropLogUnix     atomic.Int64

	// Local scanner coordination (optional).
	scannerOnce          sync.Once
	scannerHTTP          *http.Client
	scannerAddr          string
	scannerClientID      string
	scannerInstances     []scannerIdentity
	scannerSpawned       bool
	scannerStopHB        context.CancelFunc
	scannerLastDemandAt  atomic.Int64
	scannerBootstrapMu   sync.RWMutex
	scannerBootstrapUp   int
	scannerBootstrapDown int
	controlLaneMu        sync.RWMutex
	controlLaneDomain    string
	controlLaneKey       string

	// Async Runtime Workers & Channels
	asyncWG              sync.WaitGroup
	asyncCancel          context.CancelFunc
	tunnelConns          []*net.UDPConn
	plannerQueue         chan plannerTask
	encodedTXChannel     chan writerTask
	rxChannel            chan asyncReadPacket
	tunnelRX_TX_Workers  int
	tunnelProcessWorkers int
	tunnelPacketTimeout  time.Duration

	// Local Proxy Daemons
	tcpListener *TCPListener
	dnsListener *DNSListener

	// Stream Management
	streamsMu             sync.RWMutex
	active_streams        map[uint16]*Stream_client
	last_stream_id        uint16
	streamSetVersion      atomic.Uint64
	orphanQueue           *mlq.MultiLevelQueue[VpnProto.Packet]
	recentlyClosedMu      sync.Mutex
	recentlyClosedStreams map[uint16]time.Time
	recentlyClosedHeap    recentlyClosedHeap

	// Signals to wake up dispatcher and downstream stages.
	dispatchSignal          chan struct{}
	plannerQueueSpaceSignal chan struct{}
	writerQueueSpaceSignal  chan struct{}

	// Autonomous Ping Manager
	pingManager *PingManager

	// DNS Management
	localDNSCache          *dnsCache.Store
	dnsResponses           *fragmentStore.Store[dnsFragmentKey]
	localDNSCachePersist   bool
	localDNSCachePath      string
	localDNSCacheFlushTick time.Duration
	localDNSCacheLoadOnce  sync.Once
	localDNSCacheFlushOnce sync.Once

	// SOCKS5 brute-force rate limiter
	socksRateLimit *socksRateLimiter

	// Phase-1 fixed-layout TUI dashboard (no scrolling logs).
	dashboard *autoProfileDashboard

	telemetryPersistStarted atomic.Bool

	// Full-lifecycle TUI dashboard (tview/tcell).
	ui         *fullTUI
	tuiEnabled bool

	// Runtime adaptation controller (v0.1).
	runtimeController        *runtimeController
	runtimeControllerStarted atomic.Bool
}

func (c *Client) stripingEnabled() bool {
	if c == nil {
		return false
	}
	// Enable striping when multiple domains exist and a domain keyring is available.
	// Control-plane packets are still restricted to the default domain until the
	// session cookie is established.
	return len(c.cfg.Domains) > 1 && c.codecByDomain != nil && len(c.codecByDomain) > 1
}

// clientStreamTXPacket represents a queued packet pending transmission or retransmission.
type clientStreamTXPacket struct {
	PacketType       uint8
	SequenceNum      uint16
	FragmentID       uint8
	TotalFragments   uint8
	CompressionType  uint8
	Payload          []byte
	CreatedAt        time.Time
	TTL              time.Duration
	LastSentAt       time.Time
	RetryDelay       time.Duration
	RetryAt          time.Time
	RetryCount       int
	Scheduled        bool
	isControlCounted atomic.Bool
}

type recentlyClosedEntry struct {
	streamID uint16
	expires  time.Time
}

type recentlyClosedHeap []recentlyClosedEntry

func (h recentlyClosedHeap) Len() int { return len(h) }

func (h recentlyClosedHeap) Less(i, j int) bool {
	return h[i].expires.Before(h[j].expires)
}

func (h recentlyClosedHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *recentlyClosedHeap) Push(x any) {
	*h = append(*h, x.(recentlyClosedEntry))
}

func (h *recentlyClosedHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// plannerTask is the handoff between dispatcher and the planner/encoder stage.
// The dispatcher only decides fairness/dequeue/packing. Resolver selection and
// fan-out happen later in the encode stage.
type plannerTask struct {
	opts      VpnProto.BuildOptions
	dupCount  int
	wasPacked bool
	item      *clientStreamTXPacket
	selected  *Stream_client
}

type encodedOutboundDatagram struct {
	addr      *net.UDPAddr
	serverKey string
	packet    []byte
}

type writerTask struct {
	wasPacked bool
	item      *clientStreamTXPacket
	selected  *Stream_client
	frames    []encodedOutboundDatagram
}

// Bootstrap initializes a new Client by loading configuration, setting up logging,
// and preparing the connection map.
func Bootstrap(configPath string, logPath string, overrides config.ClientConfigOverrides) (*Client, error) {
	cfg, err := config.LoadClientConfigWithOverrides(configPath, overrides)
	if err != nil {
		return nil, err
	}
	return BootstrapLoadedConfig(cfg, logPath)
}

func BootstrapLoadedConfig(cfg config.ClientConfig, logPath string) (*Client, error) {
	var log *logger.Logger
	if logPath != "" {
		log = logger.NewWithFile("MasterDnsVPN Client", cfg.LogLevel, logPath)
	} else {
		log = logger.New("MasterDnsVPN Client", cfg.LogLevel)
	}

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	c.tuiEnabled = true
	if cfg.DomainKeyringFile != "" {
		if m, _, err := buildCodecByDomain(cfg.ConfigDir, cfg.DomainKeyringFile); err == nil && len(m) > 0 {
			c.codecByDomain = m
		} else if err != nil {
			return nil, fmt.Errorf("client DOMAIN_KEYRING_FILE load failed: %w", err)
		}
	}
	// When the local scanner is enabled, inventory is scanner-owned; the client
	// may start with zero configured resolvers and receive warm candidates later.
	if !cfg.ScannerEnabled || len(cfg.Resolvers) > 0 {
		if err := c.BuildConnectionMap(); err != nil {
			if c.log != nil {
				c.log.Errorf("<red>%v</red>", err)
			}
			return nil, err
		}
	}
	return c, nil
}

// SetTUIEnabled allows embedding the client inside a multi-instance host where
// only one dashboard is allowed to own the terminal.
func (c *Client) SetTUIEnabled(enabled bool) {
	if c == nil {
		return
	}
	c.tuiEnabled = enabled
}

// Config returns a copy of the loaded config (read-only).
func (c *Client) Config() config.ClientConfig {
	if c == nil {
		return config.ClientConfig{}
	}
	return c.cfg
}

func New(cfg config.ClientConfig, log *logger.Logger, codec *security.Codec) *Client {
	var responseMode uint8
	if cfg.BaseEncodeData {
		responseMode = mtuProbeBase64Reply
	}

	c := &Client{
		cfg:                 cfg,
		log:                 log,
		codec:               codec,
		balancer:            NewBalancer(cfg.ResolverBalancingStrategy, log),
		telemetry:           telemetry.NewRuntimeTelemetry(),
		uploadCompression:   uint8(cfg.UploadCompressionType),
		downloadCompression: uint8(cfg.DownloadCompressionType),
		mtuCryptoOverhead:   mtuCryptoOverhead(cfg.DataEncryptionMethod),
		maxPackedBlocks:     1,
		responseMode:        responseMode,
		udpBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, RuntimeUDPReadBufferSize)
			},
		},
		resolverConns:                         make(map[string]chan pooledUDPConn),
		resolverAddrCache:                     make(map[string]*net.UDPAddr),
		mtuTestRetries:                        cfg.MTUTestRetries,
		mtuTestTimeout:                        time.Duration(cfg.MTUTestTimeout * float64(time.Second)),
		mtuSaveToFile:                         cfg.SaveMTUServersToFile,
		mtuServersFileName:                    cfg.MTUServersFileName,
		mtuServersFileFormat:                  cfg.MTUServersFileFormat,
		mtuUsingSeparatorText:                 cfg.MTUUsingSeparatorText,
		mtuRemovedServerLogFormat:             cfg.MTURemovedServerLogFormat,
		mtuAddedServerLogFormat:               cfg.MTUAddedServerLogFormat,
		mtuReactiveAddedServerLogFormat:       cfg.MTUReactiveAddedServerLogFormat,
		streamResolverFailoverResendThreshold: cfg.StreamResolverFailoverResendThreshold,
		streamResolverFailoverCooldown:        time.Duration(cfg.StreamResolverFailoverCooldownSec * float64(time.Second)),

		// Workers config
		tunnelRX_TX_Workers:     cfg.RX_TX_Workers,
		tunnelProcessWorkers:    cfg.TunnelProcessWorkers,
		tunnelPacketTimeout:     time.Duration(cfg.TunnelPacketTimeoutSec * float64(time.Second)),
		plannerQueue:            make(chan plannerTask, max(24, cfg.RX_TX_Workers*24)),
		encodedTXChannel:        make(chan writerTask, max(24, cfg.RX_TX_Workers*24)),
		rxChannel:               make(chan asyncReadPacket, cfg.EffectiveRXChannelSize()),
		active_streams:          make(map[uint16]*Stream_client),
		recentlyClosedStreams:   make(map[uint16]time.Time),
		recentlyClosedHeap:      make(recentlyClosedHeap, 0, 128),
		dispatchSignal:          make(chan struct{}, 1),
		plannerQueueSpaceSignal: make(chan struct{}, 1),
		writerQueueSpaceSignal:  make(chan struct{}, 1),

		// DNS Management
		localDNSCache: dnsCache.New(
			cfg.LocalDNSCacheMaxRecords,
			time.Duration(cfg.LocalDNSCacheTTLSeconds)*time.Second,
			time.Duration(cfg.LocalDNSPendingTimeoutSec)*time.Second,
		),
		dnsResponses:           fragmentStore.New[dnsFragmentKey](cfg.EffectiveDNSResponseFragmentStoreCap()),
		localDNSCachePersist:   cfg.LocalDNSCachePersist,
		localDNSCachePath:      cfg.LocalDNSCachePath(),
		localDNSCacheFlushTick: time.Duration(cfg.LocalDNSCacheFlushSec) * time.Second,
		orphanQueue:            mlq.New[VpnProto.Packet](cfg.EffectiveOrphanQueueInitialCapacity()),
		sessionResetSignal:     make(chan struct{}, 1),
		socksRateLimit:         newSocksRateLimiter(),
	}

	if c.streamResolverFailoverResendThreshold < 1 {
		c.streamResolverFailoverResendThreshold = 1
	}

	if c.streamResolverFailoverCooldown <= 0 {
		c.streamResolverFailoverCooldown = time.Second
	}

	c.balancer.SetStreamFailoverConfig(c.streamResolverFailoverResendThreshold, c.streamResolverFailoverCooldown)
	c.balancer.SetAutoDisableConfig(
		cfg.AutoDisableTimeoutServers,
		time.Duration(cfg.AutoDisableTimeoutWindowSeconds*float64(time.Second)),
	)
	c.balancer.SetTelemetry(c.telemetry)

	c.balancer.SetResolverDisabledHandler(func(conn *Connection, cause string) {
		c.appendMTURemovedServerLine(conn, cause)
	})

	c.balancer.SetResolverDownConfirmHandler(func(conn *Connection, window time.Duration) bool {
		return c.confirmResolverDown(conn, window)
	})

	c.pingManager = newPingManager(c)
	return c
}

func (c *Client) Telemetry() *telemetry.RuntimeTelemetry {
	if c == nil {
		return nil
	}
	return c.telemetry
}

func (c *Client) nextSessionInitRetryDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}

	delay := c.cfg.SessionInitRetryBase()
	if failures > c.cfg.SessionInitRetryLinearAfter {
		delay += time.Duration(failures-c.cfg.SessionInitRetryLinearAfter) * c.cfg.SessionInitRetryStep()
	}

	if delay > c.cfg.SessionInitRetryMax() {
		return c.cfg.SessionInitRetryMax()
	}

	return delay
}

// Run starts the main execution loop of the client.
func (c *Client) Run(ctx context.Context) error {
	c.successMTUChecks = false
	c.log.Infof("\U0001F504 <cyan>Starting main runtime loop...</cyan>")
	sessionInitRetryDelay := time.Duration(0)
	sessionInitRetryFailures := 0

	// Single full-lifecycle TUI (if interactive). When enabled it owns terminal output.
	c.startFullTUIIfInteractive()
	defer c.stopFullTUI()
	defer c.stopScannerHB()

	// Ensure local DNS cache is loaded from file if persistence is enabled
	c.ensureLocalDNSCacheLoaded()

	// Optional local scanner warm-start (inventory-first). Best-effort: runtime must not crash if scanner is down.
	c.ensureScannerOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			c.notifySessionCloseBurst(time.Second)
			c.StopAsyncRuntime()
			return nil
		default:
			if !c.successMTUChecks && c.cfg.AutoProfileResolvers {
				if c.ui != nil {
					c.ui.SetPhase("profiling")
				}
				if err := c.AutoProfileBootstrapAndApply(ctx); err != nil {
					c.log.Errorf("<red>Auto profiling failed: %v</red>", err)
					c.successMTUChecks = false
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(5 * time.Second):
					}
					continue
				}
			}

			if !c.successMTUChecks {
				// In scanner-owned inventory mode, do not run client-side MTU scanning across the whole pool.
				// Use a conservative bootstrap MTU from config; runtime observes live behavior and can adapt.
				if c.cfg.ScannerEnabled {
					if c.ui != nil {
						c.ui.SetPhase("scanner-warm")
					}
					up, down := c.scannerBootstrapTargets()
					if up <= 0 {
						up = c.cfg.MinUploadMTU
					}
					if down <= 0 {
						down = c.cfg.MinDownloadMTU
					}
					if up <= 0 {
						up = 35
					}
					if down <= 0 {
						down = 100
					}
					c.applySyncedMTUState(up, down, c.encodedCharsForPayload(up))
					c.successMTUChecks = true
				}
			}

			if !c.successMTUChecks {
				if c.ui != nil {
					c.ui.SetPhase("mtu-tests")
				}
				if err := c.RunInitialMTUTests(ctx); err != nil {
					c.log.Errorf("<red>MTU tests failed: %v</red>", err)
					c.successMTUChecks = false
					// Wait a bit before retrying or exiting if critical
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(5 * time.Second):
					}
					continue
				}

				if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
					c.successMTUChecks = false
					c.log.Errorf("<red>❌ MTU tests failed: Upload MTU: %d, Download MTU: %d</red>", c.syncedUploadMTU, c.syncedDownloadMTU)
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(5 * time.Second):
					}
					continue
				}

				c.successMTUChecks = true
				if c.runtimeController == nil {
					c.runtimeController = newRuntimeController(c)
				}
				if c.runtimeController != nil && c.runtimeControllerStarted.CompareAndSwap(false, true) {
					go c.runtimeController.Run(ctx)
				}
				// Legacy health loop is disabled when the runtime controller is present (controller owns reserve probing).
				if c.runtimeController == nil {
					if c.resolverHealthStarted.CompareAndSwap(false, true) {
						go c.runResolverHealthLoop(ctx)
					}
				}
				c.ShortPrintBanner()
			}

			// AutoProfile can make MTU checks successful without entering the legacy MTU block.
			// Ensure background health/controller loops are started in both paths.
			if c.successMTUChecks {
				if c.runtimeController == nil {
					c.runtimeController = newRuntimeController(c)
				}
				if c.runtimeController != nil && c.runtimeControllerStarted.CompareAndSwap(false, true) {
					go c.runtimeController.Run(ctx)
				}
				if c.runtimeController == nil {
					if c.resolverHealthStarted.CompareAndSwap(false, true) {
						go c.runResolverHealthLoop(ctx)
					}
				}
			}

			if !c.sessionReady {
				// Scanner-owned inventory: do not attempt session init until we have at least one ready lane.
				if c.cfg.ScannerEnabled && (c.balancer == nil || c.balancer.ActiveCount() < 1) {
					if c.ui != nil {
						c.ui.SetPhase("scanner-wait")
					}
					_ = c.scannerWarmStartAll(ctx)
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(900 * time.Millisecond):
					}
					continue
				}

				if c.ui != nil {
					c.ui.SetPhase("connecting")
				}
				retries := c.cfg.MTUTestRetries
				if retries < 1 {
					retries = 3
				}

				if err := c.InitializeSession(retries); err != nil {
					sessionInitRetryFailures++
					sessionInitRetryDelay = c.nextSessionInitRetryDelay(sessionInitRetryFailures)
					c.log.Errorf("<red>❌ Session initialization failed: %v</red>", err)
					c.log.Warnf("<yellow>Session init retry backoff: %s</yellow>", sessionInitRetryDelay)
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(sessionInitRetryDelay):
					}
					continue
				}
				c.log.Infof("<green>✅ Session Initialized Successfully (ID: <cyan>%d</cyan>)</green>", c.sessionID)
				if c.ui != nil {
					c.ui.SetPhase("connected")
				}

				sessionInitRetryFailures = 0
				sessionInitRetryDelay = 0
				if err := c.StartAsyncRuntime(ctx); err != nil {
					c.log.Errorf("<red>❌ Async Runtime failed to launch: %v</red>", err)
					return err
				}

				c.InitVirtualStream0()

				if c.pingManager != nil {
					c.pingManager.Start(ctx)
				}

				// Periodic telemetry snapshot (instrumentation-only, no adaptation).
				if c.telemetryPersistStarted.CompareAndSwap(false, true) {
					go c.runTelemetryPersistLoop(ctx)
				}

				c.ensureLocalDNSCachePersistence(ctx)
			}

			select {
			case <-ctx.Done():
				c.notifySessionCloseBurst(time.Second)
				c.StopAsyncRuntime()
				return nil
			case <-c.sessionResetSignal:
				c.StopAsyncRuntime()
				c.resetSessionState(true)
				c.clearRuntimeResetRequest()
				sessionInitRetryFailures++
				sessionInitRetryDelay = c.nextSessionInitRetryDelay(sessionInitRetryFailures)
				c.log.Warnf("<yellow>Session reset requested, retrying in %s</yellow>", sessionInitRetryDelay)
				select {
				case <-ctx.Done():
					c.notifySessionCloseBurst(time.Second)
					c.StopAsyncRuntime()
					return nil
				case <-time.After(sessionInitRetryDelay):
				}
				continue
			case <-time.After(1 * time.Second):
			}
		}
	}
}

func (c *Client) HandleStreamPacket(packet VpnProto.Packet) error {
	if !packet.HasStreamID {
		return nil
	}

	c.streamsMu.RLock()
	s, ok := c.active_streams[packet.StreamID]
	c.streamsMu.RUnlock()

	if !ok || s == nil {
		return nil
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		if (packet.PacketType == Enums.PACKET_STREAM_DATA ||
			packet.PacketType == Enums.PACKET_STREAM_RESEND ||
			packet.PacketType == Enums.PACKET_STREAM_DATA_NACK) && !c.isRecentlyClosedStream(packet.StreamID, c.now()) {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
		}
		return nil
	}

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		if arqObj.IsClosed() {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
			return nil
		}

		if !s.TerminalSince().IsZero() {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
			return nil
		}

		if !arqObj.ReceiveData(packet.SequenceNum, packet.Payload) {
			return nil
		}

	case Enums.PACKET_STREAM_DATA_NACK:
		if arqObj.IsClosed() || !s.TerminalSince().IsZero() {
			return nil
		}

		if arqObj.HandleDataNack(packet.SequenceNum) {
			c.balancer.NoteStreamProgress(packet.StreamID)
		}
	case Enums.PACKET_STREAM_CONNECTED:
		return c.handleStreamConnected(packet, s, arqObj)
	case Enums.PACKET_STREAM_CONNECT_FAIL:
		return c.handleStreamConnectFail(packet, s, arqObj)
	case Enums.PACKET_STREAM_CLOSE_READ:
		arqObj.MarkCloseReadReceived()
	case Enums.PACKET_STREAM_CLOSE_WRITE:
		arqObj.MarkCloseWriteReceived()
	case Enums.PACKET_STREAM_RST:
		arqObj.MarkRstReceived()
		arqObj.Close("peer reset received", arq.CloseOptions{Force: true})
		s.MarkTerminal(time.Now())
		if s.StatusValue() != streamStatusCancelled {
			s.SetStatus(streamStatusTimeWait)
		}
	default:
		handledAck := arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
		if handledAck {
			c.balancer.NoteStreamProgress(packet.StreamID)
		}
		if _, ok := Enums.GetPacketCloseStream(packet.PacketType); handledAck && ok {
			if s.StatusValue() == streamStatusCancelled || arqObj.IsClosed() {
				s.MarkTerminal(time.Now())
				if s.StatusValue() != streamStatusCancelled {
					s.SetStatus(streamStatusTimeWait)
				}
			}
		}
	}

	return nil
}

func (c *Client) HandleSessionReject(packet VpnProto.Packet) error {
	c.requestSessionRestart("session reject received")
	return nil
}

func (c *Client) HandleSessionBusy() error {
	c.requestSessionRestart("session busy received")
	return nil
}

func (c *Client) HandleErrorDrop(packet VpnProto.Packet) error {
	c.requestSessionRestart("error drop received")
	return nil
}

func (c *Client) HandleMTUResponse(packet VpnProto.Packet) error {
	return nil
}
