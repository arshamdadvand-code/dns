package client

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"
	"golang.org/x/term"

	"masterdnsvpn-go/internal/telemetry"
)

// fullTUI is a single-owner, full-lifecycle dashboard.
// When enabled, it is the only component allowed to write to the terminal.
type fullTUI struct {
	app *tview.Application

	header     *tview.TextView
	status     *tview.TextView
	derived    *tview.TextView
	session    *tview.TextView
	throughput *tview.TextView
	resolvers  *tview.TextView
	events     *tview.TextView

	eventsSink *tuiEventCollector

	mu        sync.RWMutex
	phase     string
	startedAt time.Time

	client *Client
	stats  *autoProfileRunStats

	lastTel telemetry.Snapshot
	lastAt  time.Time
}

func canEnableFullTUI(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok || f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func (c *Client) startFullTUIIfInteractive() {
	if c == nil || c.ui != nil || c.log == nil {
		return
	}
	if !c.tuiEnabled {
		return
	}
	if !canEnableFullTUI(os.Stdout) {
		return
	}

	ui := newFullTUI(c)
	c.ui = ui

	// Hard rule: logger must not write to terminal directly in TUI mode.
	c.log.SetConsoleWriter(ui.eventsSink)

	go func() {
		_ = ui.app.Run()
	}()
}

func (c *Client) stopFullTUI() {
	if c == nil || c.ui == nil {
		return
	}
	c.ui.app.Stop()
}

func newFullTUI(c *Client) *fullTUI {
	ui := &fullTUI{
		app:        tview.NewApplication(),
		client:     c,
		startedAt:  time.Now(),
		phase:      "starting",
		eventsSink: newTUIEventCollector(20),
	}

	ui.header = tview.NewTextView().SetDynamicColors(true)
	ui.header.SetTextAlign(tview.AlignLeft)

	box := func(title string) *tview.TextView {
		v := tview.NewTextView().SetDynamicColors(true)
		v.SetBorder(true).SetTitle(" " + title + " ")
		v.SetWrap(false)
		return v
	}

	ui.status = box("Status")
	ui.derived = box("Derived")
	ui.session = box("Session")
	ui.throughput = box("Throughput")
	ui.resolvers = box("Resolvers")
	ui.events = box("Events")
	ui.events.SetWrap(true)
	ui.events.SetMaxLines(20)

	grid := tview.NewGrid().
		SetRows(1, 7, 7, 7, 0).
		SetColumns(0, 0, 0).
		SetBorders(false)

	// Header spans full width.
	grid.AddItem(ui.header, 0, 0, 1, 3, 0, 0, false)
	// Upper panels.
	grid.AddItem(ui.status, 1, 0, 1, 1, 0, 0, false)
	grid.AddItem(ui.session, 1, 1, 1, 1, 0, 0, false)
	grid.AddItem(ui.throughput, 1, 2, 1, 1, 0, 0, false)

	grid.AddItem(ui.derived, 2, 0, 2, 1, 0, 0, false)
	grid.AddItem(ui.resolvers, 2, 1, 2, 2, 0, 0, false)

	// Events at bottom.
	grid.AddItem(ui.events, 4, 0, 1, 3, 0, 0, false)

	ui.app.SetRoot(grid, true)
	ui.app.EnableMouse(false)

	// Single render owner: one ticker that updates views via QueueUpdateDraw.
	go ui.loop()

	return ui
}

func (ui *fullTUI) SetPhase(p string) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	ui.phase = p
	ui.mu.Unlock()
}

func (ui *fullTUI) AttachAutoProfileStats(stats *autoProfileRunStats) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	ui.stats = stats
	ui.mu.Unlock()
}

func (ui *fullTUI) AddRuntimeEvent(ev runtimeControllerEvent) {
	if ui == nil || ui.eventsSink == nil {
		return
	}
	msg := strings.TrimSpace(ev.Reason + " " + ev.Details)
	if msg == "" {
		return
	}
	ui.eventsSink.Add("ADAPT", msg)
}

func (ui *fullTUI) AddSystemEvent(tag string, msg string) {
	if ui == nil || ui.eventsSink == nil {
		return
	}
	tag = strings.TrimSpace(tag)
	msg = strings.TrimSpace(msg)
	if tag == "" {
		tag = "SYS"
	}
	if msg == "" {
		return
	}
	ui.eventsSink.Add(tag, msg)
}

func (ui *fullTUI) loop() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()

	for range t.C {
		if ui.app == nil {
			return
		}
		ui.app.QueueUpdateDraw(func() {
			ui.render()
		})
	}
}

func (ui *fullTUI) render() {
	c := ui.client
	if ui == nil || c == nil {
		return
	}

	ui.mu.RLock()
	phase := ui.phase
	stats := ui.stats
	ui.mu.RUnlock()

	domain := ""
	if len(c.cfg.Domains) > 0 {
		domain = c.cfg.Domains[0]
	}

	elapsed := time.Since(ui.startedAt).Truncate(time.Second)
	adapt := c.runtimeControllerSnapshot()

	state := "idle"
	switch {
	case phase != "":
		state = phase
	case c.sessionReady:
		state = "connected"
	default:
		state = "starting"
	}

	sid := "-"
	if c.sessionReady {
		sid = fmt.Sprintf("%d", c.sessionID)
	}

	ui.header.SetText(fmt.Sprintf("[white::b]MasterDnsVPN[-:-:-]  state=[cyan]%s[-]  domain=[white]%s[-]  elapsed=[white]%s[-]  session=[white]%s[-]",
		state, domain, elapsed, sid))

	// Status
	activeCount := len(c.balancer.ActiveConnections())
	reserveCount := len(c.balancer.InactiveConnections())
	profileLine := ""
	if stats != nil && phase == "profiling" {
		snap := stats.snapshot()
		profileLine = fmt.Sprintf("profiling: input=%d viable=%d complete=%d\n", snap.UniqueInput, snap.Stage0Viable, snap.ProfileComplete)
	}
	ui.status.SetText(fmt.Sprintf(
		"%sadapt_state=%s\nactive=%d  reserve=%d\nupload_mtu=%d  download_mtu=%d\nhealth=%.3f  efficiency=%.3f\n",
		profileLine,
		emptyIf(adapt.State, "OFF"),
		activeCount, reserveCount,
		c.syncedUploadMTU, c.syncedDownloadMTU,
		adapt.ActiveSetHealth,
		adapt.ThroughputEfficiency,
	))

	// Derived (current runtime knobs)
	ui.derived.SetText(fmt.Sprintf(
		"dup_setup=%d  dup_data=%d\ntarget_up=%d  target_down=%d\nfailover_thr=%d  failover_cool=%.1fs\nlast_action=%s\nreason=%s\ncooldown=%.1fs  freeze=%.1fs\n",
		c.cfg.SetupPacketDuplicationCount,
		c.cfg.PacketDuplicationCount,
		adapt.UploadTarget,
		adapt.DownloadTarget,
		c.streamResolverFailoverResendThreshold,
		c.streamResolverFailoverCooldown.Seconds(),
		emptyIf(adapt.LastAction, "NONE"),
		emptyIf(adapt.LastReason, "-"),
		adapt.CooldownRemainS,
		adapt.StepUpFreezeS,
	))

	// Session
	sessStatus := "not-ready"
	if c.sessionReady {
		sessStatus = "ready"
	}
	ui.session.SetText(fmt.Sprintf(
		"status=%s\nsocks=%s:%d\nlocal_dns=%v\nfailover_mode_tail=%.2f\nreserve_readiness=%.3f\n",
		sessStatus,
		c.cfg.ListenIP, c.cfg.ListenPort,
		c.cfg.LocalDNSEnabled,
		adapt.TailInflation,
		adapt.ReserveReadiness,
	))

	// Throughput + efficiency
	if c.telemetry == nil {
		ui.throughput.SetText("telemetry: not available\n")
	} else {
		tel := c.telemetry.Snapshot()
		now := time.Now()
		if ui.lastAt.IsZero() {
			ui.lastAt = now
			ui.lastTel = tel
		}
		dt := now.Sub(ui.lastAt).Seconds()
		if dt <= 0 {
			dt = 1
		}
		ing := float64(tel.UsefulIngressTX-ui.lastTel.UsefulIngressTX) / dt
		ack := float64(tel.UsefulAckedTX-ui.lastTel.UsefulAckedTX) / dt
		del := float64(tel.UsefulDeliveredRX-ui.lastTel.UsefulDeliveredRX) / dt
		wtx := float64(tel.WireTX-ui.lastTel.WireTX) / dt
		wrx := float64(tel.WireRX-ui.lastTel.WireRX) / dt
		ui.lastAt = now
		ui.lastTel = tel

		txEff := 0.0
		if tel.WireTX > 0 {
			txEff = float64(tel.UsefulAckedTX) / float64(tel.WireTX)
		}
		rxEff := 0.0
		if tel.WireRX > 0 {
			rxEff = float64(tel.UsefulDeliveredRX) / float64(tel.WireRX)
		}

		ui.throughput.SetText(fmt.Sprintf(
			"tx_ingress=%s\ntx_acked=%s\nrx_delivered=%s\nwire_tx=%s\nwire_rx=%s\ntx_eff=%.3f  rx_eff=%.3f\n",
			formatBpsCompact(ing), formatBpsCompact(ack), formatBpsCompact(del),
			formatBpsCompact(wtx), formatBpsCompact(wrx),
			txEff, rxEff,
		))
	}

	// Resolvers panel: top active resolvers by OK count (from telemetry)
	ui.resolvers.SetText(ui.renderResolverPanel())

	// Events pane (bounded, no terminal scroll)
	ui.events.SetText(ui.eventsSink.Render())
}

func (ui *fullTUI) renderResolverPanel() string {
	c := ui.client
	if ui == nil || c == nil || c.telemetry == nil {
		return "no telemetry"
	}

	active := c.balancer.ActiveConnections()
	activeSet := make(map[string]struct{}, len(active))
	for _, a := range active {
		if a.Key != "" {
			activeSet[a.Key] = struct{}{}
		}
	}

	tel := c.telemetry.Snapshot()
	items := make([]telemetry.ResolverSnapshot, 0, 16)
	for _, rs := range tel.Resolvers {
		if _, ok := activeSet[rs.Key]; ok {
			items = append(items, rs)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].OK != items[j].OK {
			return items[i].OK > items[j].OK
		}
		return items[i].Key < items[j].Key
	})
	if len(items) == 0 {
		return "active resolvers: (no samples yet)"
	}
	if len(items) > 10 {
		items = items[:10]
	}

	var b strings.Builder
	b.WriteString("key                          ok  to  ref  sf  nt  streak(to/f)  rtt50  rtt90\n")
	for _, it := range items {
		fmt.Fprintf(&b, "%-28s %3d %3d %4d %3d %3d   %2d/%2d      %5.0f  %5.0f\n",
			it.Key,
			it.OK,
			it.Timeout,
			it.Refused,
			it.Servfail,
			it.NoTunnel,
			it.ConsecutiveTimeout,
			it.ConsecutiveFail,
			it.RTTP50ms,
			it.RTTP90ms,
		)
	}
	return b.String()
}

func formatBpsCompact(v float64) string {
	if v < 0 {
		v = 0
	}
	const kb = 1024.0
	const mb = 1024.0 * 1024.0
	switch {
	case v >= mb:
		return fmt.Sprintf("%.2fMiB/s", v/mb)
	case v >= kb:
		return fmt.Sprintf("%.1fKiB/s", v/kb)
	default:
		return fmt.Sprintf("%.0fB/s", v)
	}
}

func emptyIf(v string, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
