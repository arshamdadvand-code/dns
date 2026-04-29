package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"
	"golang.org/x/term"

	"masterdnsvpn-go/internal/telemetry"
)

// multiTUI is a single-owner dashboard for MultiApp.
// It does not influence runtime logic; it only observes backends + scanner.
type multiTUI struct {
	app *tview.Application

	header   *tview.TextView
	table    *tview.TextView
	scanner  *tview.TextView
	events   *tview.TextView

	eventsSink *tuiEventCollector

	mu        sync.RWMutex
	startedAt time.Time
	backends  []*Client
	scannerAddr string

	lastByDomain map[string]telemetry.Snapshot
	lastAt       time.Time

	lastScanner string
	lastScannerAt time.Time
}

func canEnableMultiTUI(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok || f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func newMultiTUI(backends []*Client, scannerAddr string) *multiTUI {
	ui := &multiTUI{
		app:          tview.NewApplication(),
		backends:     backends,
		scannerAddr:  scannerAddr,
		startedAt:    time.Now(),
		eventsSink:   newTUIEventCollector(30),
		lastByDomain: make(map[string]telemetry.Snapshot),
	}

	ui.header = tview.NewTextView().SetDynamicColors(true)
	ui.header.SetTextAlign(tview.AlignLeft)

	box := func(title string) *tview.TextView {
		v := tview.NewTextView().SetDynamicColors(true)
		v.SetBorder(true).SetTitle(" " + title + " ")
		v.SetWrap(false)
		return v
	}

	ui.table = box("Instances")
	ui.scanner = box("Scanner")
	ui.events = box("Events")
	ui.events.SetWrap(true)
	ui.events.SetMaxLines(20)

	grid := tview.NewGrid().
		SetRows(1, 0, 7).
		SetColumns(0, 0).
		SetBorders(false)
	grid.AddItem(ui.header, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(ui.table, 1, 0, 1, 1, 0, 0, false)
	grid.AddItem(ui.scanner, 1, 1, 1, 1, 0, 0, false)
	grid.AddItem(ui.events, 2, 0, 1, 2, 0, 0, false)
	ui.app.SetRoot(grid, true)

	go ui.loop()
	return ui
}

func (ui *multiTUI) AddEvent(tag string, msg string) {
	if ui == nil || ui.eventsSink == nil {
		return
	}
	ui.eventsSink.Add("INFO", tag+": "+msg)
}

func (ui *multiTUI) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for range t.C {
		ui.render()
	}
}

func (ui *multiTUI) render() {
	if ui == nil {
		return
	}

	now := time.Now()
	elapsed := now.Sub(ui.startedAt).Truncate(time.Second)

	ui.mu.Lock()
	defer ui.mu.Unlock()

	ui.header.SetText(fmt.Sprintf("[white::b]MasterDnsVPN[-:-:-]  [gray]mode[/gray]=[white]multi-instance[/white]  [gray]elapsed[/gray]=[white]%s[/white]", elapsed))

	// Per-instance table (sorted by domain for stable layout).
	type row struct {
		domain string
		status string
		active int
		reserve int
		ackTXps float64
		delRXps float64
		wireTXps float64
		wireRXps float64
		effTX float64
		effRX float64
		rttP50 string
		rttP90 string
		state string
		lastAction string
		cooldown string
	}

	rows := make([]row, 0, len(ui.backends))
	for _, c := range ui.backends {
		if c == nil {
			continue
		}
		d := ""
		if len(c.cfg.Domains) > 0 {
			d = c.cfg.Domains[0]
		}
		snap := c.telemetry.Snapshot()

		prev, ok := ui.lastByDomain[d]
		dt := now.Sub(ui.lastAt).Seconds()
		if ui.lastAt.IsZero() || dt <= 0 {
			dt = 1
		}
		var ackTXps, delRXps, wireTXps, wireRXps float64
		if ok {
			ackTXps = float64(snap.UsefulAckedTX-prev.UsefulAckedTX) / dt
			delRXps = float64(snap.UsefulDeliveredRX-prev.UsefulDeliveredRX) / dt
			wireTXps = float64(snap.WireTX-prev.WireTX) / dt
			wireRXps = float64(snap.WireRX-prev.WireRX) / dt
		}
		effTX := 0.0
		effRX := 0.0
		if wireTXps > 0 {
			effTX = ackTXps / wireTXps
		}
		if wireRXps > 0 {
			effRX = delRXps / wireRXps
		}

		// RTT aggregate across resolvers: use p50/p90 of successful tunnel responses if present.
		rttP50 := "-"
		rttP90 := "-"
		if len(snap.Resolvers) > 0 {
			// Prefer RTT from the most-successful resolver as a readable proxy.
			best := snap.Resolvers[0]
			if best.RTTP50ms > 0 {
				rttP50 = fmt.Sprintf("%.0fms", best.RTTP50ms)
			}
			if best.RTTP90ms > 0 {
				rttP90 = fmt.Sprintf("%.0fms", best.RTTP90ms)
			}
		}

		ss := c.runtimeControllerSnapshot()
		status := "warming"
		if c.sessionReady {
			status = "ready"
		}

		rows = append(rows, row{
			domain: d,
			status: status,
			active: len(c.balancer.ActiveConnections()),
			reserve: len(c.balancer.InactiveConnections()),
			ackTXps: ackTXps,
			delRXps: delRXps,
			wireTXps: wireTXps,
			wireRXps: wireRXps,
			effTX: effTX,
			effRX: effRX,
			rttP50: rttP50,
			rttP90: rttP90,
			state: ss.State,
			lastAction: ss.LastAction,
			cooldown: fmt.Sprintf("%.0fs", ss.CooldownRemainS),
		})

		ui.lastByDomain[d] = snap
	}
	ui.lastAt = now

	sort.Slice(rows, func(i, j int) bool { return rows[i].domain < rows[j].domain })

	var b strings.Builder
	b.WriteString("domain              st    act  res   ackTX/s   delRX/s   wireTX/s  wireRX/s  effTX  effRX  rtt50  rtt90  ctrl     last_action  cooldown\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("%-18s  %-5s  %3d  %3d  %8.0f  %8.0f  %8.0f  %8.0f  %5.2f  %5.2f  %5s  %5s  %-7s  %-11s  %7s\n",
			r.domain, r.status, r.active, r.reserve,
			r.ackTXps, r.delRXps, r.wireTXps, r.wireRXps,
			r.effTX, r.effRX, r.rttP50, r.rttP90, r.state, r.lastAction, r.cooldown,
		))
	}
	ui.table.SetText(b.String())

	// Scanner panel (poll low frequency).
	if ui.scannerAddr != "" && (ui.lastScannerAt.IsZero() || now.Sub(ui.lastScannerAt) > 3*time.Second) {
		ui.lastScannerAt = now
		ui.lastScanner = ui.fetchScannerHealth()
	}
	ui.scanner.SetText(ui.lastScanner)

	// Events pane (bounded).
	if ui.eventsSink != nil {
		ui.events.SetText(ui.eventsSink.Render())
	}
}

func (ui *multiTUI) fetchScannerHealth() string {
	if ui == nil || ui.scannerAddr == "" {
		return "scanner: disabled"
	}
	url := ui.scannerAddr
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	url = strings.TrimRight(url, "/") + "/health"
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return fmt.Sprintf("scanner: down (%v)", err)
	}
	defer resp.Body.Close()
	var anyObj map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&anyObj); err != nil {
		return fmt.Sprintf("scanner: bad json (%v)", err)
	}
	ready, _ := anyObj["ready"].(bool)
	ok, _ := anyObj["ok"].(bool)
	return fmt.Sprintf("ok=%v ready=%v", ok, ready)
}

func (ui *multiTUI) Start() {
	if ui == nil {
		return
	}
	go func() {
		_ = ui.app.Run()
	}()
}

func (ui *multiTUI) Stop() {
	if ui == nil {
		return
	}
	ui.app.Stop()
}
