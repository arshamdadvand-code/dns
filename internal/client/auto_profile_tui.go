// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"masterdnsvpn-go/internal/telemetry"
)

type autoProfileDashboard struct {
	stats *autoProfileRunStats
	stop  chan struct{}
	done  chan struct{}
	out   io.Writer

	telemetry *telemetry.RuntimeTelemetry
	lastSnap  telemetry.Snapshot
	lastAt    time.Time
}

func startAutoProfileDashboard(stats *autoProfileRunStats, out io.Writer) *autoProfileDashboard {
	if out == nil {
		out = os.Stdout
	}
	d := &autoProfileDashboard{
		stats: stats,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		out:   out,
	}
	go d.loop()
	return d
}

func (d *autoProfileDashboard) Close() {
	if d == nil {
		return
	}
	select {
	case <-d.stop:
	default:
		close(d.stop)
	}
	<-d.done
}

func (d *autoProfileDashboard) loop() {
	defer close(d.done)
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-d.stop:
			return
		case <-t.C:
			if d.stats == nil {
				continue
			}
			snap := d.stats.snapshot()
			var tel telemetry.Snapshot
			if d.telemetry != nil {
				tel = d.telemetry.Snapshot()
			}
			_, _ = io.WriteString(d.out, renderDashboard(snap, tel, d))
		}
	}
}

func formatBps(v float64) string {
	if v < 0 {
		v = 0
	}
	const kb = 1024.0
	const mb = 1024.0 * 1024.0
	switch {
	case v >= mb:
		return fmt.Sprintf("%.2f MiB/s", v/mb)
	case v >= kb:
		return fmt.Sprintf("%.1f KiB/s", v/kb)
	default:
		return fmt.Sprintf("%.0f B/s", v)
	}
}

func safeRatio(num uint64, den uint64) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func (d *autoProfileDashboard) rates(now time.Time, tel telemetry.Snapshot) (float64, float64, float64, float64, float64) {
	if d == nil {
		return 0, 0, 0, 0, 0
	}
	if d.lastAt.IsZero() {
		d.lastAt = now
		d.lastSnap = tel
		return 0, 0, 0, 0, 0
	}
	dt := now.Sub(d.lastAt).Seconds()
	if dt <= 0 {
		return 0, 0, 0, 0, 0
	}
	ing := float64(tel.UsefulIngressTX-d.lastSnap.UsefulIngressTX) / dt
	ack := float64(tel.UsefulAckedTX-d.lastSnap.UsefulAckedTX) / dt
	del := float64(tel.UsefulDeliveredRX-d.lastSnap.UsefulDeliveredRX) / dt
	wtx := float64(tel.WireTX-d.lastSnap.WireTX) / dt
	wrx := float64(tel.WireRX-d.lastSnap.WireRX) / dt
	d.lastAt = now
	d.lastSnap = tel
	return ing, ack, del, wtx, wrx
}

func renderDashboard(s autoProfileSnapshot, tel telemetry.Snapshot, d *autoProfileDashboard) string {
	var b strings.Builder
	// Full-screen fixed layout: clear + home.
	b.WriteString("\x1b[2J\x1b[H")
	// Header (simple ANSI coloring to keep this self-contained).
	title := "MasterDnsVPN AutoProfile (Phase 1)"
	if s.Completed {
		title = "MasterDnsVPN AutoProfile (Phase 1)  FINAL SUMMARY (FROZEN)"
	}
	fmt.Fprintf(&b, "\x1b[36m%s\x1b[0m  domain=\x1b[1m%s\x1b[0m  elapsed=%s\n", title, s.Domain, s.Elapsed.Truncate(time.Second))
	b.WriteString(strings.Repeat("=", 100) + "\n")

	// Stage summary box
	b.WriteString("\x1b[1mStage Summary\x1b[0m\n")
	fmt.Fprintf(&b, "  total_input_unique:        \x1b[36m%d\x1b[0m\n", s.UniqueInput)
	fmt.Fprintf(&b, "  blank:                     \x1b[36m%d\x1b[0m\n", s.File.BlankLines)
	fmt.Fprintf(&b, "  invalid_format:            \x1b[36m%d\x1b[0m\n", s.File.InvalidFormatLines)
	fmt.Fprintf(&b, "  duplicate:                 \x1b[36m%d\x1b[0m\n", s.File.DuplicateLines)
	fmt.Fprintf(&b, "  hard_invalid_scope:        \x1b[36m%d\x1b[0m\n", s.File.HardInvalidScopeLines)
	fmt.Fprintf(&b, "  Stage0_attempted:          \x1b[36m%d\x1b[0m\n", s.Stage0Attempted)
	fmt.Fprintf(&b, "  Stage0_viable:             \x1b[32m%d\x1b[0m\n", s.Stage0Viable)
	fmt.Fprintf(&b, "  Stage0_timeout:            \x1b[33m%d\x1b[0m\n", s.Stage0Timeout)
	fmt.Fprintf(&b, "  Stage0_malformed:          \x1b[33m%d\x1b[0m\n", s.Stage0Malformed)
	fmt.Fprintf(&b, "  Stage1_upload_fail:        \x1b[33m%d\x1b[0m\n", s.Stage1UploadFail)
	fmt.Fprintf(&b, "  Stage1_download_fail:      \x1b[33m%d\x1b[0m\n", s.Stage1DownloadFail)
	fmt.Fprintf(&b, "  Stage2_refined:            \x1b[36m%d\x1b[0m\n", s.Stage2Refined)
	fmt.Fprintf(&b, "  final_profile_complete:    \x1b[36m%d\x1b[0m\n", s.ProfileComplete)
	if s.DerivedAvailable {
		fmt.Fprintf(&b, "  active:                    \x1b[32m%d\x1b[0m\n", s.DerivedActive)
		fmt.Fprintf(&b, "  reserve:                   \x1b[36m%d\x1b[0m\n", s.DerivedReserve)
	} else {
		b.WriteString("  active:                    (pending)\n")
		b.WriteString("  reserve:                   (pending)\n")
	}
	b.WriteString("\n")

	// Reject reasons
	b.WriteString("\x1b[1mReject Reasons\x1b[0m\n")
	b.WriteString("  Stage0 malformed subreasons (top)\n")
	for _, kv := range s.MalformedSubTop {
		fmt.Fprintf(&b, "    %-36s %6d\n", kv.k, kv.v)
	}
	b.WriteString("  Stage1/2 fail reasons (top)\n")
	for _, kv := range s.StageFailTop {
		fmt.Fprintf(&b, "    %-36s %6d\n", kv.k, kv.v)
	}
	b.WriteString("\n")

	// Derived runtime
	b.WriteString("\x1b[1mDerived Runtime Parameters\x1b[0m\n")
	if !s.DerivedAvailable {
		b.WriteString("  (not derived yet)\n\n")
	} else {
		fmt.Fprintf(&b, "  upload_target=%d  download_target=%d  active=%d  reserve=%d\n", s.DerivedUpload, s.DerivedDownload, s.DerivedActive, s.DerivedReserve)
		fmt.Fprintf(&b, "  setup_dup=%d  data_dup=%d  failover(thr=%d cool=%.1fs)\n", s.DerivedSetupDup, s.DerivedDataDup, s.DerivedFailThr, s.DerivedFailCool)
		fmt.Fprintf(&b, "  confidence=%s  fragile=%v\n\n", s.DerivedConfidence, s.DerivedFragile)
		txP50, txP90 := percentileFromMinis(s.Survivors, true, 0.50), percentileFromMinis(s.Survivors, true, 0.90)
		rxP50, rxP90 := percentileFromMinis(s.Survivors, false, 0.50), percentileFromMinis(s.Survivors, false, 0.90)
		fmt.Fprintf(&b, "  tx_pref_summary: upload_recommended p50=%d p90=%d\n", txP50, txP90)
		fmt.Fprintf(&b, "  rx_pref_summary: download_recommended p50=%d p90=%d\n\n", rxP50, rxP90)
	}

	if s.Completed {
		if s.PersistedPath != "" {
			fmt.Fprintf(&b, "\n\x1b[32mPersisted summary:\x1b[0m %s\n", s.PersistedPath)
		} else {
			b.WriteString("\n\x1b[33mPersisted summary:\x1b[0m (failed to write)\n")
		}
	}

	// Spectrum (only survivors, so small)
	b.WriteString("\x1b[1mResolver Spectrum (Stage0 survivors)\x1b[0m\n")
	b.WriteString("  TX (upload recommended)\n")
	renderSpectrum(&b, s.Survivors, true, s.DerivedActiveList, s.DerivedReserveList)
	b.WriteString("  RX (download recommended)\n")
	renderSpectrum(&b, s.Survivors, false, s.DerivedActiveList, s.DerivedReserveList)
	b.WriteString("\n")

	// Throughput section (Phase 1: not instrumented yet)
	b.WriteString("\x1b[1mThroughput\x1b[0m\n")
	if d == nil || d.telemetry == nil {
		b.WriteString("  actual_throughput: not available (telemetry not attached)\n")
	} else {
		now := time.Now()
		ing, ack, del, wtx, wrx := d.rates(now, tel)
		txEff := safeRatio(tel.UsefulAckedTX, tel.WireTX)
		rxEff := safeRatio(tel.UsefulDeliveredRX, tel.WireRX)
		b.WriteString("  goodput_tx_ingress:   " + formatBps(ing) + "\n")
		b.WriteString("  goodput_tx_acked:     " + formatBps(ack) + "\n")
		b.WriteString("  goodput_rx_delivered: " + formatBps(del) + "\n")
		b.WriteString("  wire_tx:              " + formatBps(wtx) + "\n")
		b.WriteString("  wire_rx:              " + formatBps(wrx) + "\n")
		fmt.Fprintf(&b, "  tx_efficiency (acked/wire): %.3f\n", txEff)
		fmt.Fprintf(&b, "  rx_efficiency (delivered/wire): %.3f\n", rxEff)
	}
	b.WriteString("\n")

	// Resolver runtime health (top active resolvers)
	b.WriteString("\x1b[1mResolver Runtime Health (Top Active)\x1b[0m\n")
	if d == nil || d.telemetry == nil || len(s.DerivedActiveList) == 0 {
		b.WriteString("  (not available)\n\n")
	} else {
		activeSet := make(map[string]struct{}, len(s.DerivedActiveList))
		for _, a := range s.DerivedActiveList {
			activeSet[a] = struct{}{}
		}
		items := make([]telemetry.ResolverSnapshot, 0, len(s.DerivedActiveList))
		for _, rs := range tel.Resolvers {
			// Balancer keys can be "ip|port|domain". Derived lists are "ip:port".
			ipPort := rs.Key
			if parts := strings.Split(rs.Key, "|"); len(parts) >= 2 {
				ipPort = parts[0] + ":" + parts[1]
			}
			if _, ok := activeSet[ipPort]; ok {
				rs.Key = ipPort
				items = append(items, rs)
			}
		}
		if len(items) == 0 {
			b.WriteString("  (no active resolver telemetry yet)\n\n")
		} else {
			sort.Slice(items, func(i, j int) bool {
				if items[i].OK != items[j].OK {
					return items[i].OK > items[j].OK
				}
				return items[i].Key < items[j].Key
			})
			max := 6
			if max > len(items) {
				max = len(items)
			}
			b.WriteString("  key                         ok  to  ref  sf  nt  oth  streak(to/f)  rtt_p50  rtt_p90\n")
			for i := 0; i < max; i++ {
				it := items[i]
				fmt.Fprintf(&b, "  %-26s %3d %3d %4d %3d %3d %4d   %2d/%2d      %6.1f  %6.1f\n",
					it.Key,
					it.OK,
					it.Timeout,
					it.Refused,
					it.Servfail,
					it.NoTunnel,
					it.OtherFailures,
					it.ConsecutiveTimeout,
					it.ConsecutiveFail,
					it.RTTP50ms,
					it.RTTP90ms,
				)
			}
			b.WriteString("\n")
		}
	}

	// Duplication panel
	b.WriteString("\x1b[1mDuplication\x1b[0m\n")
	if d == nil || d.telemetry == nil {
		b.WriteString("  (not available)\n")
	} else {
		fmt.Fprintf(&b, "  current_duplication: setup=%d data=%d\n", s.DerivedSetupDup, s.DerivedDataDup)
		fmt.Fprintf(&b, "  logical_packets=%d targets_requested=%d targets_selected=%d\n",
			tel.LogicalPackets, tel.TargetsRequested, tel.TargetsSelected)
		b.WriteString("  effectiveness: baseline building (no adaptive changes yet)\n")
	}
	b.WriteString("\n")

	// Event pane
	b.WriteString("\x1b[1mEvents\x1b[0m (latest)\n")
	if len(s.Events) == 0 {
		b.WriteString("  (no events)\n")
	} else {
		for _, e := range s.Events {
			levelColor := "\x1b[90m"
			switch e.level {
			case "ERROR":
				levelColor = "\x1b[31m"
			case "WARN":
				levelColor = "\x1b[33m"
			}
			fmt.Fprintf(&b, "  %s%-5s\x1b[0m %s\n", levelColor, e.level, e.text)
		}
	}

	return b.String()
}

func renderSpectrum(b *strings.Builder, minis []autoProfileResolverMini, tx bool, activeList []string, reserveList []string) {
	active := map[string]struct{}{}
	reserve := map[string]struct{}{}
	for _, a := range activeList {
		active[a] = struct{}{}
	}
	for _, r := range reserveList {
		reserve[r] = struct{}{}
	}

	items := make([]autoProfileResolverMini, 0, len(minis))
	for _, m := range minis {
		if tx && m.upRec > 0 {
			items = append(items, m)
		}
		if !tx && m.downRec > 0 {
			items = append(items, m)
		}
	}
	if len(items) == 0 {
		b.WriteString("    (no data)\n")
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if tx {
			return items[i].upRec > items[j].upRec
		}
		return items[i].downRec > items[j].downRec
	})
	top := items
	if len(top) > 8 {
		top = top[:8]
	}
	lo := items
	if len(lo) > 8 {
		lo = lo[len(lo)-8:]
	}
	maxV := 1
	for _, m := range items {
		v := m.upRec
		if !tx {
			v = m.downRec
		}
		if v > maxV {
			maxV = v
		}
	}
	writeBar := func(v int) string {
		w := 28
		n := int(float64(v) / float64(maxV) * float64(w))
		if n < 0 {
			n = 0
		}
		if n > w {
			n = w
		}
		return "[" + strings.Repeat("#", n) + strings.Repeat(".", w-n) + "]"
	}
	for _, m := range top {
		v := m.upRec
		if !tx {
			v = m.downRec
		}
		mark := " "
		if _, ok := active[m.addr]; ok {
			mark = "*"
		} else if _, ok := reserve[m.addr]; ok {
			mark = "+"
		}
		fmt.Fprintf(b, "    %s%s %4d  %s\n", mark, writeBar(v), v, m.addr)
	}
	if len(items) > len(top) {
		b.WriteString("    ...\n")
	}
	for _, m := range lo {
		v := m.upRec
		if !tx {
			v = m.downRec
		}
		mark := " "
		if _, ok := active[m.addr]; ok {
			mark = "*"
		} else if _, ok := reserve[m.addr]; ok {
			mark = "+"
		}
		fmt.Fprintf(b, "    %s%s %4d  %s\n", mark, writeBar(v), v, m.addr)
	}
}

func percentileFromMinis(minis []autoProfileResolverMini, tx bool, q float64) int {
	vals := make([]int, 0, len(minis))
	for _, m := range minis {
		v := m.upRec
		if !tx {
			v = m.downRec
		}
		if v > 0 {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Ints(vals)
	if q <= 0 {
		return vals[0]
	}
	if q >= 1 {
		return vals[len(vals)-1]
	}
	pos := q * float64(len(vals)-1)
	i := int(pos)
	if i >= len(vals)-1 {
		return vals[len(vals)-1]
	}
	f := pos - float64(i)
	return int(float64(vals[i]) + (float64(vals[i+1])-float64(vals[i]))*f)
}
