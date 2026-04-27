package telemetry

import (
	"math"
	"sync"
)

// p2Quantile implements the P^2 quantile estimator (Jain & Chlamtac).
// It keeps constant memory and updates incrementally.
//
// We use it for RTT p50/p90 so the hot path doesn't sort samples.
type p2Quantile struct {
	mu sync.Mutex

	q float64

	// Marker positions (n) and desired positions (np) with increments (dn).
	n  [5]float64
	np [5]float64
	dn [5]float64

	// Marker heights.
	h [5]float64

	// Initialization samples (first 5).
	init []float64
}

func newP2Quantile(q float64) *p2Quantile {
	if q <= 0 {
		q = 0.5
	}
	if q >= 1 {
		q = 0.5
	}
	return &p2Quantile{q: q}
}

func (p *p2Quantile) Add(x float64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Collect first 5 samples.
	if len(p.init) < 5 {
		p.init = append(p.init, x)
		if len(p.init) == 5 {
			// Sort init and seed markers.
			sort5(p.init)
			for i := 0; i < 5; i++ {
				p.h[i] = p.init[i]
				p.n[i] = float64(i + 1)
			}
			p.np[0] = 1
			p.np[1] = 1 + 2*p.q
			p.np[2] = 1 + 4*p.q
			p.np[3] = 3 + 2*p.q
			p.np[4] = 5
			p.dn[0] = 0
			p.dn[1] = p.q / 2
			p.dn[2] = p.q
			p.dn[3] = (1 + p.q) / 2
			p.dn[4] = 1
		}
		return
	}

	// Find cell k such that h[k] <= x < h[k+1].
	k := 0
	switch {
	case x < p.h[0]:
		p.h[0] = x
		k = 0
	case x < p.h[1]:
		k = 0
	case x < p.h[2]:
		k = 1
	case x < p.h[3]:
		k = 2
	case x <= p.h[4]:
		k = 3
	default:
		p.h[4] = x
		k = 3
	}

	// Increment positions of markers above k.
	for i := k + 1; i < 5; i++ {
		p.n[i]++
	}
	// Update desired positions.
	for i := 0; i < 5; i++ {
		p.np[i] += p.dn[i]
	}

	// Adjust intermediate markers 1..3.
	for i := 1; i <= 3; i++ {
		d := p.np[i] - p.n[i]
		if (d >= 1 && (p.n[i+1]-p.n[i]) > 1) || (d <= -1 && (p.n[i-1]-p.n[i]) < -1) {
			s := math.Copysign(1, d)
			// Parabolic prediction.
			hNew := p.parabolic(i, s)
			if hNew > p.h[i-1] && hNew < p.h[i+1] {
				p.h[i] = hNew
			} else {
				// Linear fallback.
				p.h[i] = p.linear(i, s)
			}
			p.n[i] += s
		}
	}
}

func (p *p2Quantile) parabolic(i int, d float64) float64 {
	nim1 := p.n[i-1]
	ni := p.n[i]
	nip1 := p.n[i+1]
	him1 := p.h[i-1]
	hi := p.h[i]
	hip1 := p.h[i+1]

	return hi + d/(nip1-nim1)*((ni-nim1+d)*(hip1-hi)/(nip1-ni)+(nip1-ni-d)*(hi-him1)/(ni-nim1))
}

func (p *p2Quantile) linear(i int, d float64) float64 {
	ni := p.n[i]
	nj := p.n[i+int(d)]
	hi := p.h[i]
	hj := p.h[i+int(d)]
	return hi + d*(hj-hi)/(nj-ni)
}

func (p *p2Quantile) Value() (float64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch len(p.init) {
	case 0:
		return 0, false
	case 1:
		return p.init[0], true
	case 2:
		return (p.init[0] + p.init[1]) / 2, true
	case 3, 4:
		tmp := append([]float64(nil), p.init...)
		sort5Pad(tmp)
		// crude: pick middle of current init set
		idx := int(float64(len(p.init)-1) * p.q)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(p.init) {
			idx = len(p.init) - 1
		}
		return tmp[idx], true
	default:
		return p.h[2], true
	}
}

// sort5 sorts a slice of exactly 5 values in-place.
func sort5(v []float64) {
	// Simple insertion sort; 5 elements only.
	for i := 1; i < 5; i++ {
		x := v[i]
		j := i - 1
		for j >= 0 && v[j] > x {
			v[j+1] = v[j]
			j--
		}
		v[j+1] = x
	}
}

// sort5Pad sorts a slice up to length 5.
func sort5Pad(v []float64) {
	for i := 1; i < len(v); i++ {
		x := v[i]
		j := i - 1
		for j >= 0 && v[j] > x {
			v[j+1] = v[j]
			j--
		}
		v[j+1] = x
	}
}

