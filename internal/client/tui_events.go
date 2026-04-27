// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"bytes"
	"strings"
	"sync"
	"time"
)

type tuiEvent struct {
	at    time.Time
	level string
	text  string
}

type tuiEventSink struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	events []tuiEvent
	cap    int
}

func newTUIEventSink(capacity int) *tuiEventSink {
	if capacity < 10 {
		capacity = 10
	}
	return &tuiEventSink{cap: capacity, events: make([]tuiEvent, 0, capacity)}
}

func (s *tuiEventSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.buf.Write(p)
	for {
		line, ok := s.readLineLocked()
		if !ok {
			break
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		e := tuiEvent{
			at:    time.Now(),
			level: extractLevel(line),
			text:  strings.TrimRight(line, "\r\n"),
		}
		s.events = append(s.events, e)
		if len(s.events) > s.cap {
			// Drop oldest.
			copy(s.events, s.events[len(s.events)-s.cap:])
			s.events = s.events[:s.cap]
		}
	}
	return len(p), nil
}

func (s *tuiEventSink) readLineLocked() (string, bool) {
	data := s.buf.Bytes()
	i := bytes.IndexByte(data, '\n')
	if i == -1 {
		return "", false
	}
	line := string(data[:i+1])
	rest := data[i+1:]
	s.buf.Reset()
	_, _ = s.buf.Write(rest)
	return line, true
}

func extractLevel(line string) string {
	switch {
	case strings.Contains(line, "[ERROR]"):
		return "ERROR"
	case strings.Contains(line, "[WARN]"):
		return "WARN"
	case strings.Contains(line, "[DEBUG]"):
		return "DEBUG"
	default:
		return "INFO"
	}
}

func (s *tuiEventSink) snapshot(n int) []tuiEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 || n > len(s.events) {
		n = len(s.events)
	}
	out := make([]tuiEvent, 0, n)
	out = append(out, s.events[len(s.events)-n:]...)
	return out
}

