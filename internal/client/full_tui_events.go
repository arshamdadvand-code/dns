package client

import (
	"bytes"
	"strings"
	"sync"
	"time"
)

// tuiEventCollector captures logger console output and renders a bounded event pane.
// It does not write to stdout/stderr, by design.
type tuiEventCollector struct {
	mu    sync.Mutex
	lines []tuiEventLine
	cap   int

	// Partial line buffering (logger writes full lines, but keep safe).
	buf bytes.Buffer
}

type tuiEventLine struct {
	at    time.Time
	level string
	text  string
}

func newTUIEventCollector(capacity int) *tuiEventCollector {
	if capacity < 6 {
		capacity = 6
	}
	return &tuiEventCollector{cap: capacity}
}

func (c *tuiEventCollector) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, _ = c.buf.Write(p)
	for {
		b := c.buf.Bytes()
		idx := bytes.IndexByte(b, '\n')
		if idx < 0 {
			break
		}
		line := string(b[:idx])
		c.buf.Next(idx + 1)
		c.addLineLocked(line)
	}
	return len(p), nil
}

func (c *tuiEventCollector) addLineLocked(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	// Logger format:
	// "YYYY/MM/DD HH:MM:SS [App] [LEVEL] message"
	level := "INFO"
	msg := line
	if i := strings.Index(line, "[WARN]"); i >= 0 {
		level = "WARN"
		msg = strings.TrimSpace(line[i+len("[WARN]"):])
	} else if i := strings.Index(line, "[ERROR]"); i >= 0 {
		level = "ERROR"
		msg = strings.TrimSpace(line[i+len("[ERROR]"):])
	} else if i := strings.Index(line, "[DEBUG]"); i >= 0 {
		level = "DEBUG"
		msg = strings.TrimSpace(line[i+len("[DEBUG]"):])
	} else if i := strings.Index(line, "[INFO]"); i >= 0 {
		level = "INFO"
		msg = strings.TrimSpace(line[i+len("[INFO]"):])
	}

	// Filter: keep WARN/ERROR always; keep INFO only for a small set of lifecycle messages.
	if level == "INFO" {
		if !(strings.Contains(msg, "Session Initialized") ||
			strings.Contains(msg, "Proxy server is listening") ||
			strings.Contains(msg, "AutoProfile") ||
			strings.Contains(msg, "Starting main runtime loop") ||
			strings.Contains(msg, "Shutting down")) {
			return
		}
	}

	msg = stripNonASCII(msg)
	c.lines = append(c.lines, tuiEventLine{at: time.Now(), level: level, text: msg})
	if len(c.lines) > c.cap {
		c.lines = c.lines[len(c.lines)-c.cap:]
	}
}

func (c *tuiEventCollector) Add(level string, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	level = strings.ToUpper(strings.TrimSpace(level))
	if level == "" {
		level = "INFO"
	}
	text = stripNonASCII(strings.TrimSpace(text))
	if text == "" {
		return
	}
	c.lines = append(c.lines, tuiEventLine{at: time.Now(), level: level, text: text})
	if len(c.lines) > c.cap {
		c.lines = c.lines[len(c.lines)-c.cap:]
	}
}

func stripNonASCII(s string) string {
	// Keep the UI minimal/clean; log files still have full text.
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 32 && s[i] <= 126 {
			b.WriteByte(s[i])
		} else if s[i] == '\t' {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

func (c *tuiEventCollector) Render() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var b strings.Builder
	for _, e := range c.lines {
		// No emojis; compact.
		b.WriteString(e.at.Format("15:04:05"))
		b.WriteString(" ")
		b.WriteString(e.level)
		b.WriteString(" ")
		b.WriteString(e.text)
		b.WriteString("\n")
	}
	if len(c.lines) == 0 {
		b.WriteString("(no events)\n")
	}
	return b.String()
}
