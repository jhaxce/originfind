// Package output provides progress display for scan operations
package output

import (
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"
)

// Progress tracks and displays scan progress
type Progress struct {
	total      uint64
	scanned    *uint64 // atomic counter
	skipped    *uint64 // atomic counter
	startTime  time.Time
	enabled    bool
	lastUpdate time.Time

	// Colors
	cyan    string
	green   string
	yellow  string
	blue    string
	magenta string
	bold    string
	nc      string
}

// NewProgress creates a new progress tracker
func NewProgress(total uint64, enabled bool, useColors bool) *Progress {
	scanned := uint64(0)
	skipped := uint64(0)

	p := &Progress{
		total:     total,
		scanned:   &scanned,
		skipped:   &skipped,
		startTime: time.Now(),
		enabled:   enabled,
	}

	if useColors {
		p.cyan = "\033[36m"
		p.green = "\033[32m"
		p.yellow = "\033[33m"
		p.blue = "\033[34m"
		p.magenta = "\033[35m"
		p.bold = "\033[1m"
		p.nc = "\033[0m"
	}

	return p
}

// IncrementScanned increments the scanned counter
func (p *Progress) IncrementScanned() {
	atomic.AddUint64(p.scanned, 1)
}

// IncrementSkipped increments the skipped counter
func (p *Progress) IncrementSkipped() {
	atomic.AddUint64(p.skipped, 1)
}

// Display shows the current progress
func (p *Progress) Display() {
	if !p.enabled {
		return
	}

	// Throttle updates to avoid flickering
	now := time.Now()
	if now.Sub(p.lastUpdate) < 100*time.Millisecond {
		return
	}
	p.lastUpdate = now

	scanned := atomic.LoadUint64(p.scanned)
	skipped := atomic.LoadUint64(p.skipped)

	if p.total == 0 {
		return
	}

	elapsed := time.Since(p.startTime).Seconds()
	percent := float64(scanned) / float64(p.total) * 100
	rate := float64(scanned) / elapsed

	// Calculate ETA
	eta := p.calculateETA(scanned, rate)

	// Progress bar (40 characters wide)
	barWidth := 40
	filledWidth := int(float64(barWidth) * percent / 100)
	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)

	// Format output
	fmt.Printf("\r%s[%s]%s %s%.1f%%%s | %s%d%s/%s%d%s IPs",
		p.cyan, bar, p.nc,
		p.bold, percent, p.nc,
		p.green, scanned, p.nc,
		p.bold, p.total, p.nc,
	)

	if skipped > 0 {
		fmt.Printf(" | %s%d%s skipped", p.yellow, skipped, p.nc)
	}

	fmt.Printf(" | %s%.1f%s IPs/s | %s%s%s | ETA: %s%s%s",
		p.magenta, rate, p.nc,
		p.blue, p.formatDuration(elapsed), p.nc,
		p.yellow, eta, p.nc,
	)
}

// Clear clears the progress line
func (p *Progress) Clear() {
	if !p.enabled {
		return
	}
	fmt.Print("\r" + strings.Repeat(" ", 120) + "\r")
}

// Finish finalizes the progress display
func (p *Progress) Finish() {
	if !p.enabled {
		return
	}
	p.Display()
	fmt.Println() // New line
}

// calculateETA calculates estimated time of arrival
func (p *Progress) calculateETA(scanned uint64, rate float64) string {
	if scanned == 0 || rate == 0 {
		return "--"
	}

	remaining := float64(p.total-scanned) / rate

	if remaining < 60 {
		return fmt.Sprintf("%.0fs", remaining)
	} else if remaining < 3600 {
		return fmt.Sprintf("%.0fm%.0fs", remaining/60, math.Mod(remaining, 60))
	} else {
		return fmt.Sprintf("%.0fh%.0fm", remaining/3600, math.Mod(remaining/60, 60))
	}
}

// formatDuration formats a duration in seconds to human-readable format
func (p *Progress) formatDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%.0fs", seconds)
	} else if seconds < 3600 {
		return fmt.Sprintf("%.0fm%.0fs", seconds/60, math.Mod(seconds, 60))
	} else {
		return fmt.Sprintf("%.0fh%.0fm", seconds/3600, math.Mod(seconds/60, 60))
	}
}
