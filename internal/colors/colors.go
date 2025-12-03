// Package colors provides terminal color codes and utilities
package colors

import (
	"os"
	"runtime"
)

// Color codes
var (
	RED     string
	GREEN   string
	YELLOW  string
	BLUE    string
	CYAN    string
	MAGENTA string
	BOLD    string
	NC      string // No Color / Reset
)

// Init initializes color codes based on terminal capability
func Init(enabled bool) {
	if !enabled {
		RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, NC = "", "", "", "", "", "", "", ""
		return
	}
	RED = "\033[31m"
	GREEN = "\033[32m"
	YELLOW = "\033[33m"
	BLUE = "\033[34m"
	CYAN = "\033[36m"
	MAGENTA = "\033[35m"
	BOLD = "\033[1m"
	NC = "\033[0m"
}

// ShouldUseColors determines if colored output should be enabled
func ShouldUseColors(noColor bool) bool {
	// Explicit disable via flag or environment
	if noColor || os.Getenv("NO_COLOR") == "1" {
		return false
	}

	// Check if stdout is connected to a terminal (TTY)
	fileInfo, err := os.Stdout.Stat()
	if err == nil && (fileInfo.Mode()&os.ModeCharDevice) != 0 {
		return true // It's a terminal, enable colors
	}

	// Default: enable on Unix-like systems (Linux, macOS, WSL)
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}
