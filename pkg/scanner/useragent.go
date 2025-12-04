// Package scanner provides HTTP-based origin IP discovery with concurrent scanning.
package scanner

import (
	"math/rand"
	"time"
)

// UserAgent represents a browser user agent string
type UserAgent struct {
	Name    string
	Version string
	String  string
}

// Predefined user agents for major browsers (updated Dec 2025)
var (
	// Chrome user agents
	ChromeWindows = UserAgent{
		Name:    "Chrome",
		Version: "131.0.0.0",
		String:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}
	ChromeMac = UserAgent{
		Name:    "Chrome",
		Version: "131.0.0.0",
		String:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}
	ChromeLinux = UserAgent{
		Name:    "Chrome",
		Version: "131.0.0.0",
		String:  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}

	// Firefox user agents
	FirefoxWindows = UserAgent{
		Name:    "Firefox",
		Version: "133.0",
		String:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	}
	FirefoxMac = UserAgent{
		Name:    "Firefox",
		Version: "133.0",
		String:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
	}
	FirefoxLinux = UserAgent{
		Name:    "Firefox",
		Version: "133.0",
		String:  "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	}

	// Safari user agents
	SafariMac = UserAgent{
		Name:    "Safari",
		Version: "18.2",
		String:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	}
	SafariIOS = UserAgent{
		Name:    "Safari",
		Version: "18.2",
		String:  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	}

	// Edge user agents
	EdgeWindows = UserAgent{
		Name:    "Edge",
		Version: "131.0.0.0",
		String:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	}
	EdgeMac = UserAgent{
		Name:    "Edge",
		Version: "131.0.0.0",
		String:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	}

	// Opera user agents
	OperaWindows = UserAgent{
		Name:    "Opera",
		Version: "116.0.0.0",
		String:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/116.0.0.0",
	}
	OperaMac = UserAgent{
		Name:    "Opera",
		Version: "116.0.0.0",
		String:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/116.0.0.0",
	}

	// Brave user agents (uses Chrome base)
	BraveWindows = UserAgent{
		Name:    "Brave",
		Version: "131.0.0.0",
		String:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}
	BraveMac = UserAgent{
		Name:    "Brave",
		Version: "131.0.0.0",
		String:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}

	// Mobile user agents
	ChromeAndroid = UserAgent{
		Name:    "Chrome Mobile",
		Version: "131.0.6778.135",
		String:  "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
	}
)

// AllUserAgents is a slice of all predefined user agents
var AllUserAgents = []UserAgent{
	ChromeWindows, ChromeMac, ChromeLinux,
	FirefoxWindows, FirefoxMac, FirefoxLinux,
	SafariMac, SafariIOS,
	EdgeWindows, EdgeMac,
	OperaWindows, OperaMac,
	BraveWindows, BraveMac,
	ChromeAndroid,
}

// UserAgentsByBrowser maps browser names to their user agents
var UserAgentsByBrowser = map[string][]UserAgent{
	"chrome":  {ChromeWindows, ChromeMac, ChromeLinux},
	"firefox": {FirefoxWindows, FirefoxMac, FirefoxLinux},
	"safari":  {SafariMac, SafariIOS},
	"edge":    {EdgeWindows, EdgeMac},
	"opera":   {OperaWindows, OperaMac},
	"brave":   {BraveWindows, BraveMac},
	"mobile":  {ChromeAndroid, SafariIOS},
}

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// GetRandomUserAgent returns a random user agent from all available options
func GetRandomUserAgent() string {
	return AllUserAgents[rng.Intn(len(AllUserAgents))].String
}

// GetUserAgentByBrowser returns a random user agent for the specified browser
// Returns empty string if browser not found
func GetUserAgentByBrowser(browser string) string {
	agents, ok := UserAgentsByBrowser[browser]
	if !ok || len(agents) == 0 {
		return ""
	}
	return agents[rng.Intn(len(agents))].String
}

// GetUserAgentByName returns a specific user agent by exact name
// Supported names: chrome-windows, chrome-mac, chrome-linux, firefox-windows, etc.
func GetUserAgentByName(name string) string {
	switch name {
	case "chrome-windows":
		return ChromeWindows.String
	case "chrome-mac":
		return ChromeMac.String
	case "chrome-linux":
		return ChromeLinux.String
	case "firefox-windows":
		return FirefoxWindows.String
	case "firefox-mac":
		return FirefoxMac.String
	case "firefox-linux":
		return FirefoxLinux.String
	case "safari-mac":
		return SafariMac.String
	case "safari-ios":
		return SafariIOS.String
	case "edge-windows":
		return EdgeWindows.String
	case "edge-mac":
		return EdgeMac.String
	case "opera-windows":
		return OperaWindows.String
	case "opera-mac":
		return OperaMac.String
	case "brave-windows":
		return BraveWindows.String
	case "brave-mac":
		return BraveMac.String
	case "chrome-android":
		return ChromeAndroid.String
	default:
		return ""
	}
}
