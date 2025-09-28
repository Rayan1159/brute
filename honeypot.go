package main

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"time"
)

// HoneypotDetector handles honeypot detection
type HoneypotDetector struct {
	knownHoneypots map[string]float64
	bannerPatterns []*regexp.Regexp
}

// NewHoneypotDetector creates a new honeypot detector
func NewHoneypotDetector() *HoneypotDetector {
	detector := &HoneypotDetector{
		knownHoneypots: make(map[string]float64),
		bannerPatterns: make([]*regexp.Regexp, 0),
	}

	// Initialize known honeypot signatures
	detector.initializeHoneypotDatabase()

	return detector
}

// initializeHoneypotDatabase sets up known honeypot signatures
func (hd *HoneypotDetector) initializeHoneypotDatabase() {
	// Known honeypot banners and their confidence scores
	hd.knownHoneypots = map[string]float64{
		"SSH-2.0-Cowrie":               0.95, // Cowrie honeypot
		"SSH-2.0-Honeypot":             0.90, // Generic honeypot
		"SSH-2.0-Kippo":                0.90, // Kippo honeypot
		"SSH-2.0-Dionaea":              0.85, // Dionaea honeypot
		"SSH-2.0-Honeyd":               0.80, // Honeyd honeypot
		"SSH-2.0-Modern Honey Network": 0.90, // MHN honeypot
		"SSH-2.0-Honeypot-SSH":         0.85, // Honeypot-SSH
		"SSH-2.0-SSH-Honeypot":         0.85, // SSH Honeypot
		"SSH-2.0-Honeypot-Project":     0.80, // Honeypot Project
		"SSH-2.0-Honeypot-Server":      0.80, // Honeypot Server
	}

	// Compile regex patterns for honeypot detection
	patterns := []string{
		`(?i)honeypot`,
		`(?i)cowrie`,
		`(?i)kippo`,
		`(?i)dionaea`,
		`(?i)honeyd`,
		`(?i)kippo`,
		`(?i)modern.*honey`,
		`(?i)fake.*ssh`,
		`(?i)test.*server`,
		`(?i)demo.*ssh`,
	}

	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			hd.bannerPatterns = append(hd.bannerPatterns, regex)
		}
	}
}

// AnalyzeTarget performs comprehensive honeypot analysis
func (hd *HoneypotDetector) AnalyzeTarget(target string) *HoneypotInfo {
	info := &HoneypotInfo{
		IsHoneypot:   false,
		Confidence:   0.0,
		Reasons:      make([]string, 0),
		ResponseTime: 0,
	}

	// Parse target
	addr := target
	port := "22"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		addr = parts[0]
		port = parts[1]
	}

	hostPort := fmt.Sprintf("%s:%s", addr, port)

	// Test connection and get banner
	start := time.Now()
	banner, err := hd.getSSHBanner(hostPort)
	info.ResponseTime = time.Since(start)

	if err != nil {
		// Connection failed - not necessarily a honeypot
		return info
	}

	info.Banner = banner

	// Analyze banner for honeypot signatures
	confidence := hd.analyzeBanner(banner)
	if confidence > 0.5 {
		info.IsHoneypot = true
		info.Confidence = confidence
		info.Reasons = append(info.Reasons, "Banner analysis")
	}

	// Check response time (honeypots often respond too quickly)
	if info.ResponseTime < 100*time.Millisecond {
		info.Confidence += 0.2
		info.Reasons = append(info.Reasons, "Suspiciously fast response")
	}

	// Check for common honeypot ports
	if port != "22" && (port == "2222" || port == "2200" || port == "2022") {
		info.Confidence += 0.1
		info.Reasons = append(info.Reasons, "Non-standard SSH port")
	}

	// Final determination
	if info.Confidence > 0.6 {
		info.IsHoneypot = true
	}

	return info
}

// getSSHBanner retrieves SSH banner from target with optimized timeouts
func (hd *HoneypotDetector) getSSHBanner(hostPort string) (string, error) {
	conn, err := net.DialTimeout("tcp", hostPort, 2*time.Second) // Reduced from 5s to 2s
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // Reduced from 5s to 2s
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(buf[:n])), nil
}

// analyzeBanner analyzes SSH banner for honeypot characteristics
func (hd *HoneypotDetector) analyzeBanner(banner string) float64 {
	confidence := 0.0

	// Check against known honeypot banners
	if score, exists := hd.knownHoneypots[banner]; exists {
		confidence = score
	}

	// Check against regex patterns
	for _, pattern := range hd.bannerPatterns {
		if pattern.MatchString(banner) {
			confidence = math.Max(confidence, 0.7)
		}
	}

	// Check for suspicious characteristics
	if strings.Contains(strings.ToLower(banner), "honeypot") {
		confidence = math.Max(confidence, 0.8)
	}

	if strings.Contains(strings.ToLower(banner), "fake") {
		confidence = math.Max(confidence, 0.7)
	}

	if strings.Contains(strings.ToLower(banner), "test") {
		confidence = math.Max(confidence, 0.6)
	}

	return confidence
}
