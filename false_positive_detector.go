package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// FalsePositiveDetector handles detection and prevention of false positives
type FalsePositiveDetector struct {
	// Validation methods
	validationMethods []ValidationMethod

	// Enhanced validation methods
	enhancedMethods *EnhancedValidationMethods

	// Honeypot detection
	honeypotDetector *HoneypotDetector

	// Response patterns for validation
	successPatterns    []*regexp.Regexp
	failurePatterns    []*regexp.Regexp
	suspiciousPatterns []*regexp.Regexp

	// Configuration
	config FalsePositiveConfig

	// Statistics
	stats FalsePositiveStats
}

// ValidationMethod represents a method for validating SSH connections
type ValidationMethod struct {
	Name        string
	Description string
	Weight      float64
	Function    func(*ssh.Client, string) (bool, float64, string)
}

// FalsePositiveConfig contains configuration for false positive detection
type FalsePositiveConfig struct {
	EnableSessionValidation    bool
	EnableCommandExecution     bool
	EnableBannerAnalysis       bool
	EnableResponseVerification bool
	EnableHoneypotDetection    bool
	MaxValidationTime          time.Duration
	CommandTimeout             time.Duration
	MinConfidenceThreshold     float64
	MaxRetries                 int
}

// FalsePositiveStats tracks false positive detection statistics
type FalsePositiveStats struct {
	TotalValidations     int64
	FalsePositivesCaught int64
	TruePositives        int64
	FalseNegatives       int64
	HoneypotsDetected    int64
	ValidationMethods    map[string]int64
}

// NewFalsePositiveDetector creates a new false positive detector
func NewFalsePositiveDetector() *FalsePositiveDetector {
	fpd := &FalsePositiveDetector{
		validationMethods:  make([]ValidationMethod, 0),
		enhancedMethods:    NewEnhancedValidationMethods(),
		honeypotDetector:   NewHoneypotDetector(),
		successPatterns:    make([]*regexp.Regexp, 0),
		failurePatterns:    make([]*regexp.Regexp, 0),
		suspiciousPatterns: make([]*regexp.Regexp, 0),
		config: FalsePositiveConfig{
			EnableSessionValidation:    true,
			EnableCommandExecution:     true,
			EnableBannerAnalysis:       true,
			EnableResponseVerification: true,
			EnableHoneypotDetection:    true,
			MaxValidationTime:          30 * time.Second,
			CommandTimeout:             10 * time.Second,
			MinConfidenceThreshold:     0.7,
			MaxRetries:                 3,
		},
		stats: FalsePositiveStats{
			ValidationMethods: make(map[string]int64),
		},
	}

	fpd.initializeValidationMethods()
	fpd.initializePatterns()

	return fpd
}

// initializeValidationMethods sets up validation methods
func (fpd *FalsePositiveDetector) initializeValidationMethods() {
	fpd.validationMethods = []ValidationMethod{
		{
			Name:        "session_creation",
			Description: "Test if we can create a new session",
			Weight:      0.3,
			Function:    fpd.validateSessionCreation,
		},
		{
			Name:        "command_execution",
			Description: "Execute a simple command and verify response",
			Weight:      0.4,
			Function:    fpd.validateCommandExecution,
		},
		{
			Name:        "shell_prompt",
			Description: "Check for realistic shell prompt",
			Weight:      0.2,
			Function:    fpd.validateShellPrompt,
		},
		{
			Name:        "environment_variables",
			Description: "Verify environment variables are realistic",
			Weight:      0.1,
			Function:    fpd.validateEnvironmentVariables,
		},
	}
}

// initializePatterns sets up regex patterns for response validation
func (fpd *FalsePositiveDetector) initializePatterns() {
	// Success patterns - indicate real shell access
	successPatterns := []string{
		`\$ `,                // Bash prompt
		`# `,                 // Root prompt
		`> `,                 // PowerShell prompt
		`PS `,                // PowerShell prompt
		`[a-zA-Z0-9@-]+:~`,   // User@host:~ format
		`[a-zA-Z0-9@-]+:\w+`, // User@host:directory format
		`Last login:`,        // Login message
		`Welcome to`,         // Welcome message
		`Linux`,              // OS identification
		`Ubuntu`,             // Distribution identification
		`CentOS`,             // Distribution identification
		`Debian`,             // Distribution identification
	}

	// Failure patterns - indicate failed login or fake service
	failurePatterns := []string{
		`Permission denied`,
		`Access denied`,
		`Authentication failed`,
		`Login incorrect`,
		`Invalid credentials`,
		`Connection closed`,
		`Connection refused`,
		`No such user`,
		`User not found`,
	}

	// Suspicious patterns - might indicate honeypot or fake service
	suspiciousPatterns := []string{
		`(?i)honeypot`,
		`(?i)fake`,
		`(?i)test`,
		`(?i)demo`,
		`(?i)simulation`,
		`(?i)virtual`,
		`(?i)container`,
		`(?i)docker`,
		`(?i)vm`,
		`(?i)guest`,
		`(?i)restricted`,
		`(?i)limited`,
		`(?i)readonly`,
		`(?i)noexec`,
		`(?i)chroot`,
		`(?i)jail`,
		`(?i)sandbox`,
	}

	// Compile patterns
	for _, pattern := range successPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			fpd.successPatterns = append(fpd.successPatterns, regex)
		}
	}

	for _, pattern := range failurePatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			fpd.failurePatterns = append(fpd.failurePatterns, regex)
		}
	}

	for _, pattern := range suspiciousPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			fpd.suspiciousPatterns = append(fpd.suspiciousPatterns, regex)
		}
	}
}

// ValidateConnection performs comprehensive validation of an SSH connection
func (fpd *FalsePositiveDetector) ValidateConnection(client *ssh.Client, target string) (bool, float64, string) {
	fpd.stats.TotalValidations++

	// Quick connection health check
	if !fpd.isConnectionHealthy(client) {
		fpd.stats.FalsePositivesCaught++
		return false, 0.0, "Connection is not healthy"
	}

	// Honeypot detection
	if fpd.config.EnableHoneypotDetection {
		if isHoneypot, confidence, reason := fpd.detectHoneypot(client, target); isHoneypot {
			fpd.stats.HoneypotsDetected++
			fpd.stats.FalsePositivesCaught++
			return false, confidence, fmt.Sprintf("Honeypot detected: %s", reason)
		}
	}

	// Run enhanced validation methods first
	if fpd.enhancedMethods != nil {
		valid, confidence, reason := fpd.enhancedMethods.ValidateWithEnhancedMethods(client, target)
		if !valid {
			fpd.stats.FalsePositivesCaught++
			return false, confidence, fmt.Sprintf("Enhanced validation failed: %s", reason)
		}
	}

	// Run standard validation methods
	totalConfidence := 0.0
	totalWeight := 0.0
	var reasons []string

	for _, method := range fpd.validationMethods {
		valid, confidence, reason := method.Function(client, target)

		fpd.stats.ValidationMethods[method.Name]++

		if !valid {
			fpd.stats.FalsePositivesCaught++
			return false, confidence, fmt.Sprintf("Validation failed: %s - %s", method.Name, reason)
		}

		totalConfidence += confidence * method.Weight
		totalWeight += method.Weight
		reasons = append(reasons, reason)
	}

	// Calculate final confidence
	finalConfidence := totalConfidence / totalWeight

	// Check against minimum threshold
	if finalConfidence < fpd.config.MinConfidenceThreshold {
		fpd.stats.FalsePositivesCaught++
		return false, finalConfidence, fmt.Sprintf("Confidence too low: %.2f < %.2f", finalConfidence, fpd.config.MinConfidenceThreshold)
	}

	fpd.stats.TruePositives++
	return true, finalConfidence, strings.Join(reasons, "; ")
}

// isConnectionHealthy checks if the SSH connection is healthy
func (fpd *FalsePositiveDetector) isConnectionHealthy(client *ssh.Client) bool {
	// Try to create a session to test the connection
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()

	// Test if we can get the remote address
	conn := client.Conn
	if conn == nil {
		return false
	}

	// Check if connection is still alive
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return false
	}

	return true
}

// detectHoneypot detects if the connection is to a honeypot
func (fpd *FalsePositiveDetector) detectHoneypot(client *ssh.Client, target string) (bool, float64, string) {
	// Get SSH banner
	banner := fpd.getSSHBanner(client)
	if banner == "" {
		return false, 0.0, "No banner received"
	}

	// Check against known honeypot patterns
	for _, pattern := range fpd.suspiciousPatterns {
		if pattern.MatchString(banner) {
			return true, 0.8, fmt.Sprintf("Suspicious banner pattern: %s", pattern.String())
		}
	}

	// Use existing honeypot detector
	info := fpd.honeypotDetector.AnalyzeTarget(target)
	if info.IsHoneypot {
		return true, info.Confidence, strings.Join(info.Reasons, ", ")
	}

	return false, 0.0, "No honeypot indicators found"
}

// getSSHBanner retrieves the SSH banner
func (fpd *FalsePositiveDetector) getSSHBanner(client *ssh.Client) string {
	// This is a simplified version - in practice, you'd need to capture the banner during connection
	// For now, we'll return an empty string
	return ""
}

// validateSessionCreation tests if we can create a new session
func (fpd *FalsePositiveDetector) validateSessionCreation(client *ssh.Client, target string) (bool, float64, string) {
	session, err := client.NewSession()
	if err != nil {
		return false, 0.0, fmt.Sprintf("Cannot create session: %v", err)
	}
	defer session.Close()

	// Test if session is functional
	if session == nil {
		return false, 0.0, "Session is nil"
	}

	return true, 0.8, "Session created successfully"
}

// validateCommandExecution executes a command and verifies the response
func (fpd *FalsePositiveDetector) validateCommandExecution(client *ssh.Client, target string) (bool, float64, string) {
	if !fpd.config.EnableCommandExecution {
		return true, 0.5, "Command execution disabled"
	}

	session, err := client.NewSession()
	if err != nil {
		return false, 0.0, fmt.Sprintf("Cannot create session: %v", err)
	}
	defer session.Close()

	// Execute a simple command
	cmd := "echo 'test'"
	output, err := fpd.executeCommandWithTimeout(session, cmd, fpd.config.CommandTimeout)
	if err != nil {
		return false, 0.0, fmt.Sprintf("Command execution failed: %v", err)
	}

	// Analyze the output
	confidence := fpd.analyzeCommandOutput(output)
	if confidence < 0.5 {
		return false, confidence, fmt.Sprintf("Command output suspicious: %s", output)
	}

	return true, confidence, fmt.Sprintf("Command executed successfully: %s", output)
}

// executeCommandWithTimeout executes a command with timeout
func (fpd *FalsePositiveDetector) executeCommandWithTimeout(session *ssh.Session, cmd string, timeout time.Duration) (string, error) {
	// Set up timeout
	done := make(chan error, 1)
	var output []byte

	go func() {
		var err error
		output, err = session.CombinedOutput(cmd)
		done <- err
	}()

	select {
	case err := <-done:
		return string(output), err
	case <-time.After(timeout):
		session.Close()
		return "", fmt.Errorf("command timeout after %v", timeout)
	}
}

// analyzeCommandOutput analyzes command output for authenticity
func (fpd *FalsePositiveDetector) analyzeCommandOutput(output string) float64 {
	confidence := 0.5 // Base confidence

	// Check for success patterns
	for _, pattern := range fpd.successPatterns {
		if pattern.MatchString(output) {
			confidence += 0.2
		}
	}

	// Check for failure patterns
	for _, pattern := range fpd.failurePatterns {
		if pattern.MatchString(output) {
			confidence -= 0.3
		}
	}

	// Check for suspicious patterns
	for _, pattern := range fpd.suspiciousPatterns {
		if pattern.MatchString(output) {
			confidence -= 0.4
		}
	}

	// Ensure confidence is between 0 and 1
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	return confidence
}

// validateShellPrompt checks for realistic shell prompt
func (fpd *FalsePositiveDetector) validateShellPrompt(client *ssh.Client, target string) (bool, float64, string) {
	session, err := client.NewSession()
	if err != nil {
		return false, 0.0, fmt.Sprintf("Cannot create session: %v", err)
	}
	defer session.Close()

	// Try to get shell prompt
	cmd := "echo $PS1"
	output, err := fpd.executeCommandWithTimeout(session, cmd, fpd.config.CommandTimeout)
	if err != nil {
		return false, 0.0, fmt.Sprintf("Cannot get shell prompt: %v", err)
	}

	// Check if prompt looks realistic
	if len(output) < 2 {
		return false, 0.0, "Shell prompt too short or empty"
	}

	// Check for common prompt patterns
	promptPatterns := []string{
		`\$`,
		`#`,
		`>`,
		`PS`,
		`[a-zA-Z0-9@-]+`,
	}

	confidence := 0.0
	for _, pattern := range promptPatterns {
		if matched, _ := regexp.MatchString(pattern, output); matched {
			confidence += 0.2
		}
	}

	if confidence < 0.3 {
		return false, confidence, fmt.Sprintf("Shell prompt not realistic: %s", output)
	}

	return true, confidence, fmt.Sprintf("Realistic shell prompt: %s", output)
}

// validateEnvironmentVariables checks environment variables for authenticity
func (fpd *FalsePositiveDetector) validateEnvironmentVariables(client *ssh.Client, target string) (bool, float64, string) {
	session, err := client.NewSession()
	if err != nil {
		return false, 0.0, fmt.Sprintf("Cannot create session: %v", err)
	}
	defer session.Close()

	// Check important environment variables
	envVars := []string{"HOME", "USER", "SHELL", "PATH", "PWD"}
	realisticVars := 0

	for _, varName := range envVars {
		cmd := fmt.Sprintf("echo $%s", varName)
		output, err := fpd.executeCommandWithTimeout(session, cmd, fpd.config.CommandTimeout)
		if err != nil {
			continue
		}

		// Check if the variable has a realistic value
		if fpd.isRealisticEnvironmentVariable(varName, output) {
			realisticVars++
		}
	}

	confidence := float64(realisticVars) / float64(len(envVars))

	if confidence < 0.5 {
		return false, confidence, fmt.Sprintf("Environment variables not realistic: %d/%d", realisticVars, len(envVars))
	}

	return true, confidence, fmt.Sprintf("Realistic environment variables: %d/%d", realisticVars, len(envVars))
}

// isRealisticEnvironmentVariable checks if an environment variable has a realistic value
func (fpd *FalsePositiveDetector) isRealisticEnvironmentVariable(varName, value string) bool {
	value = strings.TrimSpace(value)

	switch varName {
	case "HOME":
		return strings.HasPrefix(value, "/") && len(value) > 1
	case "USER":
		return len(value) > 0 && !strings.Contains(value, " ")
	case "SHELL":
		return strings.Contains(value, "/bin/") || strings.Contains(value, "/usr/bin/")
	case "PATH":
		return strings.Contains(value, "/bin") && strings.Contains(value, "/usr/bin")
	case "PWD":
		return strings.HasPrefix(value, "/") && len(value) > 1
	default:
		return len(value) > 0
	}
}

// GetStats returns false positive detection statistics
func (fpd *FalsePositiveDetector) GetStats() FalsePositiveStats {
	return fpd.stats
}

// GetStatsReport returns a formatted statistics report
func (fpd *FalsePositiveDetector) GetStatsReport() string {
	stats := fpd.GetStats()

	report := "=== FALSE POSITIVE DETECTION REPORT ===\n"
	report += fmt.Sprintf("Total Validations: %d\n", stats.TotalValidations)
	report += fmt.Sprintf("False Positives Caught: %d\n", stats.FalsePositivesCaught)
	report += fmt.Sprintf("True Positives: %d\n", stats.TruePositives)
	report += fmt.Sprintf("False Negatives: %d\n", stats.FalseNegatives)
	report += fmt.Sprintf("Honeypots Detected: %d\n", stats.HoneypotsDetected)

	if stats.TotalValidations > 0 {
		report += fmt.Sprintf("False Positive Rate: %.2f%%\n", float64(stats.FalsePositivesCaught)/float64(stats.TotalValidations)*100)
		report += fmt.Sprintf("True Positive Rate: %.2f%%\n", float64(stats.TruePositives)/float64(stats.TotalValidations)*100)
	}

	report += "\nValidation Methods Used:\n"
	for method, count := range stats.ValidationMethods {
		report += fmt.Sprintf("  %s: %d\n", method, count)
	}

	// Add enhanced validation report
	if fpd.enhancedMethods != nil {
		report += "\n" + fpd.enhancedMethods.GetValidationReport()
	}

	return report
}

// SetConfig updates the false positive detection configuration
func (fpd *FalsePositiveDetector) SetConfig(config FalsePositiveConfig) {
	fpd.config = config
}

// ResetStats resets the statistics
func (fpd *FalsePositiveDetector) ResetStats() {
	fpd.stats = FalsePositiveStats{
		ValidationMethods: make(map[string]int64),
	}
}
