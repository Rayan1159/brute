package main

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// EnhancedValidationMethods provides additional validation techniques
type EnhancedValidationMethods struct {
	// Common false positive scenarios to check
	falsePositiveScenarios []FalsePositiveScenario

	// Realistic command tests
	realisticCommands []string

	// Response validation patterns
	responsePatterns map[string]*ValidationPattern
}

// FalsePositiveScenario represents a common false positive scenario
type FalsePositiveScenario struct {
	Name        string
	Description string
	TestFunc    func(*ssh.Client) (bool, string)
	Weight      float64
}

// ValidationPattern represents a pattern for validating responses
type ValidationPattern struct {
	Pattern     string
	IsPositive  bool
	Confidence  float64
	Description string
}

// NewEnhancedValidationMethods creates enhanced validation methods
func NewEnhancedValidationMethods() *EnhancedValidationMethods {
	evm := &EnhancedValidationMethods{
		falsePositiveScenarios: make([]FalsePositiveScenario, 0),
		realisticCommands:      make([]string, 0),
		responsePatterns:       make(map[string]*ValidationPattern),
	}

	evm.initializeFalsePositiveScenarios()
	evm.initializeRealisticCommands()
	evm.initializeResponsePatterns()

	return evm
}

// initializeFalsePositiveScenarios sets up common false positive scenarios
func (evm *EnhancedValidationMethods) initializeFalsePositiveScenarios() {
	evm.falsePositiveScenarios = []FalsePositiveScenario{
		{
			Name:        "honeypot_detection",
			Description: "Detect honeypot systems",
			TestFunc:    evm.testHoneypotDetection,
			Weight:      0.3,
		},
		{
			Name:        "fake_shell_detection",
			Description: "Detect fake or limited shells",
			TestFunc:    evm.testFakeShellDetection,
			Weight:      0.25,
		},
		{
			Name:        "container_detection",
			Description: "Detect containerized environments",
			TestFunc:    evm.testContainerDetection,
			Weight:      0.2,
		},
		{
			Name:        "readonly_filesystem",
			Description: "Detect readonly filesystems",
			TestFunc:    evm.testReadonlyFilesystem,
			Weight:      0.15,
		},
		{
			Name:        "limited_permissions",
			Description: "Detect limited user permissions",
			TestFunc:    evm.testLimitedPermissions,
			Weight:      0.1,
		},
	}
}

// initializeRealisticCommands sets up realistic command tests
func (evm *EnhancedValidationMethods) initializeRealisticCommands() {
	evm.realisticCommands = []string{
		"whoami",              // Check current user
		"pwd",                 // Check current directory
		"ls -la",              // List directory contents
		"uname -a",            // System information
		"id",                  // User ID information
		"echo $HOME",          // Home directory
		"echo $SHELL",         // Shell information
		"ps aux",              // Process list
		"df -h",               // Disk usage
		"free -m",             // Memory usage
		"uptime",              // System uptime
		"cat /etc/os-release", // OS information
		"which bash",          // Shell location
		"echo $PATH",          // PATH variable
		"history | tail -5",   // Command history
	}
}

// initializeResponsePatterns sets up response validation patterns
func (evm *EnhancedValidationMethods) initializeResponsePatterns() {
	evm.responsePatterns = map[string]*ValidationPattern{
		"realistic_user": {
			Pattern:     `^[a-zA-Z0-9_-]+$`,
			IsPositive:  true,
			Confidence:  0.8,
			Description: "Realistic username format",
		},
		"realistic_path": {
			Pattern:     `^/[a-zA-Z0-9/_-]+$`,
			IsPositive:  true,
			Confidence:  0.7,
			Description: "Realistic path format",
		},
		"realistic_shell": {
			Pattern:     `^/bin/[a-zA-Z]+$`,
			IsPositive:  true,
			Confidence:  0.8,
			Description: "Realistic shell path",
		},
		"suspicious_output": {
			Pattern:     `(?i)(fake|test|demo|honeypot|simulation)`,
			IsPositive:  false,
			Confidence:  0.9,
			Description: "Suspicious output detected",
		},
		"empty_response": {
			Pattern:     `^$`,
			IsPositive:  false,
			Confidence:  0.6,
			Description: "Empty response",
		},
		"error_response": {
			Pattern:     `(?i)(error|failed|denied|permission)`,
			IsPositive:  false,
			Confidence:  0.8,
			Description: "Error response detected",
		},
	}
}

// testHoneypotDetection tests for honeypot characteristics
func (evm *EnhancedValidationMethods) testHoneypotDetection(client *ssh.Client) (bool, string) {
	// Test 1: Check for suspicious hostname
	session, err := client.NewSession()
	if err != nil {
		return false, "Cannot create session"
	}
	defer session.Close()

	output, err := session.CombinedOutput("hostname")
	if err != nil {
		return false, "Cannot execute hostname command"
	}

	hostname := strings.TrimSpace(string(output))
	suspiciousHostnames := []string{"honeypot", "fake", "test", "demo", "simulation", "virtual"}

	for _, suspicious := range suspiciousHostnames {
		if strings.Contains(strings.ToLower(hostname), suspicious) {
			return false, fmt.Sprintf("Suspicious hostname: %s", hostname)
		}
	}

	// Test 2: Check for honeypot-specific files
	output, err = session.CombinedOutput("ls -la /etc/ | grep -i honeypot")
	if err == nil && len(output) > 0 {
		return false, "Honeypot files detected in /etc/"
	}

	return true, "No honeypot indicators found"
}

// testFakeShellDetection tests for fake or limited shells
func (evm *EnhancedValidationMethods) testFakeShellDetection(client *ssh.Client) (bool, string) {
	session, err := client.NewSession()
	if err != nil {
		return false, "Cannot create session"
	}
	defer session.Close()

	// Test 1: Check if we can execute basic commands
	output, err := session.CombinedOutput("echo 'test'")
	if err != nil {
		return false, "Cannot execute basic commands"
	}

	if strings.TrimSpace(string(output)) != "test" {
		return false, "Command output doesn't match expected result"
	}

	// Test 2: Check for shell limitations
	output, err = session.CombinedOutput("which ls")
	if err != nil {
		return false, "Cannot find basic commands"
	}

	if len(output) == 0 {
		return false, "No command path found"
	}

	// Test 3: Check for restricted shell
	output, err = session.CombinedOutput("echo $0")
	if err != nil {
		return false, "Cannot get shell information"
	}

	shell := strings.TrimSpace(string(output))
	if strings.Contains(shell, "rbash") || strings.Contains(shell, "restricted") {
		return false, fmt.Sprintf("Restricted shell detected: %s", shell)
	}

	return true, "Shell appears to be functional"
}

// testContainerDetection tests for containerized environments
func (evm *EnhancedValidationMethods) testContainerDetection(client *ssh.Client) (bool, string) {
	session, err := client.NewSession()
	if err != nil {
		return false, "Cannot create session"
	}
	defer session.Close()

	// Test 1: Check for container indicators
	output, err := session.CombinedOutput("cat /proc/1/cgroup")
	if err == nil {
		cgroup := string(output)
		containerIndicators := []string{"docker", "lxc", "systemd", "containerd"}

		for _, indicator := range containerIndicators {
			if strings.Contains(strings.ToLower(cgroup), indicator) {
				return false, fmt.Sprintf("Container detected: %s", indicator)
			}
		}
	}

	// Test 2: Check for Docker environment
	output, err = session.CombinedOutput("ls -la /.dockerenv")
	if err == nil {
		return false, "Docker environment detected"
	}

	// Test 3: Check for limited processes
	output, err = session.CombinedOutput("ps aux | wc -l")
	if err == nil {
		processCount := strings.TrimSpace(string(output))
		if processCount == "1" || processCount == "2" {
			return false, fmt.Sprintf("Limited process count: %s", processCount)
		}
	}

	return true, "No container indicators found"
}

// testReadonlyFilesystem tests for readonly filesystems
func (evm *EnhancedValidationMethods) testReadonlyFilesystem(client *ssh.Client) (bool, string) {
	session, err := client.NewSession()
	if err != nil {
		return false, "Cannot create session"
	}
	defer session.Close()

	// Test 1: Try to create a temporary file
	testFile := fmt.Sprintf("/tmp/test_%d", rand.Intn(10000))
	output, err := session.CombinedOutput(fmt.Sprintf("touch %s", testFile))
	if err != nil {
		return false, "Cannot create files (readonly filesystem)"
	}

	// Test 2: Try to write to the file
	output, err = session.CombinedOutput(fmt.Sprintf("echo 'test' > %s", testFile))
	if err != nil {
		return false, "Cannot write to files (readonly filesystem)"
	}

	// Test 3: Try to delete the file
	_, err = session.CombinedOutput(fmt.Sprintf("rm %s", testFile))
	if err != nil {
		return false, "Cannot delete files (readonly filesystem)"
	}

	return true, "Filesystem is writable"
}

// testLimitedPermissions tests for limited user permissions
func (evm *EnhancedValidationMethods) testLimitedPermissions(client *ssh.Client) (bool, string) {
	session, err := client.NewSession()
	if err != nil {
		return false, "Cannot create session"
	}
	defer session.Close()

	// Test 1: Check user ID
	output, err := session.CombinedOutput("id")
	if err != nil {
		return false, "Cannot get user ID"
	}

	uid := string(output)
	if strings.Contains(uid, "uid=0") {
		// Root user - this is actually good
		return true, "Root user detected"
	}

	// Test 2: Check for sudo access
	output, err = session.CombinedOutput("sudo -l")
	if err != nil {
		// No sudo access - this might be a limitation
		return false, "No sudo access available"
	}

	// Test 3: Check for home directory access
	output, err = session.CombinedOutput("ls -la $HOME")
	if err != nil {
		return false, "Cannot access home directory"
	}

	return true, "User permissions appear adequate"
}

// ValidateWithEnhancedMethods performs enhanced validation
func (evm *EnhancedValidationMethods) ValidateWithEnhancedMethods(client *ssh.Client, target string) (bool, float64, string) {
	totalConfidence := 0.0
	totalWeight := 0.0
	var reasons []string

	// Test each false positive scenario
	for _, scenario := range evm.falsePositiveScenarios {
		valid, reason := scenario.TestFunc(client)

		if !valid {
			return false, 0.0, fmt.Sprintf("Failed %s: %s", scenario.Name, reason)
		}

		totalConfidence += 0.8 * scenario.Weight
		totalWeight += scenario.Weight
		reasons = append(reasons, reason)
	}

	// Test realistic commands
	realisticCommandCount := 0
	commandTests := evm.realisticCommands[:5] // Test first 5 commands

	for _, cmd := range commandTests {
		session, err := client.NewSession()
		if err != nil {
			continue
		}

		output, err := session.CombinedOutput(cmd)
		session.Close()

		if err == nil && len(output) > 0 {
			// Validate the output
			if evm.validateCommandOutput(string(output)) {
				realisticCommandCount++
			}
		}
	}

	// Calculate command success rate
	commandSuccessRate := float64(realisticCommandCount) / float64(len(commandTests))
	totalConfidence += commandSuccessRate * 0.2
	totalWeight += 0.2

	if commandSuccessRate < 0.6 {
		return false, totalConfidence / totalWeight, fmt.Sprintf("Low command success rate: %.2f", commandSuccessRate)
	}

	finalConfidence := totalConfidence / totalWeight
	reasons = append(reasons, fmt.Sprintf("Command success rate: %.2f", commandSuccessRate))

	return true, finalConfidence, strings.Join(reasons, "; ")
}

// validateCommandOutput validates command output against patterns
func (evm *EnhancedValidationMethods) validateCommandOutput(output string) bool {
	output = strings.TrimSpace(output)

	// Check against response patterns
	for _, pattern := range evm.responsePatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, output)
		if matched {
			if !pattern.IsPositive {
				return false // Negative pattern matched
			}
		}
	}

	// Basic validation
	if len(output) == 0 {
		return false
	}

	// Check for suspicious content
	suspiciousContent := []string{"fake", "test", "demo", "honeypot", "simulation", "virtual"}
	for _, suspicious := range suspiciousContent {
		if strings.Contains(strings.ToLower(output), suspicious) {
			return false
		}
	}

	return true
}

// GetValidationReport returns a detailed validation report
func (evm *EnhancedValidationMethods) GetValidationReport() string {
	report := "=== ENHANCED VALIDATION REPORT ===\n"
	report += fmt.Sprintf("False Positive Scenarios: %d\n", len(evm.falsePositiveScenarios))
	report += fmt.Sprintf("Realistic Commands: %d\n", len(evm.realisticCommands))
	report += fmt.Sprintf("Response Patterns: %d\n", len(evm.responsePatterns))

	report += "\nFalse Positive Scenarios:\n"
	for _, scenario := range evm.falsePositiveScenarios {
		report += fmt.Sprintf("  %s: %s (weight: %.2f)\n", scenario.Name, scenario.Description, scenario.Weight)
	}

	report += "\nRealistic Commands:\n"
	for i, cmd := range evm.realisticCommands {
		if i < 10 { // Show first 10 commands
			report += fmt.Sprintf("  %s\n", cmd)
		}
	}

	return report
}
