package main

import (
	"time"
)

// Job represents a single brute force attempt
type Job struct {
	Target   string
	Username string
	Password string
}

// Result represents the result of a brute force attempt
type Result struct {
	Job     Job
	Success bool
	Error   error
}

// HoneypotInfo contains honeypot detection results
type HoneypotInfo struct {
	IsHoneypot   bool
	Confidence   float64
	Reasons      []string
	Banner       string
	ResponseTime time.Duration
}

// FailedIPInfo contains information about failed IPs
type FailedIPInfo struct {
	IP        string
	FailCount int
	LastFail  time.Time
	Reasons   []string
}

// ConnectionLimits contains connection limiting configuration
type ConnectionLimits struct {
	MaxConnsPerTarget int
	ConnectionTimeout time.Duration
	ReadTimeout       time.Duration
	RetryDelay        time.Duration
	MaxRetries        int
}

// EvasionConfig contains stealth and evasion settings
type EvasionConfig struct {
	EnableBehavioralMimicking bool
	RandomizeTiming           bool
	MinDelay                  time.Duration
	MaxDelay                  time.Duration
	UserAgentRotation         bool
	RealisticRetryPatterns    bool
}

// PerformanceConfig contains performance optimization settings
type PerformanceConfig struct {
	EnableCompression   bool
	FastCiphers         bool
	ConnectionPooling   bool
	MaxPoolSize         int
	KeepAliveInterval   time.Duration
	BufferSize          int
	EnableLoadBalancing bool
}

// DetectionAvoidance contains anti-detection settings
type DetectionAvoidance struct {
	EnableTrafficObfuscation bool
	VaryTimingPatterns       bool
	RealisticUserAgents      bool
	HumanLikeRetries         bool
	DistributedMode          bool
	MaxAttemptsPerSource     int
}
