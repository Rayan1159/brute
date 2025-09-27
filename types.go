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
