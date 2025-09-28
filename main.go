package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/akamensky/argparse"
)

func main() {
	// Create parser with better help text
	parser := argparse.NewParser("sshbruter", "real ngga bruter")

	// Required arguments
	targetArg := parser.String("t", "target", &argparse.Options{
		Required: true,
		Help:     "Target list file (txt). One target per line. Examples: '192.168.1.1' or '192.168.1.1:2222'",
	})
	userArg := parser.String("u", "user", &argparse.Options{
		Required: true,
		Help:     "Username list file (txt). One username per line. Example: 'admin' or 'root'",
	})
	passArg := parser.String("p", "pass", &argparse.Options{
		Required: true,
		Help:     "Password list file (txt). One password per line. Example: 'password' or '123456'",
	})

	// Optional arguments
	workerArg := parser.Int("w", "workers", &argparse.Options{
		Required: false,
		Help:     "Number of concurrent workers (default: CPU cores * 2)",
		Default:  runtime.NumCPU() * 2,
	})

	honeypotArg := parser.Flag("", "honeypot", &argparse.Options{
		Required: false,
		Help:     "Enable honeypot detection and checking",
		Default:  false,
	})

	// Connection limiting arguments
	maxConnsArg := parser.Int("", "max-conns", &argparse.Options{
		Required: false,
		Help:     "Maximum concurrent connections per target (default: 3)",
		Default:  3,
	})

	connTimeoutArg := parser.Int("", "conn-timeout", &argparse.Options{
		Required: false,
		Help:     "Connection timeout in seconds (default: 5)",
		Default:  5,
	})

	readTimeoutArg := parser.Int("", "read-timeout", &argparse.Options{
		Required: false,
		Help:     "Read timeout in seconds (default: 3)",
		Default:  3,
	})

	retryDelayArg := parser.Int("", "retry-delay", &argparse.Options{
		Required: false,
		Help:     "Delay between retries in milliseconds (default: 1000)",
		Default:  1000,
	})

	maxRetriesArg := parser.Int("", "max-retries", &argparse.Options{
		Required: false,
		Help:     "Maximum number of retries per target (default: 3)",
		Default:  3,
	})

	// Parse arguments
	err := parser.Parse(os.Args)
	if err != nil {
		// Show help on parse error
		fmt.Println("Error:", err)
		fmt.Println()
		parser.Help(os.Stdout)
		os.Exit(1)
	}

	// Validate required arguments
	if *targetArg == "" || *userArg == "" || *passArg == "" {
		fmt.Println("Error: All required arguments must be provided")
		fmt.Println()
		parser.Help(os.Stdout)
		os.Exit(1)
	}

	// Parse and validate input lists
	targets, err := parseTargetFile(*targetArg)
	if err != nil {
		fmt.Printf("Error reading target file: %v\n", err)
		os.Exit(1)
	}
	users, err := parseTargetFile(*userArg)
	if err != nil {
		fmt.Printf("Error reading username file: %v\n", err)
		os.Exit(1)
	}
	passwords, err := parseTargetFile(*passArg)
	if err != nil {
		fmt.Printf("Error reading password file: %v\n", err)
		os.Exit(1)
	}

	if len(targets) == 0 || len(users) == 0 || len(passwords) == 0 {
		fmt.Println("Error: All lists must contain at least one item")
		fmt.Println("   Make sure your files contain valid entries")
		fmt.Println()
		parser.Help(os.Stdout)
		os.Exit(1)
	}

	// Validate worker count
	if *workerArg <= 0 {
		fmt.Println("Error: Worker count must be greater than 0")
		os.Exit(1)
	}

	// Show configuration
	fmt.Printf("SSH Brute Force Tool\n")
	fmt.Printf("Configuration:\n")

	// Show limited target list (max 5 targets)
	targetDisplay := targets
	if len(targets) > 5 {
		targetDisplay = targets[:5]
		fmt.Printf("   Targets: %d (%s... and %d more)\n", len(targets), strings.Join(targetDisplay, ", "), len(targets)-5)
	} else {
		fmt.Printf("   Targets: %d (%s)\n", len(targets), strings.Join(targetDisplay, ", "))
	}

	// Show limited user list (max 3 users)
	userDisplay := users
	if len(users) > 3 {
		userDisplay = users[:3]
		fmt.Printf("   Users: %d (%s... and %d more)\n", len(users), strings.Join(userDisplay, ", "), len(users)-3)
	} else {
		fmt.Printf("   Users: %d (%s)\n", len(users), strings.Join(userDisplay, ", "))
	}

	// Show limited password list (max 3 passwords)
	passDisplay := passwords
	if len(passwords) > 3 {
		passDisplay = passwords[:3]
		fmt.Printf("   Passwords: %d (%s... and %d more)\n", len(passwords), strings.Join(passDisplay, ", "), len(passwords)-3)
	} else {
		fmt.Printf("   Passwords: %d (%s)\n", len(passwords), strings.Join(passDisplay, ", "))
	}

	fmt.Printf("   Workers: %d\n", *workerArg)
	fmt.Printf("   Max connections per target: %d\n", *maxConnsArg)
	fmt.Printf("   Connection timeout: %ds\n", *connTimeoutArg)
	fmt.Printf("   Read timeout: %ds\n", *readTimeoutArg)
	fmt.Printf("   Retry delay: %dms\n", *retryDelayArg)
	fmt.Printf("   Max retries per target: %d\n", *maxRetriesArg)
	fmt.Printf("   Total combinations: %d\n\n", len(targets)*len(users)*len(passwords))

	// Create connection limits
	limits := ConnectionLimits{
		MaxConnsPerTarget: *maxConnsArg,
		ConnectionTimeout: time.Duration(*connTimeoutArg) * time.Second,
		ReadTimeout:       time.Duration(*readTimeoutArg) * time.Second,
		RetryDelay:        time.Duration(*retryDelayArg) * time.Millisecond,
		MaxRetries:        *maxRetriesArg,
	}

	// Create worker pool with connection limits
	pool := NewWorkerPool(*workerArg, limits)
	defer pool.Close()

	// Check for honeypots if enabled
	if *honeypotArg {
		fmt.Println("\nChecking for honeypots...")
		honeypotTargets := pool.CheckHoneypots(targets)

		if len(honeypotTargets) > 0 {
			fmt.Println("HONEYPOT DETECTED - Skipping the following targets:")
			for target, info := range honeypotTargets {
				fmt.Printf("   %s (confidence: %.1f%%) - %s\n", target, info.Confidence*100, strings.Join(info.Reasons, ", "))
			}
			fmt.Println()
		} else {
			fmt.Println("No honeypots detected")
		}
	} else {
		fmt.Println("\nHoneypot detection disabled - use --honeypot flag to enable")
	}

	// Start brute force with worker pool
	fmt.Printf("Starting brute force with %d workers...\n", *workerArg)

	// Enable interval honeypot checking if honeypot detection is enabled
	if *honeypotArg {
		pool.EnableIntervalHoneypotChecking()
	}

	pool.BruteForceSSH(targets, users, passwords)
}
