package main

import (
	"bufio"
	"os"
	"strings"
)

// parseTargets splits comma-separated targets into a slice
func parseTargets(targets string) []string {
	return strings.Split(targets, ",")
}

// parseTargetFile reads targets from a text file, one per line
func parseTargetFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}
