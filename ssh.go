package main

import (
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// getSSHBanners retrieves SSH banners from multiple targets
func getSSHBanners(targets []string) []string {
	banners := make([]string, 0, len(targets))
	for _, target := range targets {
		addr := target
		port := "22"
		if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			addr = parts[0]
			port = parts[1]
		}
		conn, err := net.DialTimeout("tcp", addr+":"+port, 5*time.Second)
		if err != nil {
			banners = append(banners, "error: "+err.Error())
			continue
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			banners = append(banners, "error: "+err.Error())
			conn.Close()
			continue
		}
		banner := strings.TrimSpace(string(buf[:n]))
		banners = append(banners, banner)
		conn.Close()
	}
	return banners
}

// trySSHLogin attempts SSH login with proper resource management
func (wp *WorkerPool) trySSHLogin(job Job) (bool, error) {
	config := &ssh.ClientConfig{
		User: job.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(job.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Create connection with timeout
	conn, err := net.DialTimeout("tcp", job.Target, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Create SSH client
	client, chans, reqs, err := ssh.NewClientConn(conn, job.Target, config)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// Handle channels and requests
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "no channels allowed")
		}
	}()

	// Create SSH client from connection
	sshClient := ssh.NewClient(client, chans, reqs)
	defer sshClient.Close()

	// Create session to verify login
	session, err := sshClient.NewSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	return true, nil
}
