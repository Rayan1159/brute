package main

import (
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// trySSHLogin attempts SSH login with proper resource management
func (wp *WorkerPool) trySSHLogin(job Job) (bool, error) {
	config := &ssh.ClientConfig{
		User: job.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(job.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         wp.limits.ConnectionTimeout,
	}

	// Create connection with configurable timeout
	conn, err := net.DialTimeout("tcp", job.Target, wp.limits.ConnectionTimeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(wp.limits.ReadTimeout))

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
