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
