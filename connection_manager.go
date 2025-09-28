package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ConnectionManager handles advanced connection management with pooling and optimization
type ConnectionManager struct {
	// Connection pools
	connectionPools map[string]*ConnectionPool
	poolMutex       sync.RWMutex

	// Connection limits and timeouts
	maxConnections    int
	connectionTimeout time.Duration
	readTimeout       time.Duration
	keepAliveInterval time.Duration

	// Performance optimization
	enableCompression bool
	fastCiphers       bool
	bufferSize        int

	// Resource management
	resourceManager *ResourceManager
	stealthManager  *StealthManager

	// Metrics
	metrics *ConnectionMetrics
	mu      sync.RWMutex
}

// ConnectionPool manages a pool of connections for a specific target
type ConnectionPool struct {
	target      string
	connections chan *PooledConnection
	maxSize     int
	currentSize int
	createdAt   time.Time
	lastUsed    time.Time
	mu          sync.RWMutex
}

// PooledConnection represents a pooled SSH connection
type PooledConnection struct {
	client    *ssh.Client
	createdAt time.Time
	lastUsed  time.Time
	useCount  int
	isHealthy bool
	mu        sync.RWMutex
}

// ConnectionMetrics tracks connection performance
type ConnectionMetrics struct {
	TotalConnections      int64
	PooledConnections     int64
	ReusedConnections     int64
	FailedConnections     int64
	AverageConnectionTime time.Duration
	PoolHitRate           float64
	ConnectionErrors      map[string]int64
	mu                    sync.RWMutex
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(maxConnections int, connectionTimeout, readTimeout, keepAliveInterval time.Duration,
	enableCompression, fastCiphers bool, bufferSize int) *ConnectionManager {

	cm := &ConnectionManager{
		connectionPools:   make(map[string]*ConnectionPool),
		maxConnections:    maxConnections,
		connectionTimeout: connectionTimeout,
		readTimeout:       readTimeout,
		keepAliveInterval: keepAliveInterval,
		enableCompression: enableCompression,
		fastCiphers:       fastCiphers,
		bufferSize:        bufferSize,
		metrics: &ConnectionMetrics{
			ConnectionErrors: make(map[string]int64),
		},
	}

	return cm
}

// SetManagers sets the resource and stealth managers
func (cm *ConnectionManager) SetManagers(resourceMgr *ResourceManager, stealthMgr *StealthManager) {
	cm.resourceManager = resourceMgr
	cm.stealthManager = stealthMgr
}

// GetConnection gets a connection from the pool or creates a new one
func (cm *ConnectionManager) GetConnection(target string, username, password string) (*PooledConnection, error) {
	// Try to get from pool first
	if pooledConn := cm.getFromPool(target); pooledConn != nil {
		cm.metrics.mu.Lock()
		cm.metrics.ReusedConnections++
		cm.metrics.mu.Unlock()
		return pooledConn, nil
	}

	// Create new connection
	start := time.Now()
	conn, err := cm.createNewConnection(target, username, password)
	if err != nil {
		cm.metrics.mu.Lock()
		cm.metrics.FailedConnections++
		cm.metrics.ConnectionErrors[err.Error()]++
		cm.metrics.mu.Unlock()
		return nil, err
	}

	// Update metrics
	connectionTime := time.Since(start)
	cm.metrics.mu.Lock()
	cm.metrics.TotalConnections++
	if cm.metrics.AverageConnectionTime == 0 {
		cm.metrics.AverageConnectionTime = connectionTime
	} else {
		cm.metrics.AverageConnectionTime = time.Duration(
			(float64(cm.metrics.AverageConnectionTime) + float64(connectionTime)) / 2,
		)
	}
	cm.metrics.mu.Unlock()

	return conn, nil
}

// ReturnConnection returns a connection to the pool
func (cm *ConnectionManager) ReturnConnection(pooledConn *PooledConnection) {
	if pooledConn == nil {
		return
	}

	// Check if connection is still healthy
	if !cm.isConnectionHealthy(pooledConn) {
		cm.closeConnection(pooledConn)
		return
	}

	// Update last used time
	pooledConn.mu.Lock()
	pooledConn.lastUsed = time.Now()
	pooledConn.useCount++
	pooledConn.mu.Unlock()

	// Try to return to pool
	cm.returnToPool(pooledConn)
}

// getFromPool attempts to get a connection from the pool
func (cm *ConnectionManager) getFromPool(target string) *PooledConnection {
	cm.poolMutex.RLock()
	pool, exists := cm.connectionPools[target]
	cm.poolMutex.RUnlock()

	if !exists {
		return nil
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	select {
	case conn := <-pool.connections:
		// Check if connection is still healthy
		if cm.isConnectionHealthy(conn) {
			pool.lastUsed = time.Now()
			return conn
		} else {
			// Connection is unhealthy, close it
			cm.closeConnection(conn)
		}
	default:
		// No connections available in pool
	}

	return nil
}

// returnToPool returns a connection to the pool
func (cm *ConnectionManager) returnToPool(pooledConn *PooledConnection) {
	// Extract target from connection (this would need to be stored in PooledConnection)
	// For now, we'll use a simplified approach
	target := "unknown" // This should be extracted from the connection

	cm.poolMutex.Lock()
	pool, exists := cm.connectionPools[target]
	if !exists {
		pool = &ConnectionPool{
			target:      target,
			connections: make(chan *PooledConnection, cm.maxConnections),
			maxSize:     cm.maxConnections,
			createdAt:   time.Now(),
		}
		cm.connectionPools[target] = pool
	}
	cm.poolMutex.Unlock()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Try to add to pool
	select {
	case pool.connections <- pooledConn:
		pool.currentSize++
		pool.lastUsed = time.Now()
		cm.metrics.mu.Lock()
		cm.metrics.PooledConnections++
		cm.metrics.mu.Unlock()
	default:
		// Pool is full, close the connection
		cm.closeConnection(pooledConn)
	}
}

// createNewConnection creates a new SSH connection with optimized settings
func (cm *ConnectionManager) createNewConnection(target, username, password string) (*PooledConnection, error) {
	// Create SSH client config with optimizations
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cm.connectionTimeout,
	}

	// Apply cipher optimizations
	if cm.fastCiphers {
		config.Ciphers = []string{"aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"}
		config.MACs = []string{"hmac-sha2-256", "hmac-sha2-512"}
		config.KeyExchanges = []string{"curve25519-sha256", "diffie-hellman-group14-sha256"}
	}

	// Create TCP connection with keep-alive
	conn, err := net.DialTimeout("tcp", target, cm.connectionTimeout)
	if err != nil {
		return nil, err
	}

	// Set TCP keep-alive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(cm.keepAliveInterval)
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(cm.readTimeout))

	// Create SSH client connection
	client, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Handle channels and requests
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "no channels allowed")
		}
	}()

	// Create SSH client
	sshClient := ssh.NewClient(client, chans, reqs)

	// Create pooled connection
	pooledConn := &PooledConnection{
		client:    sshClient,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		useCount:  0,
		isHealthy: true,
	}

	return pooledConn, nil
}

// isConnectionHealthy checks if a connection is still healthy
func (cm *ConnectionManager) isConnectionHealthy(pooledConn *PooledConnection) bool {
	pooledConn.mu.RLock()
	defer pooledConn.mu.RUnlock()

	if !pooledConn.isHealthy {
		return false
	}

	// Check if connection is too old
	if time.Since(pooledConn.createdAt) > 30*time.Minute {
		return false
	}

	// Check if connection has been idle too long
	if time.Since(pooledConn.lastUsed) > 5*time.Minute {
		return false
	}

	// Try to create a session to test the connection
	session, err := pooledConn.client.NewSession()
	if err != nil {
		return false
	}
	session.Close()

	return true
}

// closeConnection properly closes a connection
func (cm *ConnectionManager) closeConnection(pooledConn *PooledConnection) {
	if pooledConn == nil {
		return
	}

	pooledConn.mu.Lock()
	defer pooledConn.mu.Unlock()

	if pooledConn.client != nil {
		pooledConn.client.Close()
	}
	pooledConn.isHealthy = false
}

// CleanupStaleConnections cleans up stale connections from all pools
func (cm *ConnectionManager) CleanupStaleConnections() {
	cm.poolMutex.Lock()
	defer cm.poolMutex.Unlock()

	for target, pool := range cm.connectionPools {
		pool.mu.Lock()

		// Close connections that are too old or idle
		select {
		case conn := <-pool.connections:
			if !cm.isConnectionHealthy(conn) {
				cm.closeConnection(conn)
				pool.currentSize--
			} else {
				// Put it back
				select {
				case pool.connections <- conn:
				default:
					cm.closeConnection(conn)
					pool.currentSize--
				}
			}
		default:
			// No connections to check
		}

		// Remove empty pools that haven't been used recently
		if pool.currentSize == 0 && time.Since(pool.lastUsed) > 10*time.Minute {
			delete(cm.connectionPools, target)
		}

		pool.mu.Unlock()
	}
}

// GetMetrics returns connection metrics
func (cm *ConnectionManager) GetMetrics() *ConnectionMetrics {
	cm.metrics.mu.RLock()
	defer cm.metrics.mu.RUnlock()

	// Calculate pool hit rate
	if cm.metrics.TotalConnections > 0 {
		cm.metrics.PoolHitRate = float64(cm.metrics.ReusedConnections) / float64(cm.metrics.TotalConnections)
	}

	return cm.metrics
}

// GetPerformanceReport returns a detailed performance report
func (cm *ConnectionManager) GetPerformanceReport() string {
	metrics := cm.GetMetrics()

	report := "=== CONNECTION PERFORMANCE REPORT ===\n"
	report += fmt.Sprintf("Total Connections: %d\n", metrics.TotalConnections)
	report += fmt.Sprintf("Pooled Connections: %d\n", metrics.PooledConnections)
	report += fmt.Sprintf("Reused Connections: %d\n", metrics.ReusedConnections)
	report += fmt.Sprintf("Failed Connections: %d\n", metrics.FailedConnections)
	report += fmt.Sprintf("Pool Hit Rate: %.2f%%\n", metrics.PoolHitRate*100)
	report += fmt.Sprintf("Average Connection Time: %v\n", metrics.AverageConnectionTime.Round(time.Millisecond))

	if len(metrics.ConnectionErrors) > 0 {
		report += "\nConnection Errors:\n"
		for errorType, count := range metrics.ConnectionErrors {
			report += fmt.Sprintf("  %s: %d\n", errorType, count)
		}
	}

	return report
}

// Close closes all connections and cleans up resources
func (cm *ConnectionManager) Close() {
	cm.poolMutex.Lock()
	defer cm.poolMutex.Unlock()

	for _, pool := range cm.connectionPools {
		pool.mu.Lock()
		close(pool.connections)

		// Close all connections in the pool
		for {
			select {
			case conn := <-pool.connections:
				cm.closeConnection(conn)
			default:
				goto done
			}
		}
	done:
		pool.mu.Unlock()
	}

	cm.connectionPools = make(map[string]*ConnectionPool)
}
