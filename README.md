# Advanced SSH Brute Force Tool

A sophisticated SSH brute force tool with advanced stealth, evasion, and performance optimization features.

## Features

### 🥷 Stealth & Evasion Techniques
- **Behavioral Mimicking**: Simulates human-like interaction patterns
- **Timing Randomization**: Randomizes delays to avoid detection
- **Traffic Obfuscation**: Masks network traffic patterns
- **Fingerprint Randomization**: Randomizes SSH client fingerprints
- **Session Simulation**: Creates realistic SSH session characteristics
- **Adaptive Delays**: Automatically adjusts timing based on success rates

### ⚡ Performance Optimization
- **Connection Pooling**: Reuses connections for better performance
- **Fast Ciphers**: Uses optimized cipher algorithms
- **Compression**: Enables SSH compression for faster transfers
- **Resource Management**: Automatic memory and CPU optimization
- **Load Balancing**: Distributes load across multiple workers

### 🛡️ Detection Avoidance
- **Honeypot Detection**: Identifies and avoids honeypot systems
- **Realistic User Agents**: Uses authentic SSH client signatures
- **Human-like Retry Patterns**: Mimics natural retry behavior
- **Traffic Distribution**: Spreads attempts across time and patterns

### 📊 Performance Monitoring
- **Real-time Metrics**: Tracks connections, success rates, and performance
- **Resource Utilization**: Monitors memory, CPU, and network usage
- **Adaptive Optimization**: Automatically adjusts based on performance
- **Detailed Reporting**: Comprehensive performance and stealth reports

## Usage

### Basic Usage
```bash
go run . -t targets.txt -u users.txt -p passwords.txt
```

### Advanced Stealth Mode
```bash
go run . -t targets.txt -u users.txt -p passwords.txt \
  --stealth \
  --behavioral \
  --traffic-obfuscation \
  --adaptive-delays \
  --fingerprint-randomization \
  --session-simulation
```

### Performance Optimized
```bash
go run . -t targets.txt -u users.txt -p passwords.txt \
  --compression \
  --fast-ciphers \
  --pool-size 100 \
  --performance-monitoring \
  --resource-optimization
```

### Full Stealth Configuration
```bash
go run . -t targets.txt -u users.txt -p passwords.txt \
  --stealth \
  --behavioral \
  --traffic-obfuscation \
  --adaptive-delays \
  --fingerprint-randomization \
  --session-simulation \
  --compression \
  --fast-ciphers \
  --pool-size 50 \
  --performance-monitoring \
  --resource-optimization \
  --honeypot \
  --max-conns 2 \
  --conn-timeout 10 \
  --read-timeout 5 \
  --retry-delay 2000 \
  --max-retries 2 \
  --host-delay 5
```

## Command Line Arguments

### Required Arguments
- `-t, --target`: Target list file (one target per line)
- `-u, --user`: Username list file (one username per line)
- `-p, --pass`: Password list file (one password per line)

### Connection Management
- `--max-conns`: Maximum concurrent connections per target (default: 3)
- `--conn-timeout`: Connection timeout in seconds (default: 5)
- `--read-timeout`: Read timeout in seconds (default: 3)
- `--retry-delay`: Delay between retries in milliseconds (default: 1000)
- `--max-retries`: Maximum number of retries per target (default: 3)
- `--host-delay`: Delay between attempts to same host in seconds (default: 2)

### Stealth & Evasion
- `--stealth`: Enable stealth mode with behavioral mimicking and timing randomization
- `--behavioral`: Enable behavioral mimicking to avoid detection
- `--traffic-obfuscation`: Enable traffic obfuscation techniques
- `--adaptive-delays`: Enable adaptive delay adjustment based on success rate
- `--fingerprint-randomization`: Randomize SSH client fingerprints
- `--session-simulation`: Simulate realistic SSH sessions

### Performance Optimization
- `--compression`: Enable SSH compression for better performance
- `--fast-ciphers`: Use faster cipher algorithms (aes128-ctr)
- `--pool-size`: Connection pool size for connection reuse (default: 50)
- `--performance-monitoring`: Enable detailed performance monitoring and reporting
- `--resource-optimization`: Enable automatic resource optimization

### Detection Avoidance
- `--honeypot`: Enable honeypot detection and checking

### General
- `-w, --workers`: Number of concurrent workers (default: CPU cores * 2)

## Input Files

### Target File Format
```
192.168.1.1
192.168.1.2:2222
10.0.0.1
example.com:22
```

### Username File Format
```
admin
root
user
administrator
```

### Password File Format
```
password
123456
admin
root
```

## Output

### Console Output
- Real-time progress with success/failure counts
- Performance metrics and resource utilization
- Stealth and evasion statistics
- Detailed performance reports

### File Output
- `cracked.txt`: Successfully cracked credentials in format `ip:port username:password`

## Advanced Features

### Stealth Manager
The stealth manager implements sophisticated evasion techniques:
- Human-like behavior patterns with typing speeds and pauses
- Traffic shaping with different burst patterns
- SSH fingerprint randomization
- Adaptive timing based on success rates

### Connection Manager
Advanced connection management with:
- Connection pooling for reuse
- Health checking and cleanup
- Performance metrics tracking
- Automatic resource optimization

### Resource Manager
Comprehensive resource monitoring:
- Memory usage tracking
- CPU utilization monitoring
- Adaptive scaling based on performance
- Automatic garbage collection

## Security Considerations

⚠️ **Important**: This tool is for authorized penetration testing and security research only. Always ensure you have proper authorization before testing any systems.

### Best Practices
1. Use stealth mode for production environments
2. Enable honeypot detection to avoid traps
3. Use realistic timing patterns
4. Monitor resource usage to avoid detection
5. Rotate behavior patterns regularly

## Performance Tips

1. **For Speed**: Use `--fast-ciphers` and `--compression`
2. **For Stealth**: Enable all stealth flags and use low worker counts
3. **For Reliability**: Use connection pooling and adaptive delays
4. **For Monitoring**: Enable performance monitoring and resource optimization

## Examples

### Quick Test
```bash
go run . -t targets.txt -u users.txt -p passwords.txt -w 10
```

### Stealth Operation
```bash
go run . -t targets.txt -u users.txt -p passwords.txt \
  --stealth --behavioral --adaptive-delays \
  --max-conns 1 --host-delay 10 -w 5
```

### High Performance
```bash
go run . -t targets.txt -u users.txt -p passwords.txt \
  --compression --fast-ciphers --pool-size 100 \
  --performance-monitoring -w 50
```

## Troubleshooting

### Common Issues
1. **Too many connections**: Reduce `--max-conns` and `-w`
2. **Detection**: Enable stealth mode and increase delays
3. **Performance**: Enable compression and fast ciphers
4. **Memory issues**: Enable resource optimization

### Debug Mode
Add `--performance-monitoring` to see detailed metrics and identify bottlenecks.

## License

This tool is for educational and authorized testing purposes only. Use responsibly and in accordance with applicable laws and regulations.
