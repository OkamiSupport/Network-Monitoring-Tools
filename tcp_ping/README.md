# TCP Ping Monitoring Tool

A comprehensive TCP connection monitoring tool that tests port connectivity and measures connection performance metrics.

## Features

- **TCP Connection Testing**: Tests TCP port connectivity instead of ICMP ping
- **Concurrent Connections**: Uses multi-threading for faster measurements
- **Detailed Metrics**: Measures connection success rate, latency, and jitter
- **Continuous Monitoring**: Runs continuously with configurable intervals
- **Comprehensive Logging**: Detailed logs with timestamps and statistics
- **Signal Handling**: Graceful shutdown with Ctrl+C
- **Domain Resolution**: Supports both IP addresses and domain names
- **Log Analysis**: Includes analysis tool for performance reports

## Files

- `monitor_tcp_ping.py` - Main monitoring script
- `analyze_tcp_ping_log.py` - Log analysis and reporting tool
- `README.md` - This documentation

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library)

## Usage

### Basic Monitoring

```bash
# Monitor a specific IP and port
python3 monitor_tcp_ping.py 8.8.8.8 53

# Monitor a domain with default port (80)
python3 monitor_tcp_ping.py google.com

# Monitor a domain with specific port
python3 monitor_tcp_ping.py google.com 443
```

### Configuration

Edit the configuration section in `monitor_tcp_ping.py`:

```python
# --- Configuration ---
TCP_CONNECT_COUNT = 10   # Number of TCP connection attempts per cycle
INTERVAL_SECONDS = 5     # Measurement interval (seconds)
TCP_TIMEOUT = 2          # Timeout for single connection (seconds)
DEFAULT_PORT = 80        # Default port if not specified
MAX_CONCURRENT = 5       # Maximum concurrent connections
```

### Log Analysis

```bash
# Generate markdown report
python3 analyze_tcp_ping_log.py tcp_monitor_google_com_80.log

# Generate plain text report
python3 analyze_tcp_ping_log.py tcp_monitor_google_com_80.log text
```

## Log Format

The monitoring tool generates logs with the following format:

```
=== TCP Connection Monitoring Log ===
Target Host: google.com
Target Port: 80
Server Source Public IP: xxx.xxx.xxx.xxx
Monitoring started at: 2024-01-01 12:00:00
TCP connection attempts per measurement: 10
Measurement interval: 5 seconds
TCP connection timeout: 2 seconds
--------------------------------------------------------------------------------
Attempted | Success | Failure | Success(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev RTT(ms)
--------------------------------------------------------------------------------
10        | 10      | 0       |      100.0 |       15.23 |       18.45 |       25.67 |          3.21
10        | 9       | 1       |       90.0 |       16.12 |       19.33 |       28.91 |          4.15
```

## Metrics Explained

- **Attempted**: Total number of connection attempts in the cycle
- **Success**: Number of successful connections
- **Failure**: Number of failed connections
- **Success(%)**: Percentage of successful connections
- **Min RTT**: Minimum connection time in milliseconds
- **Avg RTT**: Average connection time in milliseconds
- **Max RTT**: Maximum connection time in milliseconds
- **StdDev RTT**: Standard deviation of connection times (jitter)

## Analysis Features

The analysis tool provides:

- **Dynamic Thresholds**: Automatically calculates performance baselines
- **Violation Detection**: Identifies periods of poor performance
- **Statistical Summary**: Overall performance statistics
- **Multiple Formats**: Markdown and plain text reports
- **Trend Analysis**: Performance trends over time

### Analysis Thresholds

- **Success Rate**: Default threshold of 95%
- **Latency**: Dynamic threshold based on baseline + 50% + 10ms
- **Jitter**: Dynamic threshold based on baseline standard deviation
- **Max/Avg Ratio**: Fixed threshold of 3.0

## Use Cases

1. **Web Service Monitoring**: Monitor HTTP/HTTPS endpoints
2. **Database Connectivity**: Test database port accessibility
3. **API Endpoint Testing**: Verify API service availability
4. **Network Troubleshooting**: Diagnose connectivity issues
5. **Performance Baseline**: Establish network performance baselines
6. **SLA Monitoring**: Track service level agreement compliance

## Advantages over ICMP Ping

- **Port-Specific Testing**: Tests actual service ports, not just host reachability
- **Firewall Friendly**: Works through firewalls that block ICMP
- **Service-Level Monitoring**: Verifies that the actual service is responding
- **Real Connection Metrics**: Measures actual TCP handshake performance
- **Application Layer Testing**: More relevant for application monitoring

## Example Output

```bash
$ python3 monitor_tcp_ping.py google.com 443
Will monitor domain: google.com (resolved to IP: 142.250.191.14) on port 443
Starting continuous TCP connection monitoring of google.com:443 (IP: 142.250.191.14) ...
Logs will be recorded in: tcp_monitor_google_com_443.log
Press Ctrl+C to stop monitoring.
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Target port is closed or service is down
2. **Timeout Errors**: Network latency is high or packets are being dropped
3. **DNS Resolution Errors**: Domain name cannot be resolved
4. **Permission Errors**: Some systems may require elevated privileges

### Tips

- Use shorter timeouts for faster detection of issues
- Increase concurrent connections for better statistics
- Monitor multiple ports simultaneously with separate instances
- Use the analysis tool to identify patterns in connection issues

## License

This tool is provided as-is for network monitoring and troubleshooting purposes.