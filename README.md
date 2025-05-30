# Network Monitoring Tools Collection

[中文版 / Chinese Version](README_ZH.md)

This is a comprehensive network monitoring tools collection that includes various network connectivity and performance monitoring scripts, suitable for network diagnostics, performance analysis, and troubleshooting.

## Features

- **Multi-protocol Support**: ICMP Ping, HTTP/HTTPS (cURL), DNS Resolution, UDP Ping
- **Intelligent Analysis**: Dynamic threshold calculation, problem period identification, statistical analysis
- **Detailed Logging**: Structured logging for long-term monitoring
- **Cross-platform**: Supports macOS, Linux, Windows
- **Flexible Configuration**: Customizable monitoring parameters, intervals, timeouts, etc.
- **Multiple Output Formats**: Supports plain text and Markdown format reports

## Project Structure

```
ai_written_tools/
├── README.md                    # Project documentation
├── icmp_ping/                   # ICMP Ping monitoring tools
│   ├── monitor_ping.py          # ICMP ping monitoring script
│   └── analyze_network_log.py   # ICMP ping log analysis script
├── curl_ping/                   # HTTP/HTTPS monitoring tools
│   ├── monitor_curl.py          # cURL website connectivity monitoring script
│   └── analyze_curl_log.py      # cURL log analysis script
├── dns_lookup/                  # DNS resolution monitoring tools
│   ├── monitor_dns.py           # DNS resolution monitoring script
│   └── analyze_dns_log.py       # DNS log analysis script
└── udp_ping/                    # UDP Ping monitoring tools
    ├── ping_udp.py              # UDP ping monitoring script
    ├── analyze_udp_ping_log.py  # UDP ping log analysis script
    └── 使用说明.txt              # UDP ping usage instructions
```

## Detailed Tool Introduction

### 1. ICMP Ping Monitoring (`icmp_ping/`)

**Function**: Traditional ICMP ping monitoring to detect network connectivity and latency

**Features**:
- Automatic public IP address acquisition
- Multi-platform ping command support
- Real-time ping results and statistics display
- Detailed network latency analysis

**Usage**:
```bash
# Basic usage
python3 monitor_ping.py google.com

# Custom parameters
python3 monitor_ping.py google.com --interval 5 --timeout 10

# Analyze logs
python3 analyze_network_log.py ping_google.com.log
python3 analyze_network_log.py ping_google.com.log --markdown
```

### 2. HTTP/HTTPS Monitoring (`curl_ping/`)

**Function**: Monitor website HTTP/HTTPS connectivity using cURL

**Features**:
- DNS resolution results display
- HTTP status code and response time recording
- HTTPS and redirect support
- Detailed error information recording

**Usage**:
```bash
# Monitor websites
python3 monitor_curl.py https://github.com
python3 monitor_curl.py http://example.com --interval 10

# Analyze logs
python3 analyze_curl_log.py curl_monitor_github.com.log
python3 analyze_curl_log.py curl_monitor_example.com.log --markdown
```

### 3. DNS Resolution Monitoring (`dns_lookup/`)

**Function**: Specialized monitoring of DNS resolution performance and reliability

**Features**:
- Fixed resolution of google.com domain
- Custom DNS server support
- DNS resolution time statistics
- IP address change tracking

**Usage**:
```bash
# Use system default DNS
python3 monitor_dns.py

# Use specified DNS server
python3 monitor_dns.py --dns-server 8.8.8.8
python3 monitor_dns.py --dns-server 1.1.1.1 --interval 5

# Analyze logs
python3 analyze_dns_log.py dns_monitor_google.com_8.8.8.8.log
python3 analyze_dns_log.py dns_monitor_google.com_1.1.1.1.log --markdown
```

### 4. UDP Ping Monitoring (`udp_ping/`)

**Function**: UDP protocol connectivity testing

**Features**:
- UDP port connectivity detection
- Custom port support
- Timeout and error handling
- Detailed UDP connection statistics

**Usage**:
```bash
# Basic UDP ping
python3 ping_udp.py target_host 53

# Analyze logs
python3 analyze_udp_ping_log.py udp_ping_log.txt
```

## Log Analysis Features

All monitoring scripts are equipped with corresponding log analysis tools that provide the following analysis functions:

### Intelligent Analysis Features
- **Dynamic Threshold Calculation**: Automatically calculate performance thresholds based on historical data
- **Problem Period Identification**: Automatically identify network anomaly time periods
- **Statistical Analysis**: Success rate, average latency, maximum/minimum values, etc.
- **Trend Analysis**: Network performance change trends
- **Error Classification**: Intelligent classification of different types of network errors

### Report Formats
- **Plain Text Format**: Suitable for terminal viewing and logging
- **Markdown Format**: Suitable for document generation and sharing

## System Requirements

### Basic Requirements
- Python 3.6+
- Network connection

### System Tool Dependencies
- **ping**: Built-in system tool (ICMP ping monitoring)
- **curl**: Built-in or needs installation (HTTP/HTTPS monitoring)
- **nslookup**: Built-in system tool (DNS monitoring)
- **nc (netcat)**: Built-in or needs installation (UDP ping monitoring)

### Supported Operating Systems
- macOS
- Linux (Ubuntu, CentOS, Debian, etc.)
- Windows (requires corresponding command-line tools)

## Quick Start

1. **Clone or Download Project**
   ```bash
   # If it's a git repository
   git clone <repository_url>
   cd ai_written_tools
   ```

2. **Choose Monitoring Tool**
   ```bash
   # ICMP Ping monitoring
   cd icmp_ping
   python3 monitor_ping.py google.com
   
   # HTTP/HTTPS monitoring
   cd curl_ping
   python3 monitor_curl.py https://github.com
   
   # DNS resolution monitoring
   cd dns_lookup
   python3 monitor_dns.py --dns-server 8.8.8.8
   ```

3. **Analyze Monitoring Results**
   ```bash
   # After waiting for some time, analyze the generated logs
   python3 analyze_*.py <log_file_name> --markdown
   ```

## Use Cases

### Network Troubleshooting
- Use ICMP ping to detect basic connectivity
- Use HTTP monitoring to detect web service availability
- Use DNS monitoring to detect domain resolution issues

### Performance Monitoring
- Long-term monitoring of network latency changes
- Monitor DNS resolution performance
- Monitor web service response times

### Network Quality Assessment
- Evaluate network stability
- Analyze network performance trends
- Generate network quality reports

## Advanced Configuration

### Custom Monitoring Parameters
Most scripts support the following common parameters:
- `--interval`: Monitoring interval (seconds)
- `--timeout`: Timeout duration (seconds)
- `--output`: Custom log file name

### Environment Variables
Some scripts support configuration through environment variables:
```bash
export MONITOR_INTERVAL=30
export MONITOR_TIMEOUT=10
```

## Troubleshooting

### Common Issues

1. **Permission Issues**
   - Some systems may require administrator privileges to execute ping commands
   - Solution: Run scripts with `sudo`

2. **Command Not Found**
   - Ensure the system has necessary network tools installed (ping, curl, nslookup, nc)
   - macOS: Usually comes with all tools pre-installed
   - Linux: May need to install `iputils-ping`, `curl`, `netcat`

3. **Network Firewall**
   - Some network environments may block specific protocols
   - Solution: Check firewall settings or use alternative monitoring methods


## License

This project is licensed under the MIT License.

## Contributing

Welcome to submit Issues and Pull Requests to improve this project.

**Note**: These tools are primarily for network diagnostics and monitoring. Please use them responsibly to avoid excessive load on target servers.