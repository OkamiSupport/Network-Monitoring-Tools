# UDP Ping Tool Usage Guide

[中文版 / Chinese Version](README_ZH.md)

## Overview

This toolkit contains two scripts for UDP network connectivity testing and log analysis:

- **`ping_udp.py`**: UDP Ping tool supporting both server and client modes
- **`analyze_udp_ping_log.py`**: UDP Ping log analysis tool

## 1. ping_udp.py Usage Guide

### Feature Introduction

This script is a UDP Ping tool for testing network connectivity, latency, packet loss rate, and jitter between two hosts on specified UDP ports. It includes two operating modes:

- **Server Mode (`-s`)**: Runs on one machine, listens on a specified UDP port, receives Ping packets from clients, and immediately sends echo responses (Pong). This mode does not generate log files.
- **Client Mode (`-c`)**: Sends UDP Ping packets to a specified server IP and port, receives responses, calculates performance metrics (RTT, packet loss, jitter, etc.), and outputs results to console and log files.

### System Requirements

- Python 3.4 or higher (due to use of statistics module)

### Server Mode

#### Startup Command
```bash
python ping_udp.py -s [optional parameters]
```

#### Common Parameters

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--server` | `-s` | Flag | N/A | Required, specifies running in server mode |
| `--port <port_number>` | `-p` | Integer | 9999 | Specifies the UDP port number to listen on |
| `--host <listen_address>` | `-H` | String | 0.0.0.0 | Specifies the IP address the server binds to |
| `--buffer <size>` | `-b` | Integer | 1024 | Specifies receive buffer size (bytes) |

#### Usage Examples

```bash
# Listen on UDP port 9999 on all network interfaces (default)
python ping_udp.py -s

# Listen on UDP port 12345 on specific IP address 192.168.1.100
python ping_udp.py -s -H 192.168.1.100 -p 12345
```

#### Operation Instructions

- After startup, the server displays "UDP Ping server listening on <address>:<port>..." in the console
- It runs continuously, waiting for client connections
- Does not generate any log files
- Press `Ctrl+C` to stop the server

### Client Mode

#### Startup Command
```bash
python ping_udp.py -c <target_host> [optional parameters]
```

#### Operating Modes

The client has two main operating modes, determined by whether the `-n` parameter is provided:

##### 1. Single Run Mode (specify `-n` count)

**Purpose**: Send a fixed number (`-n` specified) of Ping packets, output statistics after completion, and exit.

**Command Examples**:
```bash
# Send 50 ping packets to port 4500 of 100.59.0.1, then exit
python ping_udp.py -c 100.59.0.1 -p 4500 -n 50

# Send 100 packets with 0.2s interval, 1s timeout, 512-byte packet size
python ping_udp.py -c 100.59.0.1 -p 4500 -n 100 -i 0.2 -t 1 -S 512
```

**Behavior**: The script executes the specified `-n` Pings, prints summary information to console after completion, records one line of summary statistics to the log file, then exits.

##### 2. Periodic Monitoring Mode (no `-n` specified)

**Purpose**: Run continuously, performing periodic measurements and logging at specified log summary intervals (`-I` parameter, default 10 seconds) until manually stopped (`Ctrl+C`).

**Packet Count Calculation**: Within each summary period, the script automatically calculates how many Ping packets to send based on the log summary interval (`-I`) and Ping packet send interval (`-i`):

```
Packets per measurement = max(1, int(summary_interval / ping_interval))
```

For example, with `-I 10 -i 0.5`, each 10-second period will measure `int(10 / 0.5) = 20` packets.

**Command Examples**:
```bash
# Continuously monitor port 4500 of 100.59.0.1, log every 10 seconds by default
# (default Ping interval 1s, 10 packets per measurement)
python ping_udp.py -c 100.59.0.1 -p 4500

# Continuous monitoring, log every 30 seconds, Ping interval 0.5s (60 packets per measurement)
python ping_udp.py -c 100.59.0.1 -p 4500 -i 0.5 -I 30

# Continuous monitoring, log every 10 seconds, Ping interval 0.1s (100 packets per measurement), enable verbose console output
python ping_udp.py -c 100.59.0.1 -p 4500 -i 0.1 -I 10 -v
```

**Behavior**: After startup, the script enters an infinite loop. In each loop (approximately equal to `-I` specified seconds), it will:

1. Execute Ping measurements for the calculated number of packets (`_perform_ping_batch`)
2. Calculate statistics for that batch
3. Record one line of summary statistics for that batch to the log file
4. Immediately start the next round of measurements
5. Press `Ctrl+C` to stop monitoring

### Command Line Parameters Details

| Parameter | Short | Type | Default | Mode | Description |
|-----------|-------|------|---------|------|-------------|
| `--server` | `-s` | Flag | N/A | Server | Required, specifies running in server mode |
| `--client <host>` | `-c` | String | N/A | Client | Required, specifies running in client mode and provides target host IP address or domain name |
| `--host <listen_address>` | `-H` | String | 0.0.0.0 | Server | IP address the server binds to |
| `--port <port_number>` | `-p` | Integer | 9999 | Server/Client | UDP port number to listen on (server) or connect to (client) |
| `--buffer <size>` | `-b` | Integer | 1024 | Server/Client | Receive buffer size (bytes) |
| `--count <number>` | `-n` | Integer | None | Client | Number of Pings to send. If provided, single run mode; otherwise periodic monitoring mode |
| `--interval <seconds>` | `-i` | Float | 1.0 | Client | Send interval time between Ping requests (seconds) |
| `--timeout <seconds>` | `-t` | Float | 1.0 | Client | Timeout for waiting for each Ping reply (seconds) |
| `--size <bytes>` | `-S` | Integer | 64 | Client | Total size of each UDP Ping packet (bytes), including internal headers |
| `--summary-interval <seconds>` | `-I` | Float | 10.0 | Client | Valid only in periodic monitoring mode. Time interval for recording summary logs (seconds), used to calculate packets per measurement |
| `--verbose` | `-v` | Flag | False | Client | Enable verbose console output (e.g., show send/receive/timeout status for each packet). Does not affect log file content level |

### Output Interpretation

#### 1. Console Output (Client)

**Startup Information**: Shows target IP, port, packet size, count (or periodic), interval, timeout, etc.

**Ping Process (Normal Mode)**:
- `Reply from <IP>: seq=<N> time=<RTT> ms`: Successfully received reply
- `Request timeout (seq=<N>)`: No reply received within timeout
- **Error Messages**: May show Socket errors during send or receive

**Ping Process (`-v` Verbose Mode)**: Shows more detailed send/receive success/failure information for each packet.

**Summary Information** (single mode or end of each round in periodic mode):
```
--- UDP Ping statistics for <target> ---
<sent> packets transmitted, <received> packets received, <errors> errors, <loss_rate>% packet loss
round-trip RTT (ms): min = ..., avg = ..., max = ...
stddev = ..., jitter = ...
```

**Periodic Monitoring Prompt**: Prompts to press `Ctrl+C` to stop.

#### 2. Log File Output (Client Only)

**Filename**: `udp_ping_client_<target_IP>_<target_port>_<startup_timestamp>.log`

Example: `udp_ping_client_100.59.0.1_4500_20250417_163135.log`

File is created in the script's running directory.

**File Content**:

1. **Header Information**: Records monitoring target, port, startup time, and all parameters used (such as Ping packet count, interval, size, timeout, summary interval, etc.)

2. **Table Header Row**: Defines column names for subsequent data rows
   ```
   Sent | Received | Loss(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev(ms) | Jitter(ms) | Size(bytes)
   ```

3. **Data Rows**:
   - **Single Run Mode** (`-n`): Records only one row representing summary statistics for `-n` packets in this run
   - **Periodic Monitoring Mode** (no `-n`): Records one row approximately every `-I` specified time, representing summary statistics for all packets measured in that period

**Column Meanings**:

| Column | Description |
|--------|-------------|
| Sent | Number of packets sent in this period/batch |
| Received | Number of packets successfully received in this period/batch |
| Loss(%) | Packet loss percentage for this period/batch |
| Min RTT(ms) | Minimum round-trip time for this period/batch |
| Avg RTT(ms) | Average round-trip time for this period/batch |
| Max RTT(ms) | Maximum round-trip time for this period/batch |
| StdDev(ms) | Standard deviation of RTT for this period/batch |
| Jitter(ms) | RTT jitter for this period/batch (average of absolute differences between consecutive RTTs) |
| Size(bytes) | Ping packet size used in this measurement |

## 2. analyze_udp_ping_log.py Usage Guide

### Overview

This script is used to parse log files generated by `ping_udp.py` (client mode). It can read log data, calculate overall statistical metrics, identify potential network problem periods based on dynamic or fixed thresholds (high packet loss, high latency, high jitter), and finally generate an easy-to-read analysis report (plain text or Markdown format).

### System Requirements

- Python 3.4 or higher
- Script file `analyze_udp_ping_log.py`
- UDP Ping log file to analyze (generated by `ping_udp.py`)
- No additional Python packages required

### Usage

#### Basic Usage (generate plain text report to console)
```bash
python analyze_udp_ping_log.py <your_udp_ping_log_file_path>
```

#### Generate Markdown Format Report
```bash
python analyze_udp_ping_log.py <your_udp_ping_log_file_path> --md
```

This will generate a Markdown file named `<log_file_basename>_udp_report.md` in the same directory as the log file. If unable to write the file, report content will be printed to console.

#### Usage Examples

```bash
# Analyze udp_ping_client_100.59.0.1_4500_....log file in current directory, output text report
python analyze_udp_ping_log.py udp_ping_client_100.59.0.1_4500_20250417_163135.log

# Analyze log file at specified path and generate Markdown report
python analyze_udp_ping_log.py /var/log/ping_logs/udp_ping_client_100.59.0.1_4500_20250417_163135.log --md
```

### Command Line Parameters Details

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `<udp_ping_log_file_path>` | String | Yes | Specifies the path to the UDP Ping log file to analyze |
| `--md` | Flag | No | If provided, script will generate Markdown format report and attempt to save to file; otherwise, generates plain text report and prints to console |

### Output Interpretation (Report Content)

Reports (whether plain text or Markdown) typically contain the following sections:

#### 1. Report Title
Indicates which target IP and port this analysis report is for.

#### 2. Analysis Environment and Monitoring Configuration
Shows monitoring configuration information parsed from the log file, such as:
- Target IP/port
- Monitoring start time
- Description of packets per measurement
- Ping interval/size/timeout
- Log summary interval (if periodic mode), etc.
- Hostname and timezone of the machine running the analysis script

#### 3. Overall Statistics
Shows summary statistics for the entire log file time range, including:
- Total sent/received packet count
- Overall average packet loss rate
- Overall average/minimum/maximum RTT
- Overall average standard deviation (StdDev)
- Overall average jitter

#### 4. Analysis Thresholds

**Key Section!** Shows thresholds used in this analysis. Will indicate whether **dynamic thresholds** or **fixed thresholds** were used.

##### Dynamic Thresholds
If there is sufficient stable data at the beginning of the log file, the script will calculate a network baseline (Baseline RTT, StdDev, Jitter) based on this data, then dynamically calculate high latency and high jitter thresholds for this analysis based on these baselines. This allows thresholds to adapt to the normal levels of different network environments.

##### Fixed Thresholds
If log data is insufficient or initial data is unstable (high packet loss rate), preventing reliable baseline calculation, the script will fall back to using preset fixed thresholds in the script. The report will explain the reason for fallback.

##### Displayed Thresholds
The report will list all thresholds finally used for problem judgment, including:
- High packet loss rate
- High latency
- High jitter (Jitter, StdDev, Max/Avg Ratio)

#### 5. Potential Problem Periods
Lists which time points during the analysis period had measurement results exceeding the corresponding thresholds defined in the "Analysis Thresholds" section above.

- Will be categorized by problem type (high packet loss, high latency, high jitter)
- For high jitter, will specifically indicate which jitter metric exceeded limits (Jitter value, StdDev value, or Max/Avg Ratio)
- If no periods exceed thresholds, will clearly state this

#### 6. Summary
Provides a high-level qualitative summary based on overall statistics and problem period detection results.

- Evaluates network connectivity (packet loss situation)
- Latency level and stability (jitter situation)
- Indicates whether potential problem periods were detected

### About Dynamic vs Fixed Thresholds

#### Goal
Dynamic thresholds aim to make analysis more adaptable to the "normal" performance of the tested network. For example, for a network that has inherently high but stable latency, fixed thresholds might always falsely report high latency, while dynamic thresholds can set more reasonable judgment criteria based on its own baseline.

#### Conditions
Dynamic thresholds require sufficient quantity (default at least 20 records) of stable data records with low packet loss rates (default <= 0.5%) at the beginning of the log file to calculate baselines.

#### Fallback
If conditions are not met, the script will automatically use preset fixed thresholds and explain the reason in the report. This ensures analysis can still be performed even with less-than-ideal data.

## 3. Common Issues and Tips

### Log Format Misalignment
This is usually caused by the terminal or text editor used to view log files not being set to a monospaced font. Please check and modify the display environment's font settings. The script itself generates alignment based on character count.

### Cannot Connect/100% Packet Loss

#### Firewall
This is the most common cause. Please ensure:
- Server firewall (system firewalls like iptables/firewalld/ufw or cloud platform security groups) allows UDP inbound traffic from client IP to the specified port
- Check if client outbound and related inbound reply traffic is blocked
- Intermediate network devices may also have firewalls

#### Server Not Running
Confirm that `ping_udp.py -s` is actually running on the target machine and listening on the correct IP and port.

#### NAT Issues
If the client is behind NAT (like home routers), UDP's connectionless nature may cause NAT mapping failures or firewalls blocking reply packets. Try testing in an environment where both ends have public IPs to exclude NAT effects.

#### Routing Issues
Ensure network routing configuration is correct.

### Log File Not Generated (Client)

- Ensure you're running in client mode (`-c`). Server mode does not generate logs
- Check if the script has permission to create files in the current directory
- Check if the startup command exited early due to parameter errors or unresolvable target hosts

### Analysis Script Errors

- Ensure the provided log file path is correct
- Ensure the log file was generated by a compatible version of `ping_udp.py` and the format is not corrupted
- Check file read permissions