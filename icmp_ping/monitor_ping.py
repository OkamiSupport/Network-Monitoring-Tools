#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import time
import re
import logging
import platform
import signal # Used to handle interrupt signals more gracefully
import urllib.request # <--- Added: Used to get public IP
import socket # <--- Added: Used to handle network timeout errors, etc.

# --- Configuration ---
PING_COUNT = 10          # Number of PING packets sent per measurement cycle (can be appropriately increased for smoother data)
INTERVAL_SECONDS = 5     # Measurement interval time (seconds) (shorten the interval to get a feeling closer to "continuous")
PING_TIMEOUT = 2         # Timeout for a single ping (seconds), used for -W or -w parameters
IP_FETCH_TIMEOUT = 5     # Timeout for fetching public IP (seconds)
# --- Configuration End ---

# Global variable for signal handling
keep_running = True

def signal_handler(sig, frame):
    """Handle interrupt signal (Ctrl+C)"""
    global keep_running
    print("\nInterrupt signal received, stopping monitoring...")
    keep_running = False

def get_public_ip():
    """Try to get the public IP address from api.ipify.org"""
    urls = ["https://api.ipify.org", "https://ipinfo.io/ip", "https://checkip.amazonaws.com"]
    for url in urls:
        try:
            # Set User-Agent to avoid being blocked by some services
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=IP_FETCH_TIMEOUT) as response:
                ip = response.read().decode('utf-8').strip()
                # Simple verification of IP format
                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
                    return ip
                else:
                    print(f"Warning: Fetched invalid IP format from {url}: {ip}")
                    continue # Try next URL
        except (urllib.error.URLError, socket.timeout, ConnectionResetError) as e:
            print(f"Warning: Could not fetch public IP from {url}: {e}")
        except Exception as e:
            print(f"Warning: An unexpected error occurred while fetching public IP from {url}: {e}")
    # If all URLs fail
    print("Warning: Failed to fetch public IP from all sources.")
    return "N/A" # Return N/A to indicate failure to fetch

def setup_logging(target_ip):
    """Configure logger"""
    log_filename = f"network_monitor_{target_ip.replace('.', '_')}.log"
    logger = logging.getLogger('NetworkMonitor')
    logger.setLevel(logging.INFO)

    # Create file handler
    fh = logging.FileHandler(log_filename, encoding='utf-8')
    fh.setLevel(logging.INFO)

    # Create log format
    formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)

    # Add handler to logger (prevent duplicate additions)
    if not logger.hasHandlers():
        logger.addHandler(fh)
        # If you also want to output logs to the screen, uncomment the next two lines
        # ch = logging.StreamHandler()
        # ch.setFormatter(formatter)
        # logger.addHandler(ch)

    # Check if the log file is empty, if so, write header information
    try:
        # Try to read the file size to determine if it is empty
        with open(log_filename, 'r', encoding='utf-8') as f:
            f.seek(0, 2) # Go to end of file
            if f.tell() == 0: # Check if file is empty
                 raise FileNotFoundError # Treat empty file as new
            # If the file is not empty, assume the header already exists and do not write it again
    except (FileNotFoundError, IOError):
         # File does not exist or is empty, write header information
         source_ip = get_public_ip() # <--- Get public IP before writing header
         logger.info(f"=== Network Monitoring Log ===")
         logger.info(f"Target IP: {target_ip}")
         logger.info(f"Server Source Public IP: {source_ip}") # <--- New line: Display source public IP
         logger.info(f"Monitoring started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
         logger.info(f"PING packets per measurement: {PING_COUNT}")
         logger.info(f"Measurement interval: {INTERVAL_SECONDS} seconds")
         logger.info(f"Ping timeout: {PING_TIMEOUT} seconds")
         logger.info("-" * 80)
         logger.info("Sent | Received | Loss(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev RTT(ms)")
         logger.info("-" * 80)

    return logger

def parse_ping_output(output, ping_count):
    """Parse the output of the ping command (compatible with common formats for Linux and macOS/Windows)"""
    loss_percent = "ERR"
    rtt_min, rtt_avg, rtt_max, rtt_mdev = "N/A", "N/A", "N/A", "N/A"
    packets_transmitted, packets_received = "ERR", "ERR"

    # Parse packet loss rate and packet count (multiple format adaptation)
    loss_match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+received.*,\s+([\d.]+)%\s+packet loss", output, re.IGNORECASE | re.DOTALL)
    if not loss_match: # Try another common format (e.g., Windows Chinese)
         loss_match = re.search(r"Packets: Sent = (\d+), Received = (\d+), Lost = \d+ \((.*)%\s+loss\)", output, re.IGNORECASE | re.DOTALL)
    if not loss_match: # Try macOS format (may not have a comma)
        loss_match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+packets received,\s*([\d.]+)%\s+packet loss", output, re.IGNORECASE | re.DOTALL)
    if not loss_match: # Another Linux format (e.g., busybox ping)
        loss_match = re.search(r"(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss", output, re.IGNORECASE | re.DOTALL)


    if loss_match:
        packets_transmitted = loss_match.group(1)
        packets_received = loss_match.group(2)
        loss_percent = loss_match.group(3).strip() # Remove possible trailing spaces
    else:
        # If nothing is received at all, there may only be a 100% loss prompt
        if "100% packet loss" in output or "100% loss" in output:
             loss_percent = "100"
             packets_transmitted = str(ping_count) # Assume this many were attempted to be sent
             packets_received = "0"
        elif " 0% packet loss" in output or "0% loss" in output:
             # Even with 0% packet loss, try to extract sent/received counts
             tx_rx_match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+received", output, re.IGNORECASE | re.DOTALL)
             if not tx_rx_match:
                 tx_rx_match = re.search(r"Packets: Sent = (\d+), Received = (\d+)", output, re.IGNORECASE | re.DOTALL)
             if tx_rx_match:
                 packets_transmitted = tx_rx_match.group(1)
                 packets_received = tx_rx_match.group(2)
                 loss_percent = "0"
             else: # If even sent/received cannot be found, but it is indeed 0% packet loss
                 packets_transmitted = str(ping_count)
                 packets_received = str(ping_count)
                 loss_percent = "0"

    # Parse RTT (min/avg/max/stddev or mdev)
    rtt_match = re.search(r"min/avg/max/(?:stddev|mdev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", output, re.IGNORECASE | re.DOTALL)
    if not rtt_match: # Try Windows format (min/max/avg)
        rtt_match_win = re.search(r"Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms", output, re.IGNORECASE | re.DOTALL)
        if rtt_match_win:
             rtt_min = rtt_match_win.group(1)
             rtt_max = rtt_match_win.group(2)
             rtt_avg = rtt_match_win.group(3)
             rtt_mdev = "N/A" # Windows ping does not directly provide standard deviation

    if rtt_match:
        rtt_min = rtt_match.group(1)
        rtt_avg = rtt_match.group(2)
        rtt_max = rtt_match.group(3)
        rtt_mdev = rtt_match.group(4)

    # If nothing can be parsed and the output is not empty, return an error flag
    if loss_percent == "ERR" and packets_transmitted == "ERR" and output and "unknown host" not in output.lower() and "unreachable" not in output.lower():
        return "ERR", "ERR", "ERR", "N/A", "N/A", "N/A", "N/A", True # Return parse_error = True

    # Handle cases of complete inaccessibility
    if "unknown host" in output.lower() or "host unreachable" in output.lower() or "request timed out" in output.lower() and packets_transmitted == "ERR":
        packets_transmitted = str(ping_count)
        packets_received = "0"
        loss_percent = "100"
        rtt_min, rtt_avg, rtt_max, rtt_mdev = "N/A", "N/A", "N/A", "N/A"

    # Ensure uniform number format
    try:
        if loss_percent != "ERR" and loss_percent != "N/A":
            loss_percent = "{:.1f}".format(float(loss_percent)) # Keep one decimal place
    except ValueError:
        pass # If conversion fails, keep original

    return packets_transmitted, packets_received, loss_percent, rtt_min, rtt_avg, rtt_max, rtt_mdev, False # Return parse_error = False

def run_ping(target_ip, count, timeout):
    """Execute ping command and return its output and whether there was an execution error"""
    system = platform.system().lower()
    if system == "windows":
        # Windows ping: -n count, -w timeout (milliseconds)
        command = ['ping', '-n', str(count), '-w', str(int(timeout * 1000)), target_ip]
    else:
        # Linux/macOS ping: -c count, -W timeout (seconds)
        command = ['ping', '-c', str(count), '-W', str(timeout), target_ip]

    try:
        # Set Popen's locale to C to make the output English, which is easier to parse
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore', env={'LANG': 'C'})
        # Set a reasonable total timeout to prevent the ping command itself from freezing
        # For example, send count packets, wait at most timeout seconds for each, plus some extra time
        communicate_timeout = (count * timeout) + 5 # Add a 5-second buffer
        stdout, stderr = process.communicate(timeout=communicate_timeout)

        # Exit code > 1 usually indicates a serious error (e.g., unknown host, network unreachable)
        # Exit code 1 on Linux/macOS may indicate packet loss but with a response, this is not considered an execution error
        # Windows exit code 0 means success, non-zero means failure
        is_error = False
        if system == "windows":
            if process.returncode != 0:
                is_error = True
        else: # Linux/macOS
            if process.returncode > 1:
                 is_error = True

        if is_error:
             # Prioritize information in stderr, if empty, use stdout
             error_message = stderr.strip() if stderr.strip() else stdout.strip()
             if not error_message: error_message = f"Ping command failed with return code {process.returncode}"
             # For 'unknown host' or 'unreachable', the output may be in stdout
             if "unknown host" in stdout.lower() or "host unreachable" in stdout.lower():
                 error_message = stdout.strip()
             return f"Execution Error: {error_message}", True # Return execution error

        return stdout + stderr, False # Merge stdout and stderr, return no execution error
    except subprocess.TimeoutExpired:
        # If communicate times out, forcibly terminate the process
        try:
            process.kill()
            process.wait() # Wait for the process to terminate completely
        except OSError:
            pass # Process may have already ended
        return f"Execution Error: Ping command timed out after {communicate_timeout} seconds.", True
    except FileNotFoundError:
        return "Execution Error: 'ping' command not found. Please install it.", True
    except Exception as e:
        return f"Execution Error: An unexpected error occurred: {e}", True


def main():
    global keep_running
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <Target IP Address or Domain Name>")
        print("The script will run continuously. Press Ctrl+C to stop.")
        sys.exit(1)

    target_ip_or_domain = sys.argv[1]
    target_ip = target_ip_or_domain # Default to user input

    # Try to resolve the domain name to get the IP (if the input is a domain name), the log file name still uses the domain name
    try:
        target_ip = socket.gethostbyname(target_ip_or_domain)
        print(f"Will monitor domain: {target_ip_or_domain} (resolved to IP: {target_ip})")
    except socket.gaierror:
        # If resolution fails, check if it is an IP format
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(target_ip_or_domain):
            print(f"Error: Invalid target IP address or unresolvable domain name '{target_ip_or_domain}'")
            sys.exit(1)
        else:
            print(f"Will monitor IP: {target_ip}")
    except Exception as e:
         print(f"Error resolving target '{target_ip_or_domain}': {e}")
         sys.exit(1)

    # Use the original input (possibly a domain name) to generate the log file name to avoid special character issues
    log_file_prefix = re.sub(r'[^\w\-.]', '_', target_ip_or_domain) # Replace characters unsuitable for file names
    logger = setup_logging(log_file_prefix) # Set up logging using the processed name

    print(f"Starting continuous monitoring of {target_ip_or_domain} (IP: {target_ip}) ...")
    print(f"Logs will be recorded in: network_monitor_{log_file_prefix}.log")
    print("Press Ctrl+C to stop monitoring.")

    # Register signal handler function
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler) # Handle kill command

    while keep_running:
        start_time = time.time() # Record start time

        # Use the resolved IP address for pinging
        ping_output, execution_error = run_ping(target_ip, PING_COUNT, PING_TIMEOUT)

        if execution_error:
            # Log ping execution error, ensure timestamp is correct
            error_message = f"ERR  | ERR  | ERR       | N/A         | N/A         | N/A         | N/A         | {ping_output}"
            logger.error(error_message)
        else:
            tx, rx, loss, rtt_min, rtt_avg, rtt_max, rtt_mdev, parse_error = parse_ping_output(ping_output, PING_COUNT)

            if parse_error:
                 warning_message = f"Could not parse Ping output. Raw output (partial): {ping_output[:250].replace(chr(10),' ')}..."
                 logger.warning(warning_message)
                 log_message = f"PARSE_ERR | PARSE_ERR | ERR | N/A | N/A | N/A | N/A"
            else:
                # Format log message, add alignment
                log_message = (
                    f"{str(tx):<4} | "
                    f"{str(rx):<4} | "
                    f"{str(loss):>9} | " # Right-align packet loss rate
                    f"{str(rtt_min):>11} | " # Right-align RTT
                    f"{str(rtt_avg):>11} | "
                    f"{str(rtt_max):>11} | "
                    f"{str(rtt_mdev):>14}"
                )
            # Log info level logs normally
            logger.info(log_message)

        # Calculate the time spent in this loop
        elapsed_time = time.time() - start_time
        # Calculate the time to wait
        wait_time = max(0, INTERVAL_SECONDS - elapsed_time)

        # Segmented sleep to respond to interrupt signals in time
        sleep_end_time = time.time() + wait_time
        while keep_running and time.time() < sleep_end_time:
            # Check remaining time to avoid sleeping too long
            remaining_wait = sleep_end_time - time.time()
            sleep_interval = min(0.5, remaining_wait) # Sleep for a maximum of 0.5 seconds to check once
            if sleep_interval > 0:
                time.sleep(sleep_interval)

    # Execute cleanup or record end information after the loop ends
    print("Monitoring stopped.")
    logger.info(f"Monitoring stopped at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.shutdown() # Close log handler

if __name__ == "__main__":
    main()
