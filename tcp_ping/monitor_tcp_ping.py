#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import re
import logging
import signal
import urllib.request
import socket
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
TCP_CONNECT_COUNT = 10   # Number of TCP connection attempts per measurement cycle
INTERVAL_SECONDS = 5     # Measurement interval time (seconds)
TCP_TIMEOUT = 2          # Timeout for a single TCP connection attempt (seconds)
IP_FETCH_TIMEOUT = 5     # Timeout for fetching public IP (seconds)
DEFAULT_PORT = 80        # Default port to test if not specified
MAX_CONCURRENT = 5       # Maximum concurrent connection attempts
# --- Configuration End ---

# Global variable for signal handling
keep_running = True

def signal_handler(sig, frame):
    """Handle interrupt signal (Ctrl+C)"""
    global keep_running
    print("\nInterrupt signal received, stopping monitoring...")
    keep_running = False

def get_public_ip():
    """Try to get the public IP address from multiple sources"""
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

def setup_logging(target_host, target_port):
    """Configure logger"""
    log_filename = f"tcp_monitor_{target_host.replace('.', '_')}_{target_port}.log"
    logger = logging.getLogger('TCPMonitor')
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
         source_ip = get_public_ip()
         logger.info(f"=== TCP Connection Monitoring Log ===")
         logger.info(f"Target Host: {target_host}")
         logger.info(f"Target Port: {target_port}")
         logger.info(f"Server Source Public IP: {source_ip}")
         logger.info(f"Monitoring started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
         logger.info(f"TCP connection attempts per measurement: {TCP_CONNECT_COUNT}")
         logger.info(f"Measurement interval: {INTERVAL_SECONDS} seconds")
         logger.info(f"TCP connection timeout: {TCP_TIMEOUT} seconds")
         logger.info("-" * 80)
         logger.info("Attempted | Success | Failure | Success(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev RTT(ms)")
         logger.info("-" * 80)

    return logger

def tcp_connect_single(target_ip, target_port, timeout):
    """Perform a single TCP connection attempt and return (success, rtt_ms, error_msg)"""
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, target_port))
        end_time = time.time()
        sock.close()
        
        rtt_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        
        if result == 0:
            return True, rtt_ms, None
        else:
            return False, None, f"Connection failed with error code {result}"
            
    except socket.timeout:
        return False, None, "Connection timeout"
    except socket.gaierror as e:
        return False, None, f"DNS resolution error: {e}"
    except Exception as e:
        return False, None, f"Unexpected error: {e}"

def run_tcp_ping(target_ip, target_port, count, timeout):
    """Execute multiple TCP connection attempts and return statistics"""
    successful_connections = 0
    failed_connections = 0
    rtt_times = []
    error_messages = []
    
    # Use ThreadPoolExecutor for concurrent connections
    with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT, count)) as executor:
        # Submit all connection attempts
        futures = [executor.submit(tcp_connect_single, target_ip, target_port, timeout) for _ in range(count)]
        
        # Collect results
        for future in as_completed(futures):
            try:
                success, rtt, error_msg = future.result()
                if success:
                    successful_connections += 1
                    rtt_times.append(rtt)
                else:
                    failed_connections += 1
                    if error_msg:
                        error_messages.append(error_msg)
            except Exception as e:
                failed_connections += 1
                error_messages.append(f"Future execution error: {e}")
    
    # Calculate statistics
    total_attempts = successful_connections + failed_connections
    success_rate = (successful_connections / total_attempts * 100) if total_attempts > 0 else 0
    
    if rtt_times:
        min_rtt = min(rtt_times)
        avg_rtt = statistics.mean(rtt_times)
        max_rtt = max(rtt_times)
        stddev_rtt = statistics.stdev(rtt_times) if len(rtt_times) > 1 else 0
    else:
        min_rtt = avg_rtt = max_rtt = stddev_rtt = None
    
    return {
        'attempted': total_attempts,
        'successful': successful_connections,
        'failed': failed_connections,
        'success_rate': success_rate,
        'min_rtt': min_rtt,
        'avg_rtt': avg_rtt,
        'max_rtt': max_rtt,
        'stddev_rtt': stddev_rtt,
        'error_messages': error_messages
    }

def format_rtt_value(value):
    """Format RTT value for display"""
    if value is None:
        return "N/A"
    return f"{value:.2f}"

def main():
    global keep_running
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <Target IP/Domain> [Port]")
        print(f"Example: {sys.argv[0]} google.com 80")
        print(f"Example: {sys.argv[0]} 8.8.8.8 53")
        print("The script will run continuously. Press Ctrl+C to stop.")
        sys.exit(1)

    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    
    # Validate port range
    if not (1 <= target_port <= 65535):
        print(f"Error: Port must be between 1 and 65535, got {target_port}")
        sys.exit(1)

    # Try to resolve the domain name to get the IP
    try:
        target_ip = socket.gethostbyname(target_host)
        if target_host != target_ip:
            print(f"Will monitor domain: {target_host} (resolved to IP: {target_ip}) on port {target_port}")
        else:
            print(f"Will monitor IP: {target_ip} on port {target_port}")
    except socket.gaierror:
        # If resolution fails, check if it is an IP format
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(target_host):
            print(f"Error: Invalid target IP address or unresolvable domain name '{target_host}'")
            sys.exit(1)
        else:
            target_ip = target_host
            print(f"Will monitor IP: {target_ip} on port {target_port}")
    except Exception as e:
         print(f"Error resolving target '{target_host}': {e}")
         sys.exit(1)

    # Use the original input (possibly a domain name) to generate the log file name
    log_file_prefix = re.sub(r'[^\w\-.]', '_', target_host)
    logger = setup_logging(log_file_prefix, target_port)

    print(f"Starting continuous TCP connection monitoring of {target_host}:{target_port} (IP: {target_ip}) ...")
    print(f"Logs will be recorded in: tcp_monitor_{log_file_prefix}_{target_port}.log")
    print("Press Ctrl+C to stop monitoring.")

    # Register signal handler function
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler) # Handle kill command

    while keep_running:
        start_time = time.time() # Record start time

        # Perform TCP connection attempts
        try:
            results = run_tcp_ping(target_ip, target_port, TCP_CONNECT_COUNT, TCP_TIMEOUT)
            
            # Format log message with alignment
            log_message = (
                f"{results['attempted']:<9} | "
                f"{results['successful']:<7} | "
                f"{results['failed']:<7} | "
                f"{results['success_rate']:>10.1f} | "
                f"{format_rtt_value(results['min_rtt']):>11} | "
                f"{format_rtt_value(results['avg_rtt']):>11} | "
                f"{format_rtt_value(results['max_rtt']):>11} | "
                f"{format_rtt_value(results['stddev_rtt']):>14}"
            )
            
            logger.info(log_message)
            
            # Log error messages if any (but not too many to avoid log spam)
            if results['error_messages'] and results['failed'] > 0:
                unique_errors = list(set(results['error_messages'][:5]))  # Limit to 5 unique errors
                for error in unique_errors:
                    logger.warning(f"Connection error: {error}")
                    
        except Exception as e:
            error_message = f"ERR       | ERR     | ERR     | ERR        | N/A         | N/A         | N/A         | N/A           | Execution Error: {e}"
            logger.error(error_message)

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