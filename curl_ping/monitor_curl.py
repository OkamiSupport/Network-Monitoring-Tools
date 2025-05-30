#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import time
import re
import logging
import platform
import signal
import urllib.request
import socket
import json
from urllib.parse import urlparse

# --- Configuration ---
INTERVAL_SECONDS = 5     # Measurement interval (seconds)
CURL_TIMEOUT = 10        # curl request timeout (seconds)
DNS_TIMEOUT = 5          # DNS resolution timeout (seconds)
IP_FETCH_TIMEOUT = 5     # Timeout for fetching public IP (seconds)
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# --- Configuration End ---

# Global variable for signal handling
keep_running = True

def signal_handler(sig, frame):
    """Handle interrupt signal (Ctrl+C)"""
    global keep_running
    print("\nInterrupt signal received, stopping monitoring...")
    keep_running = False

def get_public_ip():
    """Attempt to get the public IP address"""
    urls = ["https://api.ipify.org", "https://ipinfo.io/ip", "https://checkip.amazonaws.com"]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req, timeout=IP_FETCH_TIMEOUT) as response:
                ip = response.read().decode('utf-8').strip()
                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
                    return ip
                else:
                    print(f"Warning: Fetched invalid IP format from {url}: {ip}")
                    continue
        except Exception as e:
            print(f"Warning: Could not fetch public IP from {url}: {e}")
    print("Warning: Failed to fetch public IP from all sources.")
    return "N/A"

def is_ip_address(target):
    """Check if the target is an IP address"""
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(target) is not None

def resolve_dns(hostname):
    """Resolve DNS and return resolution time and IP address"""
    if is_ip_address(hostname):
        return "N/A", hostname, "N/A"  # DNS time, Resolved IP, Status
    
    try:
        start_time = time.time()
        resolved_ip = socket.gethostbyname(hostname)
        dns_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        return f"{dns_time:.1f}", resolved_ip, "SUCCESS"
    except socket.gaierror as e:
        return "N/A", "N/A", f"DNS_ERROR: {str(e)}"
    except Exception as e:
        return "N/A", "N/A", f"ERROR: {str(e)}"

def normalize_url(target):
    """Normalize URL format"""
    if not target.startswith(('http://', 'https://')):
        # If it's an IP address, use http by default
        if is_ip_address(target):
            return f"http://{target}"
        else:
            # If it's a domain name, use https by default
            return f"https://{target}"
    return target

def run_curl(url):
    """Execute curl command and return detailed information"""
    # curl command parameters
    command = [
        'curl',
        '-s',  # Silent mode
        '-o', '/dev/null',  # Do not save response content
        '-w', json.dumps({
            'http_code': '%{http_code}',
            'time_total': '%{time_total}',
            'time_namelookup': '%{time_namelookup}',
            'time_connect': '%{time_connect}',
            'time_pretransfer': '%{time_pretransfer}',
            'time_starttransfer': '%{time_starttransfer}',
            'size_download': '%{size_download}',
            'speed_download': '%{speed_download}'
        }),
        '--max-time', str(CURL_TIMEOUT),
        '--connect-timeout', str(CURL_TIMEOUT),
        '--user-agent', USER_AGENT,
        '--location',  # Follow redirects
        '--insecure',  # Ignore SSL certificate errors
        '--http2',  # Force HTTP/2 to avoid QUIC
        url
    ]
    
    try:
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding='utf-8'
        )
        stdout, stderr = process.communicate(timeout=CURL_TIMEOUT + 5)
        
        if process.returncode == 0:
            try:
                # Parse curl output
                curl_stats = json.loads(stdout.strip())
                return {
                    'success': True,
                    'http_code': curl_stats['http_code'],
                    'total_time': float(curl_stats['time_total']) * 1000,  # Convert to milliseconds
                    'dns_time': float(curl_stats['time_namelookup']) * 1000,
                    'connect_time': float(curl_stats['time_connect']) * 1000,
                    'transfer_time': float(curl_stats['time_starttransfer']) * 1000,
                    'size': int(float(curl_stats['size_download'])),
                    'speed': float(curl_stats['speed_download']),
                    'error': None
                }
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                return {
                    'success': False,
                    'error': f"PARSE_ERROR: {str(e)}",
                    'raw_output': stdout[:200]
                }
        else:
            # curl execution failed
            error_msg = stderr.strip() if stderr.strip() else "Unknown curl error"
            
            # Identify common error types
            if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                error_type = "TIMEOUT"
            elif "could not resolve host" in error_msg.lower():
                error_type = "DNS_ERROR"
            elif "connection refused" in error_msg.lower():
                error_type = "CONNECTION_REFUSED"
            elif "ssl" in error_msg.lower() or "certificate" in error_msg.lower():
                error_type = "SSL_ERROR"
            else:
                error_type = "NETWORK_ERROR"
            
            return {
                'success': False,
                'error': f"{error_type}: {error_msg}",
                'return_code': process.returncode
            }
            
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait()
        except OSError:
            pass
        return {
            'success': False,
            'error': f"TIMEOUT: curl command timed out after {CURL_TIMEOUT + 5} seconds"
        }
    except FileNotFoundError:
        return {
            'success': False,
            'error': "ERROR: 'curl' command not found. Please install curl."
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"ERROR: An unexpected error occurred: {e}"
        }

def setup_logging(target):
    """Configure logger"""
    # Clean target name for filename
    clean_target = re.sub(r'[^\w\-.]', '_', target.replace('://', '_').replace('/', '_'))
    log_filename = f"curl_monitor_{clean_target}.log"
    
    logger = logging.getLogger('CurlMonitor')
    logger.setLevel(logging.INFO)
    
    # Create file handler
    fh = logging.FileHandler(log_filename, encoding='utf-8')
    fh.setLevel(logging.INFO)
    
    # Create log format
    formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)
    
    # Add handler to logger
    if not logger.hasHandlers():
        logger.addHandler(fh)
    
    # Check if log file is empty, write header if it is
    try:
        with open(log_filename, 'r', encoding='utf-8') as f:
            f.seek(0, 2)
            if f.tell() == 0:
                raise FileNotFoundError
    except (FileNotFoundError, IOError):
        # File does not exist or is empty, write header information
        source_ip = get_public_ip()
        logger.info(f"=== CURL Network Monitoring Log ===")
        logger.info(f"Target URL: {target}")
        logger.info(f"Server Source Public IP: {source_ip}")
        logger.info(f"Monitoring Started At: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Measurement Interval: {INTERVAL_SECONDS} seconds")
        logger.info(f"CURL Timeout: {CURL_TIMEOUT} seconds")
        logger.info(f"User-Agent: {USER_AGENT}")
        logger.info("-" * 120)
        logger.info("DNS Resolution(ms) | Resolved IP | HTTP Status Code | Total Time(ms) | Connect Time(ms) | Transfer Time(ms) | Response Size(B) | Status")
        logger.info("-" * 120)
    
    return logger, log_filename

def main():
    global keep_running
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <Target URL or Domain or IP Address>")
        print("Examples:")
        print(f"  {sys.argv[0]} https://www.google.com")
        print(f"  {sys.argv[0]} www.baidu.com")
        print(f"  {sys.argv[0]} 8.8.8.8")
        print("The script will run continuously. Press Ctrl+C to stop.")
        sys.exit(1)
    
    target = sys.argv[1]
    url = normalize_url(target)
    
    # Parse URL to get hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.netloc
    
    print(f"Starting continuous monitoring for: {target}")
    print(f"Normalized URL: {url}")
    
    logger, log_filename = setup_logging(target)
    print(f"Logs will be recorded in: {log_filename}")
    print("Press Ctrl+C to stop monitoring.")
    print()
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    while keep_running:
        start_time = time.time()
        
        # DNS resolution (if needed)
        dns_time, resolved_ip, dns_status = resolve_dns(hostname)
        
        # Execute curl request
        curl_result = run_curl(url)
        
        # Format output and log
        if curl_result['success']:
            http_code = curl_result['http_code']
            total_time = curl_result['total_time']
            connect_time = curl_result['connect_time']
            transfer_time = curl_result['transfer_time']
            size = curl_result['size']
            
            # Check if HTTP status code indicates success
            if http_code.startswith('2') or http_code.startswith('3'):
                status = "SUCCESS"
                print(f"✓ DNS: {dns_time}ms | IP: {resolved_ip} | HTTP: {http_code} | Total Time: {total_time:.1f}ms | Connect: {connect_time:.1f}ms | Size: {size}B")
            else:
                status = f"HTTP_ERROR_{http_code}"
                print(f"✗ DNS: {dns_time}ms | IP: {resolved_ip} | HTTP: {http_code} | Total Time: {total_time:.1f}ms | Status: HTTP Error")
            
            # Record log
            log_message = (
                f"{str(dns_time):>11} | "
                f"{str(resolved_ip):>15} | "
                f"{str(http_code):>10} | "
                f"{total_time:>10.1f} | "
                f"{connect_time:>12.1f} | "
                f"{transfer_time:>12.1f} | "
                f"{size:>11} | "
                f"{status}"
            )
        else:
            error = curl_result['error']
            print(f"✗ DNS: {dns_time}ms | IP: {resolved_ip} | Error: {error}")
            
            # Record error log
            log_message = (
                f"{str(dns_time):>11} | "
                f"{str(resolved_ip):>15} | "
                f"{'N/A':>10} | "
                f"{'N/A':>10} | "
                f"{'N/A':>12} | "
                f"{'N/A':>12} | "
                f"{'N/A':>11} | "
                f"{error}"
            )
        
        logger.info(log_message)
        
        # Calculate wait time
        elapsed_time = time.time() - start_time
        wait_time = max(0, INTERVAL_SECONDS - elapsed_time)
        
        # Segmented sleep to respond to interrupt signals promptly
        sleep_end_time = time.time() + wait_time
        while keep_running and time.time() < sleep_end_time:
            remaining_wait = sleep_end_time - time.time()
            sleep_interval = min(0.5, remaining_wait)
            if sleep_interval > 0:
                time.sleep(sleep_interval)
    
    # Cleanup
    print("\nMonitoring stopped.")
    logger.info(f"Monitoring stopped at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.shutdown()

if __name__ == "__main__":
    main()