#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import re
import logging
import signal
import urllib.request
import socket
import subprocess
import platform
import argparse
from datetime import datetime

# --- Configuration ---
INTERVAL_SECONDS = 5     # Measurement interval in seconds
DNS_TIMEOUT = 5          # DNS resolution timeout in seconds
IP_FETCH_TIMEOUT = 5     # Timeout for fetching public IP in seconds
TARGET_DOMAIN = "google.com"  # Domain to resolve
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# --- Configuration End ---

# Global variable for signal handling
keep_running = True

def signal_handler(sig, frame):
    """Handle interrupt signal (Ctrl+C)"""
    global keep_running
    print("\nInterrupt signal received, stopping DNS monitoring...")
    keep_running = False

def get_public_ip():
    """Attempt to fetch the public IP address"""
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

def get_system_dns_servers():
    """Get system default DNS servers"""
    dns_servers = []
    try:
        if platform.system() == "Darwin":  # macOS
            result = subprocess.run(['scutil', '--dns'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'nameserver[0]' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            dns_ip = parts[1].strip()
                            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", dns_ip):
                                dns_servers.append(dns_ip)
        elif platform.system() == "Linux":
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) > 1:
                            dns_ip = parts[1].strip()
                            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", dns_ip):
                                dns_servers.append(dns_ip)
    except Exception as e:
        print(f"Warning: Could not get system DNS servers: {e}")
    
    # Deduplicate and return the first 3
    return list(dict.fromkeys(dns_servers))[:3]

def resolve_dns_with_server(domain, dns_server=None, use_tcp=False):
    """Resolve domain name using specified DNS server"""
    try:
        start_time = time.time()
        
        # If TCP is requested but no DNS server specified, get system default DNS
        if use_tcp and not dns_server:
            system_dns_servers = get_system_dns_servers()
            if system_dns_servers:
                dns_server = system_dns_servers[0]  # Use the first system DNS server
                print(f"TCP mode enabled, using system DNS server: {dns_server}")
            else:
                print("Warning: TCP mode requested but no system DNS server found, falling back to UDP")
                use_tcp = False
        
        if dns_server:
            # Use dig command for better TCP/UDP control
            if use_tcp:
                cmd = ['dig', '+tcp', f'@{dns_server}', domain, 'A']
            else:
                cmd = ['dig', '+notcp', f'@{dns_server}', domain, 'A']
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=DNS_TIMEOUT)
                dns_time = (time.time() - start_time) * 1000
                
                if result.returncode == 0:
                    # Parse dig output to get IP addresses
                    output = result.stdout
                    ip_addresses = []
                    
                    # Find IP addresses in ANSWER section
                    in_answer_section = False
                    for line in output.split('\n'):
                        if ';; ANSWER SECTION:' in line:
                            in_answer_section = True
                            continue
                        if in_answer_section and line.strip() and not line.startswith(';'):
                            if line.strip() == '':
                                break
                            parts = line.split()
                            if len(parts) >= 5 and parts[3] == 'A':
                                ip = parts[4].strip()
                                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
                                    ip_addresses.append(ip)
                    
                    if ip_addresses:
                        return f"{dns_time:.1f}", ip_addresses[0], "SUCCESS", ip_addresses
                    else:
                        return f"{dns_time:.1f}", "N/A", "NO_IP_FOUND", []

                else:
                    dns_time = (time.time() - start_time) * 1000
                    error_msg = result.stderr.strip() if result.stderr.strip() else "Unknown dig error"
                    return f"{dns_time:.1f}", "N/A", f"DIG_ERROR: {error_msg}", []
                    
            except subprocess.TimeoutExpired:
                dns_time = DNS_TIMEOUT * 1000
                return f"{dns_time:.1f}", "N/A", "TIMEOUT", []
            except Exception as e:
                dns_time = (time.time() - start_time) * 1000
                return f"{dns_time:.1f}", "N/A", f"ERROR: {str(e)}", []
        else:
            # Use system default DNS (always UDP for system calls)
            resolved_ip = socket.gethostbyname(domain)
            dns_time = (time.time() - start_time) * 1000
            
            # Get all IP addresses
            try:
                addr_info = socket.getaddrinfo(domain, None)
                ip_addresses = list(set([addr[4][0] for addr in addr_info if addr[0] == socket.AF_INET]))
            except:
                ip_addresses = [resolved_ip]
            
            return f"{dns_time:.1f}", resolved_ip, "SUCCESS", ip_addresses
            
    except socket.gaierror as e:
        dns_time = (time.time() - start_time) * 1000
        return f"{dns_time:.1f}", "N/A", f"DNS_ERROR: {str(e)}", []
    except Exception as e:
        dns_time = (time.time() - start_time) * 1000
        return f"{dns_time:.1f}", "N/A", f"ERROR: {str(e)}", []

def setup_logging(dns_server, use_tcp=False):
    """Configure logger"""
    # Clean DNS server name for filename
    if dns_server:
        clean_dns = re.sub(r'[^\w\-.]', '_', dns_server)
        protocol_suffix = "_tcp" if use_tcp else "_udp"
        log_filename = f"dns_monitor_{TARGET_DOMAIN}_{clean_dns}{protocol_suffix}.log"
    else:
        log_filename = f"dns_monitor_{TARGET_DOMAIN}_system.log"
    
    logger = logging.getLogger('DNSMonitor')
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create file handler
    fh = logging.FileHandler(log_filename, encoding='utf-8')
    fh.setLevel(logging.INFO)
    
    # Create log format
    formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)
    
    # Add handler to logger
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
        system_dns = get_system_dns_servers()
        
        logger.info(f"=== DNS Resolution Monitoring Log ===")
        logger.info(f"Target Domain: {TARGET_DOMAIN}")
        logger.info(f"DNS Server: {dns_server if dns_server else 'System Default'}")
        logger.info(f"Query Protocol: {'TCP' if use_tcp else 'UDP'}")
        if not dns_server and system_dns:
            logger.info(f"System DNS Servers: {', '.join(system_dns)}")
        logger.info(f"Server Source Public IP: {source_ip}")
        logger.info(f"Monitoring Started At: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Measurement Interval: {INTERVAL_SECONDS} seconds")
        logger.info(f"DNS Timeout: {DNS_TIMEOUT} seconds")
        logger.info("-" * 100)
        logger.info("Resolution Time(ms) | Resolved IP | All IP Addresses | Protocol | Status")
        logger.info("-" * 100)
    
    return logger, log_filename

def validate_dns_server(dns_server):
    """Validate DNS server address format"""
    if not dns_server:
        return True
    
    # Check if it is a valid IP address
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not ip_pattern.match(dns_server):
        return False
    
    # Check IP address range
    parts = dns_server.split('.')
    for part in parts:
        if int(part) > 255:
            return False
    
    return True

def test_dns_server_connectivity(dns_server):
    """Test DNS server connectivity"""
    if not dns_server:
        return True, "Using system default DNS"
    
    try:
        # Attempt to connect to DNS server's port 53
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.connect((dns_server, 53))
        sock.close()
        return True, "DNS server connectivity is normal"
    except Exception as e:
        return False, f"DNS server connectivity test failed: {str(e)}"

def main():
    global keep_running
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description=f'DNS Resolution Monitoring Tool - Target Domain: {TARGET_DOMAIN}')
    parser.add_argument('dns_server', nargs='?', help='DNS server IP address (optional, uses system default if not specified)')
    parser.add_argument('--tcp', action='store_true', help='Use TCP for DNS queries instead of UDP')
    
    args = parser.parse_args()
    
    print(f"DNS Resolution Monitoring Tool - Target Domain: {TARGET_DOMAIN}")
    print("Usage: python3 monitor_dns.py [DNS Server IP] [--tcp]")
    print("Examples:")
    print("  python3 monitor_dns.py                    # Use system default DNS with UDP")
    print("  python3 monitor_dns.py 8.8.8.8           # Use Google DNS with UDP")
    print("  python3 monitor_dns.py 8.8.8.8 --tcp     # Use Google DNS with TCP")
    print("  python3 monitor_dns.py --tcp             # Use system default DNS with TCP")
    print()
    
    dns_server = args.dns_server
    use_tcp = args.tcp
    
    # Validate DNS server address if provided
    if dns_server:
        if not validate_dns_server(dns_server):
            print(f"Error: Invalid DNS server address: {dns_server}")
            print("Please provide a valid IPv4 address, e.g., 8.8.8.8")
            sys.exit(1)
        
        # Test DNS server connectivity
        is_reachable, message = test_dns_server_connectivity(dns_server)
        print(f"DNS Server Test: {message}")
        if not is_reachable:
            print("Warning: DNS server may not be working correctly, but monitoring will continue.")
    
    # Check if dig command is available when using TCP
    if use_tcp and dns_server:
        try:
            subprocess.run(['dig', '-v'], capture_output=True, timeout=3)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("Error: 'dig' command is required for TCP queries but not found.")
            print("Please install dig (usually part of bind-utils or dnsutils package) or use UDP queries.")
            sys.exit(1)
    
    print(f"Starting DNS resolution monitoring: {TARGET_DOMAIN}")
    print(f"Using DNS Server: {dns_server if dns_server else 'System Default'}")
    print(f"Query Protocol: {'TCP' if use_tcp else 'UDP'}")
    
    # Display system DNS information
    if not dns_server:
        system_dns = get_system_dns_servers()
        if system_dns:
            print(f"System DNS Servers: {', '.join(system_dns)}")
        if use_tcp:
            print("Warning: TCP mode with system default DNS may not work as expected.")
    
    logger, log_filename = setup_logging(dns_server, use_tcp)
    print(f"Logs will be recorded in: {log_filename}")
    print("Press Ctrl+C to stop monitoring.")
    print()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Statistics
    total_queries = 0
    successful_queries = 0
    failed_queries = 0
    total_time = 0.0
    
    while keep_running:
        start_time = time.time()
        
        # DNS resolution
        dns_time, resolved_ip, status, all_ips = resolve_dns_with_server(TARGET_DOMAIN, dns_server, use_tcp)
        
        # Update statistics
        total_queries += 1
        if status == "SUCCESS":
            successful_queries += 1
            if dns_time != "N/A":
                total_time += float(dns_time)
        else:
            failed_queries += 1
        
        # Format all IP addresses
        all_ips_str = ", ".join(all_ips) if all_ips else "N/A"
        
        # Determine protocol for display and logging
        protocol = "TCP" if use_tcp else "UDP"
        
        # Display results
        if status == "SUCCESS":
            print(f"✓ DNS Resolution: {dns_time}ms | Main IP: {resolved_ip} | All IPs: [{all_ips_str}] | Protocol: {protocol} | Status: {status}")
        else:
            print(f"✗ DNS Resolution: {dns_time}ms | Main IP: {resolved_ip} | Protocol: {protocol} | Status: {status}")
        
        # Record log
        log_message = (
            f"{str(dns_time):>13} | "
            f"{str(resolved_ip):>15} | "
            f"{all_ips_str:>30} | "
            f"{protocol:>8} | "
            f"{status}"
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
    
    # Display statistics
    print("\n=== Monitoring Statistics ===")
    print(f"Total Queries: {total_queries}")
    print(f"Successful Queries: {successful_queries}")
    print(f"Failed Queries: {failed_queries}")
    if total_queries > 0:
        success_rate = (successful_queries / total_queries) * 100
        print(f"Success Rate: {success_rate:.2f}%")
    if successful_queries > 0:
        avg_time = total_time / successful_queries
        print(f"Average Resolution Time: {avg_time:.1f}ms")
    
    # Cleanup
    print("\nDNS monitoring stopped.")
    logger.info(f"Monitoring stopped at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Statistics - Total Queries: {total_queries}, Successful: {successful_queries}, Failed: {failed_queries}")
    if total_queries > 0:
        success_rate = (successful_queries / total_queries) * 100
        logger.info(f"Success Rate: {success_rate:.2f}%")
    if successful_queries > 0:
        avg_time = total_time / successful_queries
        logger.info(f"Average Resolution Time: {avg_time:.1f}ms")
    logging.shutdown()

if __name__ == "__main__":
    main()