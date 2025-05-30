#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import argparse
import time
import statistics # For calculating averages and standard deviation
import logging
import os
import struct # For packing and unpacking header data
import sys
from datetime import datetime
import math # For handling NaN values

# --- Configuration Constants ---
DEFAULT_PORT = 9999
# DEFAULT_COUNT is no longer the number of packets in periodic mode, only a conceptual marker when -n is not specified
# DEFAULT_COUNT = 10
DEFAULT_INTERVAL = 1.0    # Interval between Ping packets (seconds)
DEFAULT_SUMMARY_INTERVAL = 10.0 # Interval for recording summary logs (seconds)
DEFAULT_TIMEOUT = 1.0
DEFAULT_PAYLOAD_SIZE = 64
HEADER_FORMAT = '!Qd'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

logger = None
log_filepath = None

# --- Helper Functions (Unchanged) ---
def create_packet(seq_num, payload_size):
    timestamp = time.time()
    header = struct.pack(HEADER_FORMAT, seq_num, timestamp)
    padding_size = payload_size - HEADER_SIZE
    if padding_size < 0:
        padding_size = 0
    padding = b'P' * padding_size
    return header + padding

def unpack_packet(data):
    if len(data) < HEADER_SIZE:
        raise ValueError("Received packet is too small to contain a full header")
    seq_num, timestamp = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    return seq_num, timestamp, data[HEADER_SIZE:]

# --- Server Mode (Unchanged, No Logging) ---
def run_server(host, port, buffer_size):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((host, port))
        print(f"UDP Ping server listening on {host}:{port}...")
        while True:
            try:
                message, address = server_socket.recvfrom(buffer_size)
                reply_packet = message
                server_socket.sendto(reply_packet, address)
            except ValueError as e:
                print(f"Server error (from {address}): Unpack error - {e}", file=sys.stderr)
            except socket.error as e:
                print(f"Server Socket error: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Server encountered an unexpected error: {e}", file=sys.stderr)
    except socket.error as e:
        print(f"Error: Server failed to bind to {host}:{port} - {e}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    finally:
        server_socket.close()
        print("Server socket closed.")

# --- Client Mode ---
def setup_client_logger(target_host, target_port):
    """Configure client logger"""
    global logger, log_filepath
    safe_target_host = target_host.replace(':', '_').replace('/', '_')
    log_filename = f"udp_ping_client_{safe_target_host}_{target_port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_filename)
    logger = logging.getLogger(f'udp_ping_client_{target_host}_{target_port}')
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        log_formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)

    print(f"Detailed logs will be recorded to: {log_filepath}")
    return True

def write_log_header(host, port, packets_per_run_arg, interval, payload_size, timeout, summary_interval, calculated_packets_per_cycle):
    """Write header information and table headers to the log file"""
    global logger
    start_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info("=" * 90)
    logger.info(f"UDP Ping Monitoring Log")
    logger.info(f"Target IP: {host}")
    logger.info(f"Target Port: {port}")
    logger.info(f"Monitoring started at: {start_time_str}")
    if packets_per_run_arg is None: # Periodic mode
        logger.info(f"Packets per measurement: {calculated_packets_per_cycle} (calculated from summary interval and Ping interval)")
        logger.info(f"Log summary interval (seconds): {summary_interval}")
    else: # Single run mode
         logger.info(f"Packets in this run: {packets_per_run_arg} (specified by -n)")
    logger.info(f"Ping interval (seconds): {interval}")
    logger.info(f"Ping payload size (bytes): {payload_size}")
    logger.info(f"Ping timeout (seconds): {timeout}")
    logger.info("-" * 90)

    col_sent = 5; col_recv = 5; col_loss = 10; col_min = 12; col_avg = 12; col_max = 12; col_std = 12; col_jit = 12; col_siz = 12
    header_line = (f"{'Sent':<{col_sent}} | {'Recv':<{col_recv}} | {'Loss(%)':<{col_loss}} | "
                   f"{'Min RTT(ms)':<{col_min}} | {'Avg RTT(ms)':<{col_avg}} | {'Max RTT(ms)':<{col_max}} | "
                   f"{'StdDev(ms)':<{col_std}} | {'Jitter(ms)':<{col_jit}} | "
                   f"{'Size(bytes)':<{col_siz}}")
    logger.info(header_line)
    total_width = col_sent + col_recv + col_loss + col_min + col_avg + col_max + col_std + col_jit + col_siz + (8 * 3)
    logger.info("-" * total_width)

def log_batch_stats(sent, received, loss_percent, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, size):
    """Format and write single batch statistics to log"""
    global logger
    col_sent = 5; col_recv = 5; col_loss = 10; col_min = 12; col_avg = 12; col_max = 12; col_std = 12; col_jit = 12; col_siz = 12

    def format_float(value, width, precision):
        if math.isnan(value): return f"{'nan':>{width}}"
        return f"{value:>{width}.{precision}f}"

    log_line = (f"{sent:>{col_sent}} | {received:>{col_recv}} | {loss_percent:>{col_loss}.1f} | "
                f"{format_float(rtt_min, col_min, 3)} | {format_float(rtt_avg, col_avg, 3)} | {format_float(rtt_max, col_max, 3)} | "
                f"{format_float(rtt_stdev, col_std, 3)} | {format_float(jitter, col_jit, 3)} | "
                f"{size:>{col_siz}}")
    logger.info(log_line)

def _perform_ping_batch(target_addr, batch_count, interval, timeout, payload_size, buffer_size, verbose):
    """Perform a round of Ping tests containing batch_count packets"""
    # (The internal logic of this function is basically the same as v4, no modification needed)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(timeout)
    results = {'sent': 0, 'received': 0, 'rtts': [], 'errors': 0}
    sent_timestamps = {}
    ping_batch_start_time = time.time()

    if verbose: print(f"  Starting to send {batch_count} packets...")

    for seq in range(1, batch_count + 1):
        current_loop_time = time.time()
        results['sent'] += 1
        packet = create_packet(seq, payload_size)
        send_time = time.time()
        sent_timestamps[seq] = send_time

        try:
            client_socket.sendto(packet, target_addr)

            try:
                reply_data, server_address = client_socket.recvfrom(buffer_size)
                recv_time = time.time()
                if server_address[0] == target_addr[0]:
                    try:
                        reply_seq, original_timestamp, _ = unpack_packet(reply_data)
                        if reply_seq == seq:
                            if seq in sent_timestamps:
                                rtt = (recv_time - original_timestamp) * 1000
                                results['received'] += 1
                                results['rtts'].append(rtt)
                                if verbose: print(f"    Reply from {server_address[0]}: seq={seq} time={rtt:.3f} ms")
                                del sent_timestamps[seq]
                    except ValueError as e:
                         if verbose: print(f"    Warning: Error unpacking reply: {e}", file=sys.stderr)
                         results['errors'] += 1
                         if seq in sent_timestamps: del sent_timestamps[seq]
            except socket.timeout:
                if verbose: print(f"    Request timed out (seq={seq})")
            except socket.error as e:
                 if verbose: print(f"    Warning: Error receiving: {e}", file=sys.stderr)
                 results['errors'] += 1
                 if seq in sent_timestamps: del sent_timestamps[seq]
        except socket.error as e:
            if verbose: print(f"    Error: Failed to send SEQ={seq}: {e}", file=sys.stderr)
            results['errors'] += 1
            if seq in sent_timestamps: del sent_timestamps[seq]

        if seq < batch_count:
            elapsed_since_send = time.time() - send_time
            sleep_time = interval - elapsed_since_send
            if sleep_time > 0:
                time.sleep(sleep_time)

    client_socket.close()
    ping_batch_duration = time.time() - ping_batch_start_time

    sent = results['sent']
    received = results['received']
    lost = sent - received
    loss_percent = (lost / sent) * 100 if sent > 0 else 0
    rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter = math.nan, math.nan, math.nan, math.nan, math.nan

    if results['rtts']:
        rtt_min = min(results['rtts'])
        rtt_max = max(results['rtts'])
        rtt_avg = statistics.mean(results['rtts'])
        if len(results['rtts']) > 1:
            rtt_stdev = statistics.stdev(results['rtts'])
            rtt_diffs = [abs(results['rtts'][i] - results['rtts'][i-1]) for i in range(1, len(results['rtts']))]
            jitter = statistics.mean(rtt_diffs) if rtt_diffs else 0.0
        else:
            rtt_stdev = 0.0; jitter = 0.0

    if verbose: print(f"  This Ping round ({batch_count} packets) completed, duration: {ping_batch_duration:.3f} s, loss rate: {loss_percent:.1f}%")

    return results, loss_percent, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, ping_batch_duration


def run_client(host, port, count_arg, interval, timeout, payload_size, buffer_size, summary_interval, verbose):
    """Run UDP Ping client (supports single run or periodic monitoring)"""
    global logger, log_filepath

    try:
        target_addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        target_addr = target_addr_info[0][4]
        target_ip = target_addr[0]
    except socket.gaierror as e:
        print(f"Error: Cannot resolve target host '{host}' - {e}", file=sys.stderr); return
    except Exception as e:
        print(f"Error: Unknown error occurred while setting target address - {e}", file=sys.stderr); return

    if not setup_client_logger(target_ip, port):
         print("Error: Failed to initialize logger.", file=sys.stderr); return

    run_once = count_arg is not None
    packets_per_batch = count_arg # Use specified count in single run mode
    calculated_packets_per_cycle = None # Calculated value in periodic mode

    if not run_once:
        # --- Periodic monitoring mode ---
        if interval <= 0:
             print("Error: Ping interval -i must be positive, especially in periodic mode.", file=sys.stderr)
             return
        calculated_packets_per_cycle = max(1, int(summary_interval / interval))
        packets_per_batch = calculated_packets_per_cycle # Use calculated packet count in periodic mode

    # Write log header
    write_log_header(target_ip, port, count_arg, interval, payload_size, timeout, summary_interval if not run_once else math.nan, calculated_packets_per_cycle)

    try:
        if run_once:
            # --- Single run mode ---
            if verbose: print(f"Starting single Ping -> {target_ip}:{port} ({count_arg} times)...")
            results, loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, duration = _perform_ping_batch(target_addr, count_arg, interval, timeout, payload_size, buffer_size, verbose)
            log_batch_stats(results['sent'], results['received'], loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, payload_size)
            print(f"Statistics recorded to: {log_filepath}")

        else:
            # --- Periodic monitoring mode ---
            print(f"Starting periodic Ping monitoring -> {target_ip}:{port} (measure {packets_per_batch} times every ~{summary_interval}s, press Ctrl+C to stop)")
            while True:
                cycle_start_time = time.time()
                if verbose: print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting new periodic Ping round ({packets_per_batch} times)...")

                results, loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, duration = _perform_ping_batch(target_addr, packets_per_batch, interval, timeout, payload_size, buffer_size, verbose)

                log_batch_stats(results['sent'], results['received'], loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, payload_size)

                # No sleep needed in periodic mode, as _perform_ping_batch duration determines the cycle
                # If execution time < summary_interval, next round starts immediately, higher logging frequency
                # If execution time > summary_interval, next round starts after completion, lower logging frequency
                # This aligns more with "send as many packets as possible within a window"
                # More complex logic needed for strict summary_interval *start* time triggering

    except KeyboardInterrupt:
        print("\nMonitoring interrupted, exiting...")
    except Exception as e:
        print(f"\nClient encountered a critical error, exiting: {e}", file=sys.stderr)
        if logger: logger.error(f"Client encountered a critical error: {e}", exc_info=True)
    finally:
        print(f"Monitoring finished. Log file located at: {log_filepath}")
        if logger:
            handlers = logger.handlers[:]
            for handler in handlers:
                handler.close(); logger.removeHandler(handler)

# --- Main program entry point (Unchanged) ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Ping Tool v5 - Periodic monitoring or single run, fills period by interval.")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-s', '--server', action='store_true', help="Run in server mode (no logging)")
    mode_group.add_argument('-c', '--client', metavar='TARGET_HOST', help="Run in client mode, specify target host IP or domain name")
    parser.add_argument('-H', '--host', default='0.0.0.0', help="Server binding host address (default: 0.0.0.0)")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help=f"UDP port number (default: {DEFAULT_PORT})")
    parser.add_argument('-b', '--buffer', type=int, default=1024, help="Receive buffer size (bytes, default: 1024)")
    parser.add_argument('-n', '--count', type=int, default=None, metavar='N',
                        help="Number of pings to send (specifying count runs once then exits, default: infinite loop monitoring)")
    parser.add_argument('-i', '--interval', type=float, default=DEFAULT_INTERVAL, metavar='SEC',
                        help=f"Wait interval between pings (seconds, default: {DEFAULT_INTERVAL})")
    parser.add_argument('-t', '--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SEC',
                        help=f"Wait timeout for each reply (seconds, default: {DEFAULT_TIMEOUT})")
    parser.add_argument('-S', '--size', type=int, default=DEFAULT_PAYLOAD_SIZE, metavar='BYTES',
                        help=f"Total size of packet to send (bytes, default: {DEFAULT_PAYLOAD_SIZE})")
    parser.add_argument('-I', '--summary-interval', type=float, default=DEFAULT_SUMMARY_INTERVAL, metavar='SEC',
                        help=f"Log summary interval (seconds, used in periodic monitoring to calculate packets per measurement, default: {DEFAULT_SUMMARY_INTERVAL})")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose console output for client (not logged)")

    args = parser.parse_args()

    if args.client:
        if args.count is not None and args.count <= 0:
             print(f"Error: -n/--count specified count ({args.count}) must be a positive integer.", file=sys.stderr); sys.exit(1)
        if args.size < HEADER_SIZE:
            print(f"Error: Specified packet size ({args.size}) is smaller than header size ({HEADER_SIZE}).", file=sys.stderr); sys.exit(1)
        if args.summary_interval <= 0:
             print(f"Error: Log summary interval -I/--summary-interval ({args.summary_interval}) must be positive.", file=sys.stderr); sys.exit(1)
        if args.interval <= 0 and args.count is None: # Interval must be > 0 in periodic mode
            print(f"Error: In periodic monitoring mode, Ping interval -i ({args.interval}) must be positive.", file=sys.stderr); sys.exit(1)


    if args.server:
        run_server(args.host, args.port, args.buffer)
    elif args.client:
        run_client(args.client, args.port, args.count, args.interval, args.timeout, args.size, args.buffer, args.summary_interval, args.verbose)
