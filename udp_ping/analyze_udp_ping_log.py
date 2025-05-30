#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
from datetime import datetime
import statistics
import socket
import time
import os
import math # Needed for isnan

# --- Configurable Thresholds (Fixed Thresholds - as fallback options) ---
# Packet loss threshold
HIGH_LOSS_THRESHOLD = 1.0 # (%)
# Latency threshold
HIGH_LATENCY_THRESHOLD = 100.0 # Fixed average RTT threshold (ms)
# Jitter threshold (multiple metrics)
HIGH_JITTER_THRESHOLD_DIRECT = 50.0 # Fixed direct Jitter value threshold (ms) - from the last column of the log
HIGH_JITTER_THRESHOLD_STDDEV = 50.0 # Fixed Jitter StdDev value threshold (ms) - from the second to last column of the log
HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO = 3.0 # Fixed Jitter Max/Avg ratio threshold

# --- Dynamic Baseline Calculation Parameters ---
MAX_BASELINE_CANDIDATES = 100 # Maximum number of initial records to use for baseline calculation
MIN_BASELINE_SAMPLES = 20    # Minimum number of stable samples required to calculate baseline
STABLE_LOSS_THRESHOLD = 0.5  # Upper limit of packet loss rate for defining a stable record (%)

# --- Dynamic Threshold Calculation Parameters ---
# Latency
DYNAMIC_LATENCY_FACTOR = 1.5   # Average RTT baseline multiplier
DYNAMIC_LATENCY_OFFSET = 10.0  # Fixed RTT offset (ms)
MIN_DYNAMIC_LATENCY_THRESHOLD = 30.0 # Minimum dynamically calculated latency threshold (ms)
# Jitter (Direct Value)
DYNAMIC_JITTER_DIRECT_FACTOR = 2.0 # Direct Jitter baseline multiplier
DYNAMIC_JITTER_DIRECT_OFFSET = 5.0 # Direct Jitter fixed offset (ms)
MIN_DYNAMIC_JITTER_DIRECT_THRESHOLD = 15.0 # Minimum dynamically calculated direct Jitter threshold (ms)
# Jitter (Standard Deviation)
DYNAMIC_JITTER_STDDEV_FACTOR = 2.0 # StdDev Jitter baseline multiplier
DYNAMIC_JITTER_RTT_RATIO = 0.3   # StdDev ratio to average RTT factor
MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD = 10.0 # Minimum dynamically calculated StdDev Jitter threshold (ms)
# DYNAMIC_JITTER_MAX_AVG_RATIO remains fixed

# --- Functions to get system information (Unchanged) ---
def get_hostname():
    try: return socket.gethostname()
    except socket.error as e: print(f"Warning: Unable to get hostname: {e}", file=sys.stderr); return "Unknown (Unable to fetch)"

def get_timezone_info():
    # (Code is the same as the previous version, remains unchanged)
    try:
        tz_name = datetime.now().astimezone().tzname()
        if tz_name and not re.match(r"^[+-]\d{2}$", tz_name) and tz_name.upper() != 'UTC':
             is_dst = time.daylight and time.localtime().tm_isdst > 0
             offset_seconds = -time.timezone if not is_dst else -time.altzone
             offset_hours = offset_seconds / 3600
             sign = "+" if offset_hours >= 0 else "-"
             offset_str = f"UTC{sign}{int(abs(offset_hours)):02d}:{int(abs(offset_seconds) % 3600 / 60):02d}"
             return f"{tz_name} ({offset_str})"
    except Exception: pass
    try:
        is_dst = time.daylight and time.localtime().tm_isdst > 0
        current_tz_name = time.tzname[1] if is_dst else time.tzname[0]
        offset_seconds = -time.timezone if not is_dst else -time.altzone
        offset_hours = offset_seconds / 3600
        sign = "+" if offset_hours >= 0 else "-"
        offset_str = f"UTC{sign}{int(abs(offset_hours)):02d}:{int(abs(offset_seconds) % 3600 / 60):02d}"
        if current_tz_name and current_tz_name != 'UTC': return f"{current_tz_name} ({offset_str})"
        else: return offset_str
    except Exception as e: print(f"Warning: Unable to get timezone information: {e}", file=sys.stderr); return "Unknown (Unable to fetch)"

# --- Function to parse UDP Ping log lines ---
def parse_udp_log_line(line):
    """Parse data lines from UDP Ping log"""
    # Regex to match log data line format
    # Timestamp | Sent | Received | Loss(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev(ms) | Jitter(ms) | Size(bytes)
    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s*\|\s*" # 1: Timestamp
        r"(\d+)\s*\|\s*"                                   # 2: Sent
        r"(\d+)\s*\|\s*"                                   # 3: Received
        r"([\d.]+)\s*\|\s*"                                # 4: Loss %
        r"([\d.nan]+)\s*\|\s*"                             # 5: Min RTT (allow 'nan')
        r"([\d.nan]+)\s*\|\s*"                             # 6: Avg RTT (allow 'nan')
        r"([\d.nan]+)\s*\|\s*"                             # 7: Max RTT (allow 'nan')
        r"([\d.nan]+)\s*\|\s*"                             # 8: StdDev RTT (allow 'nan')
        r"([\d.nan]+)\s*\|\s*"                             # 9: Jitter RTT (allow 'nan')
        r"(\d+)$"                                          # 10: Size (bytes)
    )
    match = pattern.match(line)
    if match:
        try:
            # Helper function to handle floats that might be 'nan'
            def safe_float(value):
                return float(value) if value.lower() != 'nan' else math.nan

            timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
            sent = int(match.group(2))
            received = int(match.group(3))
            loss_perc = safe_float(match.group(4))
            min_rtt = safe_float(match.group(5))
            avg_rtt = safe_float(match.group(6))
            max_rtt = safe_float(match.group(7))
            stddev_rtt = safe_float(match.group(8))
            jitter_rtt = safe_float(match.group(9))
            size_bytes = int(match.group(10))

            return {
                "timestamp": timestamp, "sent": sent, "received": received,
                "loss_perc": loss_perc, "min_rtt": min_rtt, "avg_rtt": avg_rtt,
                "max_rtt": max_rtt, "stddev_rtt": stddev_rtt, "jitter_rtt": jitter_rtt,
                "size_bytes": size_bytes
            }
        except (ValueError, IndexError) as e:
            print(f"Warning: Error parsing data line: {line.strip()} - {e}", file=sys.stderr)
            return None
    return None

# --- Main analysis and report generation function ---
def analyze_udp_ping_log(log_file_path, markdown_format=False):
    """Analyze UDP Ping log file and generate report content (text or Markdown)"""

    analysis_hostname = get_hostname()
    analysis_timezone = get_timezone_info()

    # Initialize metadata dictionary, matching UDP log header
    metadata = {
        "target_ip": "Unknown", "target_port": "Unknown",
        "start_time_str": "Unknown", "packets_per_measurement_desc": "Unknown",
        "summary_interval_seconds": "Unknown (Periodic mode only)",
        "ping_interval_seconds": "Unknown", "ping_size_bytes": "Unknown",
        "ping_timeout_seconds": "Unknown",
        "analysis_hostname": analysis_hostname, "analysis_timezone": analysis_timezone,
    }
    data_records = []
    header_parsed = False
    data_section_started = False

    # Parse log file header and data
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue

                if not header_parsed:
                    # Parse header information
                    match_ip = re.match(r".*Target IP:\s*(.*)", line)
                    if match_ip: metadata["target_ip"] = match_ip.group(1).strip(); continue
                    match_port = re.match(r".*Target Port:\s*(\d+)", line)
                    if match_port: metadata["target_port"] = match_port.group(1).strip(); continue
                    match_start = re.match(r".*Monitoring started at:\s*(.*)", line)
                    if match_start: metadata["start_time_str"] = match_start.group(1).strip(); continue
                    # Handle two types of packet count descriptions
                    match_packets = re.match(r".*(?:Packets per measurement|Packets in this run):\s*(.*)", line)
                    if match_packets: metadata["packets_per_measurement_desc"] = match_packets.group(1).strip(); continue
                    match_summary_interval = re.match(r".*Log summary interval \(seconds\):\s*([\d.]+)", line)
                    if match_summary_interval: metadata["summary_interval_seconds"] = match_summary_interval.group(1).strip(); continue
                    match_ping_interval = re.match(r".*Ping interval \(seconds\):\s*([\d.]+)", line)
                    if match_ping_interval: metadata["ping_interval_seconds"] = match_ping_interval.group(1).strip(); continue
                    match_size = re.match(r".*Ping payload size \(bytes\):\s*(\d+)", line) # Corrected key from PING 大小 to Ping payload size
                    if match_size: metadata["ping_size_bytes"] = match_size.group(1).strip(); continue
                    match_timeout = re.match(r".*Ping timeout \(seconds\):\s*([\d.]+)", line)
                    if match_timeout: metadata["ping_timeout_seconds"] = match_timeout.group(1).strip(); continue

                    # Check if data section header or separator line is reached
                    if "---" in line or "Sent | Recv | Loss(%)" in line: # Adjusted for English table header
                        data_section_started = True
                        header_parsed = True # Assume header ends here
                        continue # Skip separator or header line itself

                if header_parsed:
                    record = parse_udp_log_line(line)
                    if record: data_records.append(record)

    except FileNotFoundError: return f"Error: File not found: {log_file_path}"
    except Exception as e: return f"Error: Exception occurred while reading or parsing file: {e}"

    if not data_records: return f"Error: No valid data records found in file {log_file_path}."

    # --- Dynamic Baseline and Threshold Calculation ---
    baseline_rtt, baseline_stddev, baseline_jitter = None, None, None # Add jitter baseline
    dynamic_thresholds_calculated = False
    baseline_fallback_reason = ""

    # Select stable records for baseline calculation (low loss rate)
    stable_initial_records = [r for r in data_records[:MAX_BASELINE_CANDIDATES]
                              if not math.isnan(r['loss_perc']) and r['loss_perc'] <= STABLE_LOSS_THRESHOLD
                              and not math.isnan(r['avg_rtt']) and not math.isnan(r['stddev_rtt']) and not math.isnan(r['jitter_rtt'])] # Ensure relevant values are not NaN

    if len(stable_initial_records) >= MIN_BASELINE_SAMPLES:
        try:
            baseline_rtt = statistics.mean(r['avg_rtt'] for r in stable_initial_records)
            baseline_stddev = statistics.mean(r['stddev_rtt'] for r in stable_initial_records)
            baseline_jitter = statistics.mean(r['jitter_rtt'] for r in stable_initial_records) # Calculate jitter baseline
            dynamic_thresholds_calculated = True

            # Calculate dynamic thresholds
            current_latency_threshold = max(baseline_rtt * DYNAMIC_LATENCY_FACTOR + DYNAMIC_LATENCY_OFFSET, MIN_DYNAMIC_LATENCY_THRESHOLD)
            current_jitter_direct_threshold = max(baseline_jitter * DYNAMIC_JITTER_DIRECT_FACTOR + DYNAMIC_JITTER_DIRECT_OFFSET, MIN_DYNAMIC_JITTER_DIRECT_THRESHOLD) # Add direct Jitter dynamic threshold
            current_jitter_stddev_threshold = max(baseline_stddev * DYNAMIC_JITTER_STDDEV_FACTOR, baseline_rtt * DYNAMIC_JITTER_RTT_RATIO, MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD)
            current_jitter_max_avg_ratio = HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO # Max/Avg ratio remains fixed

        except statistics.StatisticsError as e:
            dynamic_thresholds_calculated = False
            baseline_fallback_reason = f"Baseline statistics calculation error: {e}"
    else:
        dynamic_thresholds_calculated = False
        if len(data_records) < MIN_BASELINE_SAMPLES: baseline_fallback_reason = f"Insufficient log data (less than {MIN_BASELINE_SAMPLES} records)"
        else: baseline_fallback_reason = f"Insufficient stable samples in the initial {MAX_BASELINE_CANDIDATES} log records (< {MIN_BASELINE_SAMPLES} records, stable loss rate <= {STABLE_LOSS_THRESHOLD}%)"

    # If dynamic calculation fails, use fixed thresholds
    if not dynamic_thresholds_calculated:
        current_latency_threshold = HIGH_LATENCY_THRESHOLD
        current_jitter_direct_threshold = HIGH_JITTER_THRESHOLD_DIRECT
        current_jitter_stddev_threshold = HIGH_JITTER_THRESHOLD_STDDEV
        current_jitter_max_avg_ratio = HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO
    # Packet loss threshold is always fixed
    current_loss_threshold = HIGH_LOSS_THRESHOLD
    # --- End of dynamic baseline and threshold calculation ---

    # --- Analysis Logic ---
    total_measurements = len(data_records)
    first_timestamp = data_records[0]['timestamp']
    last_timestamp = data_records[-1]['timestamp']
    duration = last_timestamp - first_timestamp

    # Calculate overall statistics, filtering out NaN values
    valid_sent = [r['sent'] for r in data_records if not math.isnan(r['sent'])]
    valid_received = [r['received'] for r in data_records if not math.isnan(r['received'])]
    total_sent = sum(valid_sent)
    total_received = sum(valid_received)
    overall_loss_perc = ((total_sent - total_received) / total_sent) * 100.0 if total_sent > 0 else 0.0

    all_avg_rtts = [r['avg_rtt'] for r in data_records if not math.isnan(r['avg_rtt'])]
    all_min_rtts = [r['min_rtt'] for r in data_records if not math.isnan(r['min_rtt'])]
    all_max_rtts = [r['max_rtt'] for r in data_records if not math.isnan(r['max_rtt'])]
    all_stddev_rtts = [r['stddev_rtt'] for r in data_records if not math.isnan(r['stddev_rtt'])]
    all_jitter_rtts = [r['jitter_rtt'] for r in data_records if not math.isnan(r['jitter_rtt'])] # Get all valid jitter values

    overall_avg_rtt = statistics.mean(all_avg_rtts) if all_avg_rtts else 0.0
    overall_min_rtt = min(all_min_rtts) if all_min_rtts else 0.0
    overall_max_rtt = max(all_max_rtts) if all_max_rtts else 0.0
    overall_avg_stddev_rtt = statistics.mean(all_stddev_rtts) if all_stddev_rtts else 0.0
    overall_avg_jitter = statistics.mean(all_jitter_rtts) if all_jitter_rtts else 0.0 # Calculate overall average jitter

    # Find periods exceeding thresholds
    high_loss_periods, high_latency_periods, high_jitter_periods = [], [], []
    for r in data_records:
        # Skip threshold checks for records containing NaN values
        if any(math.isnan(val) for val in [r['loss_perc'], r['avg_rtt'], r['max_rtt'], r['stddev_rtt'], r['jitter_rtt']]):
            continue

        ts = r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        # Check for high packet loss
        if r['loss_perc'] > current_loss_threshold:
            high_loss_periods.append(f"{ts} (Loss Rate: {r['loss_perc']:.1f}%)")
        # Check for high latency
        if r['avg_rtt'] > current_latency_threshold:
            high_latency_periods.append(f"{ts} (Avg RTT: {r['avg_rtt']:.1f}ms)")
        # Check for high jitter (multiple dimensions)
        jit_direct = r['jitter_rtt'] > current_jitter_direct_threshold
        jit_std = r['stddev_rtt'] > current_jitter_stddev_threshold
        jit_rat = (r['avg_rtt'] > 0 and (r['max_rtt']/r['avg_rtt']) > current_jitter_max_avg_ratio)

        if jit_direct or jit_std or jit_rat:
            rea = []; md_rea = []
            if jit_direct: rea.append(f"Jitter={r['jitter_rtt']:.1f}ms"); md_rea.append(f"Jitter=`{r['jitter_rtt']:.1f}ms`")
            if jit_std: rea.append(f"StdDev={r['stddev_rtt']:.1f}ms"); md_rea.append(f"StdDev=`{r['stddev_rtt']:.1f}ms`")
            if jit_rat: rea.append(f"Max/Avg Ratio={(r['max_rtt'] / r['avg_rtt']):.1f}"); md_rea.append(f"Max/Avg Ratio=`{(r['max_rtt'] / r['avg_rtt']):.1f}`")
            high_jitter_periods.append({"ts": ts, "reason": ', '.join(rea), "md_reason": ', '.join(md_rea)})
    # --- End of Analysis Logic ---

    # --- Generate Report Content ---
    report = []
    if markdown_format:
        # --- Markdown Report Generation ---
        sep_line = "---"; title_prefix = "# "; section_prefix = "## "; subsection_prefix = "### "
        list_item = "*   "; code_wrapper = "`"; bold_wrapper = "**"

        report.append(f"{title_prefix}UDP Ping Log Analysis Report: {code_wrapper}{metadata['target_ip']}:{metadata['target_port']}{code_wrapper}")
        report.append(sep_line)
        report.append(f"{section_prefix}Analysis Environment & Monitoring Configuration")
        report.append(f"{list_item}{bold_wrapper}Target IP:{bold_wrapper} {code_wrapper}{metadata['target_ip']}{code_wrapper}")
        report.append(f"{list_item}{bold_wrapper}Target Port:{bold_wrapper} {code_wrapper}{metadata['target_port']}{code_wrapper}")
        report.append(f"{list_item}Log File: {code_wrapper}{os.path.basename(log_file_path)}{code_wrapper}")
        report.append(f"{list_item}Monitoring Started (Log Time): {metadata['start_time_str']}")
        report.append(f"{list_item}Analysis Data Range: {code_wrapper}{first_timestamp}{code_wrapper} to {code_wrapper}{last_timestamp}{code_wrapper}")
        report.append(f"{list_item}Total Duration: {duration}")
        report.append(f"{list_item}Total Measurements (Log Lines): {total_measurements}")
        report.append(f"{list_item}Packets Description: {metadata['packets_per_measurement_desc']}")
        if metadata['summary_interval_seconds'] != "Unknown (Periodic mode only)":
            report.append(f"{list_item}Log Summary Interval: {metadata['summary_interval_seconds']} seconds")
        report.append(f"{list_item}Ping Interval: {metadata['ping_interval_seconds']} seconds")
        report.append(f"{list_item}Ping Payload Size: {metadata['ping_size_bytes']} bytes")
        report.append(f"{list_item}Ping Timeout: {metadata['ping_timeout_seconds']} seconds")
        report.append(f"{list_item}Analysis Script Hostname: {code_wrapper}{metadata['analysis_hostname']}{code_wrapper}")
        report.append(f"{list_item}Analysis Script Timezone: {metadata['analysis_timezone']}")
        report.append("")
        report.append(f"{section_prefix}Overall Statistics")
        report.append(f"{list_item}Total Sent/Received: {total_sent} / {total_received}")
        report.append(f"{list_item}Overall Average Loss Rate: {bold_wrapper}{overall_loss_perc:.2f}%{bold_wrapper}")
        report.append(f"{list_item}Overall Average RTT: {code_wrapper}{overall_avg_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}Overall Minimum RTT: {code_wrapper}{overall_min_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}Overall Maximum RTT: {code_wrapper}{overall_max_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}Overall Average Standard Deviation (StdDev): {code_wrapper}{overall_avg_stddev_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}Overall Average Jitter: {code_wrapper}{overall_avg_jitter:.3f} ms{code_wrapper}") # Added Jitter
        report.append("")
        report.append(f"{section_prefix}Analysis Thresholds")
        if dynamic_thresholds_calculated:
            report.append(f"{list_item}Using {bold_wrapper}Dynamic Thresholds{bold_wrapper} (calculated from initial log data):")
            report.append(f"    {list_item}Baseline RTT: {code_wrapper}{baseline_rtt:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}Baseline StdDev: {code_wrapper}{baseline_stddev:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}Baseline Jitter: {code_wrapper}{baseline_jitter:.1f} ms{code_wrapper}") # Added Jitter baseline
            report.append(f"    {list_item}High Latency Threshold: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (Direct) Threshold: > {code_wrapper}{current_jitter_direct_threshold:.1f} ms{code_wrapper}") # Added Jitter threshold
            report.append(f"    {list_item}High Jitter (StdDev) Threshold: > {code_wrapper}{current_jitter_stddev_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (Max/Avg Ratio) Threshold: > {code_wrapper}{current_jitter_max_avg_ratio:.1f}{code_wrapper}")
        else:
            report.append(f"{list_item}Using {bold_wrapper}Fixed Thresholds{bold_wrapper} (Reason: {baseline_fallback_reason}):")
            report.append(f"    {list_item}High Latency Threshold: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (Direct) Threshold: > {code_wrapper}{current_jitter_direct_threshold:.1f} ms{code_wrapper}") # Added Jitter threshold
            report.append(f"    {list_item}High Jitter (StdDev) Threshold: > {code_wrapper}{current_jitter_stddev_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (Max/Avg Ratio) Threshold: > {code_wrapper}{current_jitter_max_avg_ratio:.1f}{code_wrapper}")
        report.append(f"    {list_item}High Loss Rate Threshold: > {code_wrapper}{current_loss_threshold:.1f}%{code_wrapper}")
        report.append("")
        report.append(f"{section_prefix}Potential Problem Periods")
        if high_loss_periods or high_latency_periods or high_jitter_periods:
            if high_loss_periods:
                report.append(f"{subsection_prefix}High Loss (>{current_loss_threshold:.1f}%) - {len(high_loss_periods)} occurrences")
                for p in high_loss_periods: report.append(f"{list_item}{p}")
                report.append("")
            if high_latency_periods:
                report.append(f"{subsection_prefix}High Latency (>{current_latency_threshold:.1f}ms) - {len(high_latency_periods)} occurrences")
                for p in high_latency_periods: report.append(f"{list_item}{p}")
                report.append("")
            if high_jitter_periods:
                report.append(f"{subsection_prefix}High Jitter (Jitter>{current_jitter_direct_threshold:.1f}ms or StdDev>{current_jitter_stddev_threshold:.1f}ms or Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} occurrences")
                for p_dict in high_jitter_periods: report.append(f"{list_item}{p_dict['ts']} ({p_dict['md_reason']})")
                report.append("")
        else: report.append(f"{list_item}No significant problem periods detected exceeding thresholds."); report.append("")
        report.append(f"{section_prefix}Summary")
        summary_points = []
        # (Summary text generation logic remains largely unchanged, consider adding Jitter evaluation)
        if overall_loss_perc == 0.0: summary_points.append(f"Network connectivity is excellent, {bold_wrapper}no packet loss occurred{bold_wrapper}.")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"Network connectivity is good, overall loss rate is low ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper}).")
        elif overall_loss_perc < 5.0: summary_points.append(f"Minor packet loss detected ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper}), may affect sensitive applications.")
        else: summary_points.append(f"Significant packet loss ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper}), {bold_wrapper}requires attention{bold_wrapper}.")

        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"Average latency is low ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper}), performance is {bold_wrapper}excellent{bold_wrapper}.")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"Average latency is moderate ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper}), generally usable.")
        else: summary_points.append(f"Average latency is high ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper}), may impact real-time interactive experience.")

        # Evaluate jitter based on jitter_direct and stddev_rtt
        jitter_eval = "stable"; jitter_qual = "good"
        if overall_avg_jitter > current_jitter_direct_threshold or overall_avg_stddev_rtt > current_jitter_stddev_threshold:
            jitter_eval = "has significant fluctuations"; jitter_qual = f"{bold_wrapper}poor{bold_wrapper}"
        elif overall_avg_jitter > current_jitter_direct_threshold / 2 or overall_avg_stddev_rtt > current_jitter_stddev_threshold / 2:
            jitter_eval = "has some fluctuations"; jitter_qual = "fair"
        summary_points.append(f"Network latency is {jitter_eval} ({code_wrapper}Avg Jitter: {overall_avg_jitter:.1f}ms{code_wrapper}, {code_wrapper}Avg StdDev: {overall_avg_stddev_rtt:.1f}ms{code_wrapper}), stability is {jitter_qual}.")

        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("Potential network issue periods detected, see list above for details.")
        else: summary_points.append("Based on current thresholds, no significant network issue periods were found.")
        for point in summary_points: report.append(f"{list_item}{point}")

    else:
        # --- Plain Text Report Generation ---
        sep = "=" * 70 # Adjust separator length
        sub_sep = "-" * 70
        list_indent = "  "

        report.append(sep)
        report.append(f" UDP Ping Log Analysis Report: {metadata['target_ip']}:{metadata['target_port']}")
        report.append(sep)
        report.append("")

        report.append("--- Analysis Environment & Monitoring Configuration ---")
        report.append(f"{list_indent}Target IP:                 {metadata['target_ip']}")
        report.append(f"{list_indent}Target Port:               {metadata['target_port']}")
        report.append(f"{list_indent}Log File:                  {os.path.basename(log_file_path)}")
        report.append(f"{list_indent}Monitoring Started (Log Time): {metadata['start_time_str']}")
        report.append(f"{list_indent}Analysis Data Range:       {first_timestamp} to {last_timestamp}")
        report.append(f"{list_indent}Total Duration:            {duration}")
        report.append(f"{list_indent}Total Measurements (Log Lines): {total_measurements}")
        report.append(f"{list_indent}Packets Description:       {metadata['packets_per_measurement_desc']}")
        if metadata['summary_interval_seconds'] != "Unknown (Periodic mode only)":
            report.append(f"{list_indent}Log Summary Interval:      {metadata['summary_interval_seconds']} seconds")
        report.append(f"{list_indent}Ping Interval:             {metadata['ping_interval_seconds']} seconds")
        report.append(f"{list_indent}Ping Payload Size:         {metadata['ping_size_bytes']} bytes")
        report.append(f"{list_indent}Ping Timeout:              {metadata['ping_timeout_seconds']} seconds")
        report.append(f"{list_indent}Analysis Script Hostname:  {metadata['analysis_hostname']}")
        report.append(f"{list_indent}Analysis Script Timezone:  {metadata['analysis_timezone']}")
        report.append("")

        report.append("--- Overall Statistics ---")
        report.append(f"{list_indent}Total Sent/Received:       {total_sent} / {total_received}")
        report.append(f"{list_indent}Overall Average Loss Rate: {overall_loss_perc:.2f}%")
        report.append(f"{list_indent}Overall Average RTT:       {overall_avg_rtt:.3f} ms")
        report.append(f"{list_indent}Overall Minimum RTT:       {overall_min_rtt:.3f} ms")
        report.append(f"{list_indent}Overall Maximum RTT:       {overall_max_rtt:.3f} ms")
        report.append(f"{list_indent}Overall Avg StdDev:        {overall_avg_stddev_rtt:.3f} ms")
        report.append(f"{list_indent}Overall Avg Jitter:        {overall_avg_jitter:.3f} ms") # Added Jitter
        report.append("")

        report.append("--- Analysis Thresholds ---")
        if dynamic_thresholds_calculated:
            report.append(f"{list_indent}Mode: Dynamic Thresholds (based on initial log data)")
            report.append(f"{list_indent}  - Baseline RTT:           {baseline_rtt:.1f} ms")
            report.append(f"{list_indent}  - Baseline StdDev:        {baseline_stddev:.1f} ms")
            report.append(f"{list_indent}  - Baseline Jitter:        {baseline_jitter:.1f} ms") # Added Jitter baseline
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High Latency:             > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (Direct):    > {current_jitter_direct_threshold:.1f} ms") # Added Jitter threshold
            report.append(f"{list_indent}  - High Jitter (StdDev):    > {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (Max/Avg Ratio): > {current_jitter_max_avg_ratio:.1f}")
        else:
            report.append(f"{list_indent}Mode: Fixed Thresholds (Reason: {baseline_fallback_reason})")
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High Latency:             > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (Direct):    > {current_jitter_direct_threshold:.1f} ms") # Added Jitter threshold
            report.append(f"{list_indent}  - High Jitter (StdDev):    > {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (Max/Avg Ratio): > {current_jitter_max_avg_ratio:.1f}")
        report.append(f"{list_indent}  - High Loss Rate:           > {current_loss_threshold:.1f}%")
        report.append("")

        report.append("--- Potential Problem Periods ---")
        if not (high_loss_periods or high_latency_periods or high_jitter_periods):
            report.append(f"{list_indent}No significant problem periods detected exceeding thresholds.")
        else:
            if high_loss_periods:
                report.append(f"\n{list_indent}High Loss (>{current_loss_threshold:.1f}%) - {len(high_loss_periods)} occurrences:")
                for p in high_loss_periods: report.append(f"{list_indent}  - {p}")
            if high_latency_periods:
                report.append(f"\n{list_indent}High Latency (>{current_latency_threshold:.1f}ms) - {len(high_latency_periods)} occurrences:")
                for p in high_latency_periods: report.append(f"{list_indent}  - {p}")
            if high_jitter_periods:
                report.append(f"\n{list_indent}High Jitter (Jitter>{current_jitter_direct_threshold:.1f}ms or StdDev>{current_jitter_stddev_threshold:.1f}ms or Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} occurrences:")
                for p_dict in high_jitter_periods: report.append(f"{list_indent}  - {p_dict['ts']} ({p_dict['reason']})")
        report.append("")

        report.append("--- Summary ---")
        summary_points = []
        # (Summary text generation logic is consistent with Markdown version)
        if overall_loss_perc == 0.0: summary_points.append("Network connectivity is excellent, no packet loss occurred.")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"Network connectivity is good, overall loss rate is low ({overall_loss_perc:.2f}%).")
        elif overall_loss_perc < 5.0: summary_points.append(f"Minor packet loss detected ({overall_loss_perc:.2f}%), may affect sensitive applications.")
        else: summary_points.append(f"Significant packet loss ({overall_loss_perc:.2f}%), requires attention.")

        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"Average latency is low ({overall_avg_rtt:.1f}ms), performance is excellent.")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"Average latency is moderate ({overall_avg_rtt:.1f}ms), generally usable.")
        else: summary_points.append(f"Average latency is high ({overall_avg_rtt:.1f}ms), may impact real-time interactive experience.")

        jitter_eval = "stable"; jitter_qual = "good"
        if overall_avg_jitter > current_jitter_direct_threshold or overall_avg_stddev_rtt > current_jitter_stddev_threshold:
            jitter_eval = "has significant fluctuations"; jitter_qual = "poor"
        elif overall_avg_jitter > current_jitter_direct_threshold / 2 or overall_avg_stddev_rtt > current_jitter_stddev_threshold / 2:
            jitter_eval = "has some fluctuations"; jitter_qual = "fair"
        summary_points.append(f"Network latency is {jitter_eval} (Avg Jitter: {overall_avg_jitter:.1f}ms, Avg StdDev: {overall_avg_stddev_rtt:.1f}ms), stability is {jitter_qual}.")

        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("Potential network issue periods detected, see list above for details.")
        else: summary_points.append("Based on current thresholds, no significant network issue periods were found.")
        for point in summary_points: report.append(f"{list_indent}- {point}")

        report.append("\n" + sep)

    return "\n".join(report)

# --- Main program entry point (unchanged) ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {os.path.basename(sys.argv[0])} <udp_ping_log_file_path> [--md]")
        sys.exit(1)

    log_file = sys.argv[1]
    output_markdown = False
    if len(sys.argv) > 2 and "--md" in sys.argv[2:]:
        output_markdown = True

    analysis_report_content = analyze_udp_ping_log(log_file, output_markdown)

    if output_markdown:
        base_name = os.path.splitext(os.path.basename(log_file))[0]
        # Remove possible '_client' suffix
        if base_name.endswith('_client'): base_name = base_name[:-7]
        md_filename = f"{base_name}_udp_report.md" # Add _udp_ to differentiate
        try:
            with open(md_filename, 'w', encoding='utf-8') as f:
                f.write(analysis_report_content)
            print(f"Markdown report saved to: {md_filename}")
        except IOError as e:
            print(f"Error: Unable to write Markdown file {md_filename}: {e}", file=sys.stderr)
            print("\n--- Analysis Report (printed to console due to file write error) ---")
            print(analysis_report_content)
    else:
        print(analysis_report_content)
