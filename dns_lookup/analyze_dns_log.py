#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import os
from datetime import datetime
import statistics
import socket
import time

# --- Configurable Thresholds ---
HIGH_DNS_TIME_THRESHOLD = 500.0        # High DNS resolution time threshold (ms)
ERROR_RATE_THRESHOLD = 5.0             # Error rate threshold (%)
SLOW_DNS_THRESHOLD = 200.0             # Slow DNS resolution threshold (ms)

# --- Dynamic Baseline Calculation Parameters ---
MAX_BASELINE_CANDIDATES = 100
MIN_BASELINE_SAMPLES = 20
STABLE_SUCCESS_THRESHOLD = 95.0  # Success rate threshold

# --- Dynamic Threshold Calculation Parameters ---
DYNAMIC_DNS_TIME_FACTOR = 2.5
DYNAMIC_DNS_TIME_OFFSET = 50.0
MIN_DYNAMIC_DNS_TIME_THRESHOLD = 100.0

# --- Functions to get system information ---
def get_hostname():
    try:
        return socket.gethostname()
    except socket.error as e:
        print(f"Warning: Unable to get hostname: {e}", file=sys.stderr)
        return "Unknown (Unable to fetch)"

def get_timezone_info():
    try:
        tz_name = datetime.now().astimezone().tzname()
        if tz_name and not re.match(r"^[+-]\d{2}$", tz_name) and tz_name.upper() != 'UTC':
            is_dst = time.daylight and time.localtime().tm_isdst > 0
            offset_seconds = -time.timezone if not is_dst else -time.altzone
            offset_hours = offset_seconds / 3600
            sign = "+" if offset_hours >= 0 else "-"
            offset_str = f"UTC{sign}{int(abs(offset_hours)):02d}:{int(abs(offset_seconds) % 3600 / 60):02d}"
            return f"{tz_name} ({offset_str})"
    except Exception:
        pass
    
    try:
        is_dst = time.daylight and time.localtime().tm_isdst > 0
        current_tz_name = time.tzname[1] if is_dst else time.tzname[0]
        offset_seconds = -time.timezone if not is_dst else -time.altzone
        offset_hours = offset_seconds / 3600
        sign = "+" if offset_hours >= 0 else "-"
        offset_str = f"UTC{sign}{int(abs(offset_hours)):02d}:{int(abs(offset_seconds) % 3600 / 60):02d}"
        if current_tz_name and current_tz_name != 'UTC':
            return f"{current_tz_name} ({offset_str})"
        else:
            return offset_str
    except Exception as e:
        print(f"Warning: Unable to get timezone information: {e}", file=sys.stderr)
        return "Unknown (Unable to fetch)"

# --- Function to parse log lines ---
def parse_log_line(line):
    # Parse format: Resolution Time(ms) | Resolved IP | All IP Addresses | Status
    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s*\|\s*"
        r"([\d.]+|N/A)\s*\|\s*"
        r"([\d.]+|N/A)\s*\|\s*"
        r"([^|]+)\s*\|\s*"
        r"(.+)$"
    )
    
    match = pattern.match(line)
    if match:
        try:
            timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
            
            # Parse individual fields
            dns_time = match.group(2).strip()
            resolved_ip = match.group(3).strip()
            all_ips = match.group(4).strip()
            status = match.group(5).strip()
            
            return {
                "timestamp": timestamp,
                "dns_time": dns_time,
                "resolved_ip": resolved_ip,
                "all_ips": all_ips,
                "status": status
            }
        except (ValueError, IndexError) as e:
            print(f"Warning: Error parsing data line: {line.strip()} - {e}", file=sys.stderr)
            return None
    return None

def is_success_status(status):
    """Check if the status indicates success"""
    return status == "SUCCESS"

def is_numeric(value):
    """Check if the value is numeric"""
    if value == "N/A":
        return False
    try:
        float(value)
        return True
    except ValueError:
        return False

def safe_float(value, default=0.0):
    """Safely convert to float"""
    if not is_numeric(value):
        return default
    try:
        return float(value)
    except ValueError:
        return default

def extract_unique_ips(all_ips_str):
    """Extract unique IP addresses from the all_ips string"""
    if all_ips_str == "N/A" or not all_ips_str:
        return []
    
    # Remove brackets and split
    clean_str = all_ips_str.replace('[', '').replace(']', '')
    ips = [ip.strip() for ip in clean_str.split(',') if ip.strip()]
    
    # Filter valid IP addresses
    valid_ips = []
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    for ip in ips:
        if ip_pattern.match(ip):
            valid_ips.append(ip)
    
    return list(set(valid_ips))  # Deduplicate

def categorize_error(status):
    """Categorize error type"""
    if "TIMEOUT" in status:
        return "Timeout Error"
    elif "DNS_ERROR" in status:
        return "DNS Resolution Error"
    elif "NSLOOKUP_ERROR" in status:
        return "nslookup Error"
    elif "NO_IP_FOUND" in status:
        return "No IP Address Found"
    else:
        return "Other Error"

def analyze_dns_log(log_file_path, markdown_format=False):
    """Analyze DNS log file and generate report content"""
    
    analysis_hostname = get_hostname()
    analysis_timezone = get_timezone_info()
    
    metadata = {
        "target_domain": "Unknown",
        "dns_server": "Unknown",
        "system_dns_servers": "Unknown",
        "source_public_ip": "Unknown (Not found in log)",
        "start_time_str": "Unknown",
        "interval_seconds": "Unknown",
        "dns_timeout": "Unknown",
        "analysis_hostname": analysis_hostname,
        "analysis_timezone": analysis_timezone,
    }
    
    data_records = []
    header_parsed = False
    data_section_started = False
    
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if not header_parsed:
                    # Parse header information
                    match_source_ip = re.match(r".*Server Source Public IP:\s*(.*)", line)
                    if match_source_ip:
                        metadata["source_public_ip"] = match_source_ip.group(1).strip()
                        continue
                    
                    match_domain = re.match(r".*Target Domain:\s*(.*)", line)
                    if match_domain:
                        metadata["target_domain"] = match_domain.group(1).strip()
                        continue
                    
                    match_dns_server = re.match(r".*DNS Server:\s*(.*)", line)
                    if match_dns_server:
                        metadata["dns_server"] = match_dns_server.group(1).strip()
                        continue
                    
                    match_system_dns = re.match(r".*System DNS Servers:\s*(.*)", line)
                    if match_system_dns:
                        metadata["system_dns_servers"] = match_system_dns.group(1).strip()
                        continue
                    
                    match_start = re.match(r".*Monitoring started at:\s*(.*)", line)
                    if match_start:
                        metadata["start_time_str"] = match_start.group(1).strip()
                        continue
                    
                    match_interval = re.match(r".*Measurement Interval:\s*(\d+)\s*seconds", line)
                    if match_interval:
                        metadata["interval_seconds"] = match_interval.group(1).strip()
                        continue
                    
                    match_timeout = re.match(r".*DNS Timeout:\s*(\d+)\s*seconds", line)
                    if match_timeout:
                        metadata["dns_timeout"] = match_timeout.group(1).strip()
                        continue
                    
                    if "---" in line:
                        if data_section_started:
                            header_parsed = True
                        else:
                            data_section_started = True
                        continue
                    
                    if "Resolution Time(ms)" in line:
                        data_section_started = True
                        header_parsed = True
                        continue
                
                if header_parsed:
                    record = parse_log_line(line)
                    if record:
                        data_records.append(record)
    
    except FileNotFoundError:
        return f"Error: File not found: {log_file_path}"
    except Exception as e:
        return f"Error: Exception occurred while reading or parsing file: {e}"
    
    if not data_records:
        return f"Error: No valid data records found in file {log_file_path}."
    
    # --- Analysis Logic ---
    total_queries = len(data_records)
    first_timestamp = data_records[0]['timestamp']
    last_timestamp = data_records[-1]['timestamp']
    duration = last_timestamp - first_timestamp
    
    # Count successes and failures
    success_records = [r for r in data_records if is_success_status(r['status'])]
    error_records = [r for r in data_records if not is_success_status(r['status'])]
    
    success_count = len(success_records)
    error_count = len(error_records)
    success_rate = (success_count / total_queries) * 100.0 if total_queries > 0 else 0.0
    error_rate = (error_count / total_queries) * 100.0 if total_queries > 0 else 0.0
    
    # Calculate time statistics (successful queries only)
    if success_records:
        dns_times = [safe_float(r['dns_time']) for r in success_records if is_numeric(r['dns_time'])]
        
        avg_dns_time = statistics.mean(dns_times) if dns_times else 0.0
        min_dns_time = min(dns_times) if dns_times else 0.0
        max_dns_time = max(dns_times) if dns_times else 0.0
        median_dns_time = statistics.median(dns_times) if dns_times else 0.0
    else:
        avg_dns_time = min_dns_time = max_dns_time = median_dns_time = 0.0
    
    # Analyze IP address changes
    unique_ips = set()
    ip_changes = []
    last_ip = None
    
    for r in success_records:
        if r['resolved_ip'] != "N/A":
            if last_ip and last_ip != r['resolved_ip']:
                ip_changes.append({
                    'timestamp': r['timestamp'],
                    'old_ip': last_ip,
                    'new_ip': r['resolved_ip']
                })
            last_ip = r['resolved_ip']
            unique_ips.add(r['resolved_ip'])
        
        # Collect all IP addresses
        all_ips = extract_unique_ips(r['all_ips'])
        unique_ips.update(all_ips)
    
    # Error type statistics
    error_types = {}
    for r in error_records:
        error_type = categorize_error(r['status'])
        error_types[error_type] = error_types.get(error_type, 0) + 1
    
    # Dynamic threshold calculation
    baseline_dns_time = None
    dynamic_thresholds_calculated = False
    baseline_fallback_reason = ""
    
    stable_initial_records = [r for r in data_records[:MAX_BASELINE_CANDIDATES] if is_success_status(r['status'])]
    
    if len(stable_initial_records) >= MIN_BASELINE_SAMPLES:
        try:
            baseline_dns_times = [safe_float(r['dns_time']) for r in stable_initial_records if is_numeric(r['dns_time'])]
            
            if baseline_dns_times:
                baseline_dns_time = statistics.mean(baseline_dns_times)
                dynamic_thresholds_calculated = True
                
                current_dns_time_threshold = max(
                    baseline_dns_time * DYNAMIC_DNS_TIME_FACTOR + DYNAMIC_DNS_TIME_OFFSET,
                    MIN_DYNAMIC_DNS_TIME_THRESHOLD
                )
            else:
                dynamic_thresholds_calculated = False
                baseline_fallback_reason = "Missing valid time data in baseline"
        except statistics.StatisticsError as e:
            dynamic_thresholds_calculated = False
            baseline_fallback_reason = f"Baseline statistics calculation error: {e}"
    else:
        dynamic_thresholds_calculated = False
        if len(data_records) < MIN_BASELINE_SAMPLES:
            baseline_fallback_reason = f"Insufficient log data (less than {MIN_BASELINE_SAMPLES} records)"
        else:
            baseline_fallback_reason = f"Insufficient successful samples in the initial {MAX_BASELINE_CANDIDATES} log records (< {MIN_BASELINE_SAMPLES})"
    
    if not dynamic_thresholds_calculated:
        current_dns_time_threshold = HIGH_DNS_TIME_THRESHOLD
    
    current_error_rate_threshold = ERROR_RATE_THRESHOLD
    
    # Identify problematic periods
    slow_dns_periods = []
    error_periods = []
    
    for r in data_records:
        ts = r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        # Check DNS resolution time
        if is_numeric(r['dns_time']) and safe_float(r['dns_time']) > current_dns_time_threshold:
            slow_dns_periods.append(f"{ts} (DNS Time: {r['dns_time']}ms)")
        
        # Check for errors
        if not is_success_status(r['status']):
            error_periods.append(f"{ts} (Status: {r['status']})")
    
    # --- Generate Report Content ---
    report = []
    
    if markdown_format:
        # Markdown Report
        sep_line = "---"
        title_prefix = "# "
        section_prefix = "## "
        subsection_prefix = "### "
        list_item = "*   "
        code_wrapper = "`"
        bold_wrapper = "**"
        
        report.append(f"{title_prefix}DNS Resolution Monitoring Analysis Report: {code_wrapper}{metadata['target_domain']}{code_wrapper}")
        report.append(sep_line)
        
        report.append(f"{section_prefix}Monitoring Configuration and Environment")
        report.append(f"{list_item}{bold_wrapper}Target Domain:{bold_wrapper} {code_wrapper}{metadata['target_domain']}{code_wrapper}")
        report.append(f"{list_item}{bold_wrapper}DNS Server:{bold_wrapper} {code_wrapper}{metadata['dns_server']}{code_wrapper}")
        if metadata['system_dns_servers'] != "Unknown":
            report.append(f"{list_item}{bold_wrapper}System DNS Servers:{bold_wrapper} {metadata['system_dns_servers']}")
        report.append(f"{list_item}{bold_wrapper}Source Public IP:{bold_wrapper} {code_wrapper}{metadata['source_public_ip']}{code_wrapper}")
        report.append(f"{list_item}Log File: {code_wrapper}{os.path.basename(log_file_path)}{code_wrapper}")
        report.append(f"{list_item}Monitoring Start: {metadata['start_time_str']}")
        report.append(f"{list_item}Analyzed Data Range: {code_wrapper}{first_timestamp}{code_wrapper} to {code_wrapper}{last_timestamp}{code_wrapper}")
        report.append(f"{list_item}Total Duration: {duration}")
        report.append(f"{list_item}Total Queries: {total_queries}")
        report.append(f"{list_item}Measurement Interval: {metadata['interval_seconds']} seconds")
        report.append(f"{list_item}DNS Timeout: {metadata['dns_timeout']} seconds")
        report.append(f"{list_item}Analysis Hostname: {code_wrapper}{metadata['analysis_hostname']}{code_wrapper}")
        report.append(f"{list_item}Analysis Timezone: {metadata['analysis_timezone']}")
        report.append("")
        
        report.append(f"{section_prefix}Overall Statistics")
        report.append(f"{list_item}Total Queries: {total_queries}")
        report.append(f"{list_item}Successful Queries: {success_count}")
        report.append(f"{list_item}Failed Queries: {error_count}")
        report.append(f"{list_item}Success Rate: {bold_wrapper}{success_rate:.2f}%{bold_wrapper}")
        report.append(f"{list_item}Error Rate: {bold_wrapper}{error_rate:.2f}%{bold_wrapper}")
        report.append(f"{list_item}Average DNS Resolution Time: {code_wrapper}{avg_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Minimum DNS Resolution Time: {code_wrapper}{min_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Maximum DNS Resolution Time: {code_wrapper}{max_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Median DNS Resolution Time: {code_wrapper}{median_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Number of Unique IPs Resolved: {len(unique_ips)}")
        if unique_ips:
            report.append(f"{list_item}All Resolved IPs: {', '.join(sorted(unique_ips))}")
        report.append("")
        
        if ip_changes:
            report.append(f"{section_prefix}IP Address Change Log")
            report.append(f"{list_item}Detected {len(ip_changes)} IP address changes:")
            for change in ip_changes:
                report.append(f"    {list_item}{change['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {change['old_ip']} → {change['new_ip']}")
            report.append("")
        
        if error_types:
            report.append(f"{section_prefix}Error Type Statistics")
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_queries) * 100
                report.append(f"{list_item}{error_type}: {count} times ({percentage:.1f}%)")
            report.append("")
        
        report.append(f"{section_prefix}Analysis Thresholds")
        if dynamic_thresholds_calculated:
            report.append(f"{list_item}Using {bold_wrapper}Dynamic Thresholds{bold_wrapper} (calculated based on initial log data):")
            report.append(f"    {list_item}Baseline DNS Resolution Time: {code_wrapper}{baseline_dns_time:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High DNS Resolution Time Threshold: > {code_wrapper}{current_dns_time_threshold:.1f} ms{code_wrapper}")
        else:
            report.append(f"{list_item}Using {bold_wrapper}Fixed Thresholds{bold_wrapper} (reason: {baseline_fallback_reason}):")
            report.append(f"    {list_item}High DNS Resolution Time Threshold: > {code_wrapper}{current_dns_time_threshold:.1f} ms{code_wrapper}")
        
        report.append(f"    {list_item}High Error Rate Threshold: > {code_wrapper}{current_error_rate_threshold:.1f}%{code_wrapper}")
        report.append("")
        
        report.append(f"{section_prefix}Potential Problem Periods")
        if slow_dns_periods or error_periods:
            if slow_dns_periods:
                report.append(f"{subsection_prefix}Slow DNS Resolution (>{current_dns_time_threshold:.1f}ms) - {len(slow_dns_periods)} times")
                for p in slow_dns_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
            
            if error_periods:
                report.append(f"{subsection_prefix}DNS Resolution Errors - {len(error_periods)} times")
                for p in error_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
        else:
            report.append(f"{list_item}No significant problem periods exceeding thresholds detected.")
            report.append("")
        
        report.append(f"{section_prefix}Summary")
        summary_points = []
        
        if success_rate >= 99.0:
            summary_points.append(f"DNS resolution reliability is {bold_wrapper}excellent{bold_wrapper}, with a success rate of {code_wrapper}{success_rate:.2f}%{code_wrapper}.")
        elif success_rate >= 95.0:
            summary_points.append(f"DNS resolution reliability is good, with a success rate of {code_wrapper}{success_rate:.2f}%{code_wrapper}.")
        elif success_rate >= 90.0:
            summary_points.append(f"DNS resolution reliability is average, with a success rate of {code_wrapper}{success_rate:.2f}%{code_wrapper}, requires attention.")
        else:
            summary_points.append(f"DNS resolution reliability is {bold_wrapper}poor{bold_wrapper}, with a success rate of only {code_wrapper}{success_rate:.2f}%{code_wrapper}, {bold_wrapper}requires urgent attention{bold_wrapper}.")
        
        if avg_dns_time < current_dns_time_threshold / 3:
            summary_points.append(f"Average DNS resolution time is {bold_wrapper}excellent{bold_wrapper} ({code_wrapper}{avg_dns_time:.1f}ms{code_wrapper}), with fast response.")
        elif avg_dns_time < current_dns_time_threshold:
            summary_points.append(f"Average DNS resolution time is acceptable ({code_wrapper}{avg_dns_time:.1f}ms{code_wrapper}).")
        else:
            summary_points.append(f"Average DNS resolution time is {bold_wrapper}slow{bold_wrapper} ({code_wrapper}{avg_dns_time:.1f}ms{code_wrapper}), may affect network experience.")
        
        if len(unique_ips) > 1:
            summary_points.append(f"Domain resolves to {len(unique_ips)} different IP addresses, indicating load balancing or CDN configuration.")
        
        if ip_changes:
            summary_points.append(f"Detected {len(ip_changes)} IP address changes, possibly indicating DNS record updates or load balancing switches.")
        
        if error_periods:
            summary_points.append(f"Detected {len(error_periods)} DNS resolution errors, see list above for details.")
        else:
            summary_points.append("No DNS resolution errors found, service stability is good.")
        
        for point in summary_points:
            report.append(f"{list_item}{point}")
    
    else:
        # Plain text report
        sep = "=" * 60
        sub_sep = "-" * 60
        list_indent = "  "
        
        report.append(sep)
        report.append(f" DNS Resolution Monitoring Analysis Report: {metadata['target_domain']}")
        report.append(sep)
        report.append("")
        
        report.append("--- Monitoring Configuration and Environment ---")
        report.append(f"{list_indent}Target Domain:           {metadata['target_domain']}")
        report.append(f"{list_indent}DNS Server:              {metadata['dns_server']}")
        if metadata['system_dns_servers'] != "Unknown":
            report.append(f"{list_indent}System DNS Servers:      {metadata['system_dns_servers']}")
        report.append(f"{list_indent}Source Public IP:        {metadata['source_public_ip']}")
        report.append(f"{list_indent}Log File:                {os.path.basename(log_file_path)}")
        report.append(f"{list_indent}Monitoring Start:        {metadata['start_time_str']}")
        report.append(f"{list_indent}Analyzed Data Range:     {first_timestamp} to {last_timestamp}")
        report.append(f"{list_indent}Total Duration:          {duration}")
        report.append(f"{list_indent}Total Queries:           {total_queries}")
        report.append(f"{list_indent}Measurement Interval:    {metadata['interval_seconds']} seconds")
        report.append(f"{list_indent}DNS Timeout:             {metadata['dns_timeout']} seconds")
        report.append(f"{list_indent}Analysis Hostname:       {metadata['analysis_hostname']}")
        report.append(f"{list_indent}Analysis Timezone:       {metadata['analysis_timezone']}")
        report.append("")
        
        report.append("--- Overall Statistics ---")
        report.append(f"{list_indent}Total Queries:           {total_queries}")
        report.append(f"{list_indent}Successful Queries:      {success_count}")
        report.append(f"{list_indent}Failed Queries:          {error_count}")
        report.append(f"{list_indent}Success Rate:            {success_rate:.2f}%")
        report.append(f"{list_indent}Error Rate:              {error_rate:.2f}%")
        report.append(f"{list_indent}Average DNS Resolution Time: {avg_dns_time:.1f} ms")
        report.append(f"{list_indent}Minimum DNS Resolution Time: {min_dns_time:.1f} ms")
        report.append(f"{list_indent}Maximum DNS Resolution Time: {max_dns_time:.1f} ms")
        report.append(f"{list_indent}Median DNS Resolution Time:  {median_dns_time:.1f} ms")
        report.append(f"{list_indent}Number of Unique IPs Resolved: {len(unique_ips)}")
        if unique_ips:
            report.append(f"{list_indent}All Resolved IPs:        {', '.join(sorted(unique_ips))}")
        report.append("")
        
        if ip_changes:
            report.append("--- IP Address Change Log ---")
            report.append(f"{list_indent}Detected {len(ip_changes)} IP address changes:")
            for change in ip_changes:
                report.append(f"{list_indent}  - {change['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {change['old_ip']} → {change['new_ip']}")
            report.append("")
        
        if error_types:
            report.append("--- Error Type Statistics ---")
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_queries) * 100
                report.append(f"{list_indent}{error_type}: {count} times ({percentage:.1f}%)")
            report.append("")
        
        report.append("--- Analysis Thresholds ---")
        if dynamic_thresholds_calculated:
            report.append(f"{list_indent}Mode: Dynamic Thresholds (calculated based on initial log data)")
            report.append(f"{list_indent}  - Baseline DNS Resolution Time: {baseline_dns_time:.1f} ms")
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High DNS Resolution Time:   > {current_dns_time_threshold:.1f} ms")
        else:
            report.append(f"{list_indent}Mode: Fixed Thresholds (reason: {baseline_fallback_reason})")
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High DNS Resolution Time:   > {current_dns_time_threshold:.1f} ms")
        
        report.append(f"{list_indent}  - High Error Rate:         > {current_error_rate_threshold:.1f}%")
        report.append("")
        
        report.append("--- Potential Problem Periods ---")
        if slow_dns_periods or error_periods:
            if slow_dns_periods:
                report.append(f"{list_indent}Slow DNS Resolution (>{current_dns_time_threshold:.1f}ms) - {len(slow_dns_periods)} times:")
                for p in slow_dns_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
            
            if error_periods:
                report.append(f"{list_indent}DNS Resolution Errors - {len(error_periods)} times:")
                for p in error_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
        else:
            report.append(f"{list_indent}No significant problem periods exceeding thresholds detected.")
            report.append("")
        
        report.append("--- Summary ---")
        summary_points = []
        
        if success_rate >= 99.0:
            summary_points.append(f"DNS resolution reliability is excellent, with a success rate of {success_rate:.2f}%.")
        elif success_rate >= 95.0:
            summary_points.append(f"DNS resolution reliability is good, with a success rate of {success_rate:.2f}%.")
        elif success_rate >= 90.0:
            summary_points.append(f"DNS resolution reliability is average, with a success rate of {success_rate:.2f}%, requires attention.")
        else:
            summary_points.append(f"DNS resolution reliability is poor, with a success rate of only {success_rate:.2f}%, requires urgent attention.")
        
        if avg_dns_time < current_dns_time_threshold / 3:
            summary_points.append(f"Average DNS resolution time is excellent ({avg_dns_time:.1f}ms), with fast response.")
        elif avg_dns_time < current_dns_time_threshold:
            summary_points.append(f"Average DNS resolution time is acceptable ({avg_dns_time:.1f}ms).")
        else:
            summary_points.append(f"Average DNS resolution time is slow ({avg_dns_time:.1f}ms), may affect network experience.")
        
        if len(unique_ips) > 1:
            summary_points.append(f"Domain resolves to {len(unique_ips)} different IP addresses, indicating load balancing or CDN configuration.")
        
        if ip_changes:
            summary_points.append(f"Detected {len(ip_changes)} IP address changes, possibly indicating DNS record updates or load balancing switches.")
        
        if error_periods:
            summary_points.append(f"Detected {len(error_periods)} DNS resolution errors, see list above for details.")
        else:
            summary_points.append("No DNS resolution errors found, service stability is good.")
        
        for point in summary_points:
            report.append(f"{list_indent}{point}")
        
        report.append("")
        report.append(sep)
    
    return "\n".join(report)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <DNS log file path> [--markdown]")
        print("Examples:")
        print(f"  {sys.argv[0]} dns_monitor_google.com_8.8.8.8.log")
        print(f"  {sys.argv[0]} dns_monitor_google.com_system.log --markdown")
        sys.exit(1)
    
    log_file_path = sys.argv[1]
    markdown_format = '--markdown' in sys.argv
    
    if not os.path.exists(log_file_path):
        print(f"Error: Log file does not exist: {log_file_path}")
        sys.exit(1)
    
    print(f"Analyzing DNS log file: {log_file_path}")
    if markdown_format:
        print("Output format: Markdown")
    else:
        print("Output format: Plain text")
    print()
    
    result = analyze_dns_log(log_file_path, markdown_format)
    print(result)

if __name__ == "__main__":
    main()