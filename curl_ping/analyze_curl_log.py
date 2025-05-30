#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
from datetime import datetime
import statistics
import socket
import time
import os

# --- Configurable Thresholds ---
HIGH_RESPONSE_TIME_THRESHOLD = 2000.0  # High response time threshold (ms)
HIGH_CONNECT_TIME_THRESHOLD = 1000.0   # High connect time threshold (ms)
HIGH_DNS_TIME_THRESHOLD = 500.0        # High DNS resolution time threshold (ms)
ERROR_RATE_THRESHOLD = 5.0             # Error rate threshold (%)

# --- Dynamic Baseline Calculation Parameters ---
MAX_BASELINE_CANDIDATES = 100
MIN_BASELINE_SAMPLES = 20
STABLE_SUCCESS_THRESHOLD = 95.0  # Success rate threshold

# --- Dynamic Threshold Calculation Parameters ---
DYNAMIC_RESPONSE_TIME_FACTOR = 2.0
DYNAMIC_RESPONSE_TIME_OFFSET = 100.0
MIN_DYNAMIC_RESPONSE_TIME_THRESHOLD = 500.0

DYNAMIC_CONNECT_TIME_FACTOR = 2.0
DYNAMIC_CONNECT_TIME_OFFSET = 50.0
MIN_DYNAMIC_CONNECT_TIME_THRESHOLD = 200.0

# --- Functions to Get System Information ---
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

# --- Function to Parse Log Lines ---
def parse_log_line(line):
    # Parse format: DNS Resolution(ms) | Resolved IP | HTTP Status Code | Total Time(ms) | Connect Time(ms) | Transfer Time(ms) | Response Size(B) | Status
    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s*\|\s*"
        r"([\d.]+|N/A)\s*\|\s*"
        r"([\d.]+|N/A)\s*\|\s*"
        r"(\d+|N/A)\s*\|\s*"
        r"([\d.]+|N/A)\s*\|\s*"
        r"([\d.]+|N/A)\s*\|\s*"
        r"([\d.]+|N/A)\s*\|\s*"
        r"(\d+|N/A)\s*\|\s*"
        r"(.+)$"
    )
    
    match = pattern.match(line)
    if match:
        try:
            timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
            
            # Parse individual fields
            dns_time = match.group(2).strip()
            resolved_ip = match.group(3).strip()
            http_code = match.group(4).strip()
            total_time = match.group(5).strip()
            connect_time = match.group(6).strip()
            transfer_time = match.group(7).strip()
            response_size = match.group(8).strip()
            status = match.group(9).strip()
            
            return {
                "timestamp": timestamp,
                "dns_time": dns_time,
                "resolved_ip": resolved_ip,
                "http_code": http_code,
                "total_time": total_time,
                "connect_time": connect_time,
                "transfer_time": transfer_time,
                "response_size": response_size,
                "status": status
            }
        except (ValueError, IndexError) as e:
            print(f"Warning: Error parsing data line: {line.strip()} - {e}", file=sys.stderr)
            return None
    return None

def is_success_status(status):
    """Check if status indicates success"""
    return status == "SUCCESS"

def is_numeric(value):
    """Check if value is numeric"""
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

def analyze_curl_log(log_file_path, markdown_format=False):
    """Analyze curl log file and generate report content"""
    
    analysis_hostname = get_hostname()
    analysis_timezone = get_timezone_info()
    
    metadata = {
        "target_url": "Unknown",
        "source_public_ip": "Unknown (Not found in log)",
        "start_time_str": "Unknown",
        "interval_seconds": "Unknown",
        "curl_timeout": "Unknown",
        "user_agent": "Unknown",
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
                    
                    match_url = re.match(r".*Target URL:\s*(.*)", line)
                    if match_url:
                        metadata["target_url"] = match_url.group(1).strip()
                        continue
                    
                    match_start = re.match(r".*Monitoring Started At:\s*(.*)", line)
                    if match_start:
                        metadata["start_time_str"] = match_start.group(1).strip()
                        continue
                    
                    match_interval = re.match(r".*Measurement Interval:\s*(\d+)\s*seconds", line)
                    if match_interval:
                        metadata["interval_seconds"] = match_interval.group(1).strip()
                        continue
                    
                    match_timeout = re.match(r".*CURL Timeout:\s*(\d+)\s*seconds", line)
                    if match_timeout:
                        metadata["curl_timeout"] = match_timeout.group(1).strip()
                        continue
                    
                    match_ua = re.match(r".*User-Agent:\s*(.*)", line)
                    if match_ua:
                        metadata["user_agent"] = match_ua.group(1).strip()
                        continue
                    
                    if "---" in line:
                        if data_section_started:
                            header_parsed = True
                        else:
                            data_section_started = True
                        continue
                    
                    if "DNS Resolution(ms)" in line:
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
    total_requests = len(data_records)
    first_timestamp = data_records[0]['timestamp']
    last_timestamp = data_records[-1]['timestamp']
    duration = last_timestamp - first_timestamp
    
    # Count successes and failures
    success_records = [r for r in data_records if is_success_status(r['status'])]
    error_records = [r for r in data_records if not is_success_status(r['status'])]
    
    success_count = len(success_records)
    error_count = len(error_records)
    success_rate = (success_count / total_requests) * 100.0 if total_requests > 0 else 0.0
    error_rate = (error_count / total_requests) * 100.0 if total_requests > 0 else 0.0
    
    # Calculate time statistics (successful requests only)
    if success_records:
        total_times = [safe_float(r['total_time']) for r in success_records if is_numeric(r['total_time'])]
        connect_times = [safe_float(r['connect_time']) for r in success_records if is_numeric(r['connect_time'])]
        dns_times = [safe_float(r['dns_time']) for r in success_records if is_numeric(r['dns_time'])]
        
        avg_total_time = statistics.mean(total_times) if total_times else 0.0
        min_total_time = min(total_times) if total_times else 0.0
        max_total_time = max(total_times) if total_times else 0.0
        
        avg_connect_time = statistics.mean(connect_times) if connect_times else 0.0
        avg_dns_time = statistics.mean(dns_times) if dns_times else 0.0
    else:
        avg_total_time = min_total_time = max_total_time = 0.0
        avg_connect_time = avg_dns_time = 0.0
    
    # Dynamic threshold calculation
    baseline_response_time = None
    baseline_connect_time = None
    dynamic_thresholds_calculated = False
    baseline_fallback_reason = ""
    
    stable_initial_records = [r for r in data_records[:MAX_BASELINE_CANDIDATES] if is_success_status(r['status'])]
    
    if len(stable_initial_records) >= MIN_BASELINE_SAMPLES:
        try:
            baseline_total_times = [safe_float(r['total_time']) for r in stable_initial_records if is_numeric(r['total_time'])]
            baseline_connect_times = [safe_float(r['connect_time']) for r in stable_initial_records if is_numeric(r['connect_time'])]
            
            if baseline_total_times and baseline_connect_times:
                baseline_response_time = statistics.mean(baseline_total_times)
                baseline_connect_time = statistics.mean(baseline_connect_times)
                dynamic_thresholds_calculated = True
                
                current_response_time_threshold = max(
                    baseline_response_time * DYNAMIC_RESPONSE_TIME_FACTOR + DYNAMIC_RESPONSE_TIME_OFFSET,
                    MIN_DYNAMIC_RESPONSE_TIME_THRESHOLD
                )
                current_connect_time_threshold = max(
                    baseline_connect_time * DYNAMIC_CONNECT_TIME_FACTOR + DYNAMIC_CONNECT_TIME_OFFSET,
                    MIN_DYNAMIC_CONNECT_TIME_THRESHOLD
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
            baseline_fallback_reason = f"Insufficient successful samples in the initial {MAX_BASELINE_CANDIDATES} log records (< {MIN_BASELINE_SAMPLES} records)"
    
    if not dynamic_thresholds_calculated:
        current_response_time_threshold = HIGH_RESPONSE_TIME_THRESHOLD
        current_connect_time_threshold = HIGH_CONNECT_TIME_THRESHOLD
    
    current_dns_time_threshold = HIGH_DNS_TIME_THRESHOLD
    current_error_rate_threshold = ERROR_RATE_THRESHOLD
    
    # Identify problematic periods
    slow_response_periods = []
    slow_connect_periods = []
    slow_dns_periods = []
    error_periods = []
    
    for r in data_records:
        ts = r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        # Check response time
        if is_numeric(r['total_time']) and safe_float(r['total_time']) > current_response_time_threshold:
            slow_response_periods.append(f"{ts} (Response Time: {r['total_time']}ms)")
        
        # Check connect time
        if is_numeric(r['connect_time']) and safe_float(r['connect_time']) > current_connect_time_threshold:
            slow_connect_periods.append(f"{ts} (Connect Time: {r['connect_time']}ms)")
        
        # Check DNS time
        if is_numeric(r['dns_time']) and safe_float(r['dns_time']) > current_dns_time_threshold:
            slow_dns_periods.append(f"{ts} (DNS Time: {r['dns_time']}ms)")
        
        # Check errors
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
        
        report.append(f"{title_prefix}CURL Log Analysis Report: {code_wrapper}{metadata['target_url']}{code_wrapper}")
        report.append(sep_line)
        
        report.append(f"{section_prefix}Analysis Environment and Monitoring Configuration")
        report.append(f"{list_item}{bold_wrapper}Source Public IP (from log):{bold_wrapper} {code_wrapper}{metadata['source_public_ip']}{code_wrapper}")
        report.append(f"{list_item}{bold_wrapper}Target URL:{bold_wrapper} {code_wrapper}{metadata['target_url']}{code_wrapper}")
        report.append(f"{list_item}Log File: {code_wrapper}{os.path.basename(log_file_path)}{code_wrapper}")
        report.append(f"{list_item}Monitoring Start (log record): {metadata['start_time_str']}")
        report.append(f"{list_item}Analyzed Data Range: {code_wrapper}{first_timestamp}{code_wrapper} to {code_wrapper}{last_timestamp}{code_wrapper}")
        report.append(f"{list_item}Total Duration: {duration}")
        report.append(f"{list_item}Total Requests: {total_requests}")
        report.append(f"{list_item}Measurement Interval: {metadata['interval_seconds']} seconds")
        report.append(f"{list_item}CURL Timeout: {metadata['curl_timeout']} seconds")
        report.append(f"{list_item}User-Agent: {metadata['user_agent']}")
        report.append(f"{list_item}分析脚本主机名: {code_wrapper}{metadata['analysis_hostname']}{code_wrapper}")
        report.append(f"{list_item}Analysis Script Timezone: {metadata['analysis_timezone']}")
        report.append("")
        
        report.append(f"{section_prefix}Overall Statistics")
        report.append(f"{list_item}Total Requests: {total_requests}")
        report.append(f"{list_item}Successful Requests: {success_count}")
        report.append(f"{list_item}Failed Requests: {error_count}")
        report.append(f"{list_item}Success Rate: {bold_wrapper}{success_rate:.2f}%{bold_wrapper}")
        report.append(f"{list_item}Error Rate: {bold_wrapper}{error_rate:.2f}%{bold_wrapper}")
        report.append(f"{list_item}Average Response Time: {code_wrapper}{avg_total_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Minimum Response Time: {code_wrapper}{min_total_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Maximum Response Time: {code_wrapper}{max_total_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Average Connect Time: {code_wrapper}{avg_connect_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}Average DNS Resolution Time: {code_wrapper}{avg_dns_time:.1f} ms{code_wrapper}")
        report.append("")
        
        report.append(f"{section_prefix}Analysis Thresholds")
        if dynamic_thresholds_calculated:
            report.append(f"{list_item}Using {bold_wrapper}Dynamic Thresholds{bold_wrapper} (calculated based on initial log data):")
            report.append(f"    {list_item}Baseline Response Time: {code_wrapper}{baseline_response_time:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}Baseline Connect Time: {code_wrapper}{baseline_connect_time:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Response Time Threshold: > {code_wrapper}{current_response_time_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Connect Time Threshold: > {code_wrapper}{current_connect_time_threshold:.1f} ms{code_wrapper}")
        else:
            report.append(f"{list_item}Using {bold_wrapper}Fixed Thresholds{bold_wrapper} (Reason: {baseline_fallback_reason}):")
            report.append(f"    {list_item}High Response Time Threshold: > {code_wrapper}{current_response_time_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Connect Time Threshold: > {code_wrapper}{current_connect_time_threshold:.1f} ms{code_wrapper}")
        
        report.append(f"    {list_item}High DNS Resolution Time Threshold: > {code_wrapper}{current_dns_time_threshold:.1f} ms{code_wrapper}")
        report.append(f"    {list_item}High Error Rate Threshold: > {code_wrapper}{current_error_rate_threshold:.1f}%{code_wrapper}")
        report.append("")
        
        report.append(f"{section_prefix}Potential Problem Periods")
        if slow_response_periods or slow_connect_periods or slow_dns_periods or error_periods:
            if slow_response_periods:
                report.append(f"{subsection_prefix}Slow Response (>{current_response_time_threshold:.1f}ms) - {len(slow_response_periods)} times")
                for p in slow_response_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
            
            if slow_connect_periods:
                report.append(f"{subsection_prefix}Slow Connect (>{current_connect_time_threshold:.1f}ms) - {len(slow_connect_periods)} times")
                for p in slow_connect_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
            
            if slow_dns_periods:
                report.append(f"{subsection_prefix}Slow DNS Resolution (>{current_dns_time_threshold:.1f}ms) - {len(slow_dns_periods)} times")
                for p in slow_dns_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
            
            if error_periods:
                report.append(f"{subsection_prefix}Request Errors - {len(error_periods)} times")
                for p in error_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
        else:
            report.append(f"{list_item}No problem periods significantly exceeding thresholds were detected.")
            report.append("")
        
        report.append(f"{section_prefix}Summary")
        summary_points = []
        
        if success_rate >= 99.0:
            summary_points.append(f"Service availability is {bold_wrapper}excellent{bold_wrapper}, with a success rate of {code_wrapper}{success_rate:.2f}%{code_wrapper}.")
        elif success_rate >= 95.0:
            summary_points.append(f"Service availability is good, with a success rate of {code_wrapper}{success_rate:.2f}%{code_wrapper}.")
        elif success_rate >= 90.0:
            summary_points.append(f"Service availability is fair, with a success rate of {code_wrapper}{success_rate:.2f}%{code_wrapper}, and requires attention.")
        else:
            summary_points.append(f"Service availability is {bold_wrapper}poor{bold_wrapper}, with a success rate of only {code_wrapper}{success_rate:.2f}%{code_wrapper}, and {bold_wrapper}requires urgent attention{bold_wrapper}.")
        
        if avg_total_time < current_response_time_threshold / 3:
            summary_points.append(f"Average response time is {bold_wrapper}excellent{bold_wrapper} ({code_wrapper}{avg_total_time:.1f}ms{code_wrapper}), indicating a good user experience.")
        elif avg_total_time < current_response_time_threshold:
            summary_points.append(f"Average response time is acceptable ({code_wrapper}{avg_total_time:.1f}ms{code_wrapper}).")
        else:
            summary_points.append(f"Average response time is {bold_wrapper}slow{bold_wrapper} ({code_wrapper}{avg_total_time:.1f}ms{code_wrapper}), which may affect user experience.")
        
        if error_periods:
            summary_points.append(f"Detected {len(error_periods)} request errors, see list above for details.")
        else:
            summary_points.append("No request errors found, service stability is good.")
        
        for point in summary_points:
            report.append(f"{list_item}{point}")
    
    else:
        # Plain text report
        sep = "=" * 60
        sub_sep = "-" * 60
        list_indent = "  "
        
        report.append(sep)
        report.append(f" CURL Log Analysis Report: {metadata['target_url']}")
        report.append(sep)
        report.append("")
        
        report.append("--- Analysis Environment and Monitoring Configuration ---")
        report.append(f"{list_indent}Source Public IP (from log): {metadata['source_public_ip']}")
        report.append(f"{list_indent}Target URL:             {metadata['target_url']}")
        report.append(f"{list_indent}Log File:               {os.path.basename(log_file_path)}")
        report.append(f"{list_indent}Monitoring Start (log record): {metadata['start_time_str']}")
        report.append(f"{list_indent}Analyzed Data Range:   {first_timestamp} to {last_timestamp}")
        report.append(f"{list_indent}Total Duration:         {duration}")
        report.append(f"{list_indent}Total Requests:         {total_requests}")
        report.append(f"{list_indent}Measurement Interval:   {metadata['interval_seconds']} seconds")
        report.append(f"{list_indent}CURL Timeout:          {metadata['curl_timeout']} seconds")
        report.append(f"{list_indent}User-Agent:         {metadata['user_agent']}")
        report.append(f"{list_indent}Analysis Script Hostname: {metadata['analysis_hostname']}")
        report.append(f"{list_indent}Analysis Script Timezone: {metadata['analysis_timezone']}")
        report.append("")
        
        report.append("--- Overall Statistics ---")
        report.append(f"{list_indent}Total Requests:           {total_requests}")
        report.append(f"{list_indent}Successful Requests:      {success_count}")
        report.append(f"{list_indent}Failed Requests:          {error_count}")
        report.append(f"{list_indent}Success Rate:             {success_rate:.2f}%")
        report.append(f"{list_indent}Error Rate:               {error_rate:.2f}%")
        report.append(f"{list_indent}Average Response Time:    {avg_total_time:.1f} ms")
        report.append(f"{list_indent}Minimum Response Time:    {min_total_time:.1f} ms")
        report.append(f"{list_indent}Maximum Response Time:    {max_total_time:.1f} ms")
        report.append(f"{list_indent}Average Connect Time:     {avg_connect_time:.1f} ms")
        report.append(f"{list_indent}Average DNS Resolution Time: {avg_dns_time:.1f} ms")
        report.append("")
        
        report.append("--- Analysis Thresholds ---")
        if dynamic_thresholds_calculated:
            report.append(f"{list_indent}Mode: Dynamic Thresholds (calculated based on initial log data)")
            report.append(f"{list_indent}  - Baseline Response Time:   {baseline_response_time:.1f} ms")
            report.append(f"{list_indent}  - Baseline Connect Time:   {baseline_connect_time:.1f} ms")
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High Response Time:     > {current_response_time_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Connect Time:     > {current_connect_time_threshold:.1f} ms")
        else:
            report.append(f"{list_indent}Mode: Fixed Thresholds (Reason: {baseline_fallback_reason})")
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High Response Time:     > {current_response_time_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Connect Time:     > {current_connect_time_threshold:.1f} ms")
        
        report.append(f"{list_indent}  - High DNS Resolution Time:  > {current_dns_time_threshold:.1f} ms")
        report.append(f"{list_indent}  - High Error Rate:       > {current_error_rate_threshold:.1f}%")
        report.append("")
        
        report.append("--- Potential Problem Periods ---")
        if slow_response_periods or slow_connect_periods or slow_dns_periods or error_periods:
            if slow_response_periods:
                report.append(f"{list_indent}Slow Response (>{current_response_time_threshold:.1f}ms) - {len(slow_response_periods)} times:")
                for p in slow_response_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
            
            if slow_connect_periods:
                report.append(f"{list_indent}Slow Connect (>{current_connect_time_threshold:.1f}ms) - {len(slow_connect_periods)} times:")
                for p in slow_connect_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
            
            if slow_dns_periods:
                report.append(f"{list_indent}Slow DNS Resolution (>{current_dns_time_threshold:.1f}ms) - {len(slow_dns_periods)} times:")
                for p in slow_dns_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
            
            if error_periods:
                report.append(f"{list_indent}Request Errors - {len(error_periods)} times:")
                for p in error_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
        else:
            report.append(f"{list_indent}No problem periods significantly exceeding thresholds were detected.")
            report.append("")
        
        report.append("--- Summary ---")
        summary_points = []
        
        if success_rate >= 99.0:
            summary_points.append(f"Service availability is excellent, with a success rate of {success_rate:.2f}%.")
        elif success_rate >= 95.0:
            summary_points.append(f"Service availability is good, with a success rate of {success_rate:.2f}%.")
        elif success_rate >= 90.0:
            summary_points.append(f"Service availability is fair, with a success rate of {success_rate:.2f}%, and requires attention.")
        else:
            summary_points.append(f"Service availability is poor, with a success rate of only {success_rate:.2f}%, and requires urgent attention.")
        
        if avg_total_time < current_response_time_threshold / 3:
            summary_points.append(f"Average response time is excellent ({avg_total_time:.1f}ms), indicating a good user experience.")
        elif avg_total_time < current_response_time_threshold:
            summary_points.append(f"Average response time is acceptable ({avg_total_time:.1f}ms)." )
        else:
            summary_points.append(f"Average response time is slow ({avg_total_time:.1f}ms), which may affect user experience.")
        
        if error_periods:
            summary_points.append(f"Detected {len(error_periods)} request errors, see list above for details.")
        else:
            summary_points.append("No request errors found, service stability is good.")
        
        for point in summary_points:
            report.append(f"{list_indent}{point}")
        
        report.append("")
        report.append(sep)
    
    return "\n".join(report)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <curl_log_file_path> [--markdown]")
        print("Examples:")
        print(f"  {sys.argv[0]} curl_monitor_https___www_google_com.log")
        print(f"  {sys.argv[0]} curl_monitor_https___www_google_com.log --markdown")
        sys.exit(1)
    
    log_file_path = sys.argv[1]
    markdown_format = '--markdown' in sys.argv
    
    if not os.path.exists(log_file_path):
        print(f"Error: Log file not found: {log_file_path}")
        sys.exit(1)
    
    print(f"Analyzing log file: {log_file_path}")
    if markdown_format:
        print("Output format: Markdown")
    else:
        print("Output format: Plain Text")
    print()
    
    result = analyze_curl_log(log_file_path, markdown_format)
    print(result)

if __name__ == "__main__":
    main()