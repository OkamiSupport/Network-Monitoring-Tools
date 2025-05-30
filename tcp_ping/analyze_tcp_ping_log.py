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
# Connection success rate threshold
LOW_SUCCESS_THRESHOLD = 95.0 # (%)
# Latency threshold
HIGH_LATENCY_THRESHOLD = 100.0 # Fixed average RTT threshold (ms)
# Jitter threshold (multiple metrics)
HIGH_JITTER_THRESHOLD_STDDEV = 50.0 # Fixed Jitter StdDev value threshold (ms)
HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO = 3.0 # Fixed Jitter Max/Avg ratio threshold

# --- Dynamic Baseline Calculation Parameters ---
MAX_BASELINE_CANDIDATES = 100 # Maximum number of initial records to use for baseline calculation
MIN_BASELINE_SAMPLES = 20    # Minimum number of stable samples required to calculate baseline
STABLE_SUCCESS_THRESHOLD = 98.0  # Lower limit of success rate for defining a stable record (%)

# --- Dynamic Threshold Calculation Parameters ---
# Latency
DYNAMIC_LATENCY_FACTOR = 1.5   # Average RTT baseline multiplier
DYNAMIC_LATENCY_OFFSET = 10.0  # Fixed RTT offset (ms)
MIN_DYNAMIC_LATENCY_THRESHOLD = 30.0 # Minimum dynamically calculated latency threshold (ms)
# Jitter (Standard Deviation)
DYNAMIC_JITTER_STDDEV_FACTOR = 2.0 # StdDev Jitter baseline multiplier
DYNAMIC_JITTER_RTT_RATIO = 0.3   # StdDev ratio to average RTT factor
MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD = 10.0 # Minimum dynamically calculated StdDev Jitter threshold (ms)
# DYNAMIC_JITTER_MAX_AVG_RATIO remains fixed

# --- Functions to get system information ---
def get_hostname():
    try: return socket.gethostname()
    except socket.error as e: print(f"Warning: Unable to get hostname: {e}", file=sys.stderr); return "Unknown (Unable to fetch)"

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

# --- Function to parse TCP Ping log lines ---
def parse_tcp_log_line(line):
    """Parse data lines from TCP Ping log"""
    # Regex to match log data line format
    # Timestamp | Attempted | Success | Failure | Success(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev RTT(ms)
    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s*\|\s*" # 1: Timestamp
        r"(\d+)\s*\|\s*"                                   # 2: Attempted
        r"(\d+)\s*\|\s*"                                   # 3: Success
        r"(\d+)\s*\|\s*"                                   # 4: Failure
        r"([\d.]+)\s*\|\s*"                                # 5: Success %
        r"([\d.nan]+)\s*\|\s*"                             # 6: Min RTT (allow 'nan')
        r"([\d.nan]+)\s*\|\s*"                             # 7: Avg RTT (allow 'nan')
        r"([\d.nan]+)\s*\|\s*"                             # 8: Max RTT (allow 'nan')
        r"([\d.nan]+)$"                                    # 9: StdDev RTT (allow 'nan')
    )
    match = pattern.match(line)
    if match:
        try:
            # Helper function to handle floats that might be 'nan'
            def safe_float(value):
                return float(value) if value.lower() != 'nan' else math.nan

            timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
            attempted = int(match.group(2))
            success = int(match.group(3))
            failure = int(match.group(4))
            success_perc = safe_float(match.group(5))
            min_rtt = safe_float(match.group(6))
            avg_rtt = safe_float(match.group(7))
            max_rtt = safe_float(match.group(8))
            stddev_rtt = safe_float(match.group(9))

            return {
                'timestamp': timestamp,
                'attempted': attempted,
                'success': success,
                'failure': failure,
                'success_perc': success_perc,
                'min_rtt': min_rtt,
                'avg_rtt': avg_rtt,
                'max_rtt': max_rtt,
                'stddev_rtt': stddev_rtt
            }
        except (ValueError, IndexError) as e:
            print(f"Warning: Error parsing line: {line.strip()} - {e}", file=sys.stderr)
            return None
    return None

def analyze_tcp_ping_log(log_file_path):
    """Analyze TCP Ping log file and generate report"""
    
    # Initialize variables
    log_entries = []
    metadata = {}
    
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{log_file_path}' not found.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error reading log file '{log_file_path}': {e}", file=sys.stderr)
        return None

    # Parse log header and extract metadata
    header_parsing = True
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if header_parsing:
            # Parse header information
            if line.startswith("Target Host:"):
                metadata['target_host'] = line.split(":", 1)[1].strip()
            elif line.startswith("Target Port:"):
                metadata['target_port'] = line.split(":", 1)[1].strip()
            elif line.startswith("Server Source Public IP:"):
                metadata['source_ip'] = line.split(":", 1)[1].strip()
            elif line.startswith("Monitoring started at:"):
                metadata['start_time'] = line.split(":", 1)[1].strip()
            elif line.startswith("TCP connection attempts per measurement:"):
                metadata['attempts_per_cycle'] = line.split(":", 1)[1].strip()
            elif line.startswith("Measurement interval:"):
                metadata['interval'] = line.split(":", 1)[1].strip()
            elif line.startswith("TCP connection timeout:"):
                metadata['timeout'] = line.split(":", 1)[1].strip()
            elif "Attempted | Success | Failure" in line:
                header_parsing = False
                continue
        else:
            # Parse data lines
            parsed_entry = parse_tcp_log_line(line)
            if parsed_entry:
                log_entries.append(parsed_entry)

    if not log_entries:
        print("Warning: No valid data entries found in the log file.", file=sys.stderr)
        return None

    # Dynamic baseline and threshold calculation
    baseline_candidates = log_entries[:MAX_BASELINE_CANDIDATES]
    stable_entries = [entry for entry in baseline_candidates 
                     if not math.isnan(entry['success_perc']) and entry['success_perc'] >= STABLE_SUCCESS_THRESHOLD]
    
    dynamic_thresholds = {}
    baseline_fallback_reason = None
    
    if len(stable_entries) >= MIN_BASELINE_SAMPLES:
        # Calculate dynamic baselines
        stable_avg_rtts = [entry['avg_rtt'] for entry in stable_entries 
                          if not math.isnan(entry['avg_rtt'])]
        stable_stddev_rtts = [entry['stddev_rtt'] for entry in stable_entries 
                             if not math.isnan(entry['stddev_rtt'])]
        
        if stable_avg_rtts:
            baseline_avg_rtt = statistics.mean(stable_avg_rtts)
            dynamic_thresholds['latency'] = max(
                baseline_avg_rtt * DYNAMIC_LATENCY_FACTOR + DYNAMIC_LATENCY_OFFSET,
                MIN_DYNAMIC_LATENCY_THRESHOLD
            )
        
        if stable_stddev_rtts:
            baseline_stddev_rtt = statistics.mean(stable_stddev_rtts)
            dynamic_thresholds['jitter_stddev'] = max(
                baseline_stddev_rtt * DYNAMIC_JITTER_STDDEV_FACTOR,
                MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD
            )
            
            # Alternative calculation using RTT ratio
            if stable_avg_rtts:
                baseline_avg_rtt = statistics.mean(stable_avg_rtts)
                alt_jitter_threshold = baseline_avg_rtt * DYNAMIC_JITTER_RTT_RATIO
                dynamic_thresholds['jitter_stddev'] = max(
                    dynamic_thresholds['jitter_stddev'],
                    alt_jitter_threshold
                )
    else:
        # Fallback to fixed thresholds
        baseline_fallback_reason = f"Insufficient stable samples (found {len(stable_entries)}, need {MIN_BASELINE_SAMPLES})"
        dynamic_thresholds['latency'] = HIGH_LATENCY_THRESHOLD
        dynamic_thresholds['jitter_stddev'] = HIGH_JITTER_THRESHOLD_STDDEV

    # Analysis logic
    total_entries = len(log_entries)
    
    # Overall statistics
    all_attempted = [entry['attempted'] for entry in log_entries if not math.isnan(entry['attempted'])]
    all_success = [entry['success'] for entry in log_entries if not math.isnan(entry['success'])]
    all_failure = [entry['failure'] for entry in log_entries if not math.isnan(entry['failure'])]
    all_success_rates = [entry['success_perc'] for entry in log_entries if not math.isnan(entry['success_perc'])]
    all_avg_rtts = [entry['avg_rtt'] for entry in log_entries if not math.isnan(entry['avg_rtt'])]
    all_min_rtts = [entry['min_rtt'] for entry in log_entries if not math.isnan(entry['min_rtt'])]
    all_max_rtts = [entry['max_rtt'] for entry in log_entries if not math.isnan(entry['max_rtt'])]
    all_stddev_rtts = [entry['stddev_rtt'] for entry in log_entries if not math.isnan(entry['stddev_rtt'])]
    
    overall_stats = {
        'total_attempted': sum(all_attempted) if all_attempted else 0,
        'total_success': sum(all_success) if all_success else 0,
        'total_failure': sum(all_failure) if all_failure else 0,
        'overall_success_rate': (sum(all_success) / sum(all_attempted) * 100) if all_attempted and sum(all_attempted) > 0 else 0,
        'avg_success_rate': statistics.mean(all_success_rates) if all_success_rates else 0,
        'min_success_rate': min(all_success_rates) if all_success_rates else 0,
        'avg_rtt_mean': statistics.mean(all_avg_rtts) if all_avg_rtts else 0,
        'avg_rtt_min': min(all_avg_rtts) if all_avg_rtts else 0,
        'avg_rtt_max': max(all_avg_rtts) if all_avg_rtts else 0,
        'global_min_rtt': min(all_min_rtts) if all_min_rtts else 0,
        'global_max_rtt': max(all_max_rtts) if all_max_rtts else 0,
        'avg_jitter': statistics.mean(all_stddev_rtts) if all_stddev_rtts else 0
    }
    
    # Find periods exceeding thresholds
    threshold_violations = []
    
    for entry in log_entries:
        violations = []
        
        # Check success rate
        if not math.isnan(entry['success_perc']) and entry['success_perc'] < LOW_SUCCESS_THRESHOLD:
            violations.append(f"Low success rate: {entry['success_perc']:.1f}% (threshold: {LOW_SUCCESS_THRESHOLD}%)")
        
        # Check latency
        latency_threshold = dynamic_thresholds.get('latency', HIGH_LATENCY_THRESHOLD)
        if not math.isnan(entry['avg_rtt']) and entry['avg_rtt'] > latency_threshold:
            violations.append(f"High latency: {entry['avg_rtt']:.2f}ms (threshold: {latency_threshold:.2f}ms)")
        
        # Check jitter (StdDev)
        jitter_threshold = dynamic_thresholds.get('jitter_stddev', HIGH_JITTER_THRESHOLD_STDDEV)
        if not math.isnan(entry['stddev_rtt']) and entry['stddev_rtt'] > jitter_threshold:
            violations.append(f"High jitter (StdDev): {entry['stddev_rtt']:.2f}ms (threshold: {jitter_threshold:.2f}ms)")
        
        # Check Max/Avg ratio
        if (not math.isnan(entry['max_rtt']) and not math.isnan(entry['avg_rtt']) and 
            entry['avg_rtt'] > 0 and (entry['max_rtt'] / entry['avg_rtt']) > HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO):
            violations.append(f"High Max/Avg ratio: {entry['max_rtt'] / entry['avg_rtt']:.2f} (threshold: {HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO})")
        
        if violations:
            threshold_violations.append({
                'timestamp': entry['timestamp'],
                'violations': violations
            })
    
    # End analysis logic
    
    return {
        'metadata': metadata,
        'total_entries': total_entries,
        'overall_stats': overall_stats,
        'threshold_violations': threshold_violations,
        'dynamic_thresholds': dynamic_thresholds,
        'baseline_fallback_reason': baseline_fallback_reason,
        'log_entries': log_entries
    }

def generate_report(analysis_result, output_format='markdown'):
    """Generate analysis report in specified format"""
    
    if not analysis_result:
        return "Error: No analysis result to generate report from."
    
    metadata = analysis_result['metadata']
    total_entries = analysis_result['total_entries']
    overall_stats = analysis_result['overall_stats']
    threshold_violations = analysis_result['threshold_violations']
    dynamic_thresholds = analysis_result['dynamic_thresholds']
    baseline_fallback_reason = analysis_result['baseline_fallback_reason']
    
    if output_format.lower() == 'markdown':
        # Markdown format report
        report = []
        report.append("# TCP Connection Monitoring Analysis Report")
        report.append("")
        
        # Metadata section
        report.append("## Analysis Metadata")
        report.append(f"- **Analysis Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"- **Analyzer Host**: {get_hostname()}")
        report.append(f"- **Analyzer Timezone**: {get_timezone_info()}")
        report.append("")
        
        # Log information
        report.append("## Log Information")
        for key, value in metadata.items():
            formatted_key = key.replace('_', ' ').title()
            report.append(f"- **{formatted_key}**: {value}")
        report.append(f"- **Total Data Points**: {total_entries}")
        report.append("")
        
        # Threshold information
        report.append("## Threshold Configuration")
        if baseline_fallback_reason:
            report.append(f"- **Dynamic Baseline**: Failed ({baseline_fallback_reason})")
            report.append("- **Threshold Mode**: Fixed thresholds")
        else:
            report.append("- **Dynamic Baseline**: Successfully calculated")
            report.append("- **Threshold Mode**: Dynamic thresholds")
        
        report.append(f"- **Success Rate Threshold**: {LOW_SUCCESS_THRESHOLD}%")
        report.append(f"- **Latency Threshold**: {dynamic_thresholds.get('latency', HIGH_LATENCY_THRESHOLD):.2f}ms")
        report.append(f"- **Jitter (StdDev) Threshold**: {dynamic_thresholds.get('jitter_stddev', HIGH_JITTER_THRESHOLD_STDDEV):.2f}ms")
        report.append(f"- **Max/Avg Ratio Threshold**: {HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO}")
        report.append("")
        
        # Overall statistics
        report.append("## Overall Statistics")
        report.append(f"- **Total Connection Attempts**: {overall_stats['total_attempted']}")
        report.append(f"- **Total Successful Connections**: {overall_stats['total_success']}")
        report.append(f"- **Total Failed Connections**: {overall_stats['total_failure']}")
        report.append(f"- **Overall Success Rate**: {overall_stats['overall_success_rate']:.2f}%")
        report.append(f"- **Average Success Rate**: {overall_stats['avg_success_rate']:.2f}%")
        report.append(f"- **Minimum Success Rate**: {overall_stats['min_success_rate']:.2f}%")
        report.append(f"- **Average RTT (Mean)**: {overall_stats['avg_rtt_mean']:.2f}ms")
        report.append(f"- **Average RTT (Range)**: {overall_stats['avg_rtt_min']:.2f}ms - {overall_stats['avg_rtt_max']:.2f}ms")
        report.append(f"- **Global RTT Range**: {overall_stats['global_min_rtt']:.2f}ms - {overall_stats['global_max_rtt']:.2f}ms")
        report.append(f"- **Average Jitter (StdDev)**: {overall_stats['avg_jitter']:.2f}ms")
        report.append("")
        
        # Threshold violations
        report.append("## Threshold Violations")
        if threshold_violations:
            report.append(f"Found **{len(threshold_violations)}** periods with threshold violations:")
            report.append("")
            for i, violation in enumerate(threshold_violations[:20], 1):  # Limit to first 20
                report.append(f"### Violation {i}")
                report.append(f"- **Time**: {violation['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                report.append("- **Issues**:")
                for issue in violation['violations']:
                    report.append(f"  - {issue}")
                report.append("")
            
            if len(threshold_violations) > 20:
                report.append(f"... and {len(threshold_violations) - 20} more violations (truncated for brevity)")
                report.append("")
        else:
            report.append("No threshold violations detected. ✅")
            report.append("")
        
        # Summary
        report.append("## Summary")
        if threshold_violations:
            violation_rate = len(threshold_violations) / total_entries * 100
            report.append(f"- **Connection Quality**: Issues detected ({violation_rate:.1f}% of measurements had violations)")
            report.append("- **Recommendation**: Investigate network connectivity and performance")
        else:
            report.append("- **Connection Quality**: Excellent (no threshold violations)")
            report.append("- **Recommendation**: Current network performance is within acceptable parameters")
        
        return "\n".join(report)
    
    else:
        # Plain text format report
        report = []
        report.append("TCP CONNECTION MONITORING ANALYSIS REPORT")
        report.append("=" * 50)
        report.append("")
        
        # Metadata section
        report.append("ANALYSIS METADATA:")
        report.append(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Analyzer Host: {get_hostname()}")
        report.append(f"Analyzer Timezone: {get_timezone_info()}")
        report.append("")
        
        # Log information
        report.append("LOG INFORMATION:")
        for key, value in metadata.items():
            formatted_key = key.replace('_', ' ').title()
            report.append(f"{formatted_key}: {value}")
        report.append(f"Total Data Points: {total_entries}")
        report.append("")
        
        # Threshold information
        report.append("THRESHOLD CONFIGURATION:")
        if baseline_fallback_reason:
            report.append(f"Dynamic Baseline: Failed ({baseline_fallback_reason})")
            report.append("Threshold Mode: Fixed thresholds")
        else:
            report.append("Dynamic Baseline: Successfully calculated")
            report.append("Threshold Mode: Dynamic thresholds")
        
        report.append(f"Success Rate Threshold: {LOW_SUCCESS_THRESHOLD}%")
        report.append(f"Latency Threshold: {dynamic_thresholds.get('latency', HIGH_LATENCY_THRESHOLD):.2f}ms")
        report.append(f"Jitter (StdDev) Threshold: {dynamic_thresholds.get('jitter_stddev', HIGH_JITTER_THRESHOLD_STDDEV):.2f}ms")
        report.append(f"Max/Avg Ratio Threshold: {HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO}")
        report.append("")
        
        # Overall statistics
        report.append("OVERALL STATISTICS:")
        report.append(f"Total Connection Attempts: {overall_stats['total_attempted']}")
        report.append(f"Total Successful Connections: {overall_stats['total_success']}")
        report.append(f"Total Failed Connections: {overall_stats['total_failure']}")
        report.append(f"Overall Success Rate: {overall_stats['overall_success_rate']:.2f}%")
        report.append(f"Average Success Rate: {overall_stats['avg_success_rate']:.2f}%")
        report.append(f"Minimum Success Rate: {overall_stats['min_success_rate']:.2f}%")
        report.append(f"Average RTT (Mean): {overall_stats['avg_rtt_mean']:.2f}ms")
        report.append(f"Average RTT (Range): {overall_stats['avg_rtt_min']:.2f}ms - {overall_stats['avg_rtt_max']:.2f}ms")
        report.append(f"Global RTT Range: {overall_stats['global_min_rtt']:.2f}ms - {overall_stats['global_max_rtt']:.2f}ms")
        report.append(f"Average Jitter (StdDev): {overall_stats['avg_jitter']:.2f}ms")
        report.append("")
        
        # Threshold violations
        report.append("THRESHOLD VIOLATIONS:")
        if threshold_violations:
            report.append(f"Found {len(threshold_violations)} periods with threshold violations:")
            report.append("")
            for i, violation in enumerate(threshold_violations[:20], 1):  # Limit to first 20
                report.append(f"Violation {i}:")
                report.append(f"  Time: {violation['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                report.append("  Issues:")
                for issue in violation['violations']:
                    report.append(f"    - {issue}")
                report.append("")
            
            if len(threshold_violations) > 20:
                report.append(f"... and {len(threshold_violations) - 20} more violations (truncated for brevity)")
                report.append("")
        else:
            report.append("No threshold violations detected.")
            report.append("")
        
        # Summary
        report.append("SUMMARY:")
        if threshold_violations:
            violation_rate = len(threshold_violations) / total_entries * 100
            report.append(f"Connection Quality: Issues detected ({violation_rate:.1f}% of measurements had violations)")
            report.append("Recommendation: Investigate network connectivity and performance")
        else:
            report.append("Connection Quality: Excellent (no threshold violations)")
            report.append("Recommendation: Current network performance is within acceptable parameters")
        
        return "\n".join(report)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <tcp_ping_log_file> [output_format]")
        print("Output formats: markdown (default), text")
        print(f"Example: {sys.argv[0]} tcp_monitor_google_com_80.log")
        print(f"Example: {sys.argv[0]} tcp_monitor_google_com_80.log markdown")
        sys.exit(1)
    
    log_file_path = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else 'markdown'
    
    if not os.path.exists(log_file_path):
        print(f"Error: Log file '{log_file_path}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Analyzing TCP ping log: {log_file_path}")
    analysis_result = analyze_tcp_ping_log(log_file_path)
    
    if analysis_result:
        report = generate_report(analysis_result, output_format)
        print("\n" + report)
    else:
        print("Failed to analyze the log file.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()