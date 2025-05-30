#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
from datetime import datetime
import statistics
import socket
import time
import os

# --- Configurable Thresholds (Fixed Thresholds - as a fallback option) ---
HIGH_LOSS_THRESHOLD = 1.0 # Packet loss rate threshold remains fixed, not dynamically calculated
HIGH_LATENCY_THRESHOLD = 100.0 # Fixed latency threshold (ms)
HIGH_JITTER_THRESHOLD_STDDEV = 50.0 # Fixed jitter standard deviation threshold (ms)
HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO = 3.0 # Fixed jitter Max/Avg ratio threshold

# --- Dynamic Baseline Calculation Parameters ---
MAX_BASELINE_CANDIDATES = 100
MIN_BASELINE_SAMPLES = 20
STABLE_LOSS_THRESHOLD = 0.5

# --- Dynamic Threshold Calculation Parameters ---
DYNAMIC_LATENCY_FACTOR = 1.5
DYNAMIC_LATENCY_OFFSET = 10.0
MIN_DYNAMIC_LATENCY_THRESHOLD = 30.0

DYNAMIC_JITTER_STDDEV_FACTOR = 2.0
DYNAMIC_JITTER_RTT_RATIO = 0.3
MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD = 10.0
# DYNAMIC_JITTER_MAX_AVG_RATIO remains fixed

# --- Functions to Get System Information (unchanged) ---
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

# --- Function to Parse Log Lines (unchanged) ---
def parse_log_line(line):
    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s*\|\s*"
        r"(\d+)\s*\|\s*"
        r"(\d+)\s*\|\s*"
        r"([\d.]+)\s*\|\s*"
        r"([\d.]+)\s*\|\s*"
        r"([\d.]+)\s*\|\s*"
        r"([\d.]+)\s*\|\s*"
        r"([\d.]+)$"
    )
    match = pattern.match(line)
    if match:
        try:
            timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
            return { "timestamp": timestamp, "sent": int(match.group(2)), "received": int(match.group(3)),
                     "loss_perc": float(match.group(4)), "min_rtt": float(match.group(5)), "avg_rtt": float(match.group(6)),
                     "max_rtt": float(match.group(7)), "stddev_rtt": float(match.group(8)) }
        except (ValueError, IndexError) as e: print(f"Warning: Error parsing data line: {line.strip()} - {e}", file=sys.stderr); return None
    return None

# --- Main Analysis and Report Generation Function ---
def analyze_ping_log(log_file_path, markdown_format=False):
    """Analyze ping log file and generate report content (text or Markdown)"""

    analysis_hostname = get_hostname()
    analysis_timezone = get_timezone_info()

    metadata = {
        "target_ip": "Unknown", "source_public_ip": "Unknown (Not found in log)",
        "start_time_str": "Unknown", "packets_per_measurement": "Unknown",
        "interval_seconds": "Unknown", "timeout_seconds": "Unknown",
        "analysis_hostname": analysis_hostname, "analysis_timezone": analysis_timezone,
    }
    data_records = []
    header_parsed = False
    data_section_started = False

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip();
                if not line: continue
                if not header_parsed:
                    match_source_ip = re.match(r".*Server Source Public IP:\s*(.*)", line);
                    if match_source_ip: metadata["source_public_ip"] = match_source_ip.group(1).strip(); continue
                    match_ip = re.match(r".*Target IP:\s*(.*)", line);
                    if match_ip: metadata["target_ip"] = match_ip.group(1).strip(); continue
                    match_start = re.match(r".*Monitoring started at:\s*(.*)", line);
                    if match_start: metadata["start_time_str"] = match_start.group(1).strip(); continue
                    match_packets = re.match(r".*PING packets per measurement:\s*(.*)", line);
                    if match_packets: metadata["packets_per_measurement"] = match_packets.group(1).strip(); continue
                    match_interval = re.match(r".*Measurement interval:\s*(\d+)\s*seconds", line);
                    if match_interval: metadata["interval_seconds"] = match_interval.group(1).strip(); continue
                    match_timeout = re.match(r".*Ping timeout:\s*(\d+)\s*seconds", line);
                    if match_timeout: metadata["timeout_seconds"] = match_timeout.group(1).strip(); continue
                    if "---" in line:
                        if data_section_started: header_parsed = True
                        else: data_section_started = True
                        continue
                    if "Sent | Received | Loss(%)" in line:
                         data_section_started = True; header_parsed = True; continue
                if header_parsed:
                    record = parse_log_line(line)
                    if record: data_records.append(record)
    except FileNotFoundError: return f"Error: File not found: {log_file_path}"
    except Exception as e: return f"Error: An exception occurred while reading or parsing the file: {e}"

    if not data_records: return f"Error: No valid data records found in file {log_file_path}."

    # --- Dynamic Baseline and Threshold Calculation (logic unchanged) ---
    baseline_rtt, baseline_stddev = None, None
    dynamic_thresholds_calculated = False
    baseline_fallback_reason = ""
    stable_initial_records = [r for r in data_records[:MAX_BASELINE_CANDIDATES] if r['loss_perc'] <= STABLE_LOSS_THRESHOLD]

    if len(stable_initial_records) >= MIN_BASELINE_SAMPLES:
        try:
            baseline_rtt = statistics.mean(r['avg_rtt'] for r in stable_initial_records)
            baseline_stddev = statistics.mean(r['stddev_rtt'] for r in stable_initial_records)
            dynamic_thresholds_calculated = True
            current_latency_threshold = max(baseline_rtt * DYNAMIC_LATENCY_FACTOR + DYNAMIC_LATENCY_OFFSET, MIN_DYNAMIC_LATENCY_THRESHOLD)
            current_jitter_stddev_threshold = max(baseline_stddev * DYNAMIC_JITTER_STDDEV_FACTOR, baseline_rtt * DYNAMIC_JITTER_RTT_RATIO, MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD)
            current_jitter_max_avg_ratio = HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO
        except statistics.StatisticsError as e:
            dynamic_thresholds_calculated = False; baseline_fallback_reason = f"Baseline statistics calculation error: {e}"
    else:
        dynamic_thresholds_calculated = False
        if len(data_records) < MIN_BASELINE_SAMPLES: baseline_fallback_reason = f"Insufficient log data (less than {MIN_BASELINE_SAMPLES} entries)"
        else: baseline_fallback_reason = f"Insufficient stable samples in the initial {MAX_BASELINE_CANDIDATES} log entries (< {MIN_BASELINE_SAMPLES} entries, stable loss rate <= {STABLE_LOSS_THRESHOLD}%)"

    if not dynamic_thresholds_calculated:
        current_latency_threshold = HIGH_LATENCY_THRESHOLD
        current_jitter_stddev_threshold = HIGH_JITTER_THRESHOLD_STDDEV
        current_jitter_max_avg_ratio = HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO
    current_loss_threshold = HIGH_LOSS_THRESHOLD
    # --- End of Dynamic Baseline and Threshold Calculation ---

    # --- Analysis Logic (logic unchanged) ---
    total_measurements = len(data_records)
    first_timestamp = data_records[0]['timestamp']; last_timestamp = data_records[-1]['timestamp']
    duration = last_timestamp - first_timestamp
    total_sent = sum(r['sent'] for r in data_records); total_received = sum(r['received'] for r in data_records)
    overall_loss_perc = ((total_sent - total_received) / total_sent) * 100.0 if total_sent > 0 else 0.0
    all_avg_rtts = [r['avg_rtt'] for r in data_records]; all_min_rtts = [r['min_rtt'] for r in data_records]
    all_max_rtts = [r['max_rtt'] for r in data_records]; all_stddev_rtts = [r['stddev_rtt'] for r in data_records]
    overall_avg_rtt = statistics.mean(all_avg_rtts) if all_avg_rtts else 0.0; overall_min_rtt = min(all_min_rtts) if all_min_rtts else 0.0
    overall_max_rtt = max(all_max_rtts) if all_max_rtts else 0.0; overall_avg_stddev_rtt = statistics.mean(all_stddev_rtts) if all_stddev_rtts else 0.0
    high_loss_periods, high_latency_periods, high_jitter_periods = [], [], []
    for r in data_records:
        ts = r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        if r['loss_perc'] > current_loss_threshold: high_loss_periods.append(f"{ts} (Loss rate: {r['loss_perc']:.1f}%)")
        if r['avg_rtt'] > current_latency_threshold: high_latency_periods.append(f"{ts} (Avg RTT: {r['avg_rtt']:.1f}ms)")
        jit_std = r['stddev_rtt'] > current_jitter_stddev_threshold; jit_rat = (r['avg_rtt'] > 0 and (r['max_rtt']/r['avg_rtt']) > current_jitter_max_avg_ratio)
        if jit_std or jit_rat:
            rea = []; md_rea = []
            if jit_std: rea.append(f"StdDev={r['stddev_rtt']:.1f}ms"); md_rea.append(f"StdDev=`{r['stddev_rtt']:.1f}ms`")
            if jit_rat: rea.append(f"Max/Avg Ratio={(r['max_rtt'] / r['avg_rtt']):.1f}"); md_rea.append(f"Max/Avg Ratio=`{(r['max_rtt'] / r['avg_rtt']):.1f}`")
            # Store different reason strings based on format
            high_jitter_periods.append({"ts": ts, "reason": ', '.join(rea), "md_reason": ', '.join(md_rea)})
    # --- End of Analysis Logic ---


    # --- Generate Report Content ---
    report = []
    if markdown_format:
        # --- Markdown Report Generation (keep previous logic) ---
        sep_line = "---"; title_prefix = "# "; section_prefix = "## "; subsection_prefix = "### "
        list_item = "*   "; code_wrapper = "`"; bold_wrapper = "**"

        report.append(f"{title_prefix}Ping Log Analysis Report: {code_wrapper}{metadata['target_ip']}{code_wrapper}")
        report.append(sep_line)
        report.append(f"{section_prefix}Analysis Environment and Monitoring Configuration")
        report.append(f"{list_item}{bold_wrapper}Source Public IP (from log):{bold_wrapper} {code_wrapper}{metadata['source_public_ip']}{code_wrapper}")
        report.append(f"{list_item}{bold_wrapper}Target IP:{bold_wrapper} {code_wrapper}{metadata['target_ip']}{code_wrapper}")
        report.append(f"{list_item}Log File: {code_wrapper}{os.path.basename(log_file_path)}{code_wrapper}")
        report.append(f"{list_item}Monitoring Start (Log Record): {metadata['start_time_str']}")
        report.append(f"{list_item}Analysis Data Range: {code_wrapper}{first_timestamp}{code_wrapper} to {code_wrapper}{last_timestamp}{code_wrapper}")
        report.append(f"{list_item}Total Duration: {duration}")
        report.append(f"{list_item}Total Measurements: {total_measurements}")
        report.append(f"{list_item}Packets per Measurement: {metadata['packets_per_measurement']}")
        report.append(f"{list_item}Measurement Interval: {metadata['interval_seconds']} seconds")
        report.append(f"{list_item}Ping Timeout: {metadata['timeout_seconds']} seconds")
        report.append(f"{list_item}Analysis Script Hostname: {code_wrapper}{metadata['analysis_hostname']}{code_wrapper}")
        report.append(f"{list_item}Analysis Script Timezone: {metadata['analysis_timezone']}")
        report.append("")
        report.append(f"{section_prefix}Overall Statistics")
        report.append(f"{list_item}Total Sent/Received: {total_sent} / {total_received}")
        report.append(f"{list_item}Overall Average Packet Loss: {bold_wrapper}{overall_loss_perc:.2f}%{bold_wrapper}")
        report.append(f"{list_item}Overall Average RTT: {code_wrapper}{overall_avg_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}Overall Minimum RTT: {code_wrapper}{overall_min_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}Overall Maximum RTT: {code_wrapper}{overall_max_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}Overall Average Jitter (StdDev): {code_wrapper}{overall_avg_stddev_rtt:.3f} ms{code_wrapper}")
        report.append("")
        report.append(f"{section_prefix}Analysis Thresholds")
        if dynamic_thresholds_calculated:
            report.append(f"{list_item}Using {bold_wrapper}Dynamic Thresholds{bold_wrapper} (calculated from initial log data):")
            report.append(f"    {list_item}Baseline RTT: {code_wrapper}{baseline_rtt:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}Baseline StdDev: {code_wrapper}{baseline_stddev:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Latency Threshold: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (StdDev) Threshold: > {code_wrapper}{current_jitter_stddev_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (Max/Avg Ratio) Threshold: > {code_wrapper}{current_jitter_max_avg_ratio:.1f}{code_wrapper}")
        else:
            report.append(f"{list_item}Using {bold_wrapper}Fixed Thresholds{bold_wrapper} (Reason: {baseline_fallback_reason}):")
            report.append(f"    {list_item}High Latency Threshold: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (StdDev) Threshold: > {code_wrapper}{current_jitter_stddev_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}High Jitter (Max/Avg Ratio) Threshold: > {code_wrapper}{current_jitter_max_avg_ratio:.1f}{code_wrapper}")
        report.append(f"    {list_item}High Packet Loss Threshold: > {code_wrapper}{current_loss_threshold:.1f}%{code_wrapper}")
        report.append("")
        report.append(f"{section_prefix}Potential Problem Periods")
        if high_loss_periods or high_latency_periods or high_jitter_periods:
            if high_loss_periods:
                report.append(f"{subsection_prefix}High Packet Loss (>{current_loss_threshold:.1f}%) - {len(high_loss_periods)} occurrences")
                for p in high_loss_periods: report.append(f"{list_item}{p}")
                report.append("")
            if high_latency_periods:
                report.append(f"{subsection_prefix}High Latency (>{current_latency_threshold:.1f}ms) - {len(high_latency_periods)} occurrences")
                for p in high_latency_periods: report.append(f"{list_item}{p}")
                report.append("")
            if high_jitter_periods:
                report.append(f"{subsection_prefix}High Jitter (StdDev>{current_jitter_stddev_threshold:.1f}ms or Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} occurrences")
                # Using Markdown backticked reason string
                for p_dict in high_jitter_periods: report.append(f"{list_item}{p_dict['ts']} ({p_dict['md_reason']})")
                report.append("")
        else: report.append(f"{list_item}No significant problem periods detected exceeding thresholds."); report.append("")
        report.append(f"{section_prefix}Summary")
        summary_points = []
        if overall_loss_perc == 0.0: summary_points.append(f"Network connectivity is excellent, {bold_wrapper}no packet loss occurred{bold_wrapper}.")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"Network connectivity is good, overall packet loss is low ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper}).")
        elif overall_loss_perc < 5.0: summary_points.append(f"Minor packet loss detected ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper}), may affect sensitive applications.")
        else: summary_points.append(f"Significant packet loss ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper}), {bold_wrapper}requires attention{bold_wrapper}.")
        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"Average latency is low ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper}), performance is {bold_wrapper}excellent{bold_wrapper}.")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"Average latency is moderate ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper}), generally acceptable.")
        else: summary_points.append(f"Average latency is high ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper}), may impact real-time interactive experience.")
        if overall_avg_stddev_rtt < current_jitter_stddev_threshold / 2 and overall_max_rtt < overall_avg_rtt * current_jitter_max_avg_ratio : summary_points.append(f"Network latency is relatively {bold_wrapper}stable{bold_wrapper}, jitter is low.")
        elif overall_avg_stddev_rtt < current_jitter_stddev_threshold: summary_points.append("Network latency shows some fluctuation.")
        else: summary_points.append(f"Network latency has {bold_wrapper}significant jitter{bold_wrapper}, stability is poor.")
        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("Potential network problem periods detected, see list above for details.")
        else: summary_points.append("Based on current thresholds, no obvious network problem periods were found.")
        for point in summary_points: report.append(f"{list_item}{point}")
        # Markdown 报告结尾不需要额外分隔符
    else:
        # --- Plain Text Report Generation (Beautified) ---
        sep = "=" * 70 # Adjusted for potentially longer English text
        sub_sep = "-" * 70
        list_indent = "  " # List item indentation

        report.append(sep)
        report.append(f" Ping Log Analysis Report: {metadata['target_ip']}")
        report.append(sep)
        report.append("") # Blank line

        report.append("--- Analysis Environment & Monitoring Configuration ---")
        report.append(f"{list_indent}Source Public IP (from log): {metadata['source_public_ip']}")
        report.append(f"{list_indent}Target IP:                   {metadata['target_ip']}")
        report.append(f"{list_indent}Log File:                    {os.path.basename(log_file_path)}")
        report.append(f"{list_indent}Monitoring Started (log time): {metadata['start_time_str']}")
        report.append(f"{list_indent}Analyzed Data Range:         {first_timestamp} to {last_timestamp}")
        report.append(f"{list_indent}Total Duration:              {duration}")
        report.append(f"{list_indent}Total Measurements:          {total_measurements}")
        report.append(f"{list_indent}Packets per Measurement:     {metadata['packets_per_measurement']}")
        report.append(f"{list_indent}Measurement Interval:        {metadata['interval_seconds']} seconds")
        report.append(f"{list_indent}Ping Timeout:                {metadata['timeout_seconds']} seconds")
        report.append(f"{list_indent}Analysis Script Hostname:    {metadata['analysis_hostname']}")
        report.append(f"{list_indent}Analysis Script Timezone:    {metadata['analysis_timezone']}")
        report.append("")

        report.append("--- Overall Statistics ---")
        report.append(f"{list_indent}Total Sent/Received:         {total_sent} / {total_received}")
        report.append(f"{list_indent}Overall Avg Packet Loss:     {overall_loss_perc:.2f}%")
        report.append(f"{list_indent}Overall Avg RTT:             {overall_avg_rtt:.3f} ms")
        report.append(f"{list_indent}Overall Min RTT:             {overall_min_rtt:.3f} ms")
        report.append(f"{list_indent}Overall Max RTT:             {overall_max_rtt:.3f} ms")
        report.append(f"{list_indent}Overall Avg Jitter (StdDev): {overall_avg_stddev_rtt:.3f} ms")
        report.append("")

        report.append("--- Analysis Thresholds ---")
        if dynamic_thresholds_calculated:
            report.append(f"{list_indent}Mode: Dynamic Thresholds (calculated from initial log data)")
            report.append(f"{list_indent}  - Baseline RTT:        {baseline_rtt:.1f} ms")
            report.append(f"{list_indent}  - Baseline StdDev:     {baseline_stddev:.1f} ms")
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High Latency:        > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (StdDev):> {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (Ratio): > {current_jitter_max_avg_ratio:.1f}")
        else:
            report.append(f"{list_indent}Mode: Fixed Thresholds (Reason: {baseline_fallback_reason})")
            report.append(f"{list_indent}Thresholds Used:")
            report.append(f"{list_indent}  - High Latency:        > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (StdDev):> {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - High Jitter (Ratio): > {current_jitter_max_avg_ratio:.1f}")
        report.append(f"{list_indent}  - High Packet Loss:    > {current_loss_threshold:.1f}%") # Packet loss always shown
        report.append("")

        report.append("--- Potential Problem Periods ---")
        if not (high_loss_periods or high_latency_periods or high_jitter_periods):
            report.append(f"{list_indent}No significant problem periods detected exceeding thresholds.")
        else:
            if high_loss_periods:
                report.append(f"\n{list_indent}High Packet Loss (>{current_loss_threshold:.1f}%) - {len(high_loss_periods)} occurrences:")
                for p in high_loss_periods: report.append(f"{list_indent}  - {p}")
            if high_latency_periods:
                report.append(f"\n{list_indent}High Latency (>{current_latency_threshold:.1f}ms) - {len(high_latency_periods)} occurrences:")
                for p in high_latency_periods: report.append(f"{list_indent}  - {p}")
            if high_jitter_periods:
                report.append(f"\n{list_indent}High Jitter (StdDev>{current_jitter_stddev_threshold:.1f}ms or Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} occurrences:")
                # Using non-Markdown reason string
                for p_dict in high_jitter_periods: report.append(f"{list_indent}  - {p_dict['ts']} ({p_dict['reason']})")
        report.append("")

        report.append("--- Summary ---")
        summary_points = []
        # (Summary text generation logic remains the same, but translated)
        if overall_loss_perc == 0.0: summary_points.append("Network connectivity is excellent, no packet loss occurred.")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"Network connectivity is good, overall packet loss is low ({overall_loss_perc:.2f}%).")
        elif overall_loss_perc < 5.0: summary_points.append(f"Minor packet loss detected ({overall_loss_perc:.2f}%), may affect sensitive applications.")
        else: summary_points.append(f"Significant packet loss ({overall_loss_perc:.2f}%), requires attention.")
        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"Average latency is low ({overall_avg_rtt:.1f}ms), performance is excellent.")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"Average latency is moderate ({overall_avg_rtt:.1f}ms), generally acceptable.")
        else: summary_points.append(f"Average latency is high ({overall_avg_rtt:.1f}ms), may impact real-time interactive experience.")
        if overall_avg_stddev_rtt < current_jitter_stddev_threshold / 2 and overall_max_rtt < overall_avg_rtt * current_jitter_max_avg_ratio : summary_points.append("Network latency is relatively stable, jitter is low.")
        elif overall_avg_stddev_rtt < current_jitter_stddev_threshold: summary_points.append("Network latency shows some fluctuation.")
        else: summary_points.append("Network latency has significant jitter, stability is poor.")
        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("Potential network problem periods detected, see list above for details.")
        else: summary_points.append("Based on current thresholds, no obvious network problem periods were found.")

        for point in summary_points:
            report.append(f"{list_indent}- {point}") # 总结使用 "- "

        report.append("\n" + sep) # 报告结尾

    return "\n".join(report)

# --- Main Program Entry (Unchanged) ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {os.path.basename(sys.argv[0])} <log_file_path> [--md]")
        sys.exit(1)

    log_file = sys.argv[1]
    output_markdown = False
    if "--md" in sys.argv[2:]:
        output_markdown = True

    analysis_report_content = analyze_ping_log(log_file, output_markdown)

    if output_markdown:
        base_name = os.path.splitext(os.path.basename(log_file))[0]
        md_filename = f"{base_name}_report.md"
        try:
            with open(md_filename, 'w', encoding='utf-8') as f:
                f.write(analysis_report_content)
            print(f"Markdown report saved to: {md_filename}")
        except IOError as e:
            print(f"Error: Could not write Markdown file {md_filename}: {e}", file=sys.stderr)
            print("\n--- Analysis Report (printed to console due to file write error) ---")
            print(analysis_report_content)
    else:
        print(analysis_report_content)

