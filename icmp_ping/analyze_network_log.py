#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
from datetime import datetime
import statistics
import socket
import time
import os

# --- 可配置阈值 (固定阈值 - 作为回退选项) ---
HIGH_LOSS_THRESHOLD = 1.0 # 丢包率阈值保持固定，不动态计算
HIGH_LATENCY_THRESHOLD = 100.0 # 固定延迟阈值 (ms)
HIGH_JITTER_THRESHOLD_STDDEV = 50.0 # 固定抖动标准差阈值 (ms)
HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO = 3.0 # 固定抖动 Max/Avg 比率阈值

# --- 动态基线计算参数 ---
MAX_BASELINE_CANDIDATES = 100
MIN_BASELINE_SAMPLES = 20
STABLE_LOSS_THRESHOLD = 0.5

# --- 动态阈值计算参数 ---
DYNAMIC_LATENCY_FACTOR = 1.5
DYNAMIC_LATENCY_OFFSET = 10.0
MIN_DYNAMIC_LATENCY_THRESHOLD = 30.0

DYNAMIC_JITTER_STDDEV_FACTOR = 2.0
DYNAMIC_JITTER_RTT_RATIO = 0.3
MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD = 10.0
# DYNAMIC_JITTER_MAX_AVG_RATIO 保持固定

# --- 获取系统信息的函数 (保持不变) ---
def get_hostname():
    try: return socket.gethostname()
    except socket.error as e: print(f"警告: 无法获取主机名: {e}", file=sys.stderr); return "未知 (无法获取)"

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
    except Exception as e: print(f"警告: 无法获取时区信息: {e}", file=sys.stderr); return "未知 (无法获取)"

# --- 解析日志行的函数 (保持不变) ---
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
        except (ValueError, IndexError) as e: print(f"警告: 解析数据行时出错: {line.strip()} - {e}", file=sys.stderr); return None
    return None

# --- 主要分析和报告生成函数 ---
def analyze_ping_log(log_file_path, markdown_format=False):
    """分析 ping 日志文件并生成报告内容 (文本或 Markdown)"""

    analysis_hostname = get_hostname()
    analysis_timezone = get_timezone_info()

    metadata = {
        "target_ip": "未知", "source_public_ip": "未知 (未在日志中找到)",
        "start_time_str": "未知", "packets_per_measurement": "未知",
        "interval_seconds": "未知", "timeout_seconds": "未知",
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
                    match_source_ip = re.match(r".*服务器源公网 IP:\s*(.*)", line);
                    if match_source_ip: metadata["source_public_ip"] = match_source_ip.group(1).strip(); continue
                    match_ip = re.match(r".*目标 IP:\s*(.*)", line);
                    if match_ip: metadata["target_ip"] = match_ip.group(1).strip(); continue
                    match_start = re.match(r".*监控启动于:\s*(.*)", line);
                    if match_start: metadata["start_time_str"] = match_start.group(1).strip(); continue
                    match_packets = re.match(r".*每次测量 PING 包数:\s*(.*)", line);
                    if match_packets: metadata["packets_per_measurement"] = match_packets.group(1).strip(); continue
                    match_interval = re.match(r".*测量间隔:\s*(\d+)\s*秒", line);
                    if match_interval: metadata["interval_seconds"] = match_interval.group(1).strip(); continue
                    match_timeout = re.match(r".*Ping 超时:\s*(\d+)\s*秒", line);
                    if match_timeout: metadata["timeout_seconds"] = match_timeout.group(1).strip(); continue
                    if "---" in line:
                        if data_section_started: header_parsed = True
                        else: data_section_started = True
                        continue
                    if "发送 | 接收 | 丢包率(%)" in line:
                         data_section_started = True; header_parsed = True; continue
                if header_parsed:
                    record = parse_log_line(line)
                    if record: data_records.append(record)
    except FileNotFoundError: return f"错误: 文件未找到: {log_file_path}"
    except Exception as e: return f"错误: 读取或解析文件时发生异常: {e}"

    if not data_records: return f"错误: 在文件 {log_file_path} 中未找到有效的数据记录。"

    # --- 动态基线和阈值计算 (逻辑不变) ---
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
            dynamic_thresholds_calculated = False; baseline_fallback_reason = f"基线统计计算错误: {e}"
    else:
        dynamic_thresholds_calculated = False
        if len(data_records) < MIN_BASELINE_SAMPLES: baseline_fallback_reason = f"日志数据不足 (少于 {MIN_BASELINE_SAMPLES} 条)"
        else: baseline_fallback_reason = f"日志初始 {MAX_BASELINE_CANDIDATES} 条记录中稳定样本不足 (< {MIN_BASELINE_SAMPLES} 条, 稳定丢包率 <= {STABLE_LOSS_THRESHOLD}%)"

    if not dynamic_thresholds_calculated:
        current_latency_threshold = HIGH_LATENCY_THRESHOLD
        current_jitter_stddev_threshold = HIGH_JITTER_THRESHOLD_STDDEV
        current_jitter_max_avg_ratio = HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO
    current_loss_threshold = HIGH_LOSS_THRESHOLD
    # --- 结束动态基线和阈值计算 ---

    # --- 分析逻辑 (逻辑不变) ---
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
        if r['loss_perc'] > current_loss_threshold: high_loss_periods.append(f"{ts} (丢包率: {r['loss_perc']:.1f}%)")
        if r['avg_rtt'] > current_latency_threshold: high_latency_periods.append(f"{ts} (平均 RTT: {r['avg_rtt']:.1f}ms)")
        jit_std = r['stddev_rtt'] > current_jitter_stddev_threshold; jit_rat = (r['avg_rtt'] > 0 and (r['max_rtt']/r['avg_rtt']) > current_jitter_max_avg_ratio)
        if jit_std or jit_rat:
            rea = []; md_rea = []
            if jit_std: rea.append(f"StdDev={r['stddev_rtt']:.1f}ms"); md_rea.append(f"StdDev=`{r['stddev_rtt']:.1f}ms`")
            if jit_rat: rea.append(f"Max/Avg Ratio={(r['max_rtt'] / r['avg_rtt']):.1f}"); md_rea.append(f"Max/Avg Ratio=`{(r['max_rtt'] / r['avg_rtt']):.1f}`")
            # 根据格式存储不同的原因字符串
            high_jitter_periods.append({"ts": ts, "reason": ', '.join(rea), "md_reason": ', '.join(md_rea)})
    # --- 结束分析逻辑 ---


    # --- 生成报告内容 ---
    report = []
    if markdown_format:
        # --- Markdown 报告生成 (保持之前的逻辑) ---
        sep_line = "---"; title_prefix = "# "; section_prefix = "## "; subsection_prefix = "### "
        list_item = "*   "; code_wrapper = "`"; bold_wrapper = "**"

        report.append(f"{title_prefix}Ping 日志分析报告: {code_wrapper}{metadata['target_ip']}{code_wrapper}")
        report.append(sep_line)
        report.append(f"{section_prefix}分析环境与监控配置")
        report.append(f"{list_item}{bold_wrapper}源公网 IP (来自日志):{bold_wrapper} {code_wrapper}{metadata['source_public_ip']}{code_wrapper}")
        report.append(f"{list_item}{bold_wrapper}目标 IP:{bold_wrapper} {code_wrapper}{metadata['target_ip']}{code_wrapper}")
        report.append(f"{list_item}日志文件: {code_wrapper}{os.path.basename(log_file_path)}{code_wrapper}")
        report.append(f"{list_item}监控开始 (日志记录): {metadata['start_time_str']}")
        report.append(f"{list_item}分析数据范围: {code_wrapper}{first_timestamp}{code_wrapper} 至 {code_wrapper}{last_timestamp}{code_wrapper}")
        report.append(f"{list_item}总持续时间: {duration}")
        report.append(f"{list_item}总测量次数: {total_measurements}")
        report.append(f"{list_item}每次测量包数: {metadata['packets_per_measurement']}")
        report.append(f"{list_item}测量间隔: {metadata['interval_seconds']} 秒")
        report.append(f"{list_item}Ping 超时: {metadata['timeout_seconds']} 秒")
        report.append(f"{list_item}分析脚本主机名: {code_wrapper}{metadata['analysis_hostname']}{code_wrapper}")
        report.append(f"{list_item}分析脚本时区: {metadata['analysis_timezone']}")
        report.append("")
        report.append(f"{section_prefix}整体统计")
        report.append(f"{list_item}总发送/接收: {total_sent} / {total_received}")
        report.append(f"{list_item}整体平均丢包率: {bold_wrapper}{overall_loss_perc:.2f}%{bold_wrapper}")
        report.append(f"{list_item}整体平均 RTT: {code_wrapper}{overall_avg_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}整体最小 RTT: {code_wrapper}{overall_min_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}整体最大 RTT: {code_wrapper}{overall_max_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}整体平均抖动 (StdDev): {code_wrapper}{overall_avg_stddev_rtt:.3f} ms{code_wrapper}")
        report.append("")
        report.append(f"{section_prefix}分析阈值")
        if dynamic_thresholds_calculated:
            report.append(f"{list_item}使用 {bold_wrapper}动态阈值{bold_wrapper} (基于日志初始数据计算):")
            report.append(f"    {list_item}基线 RTT: {code_wrapper}{baseline_rtt:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}基线 StdDev: {code_wrapper}{baseline_stddev:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高延迟阈值: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高抖动 (StdDev) 阈值: > {code_wrapper}{current_jitter_stddev_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高抖动 (Max/Avg Ratio) 阈值: > {code_wrapper}{current_jitter_max_avg_ratio:.1f}{code_wrapper}")
        else:
            report.append(f"{list_item}使用 {bold_wrapper}固定阈值{bold_wrapper} (原因: {baseline_fallback_reason}):")
            report.append(f"    {list_item}高延迟阈值: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高抖动 (StdDev) 阈值: > {code_wrapper}{current_jitter_stddev_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高抖动 (Max/Avg Ratio) 阈值: > {code_wrapper}{current_jitter_max_avg_ratio:.1f}{code_wrapper}")
        report.append(f"    {list_item}高丢包率阈值: > {code_wrapper}{current_loss_threshold:.1f}%{code_wrapper}")
        report.append("")
        report.append(f"{section_prefix}潜在问题时段")
        if high_loss_periods or high_latency_periods or high_jitter_periods:
            if high_loss_periods:
                report.append(f"{subsection_prefix}高丢包 (>{current_loss_threshold:.1f}%) - {len(high_loss_periods)} 次")
                for p in high_loss_periods: report.append(f"{list_item}{p}")
                report.append("")
            if high_latency_periods:
                report.append(f"{subsection_prefix}高延迟 (>{current_latency_threshold:.1f}ms) - {len(high_latency_periods)} 次")
                for p in high_latency_periods: report.append(f"{list_item}{p}")
                report.append("")
            if high_jitter_periods:
                report.append(f"{subsection_prefix}高抖动 (StdDev>{current_jitter_stddev_threshold:.1f}ms 或 Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} 次")
                # 使用包含 Markdown 反引号的原因字符串
                for p_dict in high_jitter_periods: report.append(f"{list_item}{p_dict['ts']} ({p_dict['md_reason']})")
                report.append("")
        else: report.append(f"{list_item}未检测到明显超出阈值的问题时段。"); report.append("")
        report.append(f"{section_prefix}总结")
        summary_points = []
        if overall_loss_perc == 0.0: summary_points.append(f"网络连通性极好，{bold_wrapper}未发生丢包{bold_wrapper}。")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"网络连通性良好，整体丢包率低 ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper})。")
        elif overall_loss_perc < 5.0: summary_points.append(f"网络存在少量丢包 ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper})，可能影响敏感应用。")
        else: summary_points.append(f"网络丢包较为严重 ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper})，{bold_wrapper}需要关注{bold_wrapper}。")
        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"平均延迟较低 ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper})，表现{bold_wrapper}优秀{bold_wrapper}。")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"平均延迟中等 ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper})，基本可用。")
        else: summary_points.append(f"平均延迟较高 ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper})，可能影响实时交互体验。")
        if overall_avg_stddev_rtt < current_jitter_stddev_threshold / 2 and overall_max_rtt < overall_avg_rtt * current_jitter_max_avg_ratio : summary_points.append(f"网络延迟相对{bold_wrapper}稳定{bold_wrapper}，抖动较小。")
        elif overall_avg_stddev_rtt < current_jitter_stddev_threshold: summary_points.append("网络延迟存在一定波动。")
        else: summary_points.append(f"网络延迟{bold_wrapper}抖动较大{bold_wrapper}，稳定性较差。")
        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("检测到潜在的网络问题时段，详见上方列表。")
        else: summary_points.append("根据当前使用的阈值，未发现明显的网络问题时段。")
        for point in summary_points: report.append(f"{list_item}{point}")
        # Markdown 报告结尾不需要额外分隔符
    else:
        # --- 纯文本报告生成 (美化版) ---
        sep = "=" * 60
        sub_sep = "-" * 60
        list_indent = "  " # 列表项缩进

        report.append(sep)
        report.append(f" Ping 日志分析报告: {metadata['target_ip']}")
        report.append(sep)
        report.append("") # 空行

        report.append("--- 分析环境与监控配置 ---")
        report.append(f"{list_indent}源公网 IP (来自日志): {metadata['source_public_ip']}")
        report.append(f"{list_indent}目标 IP:             {metadata['target_ip']}")
        report.append(f"{list_indent}日志文件:           {os.path.basename(log_file_path)}")
        report.append(f"{list_indent}监控开始 (日志记录): {metadata['start_time_str']}")
        report.append(f"{list_indent}分析数据范围:       {first_timestamp} 至 {last_timestamp}")
        report.append(f"{list_indent}总持续时间:         {duration}")
        report.append(f"{list_indent}总测量次数:         {total_measurements}")
        report.append(f"{list_indent}每次测量包数:       {metadata['packets_per_measurement']}")
        report.append(f"{list_indent}测量间隔:           {metadata['interval_seconds']} 秒")
        report.append(f"{list_indent}Ping 超时:          {metadata['timeout_seconds']} 秒")
        report.append(f"{list_indent}分析脚本主机名:     {metadata['analysis_hostname']}")
        report.append(f"{list_indent}分析脚本时区:       {metadata['analysis_timezone']}")
        report.append("")

        report.append("--- 整体统计 ---")
        report.append(f"{list_indent}总发送/接收:        {total_sent} / {total_received}")
        report.append(f"{list_indent}整体平均丢包率:     {overall_loss_perc:.2f}%")
        report.append(f"{list_indent}整体平均 RTT:       {overall_avg_rtt:.3f} ms")
        report.append(f"{list_indent}整体最小 RTT:       {overall_min_rtt:.3f} ms")
        report.append(f"{list_indent}整体最大 RTT:       {overall_max_rtt:.3f} ms")
        report.append(f"{list_indent}整体平均抖动(StdDev): {overall_avg_stddev_rtt:.3f} ms")
        report.append("")

        report.append("--- 分析阈值 ---")
        if dynamic_thresholds_calculated:
            report.append(f"{list_indent}模式: 动态阈值 (基于日志初始数据计算)")
            report.append(f"{list_indent}  - 基线 RTT:      {baseline_rtt:.1f} ms")
            report.append(f"{list_indent}  - 基线 StdDev:   {baseline_stddev:.1f} ms")
            report.append(f"{list_indent}使用的阈值:")
            report.append(f"{list_indent}  - 高延迟:        > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动(StdDev): > {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动(Ratio): > {current_jitter_max_avg_ratio:.1f}")
        else:
            report.append(f"{list_indent}模式: 固定阈值 (原因: {baseline_fallback_reason})")
            report.append(f"{list_indent}使用的阈值:")
            report.append(f"{list_indent}  - 高延迟:        > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动(StdDev): > {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动(Ratio): > {current_jitter_max_avg_ratio:.1f}")
        report.append(f"{list_indent}  - 高丢包率:      > {current_loss_threshold:.1f}%") # 丢包率总是显示
        report.append("")

        report.append("--- 潜在问题时段 ---")
        if not (high_loss_periods or high_latency_periods or high_jitter_periods):
            report.append(f"{list_indent}未检测到明显超出阈值的问题时段。")
        else:
            if high_loss_periods:
                report.append(f"\n{list_indent}高丢包 (>{current_loss_threshold:.1f}%) - {len(high_loss_periods)} 次:")
                for p in high_loss_periods: report.append(f"{list_indent}  - {p}")
            if high_latency_periods:
                report.append(f"\n{list_indent}高延迟 (>{current_latency_threshold:.1f}ms) - {len(high_latency_periods)} 次:")
                for p in high_latency_periods: report.append(f"{list_indent}  - {p}")
            if high_jitter_periods:
                report.append(f"\n{list_indent}高抖动 (StdDev>{current_jitter_stddev_threshold:.1f}ms 或 Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} 次:")
                # 使用不包含 Markdown 反引号的原因字符串
                for p_dict in high_jitter_periods: report.append(f"{list_indent}  - {p_dict['ts']} ({p_dict['reason']})")
        report.append("")

        report.append("--- 总结 ---")
        summary_points = []
        # (总结文本生成逻辑不变)
        if overall_loss_perc == 0.0: summary_points.append("网络连通性极好，未发生丢包。")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"网络连通性良好，整体丢包率低 ({overall_loss_perc:.2f}%)。")
        elif overall_loss_perc < 5.0: summary_points.append(f"网络存在少量丢包 ({overall_loss_perc:.2f}%)，可能影响敏感应用。")
        else: summary_points.append(f"网络丢包较为严重 ({overall_loss_perc:.2f}%)，需要关注。")
        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"平均延迟较低 ({overall_avg_rtt:.1f}ms)，表现优秀。")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"平均延迟中等 ({overall_avg_rtt:.1f}ms)，基本可用。")
        else: summary_points.append(f"平均延迟较高 ({overall_avg_rtt:.1f}ms)，可能影响实时交互体验。")
        if overall_avg_stddev_rtt < current_jitter_stddev_threshold / 2 and overall_max_rtt < overall_avg_rtt * current_jitter_max_avg_ratio : summary_points.append("网络延迟相对稳定，抖动较小。")
        elif overall_avg_stddev_rtt < current_jitter_stddev_threshold: summary_points.append("网络延迟存在一定波动。")
        else: summary_points.append("网络延迟抖动较大，稳定性较差。")
        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("检测到潜在的网络问题时段，详见上方列表。")
        else: summary_points.append("根据当前使用的阈值，未发现明显的网络问题时段。")

        for point in summary_points:
            report.append(f"{list_indent}- {point}") # 总结使用 "- "

        report.append("\n" + sep) # 报告结尾

    return "\n".join(report)

# --- 主程序入口 (保持不变) ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python {os.path.basename(sys.argv[0])} <log_file_path> [--md]")
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
            print(f"Markdown 报告已保存到: {md_filename}")
        except IOError as e:
            print(f"错误: 无法写入 Markdown 文件 {md_filename}: {e}", file=sys.stderr)
            print("\n--- 分析报告 (因无法写入文件而打印到控制台) ---")
            print(analysis_report_content)
    else:
        print(analysis_report_content)

