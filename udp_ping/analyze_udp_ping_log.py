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

# --- 可配置阈值 (固定阈值 - 作为回退选项) ---
# 丢包率阈值
HIGH_LOSS_THRESHOLD = 1.0 # (%)
# 延迟阈值
HIGH_LATENCY_THRESHOLD = 100.0 # 固定平均 RTT 阈值 (ms)
# 抖动阈值 (多种衡量方式)
HIGH_JITTER_THRESHOLD_DIRECT = 50.0 # 固定直接 Jitter 值阈值 (ms) - 来自日志最后一列计算值
HIGH_JITTER_THRESHOLD_STDDEV = 50.0 # 固定抖动 StdDev 值阈值 (ms) - 来自日志倒数第二列
HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO = 3.0 # 固定抖动 Max/Avg 比率阈值

# --- 动态基线计算参数 ---
MAX_BASELINE_CANDIDATES = 100 # 最多用于计算基线的初始记录数
MIN_BASELINE_SAMPLES = 20    # 计算基线所需的最少稳定样本数
STABLE_LOSS_THRESHOLD = 0.5  # 定义稳定记录的丢包率上限 (%)

# --- 动态阈值计算参数 ---
# 延迟
DYNAMIC_LATENCY_FACTOR = 1.5   # 平均 RTT 基线倍数
DYNAMIC_LATENCY_OFFSET = 10.0  # 平均 RTT 固定偏移 (ms)
MIN_DYNAMIC_LATENCY_THRESHOLD = 30.0 # 动态计算的最小延迟阈值 (ms)
# 抖动 (直接值)
DYNAMIC_JITTER_DIRECT_FACTOR = 2.0 # 直接 Jitter 基线倍数
DYNAMIC_JITTER_DIRECT_OFFSET = 5.0 # 直接 Jitter 固定偏移 (ms)
MIN_DYNAMIC_JITTER_DIRECT_THRESHOLD = 15.0 # 动态计算的最小直接 Jitter 阈值 (ms)
# 抖动 (标准差)
DYNAMIC_JITTER_STDDEV_FACTOR = 2.0 # StdDev Jitter 基线倍数
DYNAMIC_JITTER_RTT_RATIO = 0.3   # StdDev 相对于平均 RTT 的比例因子
MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD = 10.0 # 动态计算的最小 StdDev Jitter 阈值 (ms)
# DYNAMIC_JITTER_MAX_AVG_RATIO 保持固定

# --- 获取系统信息的函数 (保持不变) ---
def get_hostname():
    try: return socket.gethostname()
    except socket.error as e: print(f"警告: 无法获取主机名: {e}", file=sys.stderr); return "未知 (无法获取)"

def get_timezone_info():
    # (代码与之前版本相同，保持不变)
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

# --- 解析 UDP Ping 日志行的函数 ---
def parse_udp_log_line(line):
    """解析 UDP Ping 日志的数据行"""
    # 正则表达式匹配日志数据行格式
    # 时间戳 | 发送 | 接收 | 丢包率(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev(ms) | Jitter(ms) | Size(bytes)
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
            # 定义一个辅助函数处理可能为 'nan' 的浮点数
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
            print(f"警告: 解析数据行时出错: {line.strip()} - {e}", file=sys.stderr)
            return None
    return None

# --- 主要分析和报告生成函数 ---
def analyze_udp_ping_log(log_file_path, markdown_format=False):
    """分析 UDP Ping 日志文件并生成报告内容 (文本或 Markdown)"""

    analysis_hostname = get_hostname()
    analysis_timezone = get_timezone_info()

    # 初始化元数据字典，匹配 UDP log header
    metadata = {
        "target_ip": "未知", "target_port": "未知",
        "start_time_str": "未知", "packets_per_measurement_desc": "未知",
        "summary_interval_seconds": "未知 (仅周期模式)",
        "ping_interval_seconds": "未知", "ping_size_bytes": "未知",
        "ping_timeout_seconds": "未知",
        "analysis_hostname": analysis_hostname, "analysis_timezone": analysis_timezone,
    }
    data_records = []
    header_parsed = False
    data_section_started = False

    # 解析日志文件头部和数据
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue

                if not header_parsed:
                    # 解析头部信息
                    match_ip = re.match(r".*目标 IP:\s*(.*)", line)
                    if match_ip: metadata["target_ip"] = match_ip.group(1).strip(); continue
                    match_port = re.match(r".*目标端口:\s*(\d+)", line)
                    if match_port: metadata["target_port"] = match_port.group(1).strip(); continue
                    match_start = re.match(r".*监控启动于:\s*(.*)", line)
                    if match_start: metadata["start_time_str"] = match_start.group(1).strip(); continue
                    # 处理两种包数描述
                    match_packets = re.match(r".*(?:每次测量|本次运行) PING 包数:\s*(.*)", line)
                    if match_packets: metadata["packets_per_measurement_desc"] = match_packets.group(1).strip(); continue
                    match_summary_interval = re.match(r".*日志汇总间隔 \(秒\):\s*([\d.]+)", line)
                    if match_summary_interval: metadata["summary_interval_seconds"] = match_summary_interval.group(1).strip(); continue
                    match_ping_interval = re.match(r".*PING 间隔 \(秒\):\s*([\d.]+)", line)
                    if match_ping_interval: metadata["ping_interval_seconds"] = match_ping_interval.group(1).strip(); continue
                    match_size = re.match(r".*PING 大小 \(字节\):\s*(\d+)", line)
                    if match_size: metadata["ping_size_bytes"] = match_size.group(1).strip(); continue
                    match_timeout = re.match(r".*PING 超时 \(秒\):\s*([\d.]+)", line)
                    if match_timeout: metadata["ping_timeout_seconds"] = match_timeout.group(1).strip(); continue

                    # 检查是否到达数据区表头或分隔线
                    if "---" in line or "发送 | 接收 | 丢包率(%)" in line:
                        data_section_started = True
                        header_parsed = True # 假设读到这里头部就结束了
                        continue # 跳过分隔线或表头本身

                if header_parsed:
                    record = parse_udp_log_line(line)
                    if record: data_records.append(record)

    except FileNotFoundError: return f"错误: 文件未找到: {log_file_path}"
    except Exception as e: return f"错误: 读取或解析文件时发生异常: {e}"

    if not data_records: return f"错误: 在文件 {log_file_path} 中未找到有效的数据记录。"

    # --- 动态基线和阈值计算 ---
    baseline_rtt, baseline_stddev, baseline_jitter = None, None, None # 添加 jitter 基线
    dynamic_thresholds_calculated = False
    baseline_fallback_reason = ""

    # 选取用于计算基线的稳定记录 (低丢包率)
    stable_initial_records = [r for r in data_records[:MAX_BASELINE_CANDIDATES]
                              if not math.isnan(r['loss_perc']) and r['loss_perc'] <= STABLE_LOSS_THRESHOLD
                              and not math.isnan(r['avg_rtt']) and not math.isnan(r['stddev_rtt']) and not math.isnan(r['jitter_rtt'])] # 确保相关值非 NaN

    if len(stable_initial_records) >= MIN_BASELINE_SAMPLES:
        try:
            baseline_rtt = statistics.mean(r['avg_rtt'] for r in stable_initial_records)
            baseline_stddev = statistics.mean(r['stddev_rtt'] for r in stable_initial_records)
            baseline_jitter = statistics.mean(r['jitter_rtt'] for r in stable_initial_records) # 计算 jitter 基线
            dynamic_thresholds_calculated = True

            # 计算动态阈值
            current_latency_threshold = max(baseline_rtt * DYNAMIC_LATENCY_FACTOR + DYNAMIC_LATENCY_OFFSET, MIN_DYNAMIC_LATENCY_THRESHOLD)
            current_jitter_direct_threshold = max(baseline_jitter * DYNAMIC_JITTER_DIRECT_FACTOR + DYNAMIC_JITTER_DIRECT_OFFSET, MIN_DYNAMIC_JITTER_DIRECT_THRESHOLD) # 新增直接 Jitter 动态阈值
            current_jitter_stddev_threshold = max(baseline_stddev * DYNAMIC_JITTER_STDDEV_FACTOR, baseline_rtt * DYNAMIC_JITTER_RTT_RATIO, MIN_DYNAMIC_JITTER_STDDEV_THRESHOLD)
            current_jitter_max_avg_ratio = HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO # Max/Avg 比率保持固定

        except statistics.StatisticsError as e:
            dynamic_thresholds_calculated = False
            baseline_fallback_reason = f"基线统计计算错误: {e}"
    else:
        dynamic_thresholds_calculated = False
        if len(data_records) < MIN_BASELINE_SAMPLES: baseline_fallback_reason = f"日志数据不足 (少于 {MIN_BASELINE_SAMPLES} 条)"
        else: baseline_fallback_reason = f"日志初始 {MAX_BASELINE_CANDIDATES} 条记录中稳定样本不足 (< {MIN_BASELINE_SAMPLES} 条, 稳定丢包率 <= {STABLE_LOSS_THRESHOLD}%)"

    # 如果动态计算失败，使用固定阈值
    if not dynamic_thresholds_calculated:
        current_latency_threshold = HIGH_LATENCY_THRESHOLD
        current_jitter_direct_threshold = HIGH_JITTER_THRESHOLD_DIRECT
        current_jitter_stddev_threshold = HIGH_JITTER_THRESHOLD_STDDEV
        current_jitter_max_avg_ratio = HIGH_JITTER_THRESHOLD_MAX_AVG_RATIO
    # 丢包率阈值总是固定的
    current_loss_threshold = HIGH_LOSS_THRESHOLD
    # --- 结束动态基线和阈值计算 ---

    # --- 分析逻辑 ---
    total_measurements = len(data_records)
    first_timestamp = data_records[0]['timestamp']
    last_timestamp = data_records[-1]['timestamp']
    duration = last_timestamp - first_timestamp

    # 计算整体统计数据，过滤掉 NaN 值
    valid_sent = [r['sent'] for r in data_records if not math.isnan(r['sent'])]
    valid_received = [r['received'] for r in data_records if not math.isnan(r['received'])]
    total_sent = sum(valid_sent)
    total_received = sum(valid_received)
    overall_loss_perc = ((total_sent - total_received) / total_sent) * 100.0 if total_sent > 0 else 0.0

    all_avg_rtts = [r['avg_rtt'] for r in data_records if not math.isnan(r['avg_rtt'])]
    all_min_rtts = [r['min_rtt'] for r in data_records if not math.isnan(r['min_rtt'])]
    all_max_rtts = [r['max_rtt'] for r in data_records if not math.isnan(r['max_rtt'])]
    all_stddev_rtts = [r['stddev_rtt'] for r in data_records if not math.isnan(r['stddev_rtt'])]
    all_jitter_rtts = [r['jitter_rtt'] for r in data_records if not math.isnan(r['jitter_rtt'])] # 获取所有有效的 jitter 值

    overall_avg_rtt = statistics.mean(all_avg_rtts) if all_avg_rtts else 0.0
    overall_min_rtt = min(all_min_rtts) if all_min_rtts else 0.0
    overall_max_rtt = max(all_max_rtts) if all_max_rtts else 0.0
    overall_avg_stddev_rtt = statistics.mean(all_stddev_rtts) if all_stddev_rtts else 0.0
    overall_avg_jitter = statistics.mean(all_jitter_rtts) if all_jitter_rtts else 0.0 # 计算整体平均 jitter

    # 查找超出阈值的时段
    high_loss_periods, high_latency_periods, high_jitter_periods = [], [], []
    for r in data_records:
        # 跳过包含 NaN 值的记录的阈值检查
        if any(math.isnan(val) for val in [r['loss_perc'], r['avg_rtt'], r['max_rtt'], r['stddev_rtt'], r['jitter_rtt']]):
            continue

        ts = r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        # 检查高丢包
        if r['loss_perc'] > current_loss_threshold:
            high_loss_periods.append(f"{ts} (丢包率: {r['loss_perc']:.1f}%)")
        # 检查高延迟
        if r['avg_rtt'] > current_latency_threshold:
            high_latency_periods.append(f"{ts} (平均 RTT: {r['avg_rtt']:.1f}ms)")
        # 检查高抖动 (多维度)
        jit_direct = r['jitter_rtt'] > current_jitter_direct_threshold
        jit_std = r['stddev_rtt'] > current_jitter_stddev_threshold
        jit_rat = (r['avg_rtt'] > 0 and (r['max_rtt']/r['avg_rtt']) > current_jitter_max_avg_ratio)

        if jit_direct or jit_std or jit_rat:
            rea = []; md_rea = []
            if jit_direct: rea.append(f"Jitter={r['jitter_rtt']:.1f}ms"); md_rea.append(f"Jitter=`{r['jitter_rtt']:.1f}ms`")
            if jit_std: rea.append(f"StdDev={r['stddev_rtt']:.1f}ms"); md_rea.append(f"StdDev=`{r['stddev_rtt']:.1f}ms`")
            if jit_rat: rea.append(f"Max/Avg Ratio={(r['max_rtt'] / r['avg_rtt']):.1f}"); md_rea.append(f"Max/Avg Ratio=`{(r['max_rtt'] / r['avg_rtt']):.1f}`")
            high_jitter_periods.append({"ts": ts, "reason": ', '.join(rea), "md_reason": ', '.join(md_rea)})
    # --- 结束分析逻辑 ---

    # --- 生成报告内容 ---
    report = []
    if markdown_format:
        # --- Markdown 报告生成 ---
        sep_line = "---"; title_prefix = "# "; section_prefix = "## "; subsection_prefix = "### "
        list_item = "*   "; code_wrapper = "`"; bold_wrapper = "**"

        report.append(f"{title_prefix}UDP Ping 日志分析报告: {code_wrapper}{metadata['target_ip']}:{metadata['target_port']}{code_wrapper}")
        report.append(sep_line)
        report.append(f"{section_prefix}分析环境与监控配置")
        report.append(f"{list_item}{bold_wrapper}目标 IP:{bold_wrapper} {code_wrapper}{metadata['target_ip']}{code_wrapper}")
        report.append(f"{list_item}{bold_wrapper}目标端口:{bold_wrapper} {code_wrapper}{metadata['target_port']}{code_wrapper}")
        report.append(f"{list_item}日志文件: {code_wrapper}{os.path.basename(log_file_path)}{code_wrapper}")
        report.append(f"{list_item}监控开始 (日志记录): {metadata['start_time_str']}")
        report.append(f"{list_item}分析数据范围: {code_wrapper}{first_timestamp}{code_wrapper} 至 {code_wrapper}{last_timestamp}{code_wrapper}")
        report.append(f"{list_item}总持续时间: {duration}")
        report.append(f"{list_item}总测量次数 (日志行数): {total_measurements}")
        report.append(f"{list_item}PING 包数描述: {metadata['packets_per_measurement_desc']}")
        if metadata['summary_interval_seconds'] != "未知 (仅周期模式)":
            report.append(f"{list_item}日志汇总间隔: {metadata['summary_interval_seconds']} 秒")
        report.append(f"{list_item}PING 间隔: {metadata['ping_interval_seconds']} 秒")
        report.append(f"{list_item}PING 大小: {metadata['ping_size_bytes']} 字节")
        report.append(f"{list_item}Ping 超时: {metadata['ping_timeout_seconds']} 秒")
        report.append(f"{list_item}分析脚本主机名: {code_wrapper}{metadata['analysis_hostname']}{code_wrapper}")
        report.append(f"{list_item}分析脚本时区: {metadata['analysis_timezone']}")
        report.append("")
        report.append(f"{section_prefix}整体统计")
        report.append(f"{list_item}总发送/接收: {total_sent} / {total_received}")
        report.append(f"{list_item}整体平均丢包率: {bold_wrapper}{overall_loss_perc:.2f}%{bold_wrapper}")
        report.append(f"{list_item}整体平均 RTT: {code_wrapper}{overall_avg_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}整体最小 RTT: {code_wrapper}{overall_min_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}整体最大 RTT: {code_wrapper}{overall_max_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}整体平均标准差 (StdDev): {code_wrapper}{overall_avg_stddev_rtt:.3f} ms{code_wrapper}")
        report.append(f"{list_item}整体平均抖动 (Jitter): {code_wrapper}{overall_avg_jitter:.3f} ms{code_wrapper}") # 新增 Jitter
        report.append("")
        report.append(f"{section_prefix}分析阈值")
        if dynamic_thresholds_calculated:
            report.append(f"{list_item}使用 {bold_wrapper}动态阈值{bold_wrapper} (基于日志初始数据计算):")
            report.append(f"    {list_item}基线 RTT: {code_wrapper}{baseline_rtt:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}基线 StdDev: {code_wrapper}{baseline_stddev:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}基线 Jitter: {code_wrapper}{baseline_jitter:.1f} ms{code_wrapper}") # 新增 Jitter 基线
            report.append(f"    {list_item}高延迟阈值: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高抖动 (Jitter) 阈值: > {code_wrapper}{current_jitter_direct_threshold:.1f} ms{code_wrapper}") # 新增 Jitter 阈值
            report.append(f"    {list_item}高抖动 (StdDev) 阈值: > {code_wrapper}{current_jitter_stddev_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高抖动 (Max/Avg Ratio) 阈值: > {code_wrapper}{current_jitter_max_avg_ratio:.1f}{code_wrapper}")
        else:
            report.append(f"{list_item}使用 {bold_wrapper}固定阈值{bold_wrapper} (原因: {baseline_fallback_reason}):")
            report.append(f"    {list_item}高延迟阈值: > {code_wrapper}{current_latency_threshold:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高抖动 (Jitter) 阈值: > {code_wrapper}{current_jitter_direct_threshold:.1f} ms{code_wrapper}") # 新增 Jitter 阈值
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
                report.append(f"{subsection_prefix}高抖动 (Jitter>{current_jitter_direct_threshold:.1f}ms 或 StdDev>{current_jitter_stddev_threshold:.1f}ms 或 Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} 次")
                for p_dict in high_jitter_periods: report.append(f"{list_item}{p_dict['ts']} ({p_dict['md_reason']})")
                report.append("")
        else: report.append(f"{list_item}未检测到明显超出阈值的问题时段。"); report.append("")
        report.append(f"{section_prefix}总结")
        summary_points = []
        # (总结文本生成逻辑基本不变，可以考虑加入 Jitter 的评价)
        if overall_loss_perc == 0.0: summary_points.append(f"网络连通性极好，{bold_wrapper}未发生丢包{bold_wrapper}。")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"网络连通性良好，整体丢包率低 ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper})。")
        elif overall_loss_perc < 5.0: summary_points.append(f"网络存在少量丢包 ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper})，可能影响敏感应用。")
        else: summary_points.append(f"网络丢包较为严重 ({code_wrapper}{overall_loss_perc:.2f}%{code_wrapper})，{bold_wrapper}需要关注{bold_wrapper}。")

        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"平均延迟较低 ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper})，表现{bold_wrapper}优秀{bold_wrapper}。")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"平均延迟中等 ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper})，基本可用。")
        else: summary_points.append(f"平均延迟较高 ({code_wrapper}{overall_avg_rtt:.1f}ms{code_wrapper})，可能影响实时交互体验。")

        # 基于 jitter_direct 和 stddev_rtt 评价抖动
        jitter_eval = "稳定"; jitter_qual = "良好"
        if overall_avg_jitter > current_jitter_direct_threshold or overall_avg_stddev_rtt > current_jitter_stddev_threshold:
            jitter_eval = "抖动较大"; jitter_qual = f"{bold_wrapper}较差{bold_wrapper}"
        elif overall_avg_jitter > current_jitter_direct_threshold / 2 or overall_avg_stddev_rtt > current_jitter_stddev_threshold / 2:
            jitter_eval = "存在一定波动"; jitter_qual = "一般"
        summary_points.append(f"网络延迟{jitter_eval} ({code_wrapper}Avg Jitter: {overall_avg_jitter:.1f}ms{code_wrapper}, {code_wrapper}Avg StdDev: {overall_avg_stddev_rtt:.1f}ms{code_wrapper})，稳定性{jitter_qual}。")

        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("检测到潜在的网络问题时段，详见上方列表。")
        else: summary_points.append("根据当前使用的阈值，未发现明显的网络问题时段。")
        for point in summary_points: report.append(f"{list_item}{point}")

    else:
        # --- 纯文本报告生成 ---
        sep = "=" * 70 # 调整分隔线长度
        sub_sep = "-" * 70
        list_indent = "  "

        report.append(sep)
        report.append(f" UDP Ping 日志分析报告: {metadata['target_ip']}:{metadata['target_port']}")
        report.append(sep)
        report.append("")

        report.append("--- 分析环境与监控配置 ---")
        report.append(f"{list_indent}目标 IP:                 {metadata['target_ip']}")
        report.append(f"{list_indent}目标端口:               {metadata['target_port']}")
        report.append(f"{list_indent}日志文件:               {os.path.basename(log_file_path)}")
        report.append(f"{list_indent}监控开始 (日志记录):     {metadata['start_time_str']}")
        report.append(f"{list_indent}分析数据范围:           {first_timestamp} 至 {last_timestamp}")
        report.append(f"{list_indent}总持续时间:             {duration}")
        report.append(f"{list_indent}总测量次数 (日志行数):   {total_measurements}")
        report.append(f"{list_indent}PING 包数描述:         {metadata['packets_per_measurement_desc']}")
        if metadata['summary_interval_seconds'] != "未知 (仅周期模式)":
            report.append(f"{list_indent}日志汇总间隔:           {metadata['summary_interval_seconds']} 秒")
        report.append(f"{list_indent}PING 间隔:              {metadata['ping_interval_seconds']} 秒")
        report.append(f"{list_indent}PING 大小:              {metadata['ping_size_bytes']} 字节")
        report.append(f"{list_indent}Ping 超时:              {metadata['ping_timeout_seconds']} 秒")
        report.append(f"{list_indent}分析脚本主机名:         {metadata['analysis_hostname']}")
        report.append(f"{list_indent}分析脚本时区:           {metadata['analysis_timezone']}")
        report.append("")

        report.append("--- 整体统计 ---")
        report.append(f"{list_indent}总发送/接收:            {total_sent} / {total_received}")
        report.append(f"{list_indent}整体平均丢包率:         {overall_loss_perc:.2f}%")
        report.append(f"{list_indent}整体平均 RTT:           {overall_avg_rtt:.3f} ms")
        report.append(f"{list_indent}整体最小 RTT:           {overall_min_rtt:.3f} ms")
        report.append(f"{list_indent}整体最大 RTT:           {overall_max_rtt:.3f} ms")
        report.append(f"{list_indent}整体平均标准差(StdDev): {overall_avg_stddev_rtt:.3f} ms")
        report.append(f"{list_indent}整体平均抖动(Jitter):   {overall_avg_jitter:.3f} ms") # 新增 Jitter
        report.append("")

        report.append("--- 分析阈值 ---")
        if dynamic_thresholds_calculated:
            report.append(f"{list_indent}模式: 动态阈值 (基于日志初始数据计算)")
            report.append(f"{list_indent}  - 基线 RTT:           {baseline_rtt:.1f} ms")
            report.append(f"{list_indent}  - 基线 StdDev:        {baseline_stddev:.1f} ms")
            report.append(f"{list_indent}  - 基线 Jitter:        {baseline_jitter:.1f} ms") # 新增 Jitter 基线
            report.append(f"{list_indent}使用的阈值:")
            report.append(f"{list_indent}  - 高延迟:             > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动 (Jitter):    > {current_jitter_direct_threshold:.1f} ms") # 新增 Jitter 阈值
            report.append(f"{list_indent}  - 高抖动 (StdDev):    > {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动 (Max/Avg Ratio): > {current_jitter_max_avg_ratio:.1f}")
        else:
            report.append(f"{list_indent}模式: 固定阈值 (原因: {baseline_fallback_reason})")
            report.append(f"{list_indent}使用的阈值:")
            report.append(f"{list_indent}  - 高延迟:             > {current_latency_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动 (Jitter):    > {current_jitter_direct_threshold:.1f} ms") # 新增 Jitter 阈值
            report.append(f"{list_indent}  - 高抖动 (StdDev):    > {current_jitter_stddev_threshold:.1f} ms")
            report.append(f"{list_indent}  - 高抖动 (Max/Avg Ratio): > {current_jitter_max_avg_ratio:.1f}")
        report.append(f"{list_indent}  - 高丢包率:           > {current_loss_threshold:.1f}%")
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
                report.append(f"\n{list_indent}高抖动 (Jitter>{current_jitter_direct_threshold:.1f}ms 或 StdDev>{current_jitter_stddev_threshold:.1f}ms 或 Max/Avg>{current_jitter_max_avg_ratio:.1f}) - {len(high_jitter_periods)} 次:")
                for p_dict in high_jitter_periods: report.append(f"{list_indent}  - {p_dict['ts']} ({p_dict['reason']})")
        report.append("")

        report.append("--- 总结 ---")
        summary_points = []
        # (总结文本生成逻辑与 Markdown 版本一致)
        if overall_loss_perc == 0.0: summary_points.append("网络连通性极好，未发生丢包。")
        elif overall_loss_perc <= current_loss_threshold : summary_points.append(f"网络连通性良好，整体丢包率低 ({overall_loss_perc:.2f}%)。")
        elif overall_loss_perc < 5.0: summary_points.append(f"网络存在少量丢包 ({overall_loss_perc:.2f}%)，可能影响敏感应用。")
        else: summary_points.append(f"网络丢包较为严重 ({overall_loss_perc:.2f}%)，需要关注。")

        if overall_avg_rtt < current_latency_threshold / 2 : summary_points.append(f"平均延迟较低 ({overall_avg_rtt:.1f}ms)，表现优秀。")
        elif overall_avg_rtt < current_latency_threshold : summary_points.append(f"平均延迟中等 ({overall_avg_rtt:.1f}ms)，基本可用。")
        else: summary_points.append(f"平均延迟较高 ({overall_avg_rtt:.1f}ms)，可能影响实时交互体验。")

        jitter_eval = "稳定"; jitter_qual = "良好"
        if overall_avg_jitter > current_jitter_direct_threshold or overall_avg_stddev_rtt > current_jitter_stddev_threshold:
            jitter_eval = "抖动较大"; jitter_qual = "较差"
        elif overall_avg_jitter > current_jitter_direct_threshold / 2 or overall_avg_stddev_rtt > current_jitter_stddev_threshold / 2:
            jitter_eval = "存在一定波动"; jitter_qual = "一般"
        summary_points.append(f"网络延迟{jitter_eval} (Avg Jitter: {overall_avg_jitter:.1f}ms, Avg StdDev: {overall_avg_stddev_rtt:.1f}ms)，稳定性{jitter_qual}。")

        if high_loss_periods or high_latency_periods or high_jitter_periods: summary_points.append("检测到潜在的网络问题时段，详见上方列表。")
        else: summary_points.append("根据当前使用的阈值，未发现明显的网络问题时段。")
        for point in summary_points: report.append(f"{list_indent}- {point}")

        report.append("\n" + sep)

    return "\n".join(report)

# --- 主程序入口 (保持不变) ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python {os.path.basename(sys.argv[0])} <udp_ping_log_file_path> [--md]")
        sys.exit(1)

    log_file = sys.argv[1]
    output_markdown = False
    if len(sys.argv) > 2 and "--md" in sys.argv[2:]:
        output_markdown = True

    analysis_report_content = analyze_udp_ping_log(log_file, output_markdown)

    if output_markdown:
        base_name = os.path.splitext(os.path.basename(log_file))[0]
        # 移除可能存在的 '_client' 后缀
        if base_name.endswith('_client'): base_name = base_name[:-7]
        md_filename = f"{base_name}_udp_report.md" # 添加 _udp_ 区分
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
