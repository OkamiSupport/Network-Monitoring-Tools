#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import os
from datetime import datetime
import statistics
import socket
import time

# --- 可配置阈值 ---
HIGH_DNS_TIME_THRESHOLD = 500.0        # 高DNS解析时间阈值 (ms)
ERROR_RATE_THRESHOLD = 5.0             # 错误率阈值 (%)
SLOW_DNS_THRESHOLD = 200.0             # 慢DNS解析阈值 (ms)

# --- 动态基线计算参数 ---
MAX_BASELINE_CANDIDATES = 100
MIN_BASELINE_SAMPLES = 20
STABLE_SUCCESS_THRESHOLD = 95.0  # 成功率阈值

# --- 动态阈值计算参数 ---
DYNAMIC_DNS_TIME_FACTOR = 2.5
DYNAMIC_DNS_TIME_OFFSET = 50.0
MIN_DYNAMIC_DNS_TIME_THRESHOLD = 100.0

# --- 获取系统信息的函数 ---
def get_hostname():
    try:
        return socket.gethostname()
    except socket.error as e:
        print(f"警告: 无法获取主机名: {e}", file=sys.stderr)
        return "未知 (无法获取)"

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
        print(f"警告: 无法获取时区信息: {e}", file=sys.stderr)
        return "未知 (无法获取)"

# --- 解析日志行的函数 ---
def parse_log_line(line):
    # 解析格式: 解析时间(ms) | 解析IP | 所有IP地址 | 状态
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
            
            # 解析各个字段
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
            print(f"警告: 解析数据行时出错: {line.strip()} - {e}", file=sys.stderr)
            return None
    return None

def is_success_status(status):
    """判断状态是否为成功"""
    return status == "SUCCESS"

def is_numeric(value):
    """检查值是否为数字"""
    if value == "N/A":
        return False
    try:
        float(value)
        return True
    except ValueError:
        return False

def safe_float(value, default=0.0):
    """安全转换为浮点数"""
    if not is_numeric(value):
        return default
    try:
        return float(value)
    except ValueError:
        return default

def extract_unique_ips(all_ips_str):
    """从所有IP字符串中提取唯一IP地址"""
    if all_ips_str == "N/A" or not all_ips_str:
        return []
    
    # 移除方括号并分割
    clean_str = all_ips_str.replace('[', '').replace(']', '')
    ips = [ip.strip() for ip in clean_str.split(',') if ip.strip()]
    
    # 过滤有效IP地址
    valid_ips = []
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    for ip in ips:
        if ip_pattern.match(ip):
            valid_ips.append(ip)
    
    return list(set(valid_ips))  # 去重

def categorize_error(status):
    """分类错误类型"""
    if "TIMEOUT" in status:
        return "超时错误"
    elif "DNS_ERROR" in status:
        return "DNS解析错误"
    elif "NSLOOKUP_ERROR" in status:
        return "nslookup错误"
    elif "NO_IP_FOUND" in status:
        return "未找到IP地址"
    else:
        return "其他错误"

def analyze_dns_log(log_file_path, markdown_format=False):
    """分析 DNS 日志文件并生成报告内容"""
    
    analysis_hostname = get_hostname()
    analysis_timezone = get_timezone_info()
    
    metadata = {
        "target_domain": "未知",
        "dns_server": "未知",
        "system_dns_servers": "未知",
        "source_public_ip": "未知 (未在日志中找到)",
        "start_time_str": "未知",
        "interval_seconds": "未知",
        "dns_timeout": "未知",
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
                    # 解析头部信息
                    match_source_ip = re.match(r".*服务器源公网 IP:\s*(.*)", line)
                    if match_source_ip:
                        metadata["source_public_ip"] = match_source_ip.group(1).strip()
                        continue
                    
                    match_domain = re.match(r".*目标域名:\s*(.*)", line)
                    if match_domain:
                        metadata["target_domain"] = match_domain.group(1).strip()
                        continue
                    
                    match_dns_server = re.match(r".*DNS 服务器:\s*(.*)", line)
                    if match_dns_server:
                        metadata["dns_server"] = match_dns_server.group(1).strip()
                        continue
                    
                    match_system_dns = re.match(r".*系统 DNS 服务器:\s*(.*)", line)
                    if match_system_dns:
                        metadata["system_dns_servers"] = match_system_dns.group(1).strip()
                        continue
                    
                    match_start = re.match(r".*监控启动于:\s*(.*)", line)
                    if match_start:
                        metadata["start_time_str"] = match_start.group(1).strip()
                        continue
                    
                    match_interval = re.match(r".*测量间隔:\s*(\d+)\s*秒", line)
                    if match_interval:
                        metadata["interval_seconds"] = match_interval.group(1).strip()
                        continue
                    
                    match_timeout = re.match(r".*DNS 超时:\s*(\d+)\s*秒", line)
                    if match_timeout:
                        metadata["dns_timeout"] = match_timeout.group(1).strip()
                        continue
                    
                    if "---" in line:
                        if data_section_started:
                            header_parsed = True
                        else:
                            data_section_started = True
                        continue
                    
                    if "解析时间(ms)" in line:
                        data_section_started = True
                        header_parsed = True
                        continue
                
                if header_parsed:
                    record = parse_log_line(line)
                    if record:
                        data_records.append(record)
    
    except FileNotFoundError:
        return f"错误: 文件未找到: {log_file_path}"
    except Exception as e:
        return f"错误: 读取或解析文件时发生异常: {e}"
    
    if not data_records:
        return f"错误: 在文件 {log_file_path} 中未找到有效的数据记录。"
    
    # --- 分析逻辑 ---
    total_queries = len(data_records)
    first_timestamp = data_records[0]['timestamp']
    last_timestamp = data_records[-1]['timestamp']
    duration = last_timestamp - first_timestamp
    
    # 统计成功和失败
    success_records = [r for r in data_records if is_success_status(r['status'])]
    error_records = [r for r in data_records if not is_success_status(r['status'])]
    
    success_count = len(success_records)
    error_count = len(error_records)
    success_rate = (success_count / total_queries) * 100.0 if total_queries > 0 else 0.0
    error_rate = (error_count / total_queries) * 100.0 if total_queries > 0 else 0.0
    
    # 计算时间统计（仅成功的查询）
    if success_records:
        dns_times = [safe_float(r['dns_time']) for r in success_records if is_numeric(r['dns_time'])]
        
        avg_dns_time = statistics.mean(dns_times) if dns_times else 0.0
        min_dns_time = min(dns_times) if dns_times else 0.0
        max_dns_time = max(dns_times) if dns_times else 0.0
        median_dns_time = statistics.median(dns_times) if dns_times else 0.0
    else:
        avg_dns_time = min_dns_time = max_dns_time = median_dns_time = 0.0
    
    # 分析IP地址变化
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
        
        # 收集所有IP地址
        all_ips = extract_unique_ips(r['all_ips'])
        unique_ips.update(all_ips)
    
    # 错误类型统计
    error_types = {}
    for r in error_records:
        error_type = categorize_error(r['status'])
        error_types[error_type] = error_types.get(error_type, 0) + 1
    
    # 动态阈值计算
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
                baseline_fallback_reason = "基线数据中缺少有效的时间数据"
        except statistics.StatisticsError as e:
            dynamic_thresholds_calculated = False
            baseline_fallback_reason = f"基线统计计算错误: {e}"
    else:
        dynamic_thresholds_calculated = False
        if len(data_records) < MIN_BASELINE_SAMPLES:
            baseline_fallback_reason = f"日志数据不足 (少于 {MIN_BASELINE_SAMPLES} 条)"
        else:
            baseline_fallback_reason = f"日志初始 {MAX_BASELINE_CANDIDATES} 条记录中成功样本不足 (< {MIN_BASELINE_SAMPLES} 条)"
    
    if not dynamic_thresholds_calculated:
        current_dns_time_threshold = HIGH_DNS_TIME_THRESHOLD
    
    current_error_rate_threshold = ERROR_RATE_THRESHOLD
    
    # 识别问题时段
    slow_dns_periods = []
    error_periods = []
    
    for r in data_records:
        ts = r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        # 检查DNS解析时间
        if is_numeric(r['dns_time']) and safe_float(r['dns_time']) > current_dns_time_threshold:
            slow_dns_periods.append(f"{ts} (DNS时间: {r['dns_time']}ms)")
        
        # 检查错误
        if not is_success_status(r['status']):
            error_periods.append(f"{ts} (状态: {r['status']})")
    
    # --- 生成报告内容 ---
    report = []
    
    if markdown_format:
        # Markdown 报告
        sep_line = "---"
        title_prefix = "# "
        section_prefix = "## "
        subsection_prefix = "### "
        list_item = "*   "
        code_wrapper = "`"
        bold_wrapper = "**"
        
        report.append(f"{title_prefix}DNS 解析监控分析报告: {code_wrapper}{metadata['target_domain']}{code_wrapper}")
        report.append(sep_line)
        
        report.append(f"{section_prefix}监控配置与环境")
        report.append(f"{list_item}{bold_wrapper}目标域名:{bold_wrapper} {code_wrapper}{metadata['target_domain']}{code_wrapper}")
        report.append(f"{list_item}{bold_wrapper}DNS 服务器:{bold_wrapper} {code_wrapper}{metadata['dns_server']}{code_wrapper}")
        if metadata['system_dns_servers'] != "未知":
            report.append(f"{list_item}{bold_wrapper}系统 DNS 服务器:{bold_wrapper} {metadata['system_dns_servers']}")
        report.append(f"{list_item}{bold_wrapper}源公网 IP:{bold_wrapper} {code_wrapper}{metadata['source_public_ip']}{code_wrapper}")
        report.append(f"{list_item}日志文件: {code_wrapper}{os.path.basename(log_file_path)}{code_wrapper}")
        report.append(f"{list_item}监控开始: {metadata['start_time_str']}")
        report.append(f"{list_item}分析数据范围: {code_wrapper}{first_timestamp}{code_wrapper} 至 {code_wrapper}{last_timestamp}{code_wrapper}")
        report.append(f"{list_item}总持续时间: {duration}")
        report.append(f"{list_item}总查询次数: {total_queries}")
        report.append(f"{list_item}测量间隔: {metadata['interval_seconds']} 秒")
        report.append(f"{list_item}DNS 超时: {metadata['dns_timeout']} 秒")
        report.append(f"{list_item}分析主机名: {code_wrapper}{metadata['analysis_hostname']}{code_wrapper}")
        report.append(f"{list_item}分析时区: {metadata['analysis_timezone']}")
        report.append("")
        
        report.append(f"{section_prefix}整体统计")
        report.append(f"{list_item}总查询数: {total_queries}")
        report.append(f"{list_item}成功查询数: {success_count}")
        report.append(f"{list_item}失败查询数: {error_count}")
        report.append(f"{list_item}成功率: {bold_wrapper}{success_rate:.2f}%{bold_wrapper}")
        report.append(f"{list_item}错误率: {bold_wrapper}{error_rate:.2f}%{bold_wrapper}")
        report.append(f"{list_item}平均DNS解析时间: {code_wrapper}{avg_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}最小DNS解析时间: {code_wrapper}{min_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}最大DNS解析时间: {code_wrapper}{max_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}中位数DNS解析时间: {code_wrapper}{median_dns_time:.1f} ms{code_wrapper}")
        report.append(f"{list_item}解析到的唯一IP数量: {len(unique_ips)}")
        if unique_ips:
            report.append(f"{list_item}所有解析IP: {', '.join(sorted(unique_ips))}")
        report.append("")
        
        if ip_changes:
            report.append(f"{section_prefix}IP地址变化记录")
            report.append(f"{list_item}检测到 {len(ip_changes)} 次IP地址变化:")
            for change in ip_changes:
                report.append(f"    {list_item}{change['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {change['old_ip']} → {change['new_ip']}")
            report.append("")
        
        if error_types:
            report.append(f"{section_prefix}错误类型统计")
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_queries) * 100
                report.append(f"{list_item}{error_type}: {count} 次 ({percentage:.1f}%)")
            report.append("")
        
        report.append(f"{section_prefix}分析阈值")
        if dynamic_thresholds_calculated:
            report.append(f"{list_item}使用 {bold_wrapper}动态阈值{bold_wrapper} (基于日志初始数据计算):")
            report.append(f"    {list_item}基线DNS解析时间: {code_wrapper}{baseline_dns_time:.1f} ms{code_wrapper}")
            report.append(f"    {list_item}高DNS解析时间阈值: > {code_wrapper}{current_dns_time_threshold:.1f} ms{code_wrapper}")
        else:
            report.append(f"{list_item}使用 {bold_wrapper}固定阈值{bold_wrapper} (原因: {baseline_fallback_reason}):")
            report.append(f"    {list_item}高DNS解析时间阈值: > {code_wrapper}{current_dns_time_threshold:.1f} ms{code_wrapper}")
        
        report.append(f"    {list_item}高错误率阈值: > {code_wrapper}{current_error_rate_threshold:.1f}%{code_wrapper}")
        report.append("")
        
        report.append(f"{section_prefix}潜在问题时段")
        if slow_dns_periods or error_periods:
            if slow_dns_periods:
                report.append(f"{subsection_prefix}慢DNS解析 (>{current_dns_time_threshold:.1f}ms) - {len(slow_dns_periods)} 次")
                for p in slow_dns_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
            
            if error_periods:
                report.append(f"{subsection_prefix}DNS解析错误 - {len(error_periods)} 次")
                for p in error_periods:
                    report.append(f"{list_item}{p}")
                report.append("")
        else:
            report.append(f"{list_item}未检测到明显超出阈值的问题时段。")
            report.append("")
        
        report.append(f"{section_prefix}总结")
        summary_points = []
        
        if success_rate >= 99.0:
            summary_points.append(f"DNS解析可靠性{bold_wrapper}极佳{bold_wrapper}，成功率达到 {code_wrapper}{success_rate:.2f}%{code_wrapper}。")
        elif success_rate >= 95.0:
            summary_points.append(f"DNS解析可靠性良好，成功率为 {code_wrapper}{success_rate:.2f}%{code_wrapper}。")
        elif success_rate >= 90.0:
            summary_points.append(f"DNS解析可靠性一般，成功率为 {code_wrapper}{success_rate:.2f}%{code_wrapper}，需要关注。")
        else:
            summary_points.append(f"DNS解析可靠性{bold_wrapper}较差{bold_wrapper}，成功率仅为 {code_wrapper}{success_rate:.2f}%{code_wrapper}，{bold_wrapper}需要紧急处理{bold_wrapper}。")
        
        if avg_dns_time < current_dns_time_threshold / 3:
            summary_points.append(f"平均DNS解析时间{bold_wrapper}优秀{bold_wrapper} ({code_wrapper}{avg_dns_time:.1f}ms{code_wrapper})，响应迅速。")
        elif avg_dns_time < current_dns_time_threshold:
            summary_points.append(f"平均DNS解析时间可接受 ({code_wrapper}{avg_dns_time:.1f}ms{code_wrapper})。")
        else:
            summary_points.append(f"平均DNS解析时间{bold_wrapper}较慢{bold_wrapper} ({code_wrapper}{avg_dns_time:.1f}ms{code_wrapper})，可能影响网络体验。")
        
        if len(unique_ips) > 1:
            summary_points.append(f"域名解析到 {len(unique_ips)} 个不同IP地址，显示负载均衡或CDN配置。")
        
        if ip_changes:
            summary_points.append(f"检测到 {len(ip_changes)} 次IP地址变化，可能表明DNS记录更新或负载均衡切换。")
        
        if error_periods:
            summary_points.append(f"检测到 {len(error_periods)} 次DNS解析错误，详见上方列表。")
        else:
            summary_points.append("未发现DNS解析错误，服务稳定性良好。")
        
        for point in summary_points:
            report.append(f"{list_item}{point}")
    
    else:
        # 纯文本报告
        sep = "=" * 60
        sub_sep = "-" * 60
        list_indent = "  "
        
        report.append(sep)
        report.append(f" DNS 解析监控分析报告: {metadata['target_domain']}")
        report.append(sep)
        report.append("")
        
        report.append("--- 监控配置与环境 ---")
        report.append(f"{list_indent}目标域名:           {metadata['target_domain']}")
        report.append(f"{list_indent}DNS 服务器:         {metadata['dns_server']}")
        if metadata['system_dns_servers'] != "未知":
            report.append(f"{list_indent}系统 DNS 服务器:    {metadata['system_dns_servers']}")
        report.append(f"{list_indent}源公网 IP:          {metadata['source_public_ip']}")
        report.append(f"{list_indent}日志文件:           {os.path.basename(log_file_path)}")
        report.append(f"{list_indent}监控开始:           {metadata['start_time_str']}")
        report.append(f"{list_indent}分析数据范围:       {first_timestamp} 至 {last_timestamp}")
        report.append(f"{list_indent}总持续时间:         {duration}")
        report.append(f"{list_indent}总查询次数:         {total_queries}")
        report.append(f"{list_indent}测量间隔:           {metadata['interval_seconds']} 秒")
        report.append(f"{list_indent}DNS 超时:           {metadata['dns_timeout']} 秒")
        report.append(f"{list_indent}分析主机名:         {metadata['analysis_hostname']}")
        report.append(f"{list_indent}分析时区:           {metadata['analysis_timezone']}")
        report.append("")
        
        report.append("--- 整体统计 ---")
        report.append(f"{list_indent}总查询数:           {total_queries}")
        report.append(f"{list_indent}成功查询数:         {success_count}")
        report.append(f"{list_indent}失败查询数:         {error_count}")
        report.append(f"{list_indent}成功率:             {success_rate:.2f}%")
        report.append(f"{list_indent}错误率:             {error_rate:.2f}%")
        report.append(f"{list_indent}平均DNS解析时间:    {avg_dns_time:.1f} ms")
        report.append(f"{list_indent}最小DNS解析时间:    {min_dns_time:.1f} ms")
        report.append(f"{list_indent}最大DNS解析时间:    {max_dns_time:.1f} ms")
        report.append(f"{list_indent}中位数DNS解析时间:  {median_dns_time:.1f} ms")
        report.append(f"{list_indent}解析到的唯一IP数量: {len(unique_ips)}")
        if unique_ips:
            report.append(f"{list_indent}所有解析IP:         {', '.join(sorted(unique_ips))}")
        report.append("")
        
        if ip_changes:
            report.append("--- IP地址变化记录 ---")
            report.append(f"{list_indent}检测到 {len(ip_changes)} 次IP地址变化:")
            for change in ip_changes:
                report.append(f"{list_indent}  - {change['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {change['old_ip']} → {change['new_ip']}")
            report.append("")
        
        if error_types:
            report.append("--- 错误类型统计 ---")
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_queries) * 100
                report.append(f"{list_indent}{error_type}: {count} 次 ({percentage:.1f}%)")
            report.append("")
        
        report.append("--- 分析阈值 ---")
        if dynamic_thresholds_calculated:
            report.append(f"{list_indent}模式: 动态阈值 (基于日志初始数据计算)")
            report.append(f"{list_indent}  - 基线DNS解析时间: {baseline_dns_time:.1f} ms")
            report.append(f"{list_indent}使用的阈值:")
            report.append(f"{list_indent}  - 高DNS解析时间:   > {current_dns_time_threshold:.1f} ms")
        else:
            report.append(f"{list_indent}模式: 固定阈值 (原因: {baseline_fallback_reason})")
            report.append(f"{list_indent}使用的阈值:")
            report.append(f"{list_indent}  - 高DNS解析时间:   > {current_dns_time_threshold:.1f} ms")
        
        report.append(f"{list_indent}  - 高错误率:         > {current_error_rate_threshold:.1f}%")
        report.append("")
        
        report.append("--- 潜在问题时段 ---")
        if slow_dns_periods or error_periods:
            if slow_dns_periods:
                report.append(f"{list_indent}慢DNS解析 (>{current_dns_time_threshold:.1f}ms) - {len(slow_dns_periods)} 次:")
                for p in slow_dns_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
            
            if error_periods:
                report.append(f"{list_indent}DNS解析错误 - {len(error_periods)} 次:")
                for p in error_periods:
                    report.append(f"{list_indent}  - {p}")
                report.append("")
        else:
            report.append(f"{list_indent}未检测到明显超出阈值的问题时段。")
            report.append("")
        
        report.append("--- 总结 ---")
        summary_points = []
        
        if success_rate >= 99.0:
            summary_points.append(f"DNS解析可靠性极佳，成功率达到 {success_rate:.2f}%。")
        elif success_rate >= 95.0:
            summary_points.append(f"DNS解析可靠性良好，成功率为 {success_rate:.2f}%。")
        elif success_rate >= 90.0:
            summary_points.append(f"DNS解析可靠性一般，成功率为 {success_rate:.2f}%，需要关注。")
        else:
            summary_points.append(f"DNS解析可靠性较差，成功率仅为 {success_rate:.2f}%，需要紧急处理。")
        
        if avg_dns_time < current_dns_time_threshold / 3:
            summary_points.append(f"平均DNS解析时间优秀 ({avg_dns_time:.1f}ms)，响应迅速。")
        elif avg_dns_time < current_dns_time_threshold:
            summary_points.append(f"平均DNS解析时间可接受 ({avg_dns_time:.1f}ms)。")
        else:
            summary_points.append(f"平均DNS解析时间较慢 ({avg_dns_time:.1f}ms)，可能影响网络体验。")
        
        if len(unique_ips) > 1:
            summary_points.append(f"域名解析到 {len(unique_ips)} 个不同IP地址，显示负载均衡或CDN配置。")
        
        if ip_changes:
            summary_points.append(f"检测到 {len(ip_changes)} 次IP地址变化，可能表明DNS记录更新或负载均衡切换。")
        
        if error_periods:
            summary_points.append(f"检测到 {len(error_periods)} 次DNS解析错误，详见上方列表。")
        else:
            summary_points.append("未发现DNS解析错误，服务稳定性良好。")
        
        for point in summary_points:
            report.append(f"{list_indent}{point}")
        
        report.append("")
        report.append(sep)
    
    return "\n".join(report)

def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <DNS日志文件路径> [--markdown]")
        print("示例:")
        print(f"  {sys.argv[0]} dns_monitor_google.com_8.8.8.8.log")
        print(f"  {sys.argv[0]} dns_monitor_google.com_system.log --markdown")
        sys.exit(1)
    
    log_file_path = sys.argv[1]
    markdown_format = '--markdown' in sys.argv
    
    if not os.path.exists(log_file_path):
        print(f"错误: 日志文件不存在: {log_file_path}")
        sys.exit(1)
    
    print(f"正在分析DNS日志文件: {log_file_path}")
    if markdown_format:
        print("输出格式: Markdown")
    else:
        print("输出格式: 纯文本")
    print()
    
    result = analyze_dns_log(log_file_path, markdown_format)
    print(result)

if __name__ == "__main__":
    main()