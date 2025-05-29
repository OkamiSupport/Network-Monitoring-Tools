#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import argparse
import time
import statistics # 用于计算平均值、标准差
import logging
import os
import struct # 用于打包和解包头部数据
import sys
from datetime import datetime
import math # 用于处理 NaN

# --- 配置常量 ---
DEFAULT_PORT = 9999
# DEFAULT_COUNT 不再作为周期模式下的包数，仅作为未指定 -n 时的概念标记
# DEFAULT_COUNT = 10
DEFAULT_INTERVAL = 1.0    # Ping 包之间的间隔 (秒)
DEFAULT_SUMMARY_INTERVAL = 10.0 # 记录汇总日志的间隔 (秒)
DEFAULT_TIMEOUT = 1.0
DEFAULT_PAYLOAD_SIZE = 64
HEADER_FORMAT = '!Qd'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

logger = None
log_filepath = None

# --- 辅助函数 (不变) ---
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
        raise ValueError("接收到的数据包太小，无法包含完整的头部")
    seq_num, timestamp = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    return seq_num, timestamp, data[HEADER_SIZE:]

# --- 服务端模式 (不变, 无日志) ---
def run_server(host, port, buffer_size):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((host, port))
        print(f"UDP Ping 服务端正在监听 {host}:{port}...")
        while True:
            try:
                message, address = server_socket.recvfrom(buffer_size)
                reply_packet = message
                server_socket.sendto(reply_packet, address)
            except ValueError as e:
                print(f"服务端错误 (来自 {address}): 解包错误 - {e}", file=sys.stderr)
            except socket.error as e:
                print(f"服务端 Socket 错误: {e}", file=sys.stderr)
            except Exception as e:
                print(f"服务端发生意外错误: {e}", file=sys.stderr)
    except socket.error as e:
        print(f"错误: 服务端绑定到 {host}:{port} 失败 - {e}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n服务端正在关闭。")
    finally:
        server_socket.close()
        print("服务端 socket 已关闭。")

# --- 客户端模式 ---
def setup_client_logger(target_host, target_port):
    """配置客户端日志记录器"""
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

    print(f"详细日志将记录到: {log_filepath}")
    return True

def write_log_header(host, port, packets_per_run_arg, interval, payload_size, timeout, summary_interval, calculated_packets_per_cycle):
    """写入日志文件的头部信息和表头"""
    global logger
    start_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info("=" * 90)
    logger.info(f"UDP Ping 监控日志")
    logger.info(f"目标 IP: {host}")
    logger.info(f"目标端口: {port}")
    logger.info(f"监控启动于: {start_time_str}")
    if packets_per_run_arg is None: # 周期模式
        logger.info(f"每次测量 PING 包数: {calculated_packets_per_cycle} (根据汇总间隔和 Ping 间隔计算)")
        logger.info(f"日志汇总间隔 (秒): {summary_interval}")
    else: # 单次模式
         logger.info(f"本次运行 PING 包数: {packets_per_run_arg} (由 -n 指定)")
    logger.info(f"PING 间隔 (秒): {interval}")
    logger.info(f"PING 大小 (字节): {payload_size}")
    logger.info(f"PING 超时 (秒): {timeout}")
    logger.info("-" * 90)

    col_sent = 5; col_recv = 5; col_loss = 10; col_min = 12; col_avg = 12; col_max = 12; col_std = 12; col_jit = 12; col_siz = 12
    header_line = (f"{'发送':<{col_sent}} | {'接收':<{col_recv}} | {'丢包率(%)':<{col_loss}} | "
                   f"{'Min RTT(ms)':<{col_min}} | {'Avg RTT(ms)':<{col_avg}} | {'Max RTT(ms)':<{col_max}} | "
                   f"{'StdDev(ms)':<{col_std}} | {'Jitter(ms)':<{col_jit}} | "
                   f"{'Size(bytes)':<{col_siz}}")
    logger.info(header_line)
    total_width = col_sent + col_recv + col_loss + col_min + col_avg + col_max + col_std + col_jit + col_siz + (8 * 3)
    logger.info("-" * total_width)

def log_batch_stats(sent, received, loss_percent, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, size):
    """将单批统计数据格式化并写入日志"""
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
    """执行一轮包含 batch_count 个包的 Ping 测试"""
    # (此函数内部逻辑与 v4 基本一致，无需修改)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(timeout)
    results = {'sent': 0, 'received': 0, 'rtts': [], 'errors': 0}
    sent_timestamps = {}
    ping_batch_start_time = time.time()

    if verbose: print(f"  开始发送 {batch_count} 个包...")

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
                                if verbose: print(f"    来自 {server_address[0]} 回复: seq={seq} time={rtt:.3f} ms")
                                del sent_timestamps[seq]
                    except ValueError as e:
                         if verbose: print(f"    警告: 解包回复错误: {e}", file=sys.stderr)
                         results['errors'] += 1
                         if seq in sent_timestamps: del sent_timestamps[seq]
            except socket.timeout:
                if verbose: print(f"    请求超时 (seq={seq})")
            except socket.error as e:
                 if verbose: print(f"    警告: 接收错误: {e}", file=sys.stderr)
                 results['errors'] += 1
                 if seq in sent_timestamps: del sent_timestamps[seq]
        except socket.error as e:
            if verbose: print(f"    错误: 发送 SEQ={seq} 失败: {e}", file=sys.stderr)
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

    if verbose: print(f"  本轮 Ping ({batch_count}次) 完成，耗时: {ping_batch_duration:.3f} 秒，丢包率: {loss_percent:.1f}%")

    return results, loss_percent, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, ping_batch_duration


def run_client(host, port, count_arg, interval, timeout, payload_size, buffer_size, summary_interval, verbose):
    """运行UDP Ping 客户端 (支持单次运行或周期监控)"""
    global logger, log_filepath

    try:
        target_addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        target_addr = target_addr_info[0][4]
        target_ip = target_addr[0]
    except socket.gaierror as e:
        print(f"错误: 无法解析目标主机 '{host}' - {e}", file=sys.stderr); return
    except Exception as e:
        print(f"错误: 设置目标地址时发生未知错误 - {e}", file=sys.stderr); return

    if not setup_client_logger(target_ip, port):
         print("错误: 初始化日志记录器失败。", file=sys.stderr); return

    run_once = count_arg is not None
    packets_per_batch = count_arg # 单次模式下使用指定的 count
    calculated_packets_per_cycle = None # 周期模式下计算的值

    if not run_once:
        # --- 周期性监控模式 ---
        if interval <= 0:
             print("错误: PING 间隔 -i 必须是正数，尤其在周期模式下。", file=sys.stderr)
             return
        calculated_packets_per_cycle = max(1, int(summary_interval / interval))
        packets_per_batch = calculated_packets_per_cycle # 周期模式下使用计算的包数

    # 写入日志头
    write_log_header(target_ip, port, count_arg, interval, payload_size, timeout, summary_interval if not run_once else math.nan, calculated_packets_per_cycle)

    try:
        if run_once:
            # --- 单次运行模式 ---
            if verbose: print(f"开始单次 Ping -> {target_ip}:{port} ({count_arg}次)...")
            results, loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, duration = _perform_ping_batch(target_addr, count_arg, interval, timeout, payload_size, buffer_size, verbose)
            log_batch_stats(results['sent'], results['received'], loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, payload_size)
            print(f"统计结果已记录到: {log_filepath}")

        else:
            # --- 周期性监控模式 ---
            print(f"开始周期性 Ping 监控 -> {target_ip}:{port} (每~{summary_interval}s 测量 {packets_per_batch} 次, 按 Ctrl+C 停止)")
            while True:
                cycle_start_time = time.time()
                if verbose: print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 开始新一轮周期性 Ping ({packets_per_batch}次)...")

                results, loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, duration = _perform_ping_batch(target_addr, packets_per_batch, interval, timeout, payload_size, buffer_size, verbose)

                log_batch_stats(results['sent'], results['received'], loss, rtt_min, rtt_avg, rtt_max, rtt_stdev, jitter, payload_size)

                # 周期模式下不再需要 sleep，因为 _perform_ping_batch 的耗时已经决定了周期
                # 如果执行时间小于 summary_interval，下一轮会立即开始，导致记录频率高于预期
                # 如果执行时间大于 summary_interval，下一轮会在完成后开始，导致记录频率低于预期
                # 这更符合“在一个窗口内尽可能多地发包”的逻辑
                # 如果需要严格按 summary_interval 触发 *开始* 时间，逻辑会更复杂

    except KeyboardInterrupt:
        print("\n监控被中断，正在退出...")
    except Exception as e:
        print(f"\n客户端发生严重错误，正在退出: {e}", file=sys.stderr)
        if logger: logger.error(f"客户端发生严重错误: {e}", exc_info=True)
    finally:
        print(f"监控结束。日志文件位于: {log_filepath}")
        if logger:
            handlers = logger.handlers[:]
            for handler in handlers:
                handler.close(); logger.removeHandler(handler)

# --- 主程序入口 (不变) ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Ping 工具 v5 - 周期性监控或单次运行，按间隔填充周期。")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-s', '--server', action='store_true', help="运行为服务端模式 (无日志)")
    mode_group.add_argument('-c', '--client', metavar='目标主机', help="运行为客户端模式，指定目标主机IP或域名")
    parser.add_argument('-H', '--host', default='0.0.0.0', help="服务端绑定的主机地址 (默认: 0.0.0.0)")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help=f"UDP 端口号 (默认: {DEFAULT_PORT})")
    parser.add_argument('-b', '--buffer', type=int, default=1024, help="接收缓冲区大小 (字节, 默认: 1024)")
    parser.add_argument('-n', '--count', type=int, default=None, metavar='N',
                        help="发送 ping 的次数 (指定次数则运行一次后退出, 默认: 无限循环监控)")
    parser.add_argument('-i', '--interval', type=float, default=DEFAULT_INTERVAL, metavar='SEC',
                        help=f"两次 PING 之间的等待间隔 (秒, 默认: {DEFAULT_INTERVAL})")
    parser.add_argument('-t', '--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SEC',
                        help=f"每次回复的等待超时时间 (秒, 默认: {DEFAULT_TIMEOUT})")
    parser.add_argument('-S', '--size', type=int, default=DEFAULT_PAYLOAD_SIZE, metavar='BYTES',
                        help=f"发送数据包的总大小 (字节, 默认: {DEFAULT_PAYLOAD_SIZE})")
    parser.add_argument('-I', '--summary-interval', type=float, default=DEFAULT_SUMMARY_INTERVAL, metavar='SEC',
                        help=f"记录日志的汇总间隔 (秒, 用于周期监控模式计算每次测量的包数, 默认: {DEFAULT_SUMMARY_INTERVAL})")
    parser.add_argument('-v', '--verbose', action='store_true', help="启用客户端详细控制台输出 (非日志)")

    args = parser.parse_args()

    if args.client:
        if args.count is not None and args.count <= 0:
             print(f"错误: -n/--count 指定的次数 ({args.count}) 必须是正整数。", file=sys.stderr); sys.exit(1)
        if args.size < HEADER_SIZE:
            print(f"错误: 指定的数据包大小 ({args.size}) 小于头部大小 ({HEADER_SIZE})。", file=sys.stderr); sys.exit(1)
        if args.summary_interval <= 0:
             print(f"错误: 日志汇总间隔 -I/--summary-interval ({args.summary_interval}) 必须是正数。", file=sys.stderr); sys.exit(1)
        if args.interval <= 0 and args.count is None: # 周期模式下 interval 必须大于 0
            print(f"错误: 在周期监控模式下，PING 间隔 -i ({args.interval}) 必须是正数。", file=sys.stderr); sys.exit(1)


    if args.server:
        run_server(args.host, args.port, args.buffer)
    elif args.client:
        run_client(args.client, args.port, args.count, args.interval, args.timeout, args.size, args.buffer, args.summary_interval, args.verbose)
