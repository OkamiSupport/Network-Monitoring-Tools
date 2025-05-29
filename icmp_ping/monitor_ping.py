#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import time
import re
import logging
import platform
import signal # 用于更优雅地处理中断信号
import urllib.request # <--- 新增：用于获取公网 IP
import socket # <--- 新增：用于处理网络超时等错误

# --- 配置 ---
PING_COUNT = 10          # 每次测量周期发送的 PING 包数量 (可以适当增加以获得更平滑的数据)
INTERVAL_SECONDS = 5     # 测量间隔时间（秒）(缩短间隔以获得更接近“连续”的感觉)
PING_TIMEOUT = 2         # 单个 ping 的超时时间（秒），用于 -W 或 -w 参数
IP_FETCH_TIMEOUT = 5     # 获取公网 IP 的超时时间（秒）
# --- 配置结束 ---

# 全局变量，用于信号处理
keep_running = True

def signal_handler(sig, frame):
    """处理中断信号 (Ctrl+C)"""
    global keep_running
    print("\n收到中断信号，正在停止监控...")
    keep_running = False

def get_public_ip():
    """尝试从 api.ipify.org 获取公网 IP 地址"""
    urls = ["https://api.ipify.org", "https://ipinfo.io/ip", "https://checkip.amazonaws.com"]
    for url in urls:
        try:
            # 设置 User-Agent 避免被某些服务阻止
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=IP_FETCH_TIMEOUT) as response:
                ip = response.read().decode('utf-8').strip()
                # 简单验证一下是否是 IP 格式
                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
                    return ip
                else:
                    print(f"Warning: Fetched invalid IP format from {url}: {ip}")
                    continue # 尝试下一个 URL
        except (urllib.error.URLError, socket.timeout, ConnectionResetError) as e:
            print(f"Warning: Could not fetch public IP from {url}: {e}")
        except Exception as e:
            print(f"Warning: An unexpected error occurred while fetching public IP from {url}: {e}")
    # 如果所有 URL 都失败了
    print("Warning: Failed to fetch public IP from all sources.")
    return "N/A" # 返回 N/A 表示获取失败

def setup_logging(target_ip):
    """配置日志记录器"""
    log_filename = f"network_monitor_{target_ip.replace('.', '_')}.log"
    logger = logging.getLogger('NetworkMonitor')
    logger.setLevel(logging.INFO)

    # 创建文件处理器
    fh = logging.FileHandler(log_filename, encoding='utf-8')
    fh.setLevel(logging.INFO)

    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)

    # 添加处理器到记录器 (防止重复添加)
    if not logger.hasHandlers():
        logger.addHandler(fh)
        # 如果也想在屏幕输出日志，取消下面两行的注释
        # ch = logging.StreamHandler()
        # ch.setFormatter(formatter)
        # logger.addHandler(ch)

    # 检查日志文件是否为空，如果为空则写入头部信息
    try:
        # 尝试读取文件大小判断是否为空
        with open(log_filename, 'r', encoding='utf-8') as f:
            f.seek(0, 2) # Go to end of file
            if f.tell() == 0: # Check if file is empty
                 raise FileNotFoundError # Treat empty file as new
            # 如果文件非空，假设头部已存在，不再写入
    except (FileNotFoundError, IOError):
         # 文件不存在或为空，写入头部信息
         source_ip = get_public_ip() # <--- 在写入头部前获取公网 IP
         logger.info(f"=== 网络监控日志 ===")
         logger.info(f"目标 IP: {target_ip}")
         logger.info(f"服务器源公网 IP: {source_ip}") # <--- 新增行：显示源公网 IP
         logger.info(f"监控启动于: {time.strftime('%Y-%m-%d %H:%M:%S')}")
         logger.info(f"每次测量 PING 包数: {PING_COUNT}")
         logger.info(f"测量间隔: {INTERVAL_SECONDS} 秒")
         logger.info(f"Ping 超时: {PING_TIMEOUT} 秒")
         logger.info("-" * 80)
         logger.info("发送 | 接收 | 丢包率(%) | Min RTT(ms) | Avg RTT(ms) | Max RTT(ms) | StdDev RTT(ms)")
         logger.info("-" * 80)

    return logger

def parse_ping_output(output, ping_count):
    """解析 ping 命令的输出 (适配 Linux 和 macOS/Windows 的常见格式)"""
    loss_percent = "ERR"
    rtt_min, rtt_avg, rtt_max, rtt_mdev = "N/A", "N/A", "N/A", "N/A"
    packets_transmitted, packets_received = "ERR", "ERR"

    # 解析丢包率和包数量 (多种格式适配)
    loss_match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+received.*,\s+([\d.]+)%\s+packet loss", output, re.IGNORECASE | re.DOTALL)
    if not loss_match: # 尝试另一种常见格式 (例如 Windows 中文)
         loss_match = re.search(r"数据包: 已发送 = (\d+)，已接收 = (\d+)，丢失 = \d+ \((.*)%\s+丢失\)", output, re.IGNORECASE | re.DOTALL)
    if not loss_match: # 尝试 macOS 格式 (可能没有逗号)
        loss_match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+packets received,\s*([\d.]+)%\s+packet loss", output, re.IGNORECASE | re.DOTALL)
    if not loss_match: # 另一种 Linux 格式 (e.g. busybox ping)
        loss_match = re.search(r"(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss", output, re.IGNORECASE | re.DOTALL)


    if loss_match:
        packets_transmitted = loss_match.group(1)
        packets_received = loss_match.group(2)
        loss_percent = loss_match.group(3).strip() # 去掉可能的尾随空格
    else:
        # 如果完全没收到，可能只有 100% loss 的提示
        if "100% packet loss" in output or "100% 丢失" in output:
             loss_percent = "100"
             packets_transmitted = str(ping_count) # 假设尝试发送了这么多
             packets_received = "0"
        elif " 0% packet loss" in output or "0% 丢失" in output:
             # 即使0%丢包，也要尝试提取发送/接收数量
             tx_rx_match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+received", output, re.IGNORECASE | re.DOTALL)
             if not tx_rx_match:
                 tx_rx_match = re.search(r"数据包: 已发送 = (\d+)，已接收 = (\d+)", output, re.IGNORECASE | re.DOTALL)
             if tx_rx_match:
                 packets_transmitted = tx_rx_match.group(1)
                 packets_received = tx_rx_match.group(2)
                 loss_percent = "0"
             else: # 如果连发送接收都找不到，但确实是0%丢包
                 packets_transmitted = str(ping_count)
                 packets_received = str(ping_count)
                 loss_percent = "0"

    # 解析 RTT (min/avg/max/stddev or mdev)
    rtt_match = re.search(r"min/avg/max/(?:stddev|mdev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", output, re.IGNORECASE | re.DOTALL)
    if not rtt_match: # 尝试 Windows 格式 (最短/最长/平均)
        rtt_match_win = re.search(r"最短\s*=\s*(\d+)ms.*最长\s*=\s*(\d+)ms.*平均\s*=\s*(\d+)ms", output, re.IGNORECASE | re.DOTALL)
        if rtt_match_win:
             rtt_min = rtt_match_win.group(1)
             rtt_max = rtt_match_win.group(2)
             rtt_avg = rtt_match_win.group(3)
             rtt_mdev = "N/A" # Windows ping 不直接提供标准差

    if rtt_match:
        rtt_min = rtt_match.group(1)
        rtt_avg = rtt_match.group(2)
        rtt_max = rtt_match.group(3)
        rtt_mdev = rtt_match.group(4)

    # 如果无法解析任何内容，且输出不为空，返回错误标记
    if loss_percent == "ERR" and packets_transmitted == "ERR" and output and "unknown host" not in output.lower() and "unreachable" not in output.lower():
        return "ERR", "ERR", "ERR", "N/A", "N/A", "N/A", "N/A", True # Return parse_error = True

    # 处理完全无法访问的情况
    if "unknown host" in output.lower() or "host unreachable" in output.lower() or "request timed out" in output.lower() and packets_transmitted == "ERR":
        packets_transmitted = str(ping_count)
        packets_received = "0"
        loss_percent = "100"
        rtt_min, rtt_avg, rtt_max, rtt_mdev = "N/A", "N/A", "N/A", "N/A"

    # 确保数字格式统一
    try:
        if loss_percent != "ERR" and loss_percent != "N/A":
            loss_percent = "{:.1f}".format(float(loss_percent)) # 保留一位小数
    except ValueError:
        pass # 如果转换失败，保持原样

    return packets_transmitted, packets_received, loss_percent, rtt_min, rtt_avg, rtt_max, rtt_mdev, False # Return parse_error = False

def run_ping(target_ip, count, timeout):
    """执行 ping 命令并返回其输出和是否有执行错误"""
    system = platform.system().lower()
    if system == "windows":
        # Windows ping: -n count, -w timeout (milliseconds)
        command = ['ping', '-n', str(count), '-w', str(int(timeout * 1000)), target_ip]
    else:
        # Linux/macOS ping: -c count, -W timeout (seconds)
        command = ['ping', '-c', str(count), '-W', str(timeout), target_ip]

    try:
        # 设置 Popen 的 locale 为 C 使得输出为英文，更容易解析
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore', env={'LANG': 'C'})
        # 设置一个合理的总超时时间，防止 ping 命令本身卡死
        # 例如，发送 count 个包，每个最多等 timeout 秒，再加上一些额外时间
        communicate_timeout = (count * timeout) + 5 # 增加 5 秒的 buffer
        stdout, stderr = process.communicate(timeout=communicate_timeout)

        # 退出码 > 1 通常表示严重错误 (e.g., unknown host, network unreachable)
        # 退出码 1 在 Linux/macOS 上可能表示有丢包但有响应，这不算执行错误
        # Windows 退出码 0 表示成功，非 0 表示失败
        is_error = False
        if system == "windows":
            if process.returncode != 0:
                is_error = True
        else: # Linux/macOS
            if process.returncode > 1:
                 is_error = True

        if is_error:
             # 优先使用 stderr 中的信息，如果为空则用 stdout
             error_message = stderr.strip() if stderr.strip() else stdout.strip()
             if not error_message: error_message = f"Ping command failed with return code {process.returncode}"
             # 对于 'unknown host' 或 'unreachable'，输出可能在 stdout
             if "unknown host" in stdout.lower() or "host unreachable" in stdout.lower():
                 error_message = stdout.strip()
             return f"Execution Error: {error_message}", True # 返回执行错误

        return stdout + stderr, False # 合并 stdout 和 stderr, 返回无执行错误
    except subprocess.TimeoutExpired:
        # 如果 communicate 超时，强制终止进程
        try:
            process.kill()
            process.wait() # 等待进程完全终止
        except OSError:
            pass # 进程可能已经结束
        return f"Execution Error: Ping command timed out after {communicate_timeout} seconds.", True
    except FileNotFoundError:
        return "Execution Error: 'ping' command not found. Please install it.", True
    except Exception as e:
        return f"Execution Error: An unexpected error occurred: {e}", True


def main():
    global keep_running
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标 IP 地址或域名>")
        print("脚本将持续运行，按 Ctrl+C 停止。")
        sys.exit(1)

    target_ip_or_domain = sys.argv[1]
    target_ip = target_ip_or_domain # 默认使用用户输入

    # 尝试解析域名获取 IP (如果输入的是域名)，日志文件名仍使用域名
    try:
        target_ip = socket.gethostbyname(target_ip_or_domain)
        print(f"将监控域名: {target_ip_or_domain} (解析为 IP: {target_ip})")
    except socket.gaierror:
        # 如果解析失败，检查是否是 IP 格式
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(target_ip_or_domain):
            print(f"错误: 无效的目标 IP 地址或无法解析的域名 '{target_ip_or_domain}'")
            sys.exit(1)
        else:
            print(f"将监控 IP: {target_ip}")
    except Exception as e:
         print(f"解析目标时发生错误 '{target_ip_or_domain}': {e}")
         sys.exit(1)

    # 使用原始输入（可能是域名）来生成日志文件名，避免特殊字符问题
    log_file_prefix = re.sub(r'[^\w\-.]', '_', target_ip_or_domain) # 替换掉不适合文件名的字符
    logger = setup_logging(log_file_prefix) # 使用处理过的名称设置日志

    print(f"开始持续监控 {target_ip_or_domain} (IP: {target_ip}) ...")
    print(f"日志将记录在: network_monitor_{log_file_prefix}.log")
    print("按 Ctrl+C 停止监控.")

    # 注册信号处理函数
    signal.signal(signal.SIGINT, signal_handler)  # 处理 Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler) # 处理 kill 命令

    while keep_running:
        start_time = time.time() # 记录开始时间

        # 使用解析后的 IP 地址进行 ping
        ping_output, execution_error = run_ping(target_ip, PING_COUNT, PING_TIMEOUT)

        if execution_error:
            # 记录 ping 执行错误，确保时间戳正确
            error_message = f"ERR  | ERR  | ERR       | N/A         | N/A         | N/A         | N/A         | {ping_output}"
            logger.error(error_message)
        else:
            tx, rx, loss, rtt_min, rtt_avg, rtt_max, rtt_mdev, parse_error = parse_ping_output(ping_output, PING_COUNT)

            if parse_error:
                 warning_message = f"无法解析 Ping 输出. Raw output (partial): {ping_output[:250].replace(chr(10),' ')}..."
                 logger.warning(warning_message)
                 log_message = f"PARSE_ERR | PARSE_ERR | ERR | N/A | N/A | N/A | N/A"
            else:
                # 格式化日志消息，增加对齐
                log_message = (
                    f"{str(tx):<4} | "
                    f"{str(rx):<4} | "
                    f"{str(loss):>9} | " # 右对齐丢包率
                    f"{str(rtt_min):>11} | " # 右对齐RTT
                    f"{str(rtt_avg):>11} | "
                    f"{str(rtt_max):>11} | "
                    f"{str(rtt_mdev):>14}"
                )
            # 正常记录 info 级别的日志
            logger.info(log_message)

        # 计算本次循环花费的时间
        elapsed_time = time.time() - start_time
        # 计算需要等待的时间
        wait_time = max(0, INTERVAL_SECONDS - elapsed_time)

        # 分段 sleep 以便能及时响应中断信号
        sleep_end_time = time.time() + wait_time
        while keep_running and time.time() < sleep_end_time:
            # 检查剩余时间，避免 sleep 过长
            remaining_wait = sleep_end_time - time.time()
            sleep_interval = min(0.5, remaining_wait) # 最多睡 0.5 秒检查一次
            if sleep_interval > 0:
                time.sleep(sleep_interval)

    # 循环结束后执行清理或记录结束信息
    print("监控已停止.")
    logger.info(f"监控停止于: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.shutdown() # 关闭日志处理器

if __name__ == "__main__":
    main()
