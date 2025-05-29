#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import time
import re
import logging
import platform
import signal
import urllib.request
import socket
import json
from urllib.parse import urlparse

# --- 配置 ---
INTERVAL_SECONDS = 5     # 测量间隔时间（秒）
CURL_TIMEOUT = 10        # curl 请求超时时间（秒）
DNS_TIMEOUT = 5          # DNS 解析超时时间（秒）
IP_FETCH_TIMEOUT = 5     # 获取公网 IP 的超时时间（秒）
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# --- 配置结束 ---

# 全局变量，用于信号处理
keep_running = True

def signal_handler(sig, frame):
    """处理中断信号 (Ctrl+C)"""
    global keep_running
    print("\n收到中断信号，正在停止监控...")
    keep_running = False

def get_public_ip():
    """尝试获取公网 IP 地址"""
    urls = ["https://api.ipify.org", "https://ipinfo.io/ip", "https://checkip.amazonaws.com"]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req, timeout=IP_FETCH_TIMEOUT) as response:
                ip = response.read().decode('utf-8').strip()
                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
                    return ip
                else:
                    print(f"Warning: Fetched invalid IP format from {url}: {ip}")
                    continue
        except Exception as e:
            print(f"Warning: Could not fetch public IP from {url}: {e}")
    print("Warning: Failed to fetch public IP from all sources.")
    return "N/A"

def is_ip_address(target):
    """检查目标是否为IP地址"""
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(target) is not None

def resolve_dns(hostname):
    """解析DNS并返回解析时间和IP地址"""
    if is_ip_address(hostname):
        return "N/A", hostname, "N/A"  # DNS时间, 解析IP, 状态
    
    try:
        start_time = time.time()
        resolved_ip = socket.gethostbyname(hostname)
        dns_time = (time.time() - start_time) * 1000  # 转换为毫秒
        return f"{dns_time:.1f}", resolved_ip, "SUCCESS"
    except socket.gaierror as e:
        return "N/A", "N/A", f"DNS_ERROR: {str(e)}"
    except Exception as e:
        return "N/A", "N/A", f"ERROR: {str(e)}"

def normalize_url(target):
    """标准化URL格式"""
    if not target.startswith(('http://', 'https://')):
        # 如果是IP地址，默认使用http
        if is_ip_address(target):
            return f"http://{target}"
        else:
            # 如果是域名，默认使用https
            return f"https://{target}"
    return target

def run_curl(url):
    """执行 curl 命令并返回详细信息"""
    # curl 命令参数
    command = [
        'curl',
        '-s',  # 静默模式
        '-o', '/dev/null',  # 不保存响应内容
        '-w', json.dumps({
            'http_code': '%{http_code}',
            'time_total': '%{time_total}',
            'time_namelookup': '%{time_namelookup}',
            'time_connect': '%{time_connect}',
            'time_pretransfer': '%{time_pretransfer}',
            'time_starttransfer': '%{time_starttransfer}',
            'size_download': '%{size_download}',
            'speed_download': '%{speed_download}'
        }),
        '--max-time', str(CURL_TIMEOUT),
        '--connect-timeout', str(CURL_TIMEOUT),
        '--user-agent', USER_AGENT,
        '--location',  # 跟随重定向
        '--insecure',  # 忽略SSL证书错误
        url
    ]
    
    try:
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding='utf-8'
        )
        stdout, stderr = process.communicate(timeout=CURL_TIMEOUT + 5)
        
        if process.returncode == 0:
            try:
                # 解析curl的输出
                curl_stats = json.loads(stdout.strip())
                return {
                    'success': True,
                    'http_code': curl_stats['http_code'],
                    'total_time': float(curl_stats['time_total']) * 1000,  # 转换为毫秒
                    'dns_time': float(curl_stats['time_namelookup']) * 1000,
                    'connect_time': float(curl_stats['time_connect']) * 1000,
                    'transfer_time': float(curl_stats['time_starttransfer']) * 1000,
                    'size': int(float(curl_stats['size_download'])),
                    'speed': float(curl_stats['speed_download']),
                    'error': None
                }
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                return {
                    'success': False,
                    'error': f"PARSE_ERROR: {str(e)}",
                    'raw_output': stdout[:200]
                }
        else:
            # curl 执行失败
            error_msg = stderr.strip() if stderr.strip() else "Unknown curl error"
            
            # 识别常见错误类型
            if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                error_type = "TIMEOUT"
            elif "could not resolve host" in error_msg.lower():
                error_type = "DNS_ERROR"
            elif "connection refused" in error_msg.lower():
                error_type = "CONNECTION_REFUSED"
            elif "ssl" in error_msg.lower() or "certificate" in error_msg.lower():
                error_type = "SSL_ERROR"
            else:
                error_type = "NETWORK_ERROR"
            
            return {
                'success': False,
                'error': f"{error_type}: {error_msg}",
                'return_code': process.returncode
            }
            
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait()
        except OSError:
            pass
        return {
            'success': False,
            'error': f"TIMEOUT: curl command timed out after {CURL_TIMEOUT + 5} seconds"
        }
    except FileNotFoundError:
        return {
            'success': False,
            'error': "ERROR: 'curl' command not found. Please install curl."
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"ERROR: An unexpected error occurred: {e}"
        }

def setup_logging(target):
    """配置日志记录器"""
    # 清理目标名称用于文件名
    clean_target = re.sub(r'[^\w\-.]', '_', target.replace('://', '_').replace('/', '_'))
    log_filename = f"curl_monitor_{clean_target}.log"
    
    logger = logging.getLogger('CurlMonitor')
    logger.setLevel(logging.INFO)
    
    # 创建文件处理器
    fh = logging.FileHandler(log_filename, encoding='utf-8')
    fh.setLevel(logging.INFO)
    
    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)
    
    # 添加处理器到记录器
    if not logger.hasHandlers():
        logger.addHandler(fh)
    
    # 检查日志文件是否为空，如果为空则写入头部信息
    try:
        with open(log_filename, 'r', encoding='utf-8') as f:
            f.seek(0, 2)
            if f.tell() == 0:
                raise FileNotFoundError
    except (FileNotFoundError, IOError):
        # 文件不存在或为空，写入头部信息
        source_ip = get_public_ip()
        logger.info(f"=== CURL 网络监控日志 ===")
        logger.info(f"目标 URL: {target}")
        logger.info(f"服务器源公网 IP: {source_ip}")
        logger.info(f"监控启动于: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"测量间隔: {INTERVAL_SECONDS} 秒")
        logger.info(f"CURL 超时: {CURL_TIMEOUT} 秒")
        logger.info(f"User-Agent: {USER_AGENT}")
        logger.info("-" * 120)
        logger.info("DNS解析(ms) | 解析IP | HTTP状态码 | 总耗时(ms) | 连接时间(ms) | 传输时间(ms) | 响应大小(B) | 状态")
        logger.info("-" * 120)
    
    return logger, log_filename

def main():
    global keep_running
    
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标 URL 或域名或IP地址>")
        print("示例:")
        print(f"  {sys.argv[0]} https://www.google.com")
        print(f"  {sys.argv[0]} www.baidu.com")
        print(f"  {sys.argv[0]} 8.8.8.8")
        print("脚本将持续运行，按 Ctrl+C 停止。")
        sys.exit(1)
    
    target = sys.argv[1]
    url = normalize_url(target)
    
    # 解析URL获取主机名
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.netloc
    
    print(f"开始持续监控: {target}")
    print(f"标准化URL: {url}")
    
    logger, log_filename = setup_logging(target)
    print(f"日志将记录在: {log_filename}")
    print("按 Ctrl+C 停止监控.")
    print()
    
    # 注册信号处理函数
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    while keep_running:
        start_time = time.time()
        
        # DNS解析（如果需要）
        dns_time, resolved_ip, dns_status = resolve_dns(hostname)
        
        # 执行curl请求
        curl_result = run_curl(url)
        
        # 格式化输出和日志
        if curl_result['success']:
            http_code = curl_result['http_code']
            total_time = curl_result['total_time']
            connect_time = curl_result['connect_time']
            transfer_time = curl_result['transfer_time']
            size = curl_result['size']
            
            # 判断HTTP状态码是否表示成功
            if http_code.startswith('2') or http_code.startswith('3'):
                status = "SUCCESS"
                print(f"✓ DNS: {dns_time}ms | IP: {resolved_ip} | HTTP: {http_code} | 总耗时: {total_time:.1f}ms | 连接: {connect_time:.1f}ms | 大小: {size}B")
            else:
                status = f"HTTP_ERROR_{http_code}"
                print(f"✗ DNS: {dns_time}ms | IP: {resolved_ip} | HTTP: {http_code} | 总耗时: {total_time:.1f}ms | 状态: HTTP错误")
            
            # 记录日志
            log_message = (
                f"{str(dns_time):>11} | "
                f"{str(resolved_ip):>15} | "
                f"{str(http_code):>10} | "
                f"{total_time:>10.1f} | "
                f"{connect_time:>12.1f} | "
                f"{transfer_time:>12.1f} | "
                f"{size:>11} | "
                f"{status}"
            )
        else:
            error = curl_result['error']
            print(f"✗ DNS: {dns_time}ms | IP: {resolved_ip} | 错误: {error}")
            
            # 记录错误日志
            log_message = (
                f"{str(dns_time):>11} | "
                f"{str(resolved_ip):>15} | "
                f"{'N/A':>10} | "
                f"{'N/A':>10} | "
                f"{'N/A':>12} | "
                f"{'N/A':>12} | "
                f"{'N/A':>11} | "
                f"{error}"
            )
        
        logger.info(log_message)
        
        # 计算等待时间
        elapsed_time = time.time() - start_time
        wait_time = max(0, INTERVAL_SECONDS - elapsed_time)
        
        # 分段sleep以便及时响应中断信号
        sleep_end_time = time.time() + wait_time
        while keep_running and time.time() < sleep_end_time:
            remaining_wait = sleep_end_time - time.time()
            sleep_interval = min(0.5, remaining_wait)
            if sleep_interval > 0:
                time.sleep(sleep_interval)
    
    # 清理
    print("\n监控已停止.")
    logger.info(f"监控停止于: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.shutdown()

if __name__ == "__main__":
    main()