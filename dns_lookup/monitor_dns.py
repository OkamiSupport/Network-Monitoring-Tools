#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import re
import logging
import signal
import urllib.request
import socket
import subprocess
import platform
from datetime import datetime

# --- 配置 ---
INTERVAL_SECONDS = 5     # 测量间隔时间（秒）
DNS_TIMEOUT = 5          # DNS 解析超时时间（秒）
IP_FETCH_TIMEOUT = 5     # 获取公网 IP 的超时时间（秒）
TARGET_DOMAIN = "google.com"  # 固定解析的域名
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# --- 配置结束 ---

# 全局变量，用于信号处理
keep_running = True

def signal_handler(sig, frame):
    """处理中断信号 (Ctrl+C)"""
    global keep_running
    print("\n收到中断信号，正在停止DNS监控...")
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

def get_system_dns_servers():
    """获取系统默认DNS服务器"""
    dns_servers = []
    try:
        if platform.system() == "Darwin":  # macOS
            result = subprocess.run(['scutil', '--dns'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'nameserver[0]' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            dns_ip = parts[1].strip()
                            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", dns_ip):
                                dns_servers.append(dns_ip)
        elif platform.system() == "Linux":
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) > 1:
                            dns_ip = parts[1].strip()
                            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", dns_ip):
                                dns_servers.append(dns_ip)
    except Exception as e:
        print(f"Warning: Could not get system DNS servers: {e}")
    
    # 去重并返回前3个
    return list(dict.fromkeys(dns_servers))[:3]

def resolve_dns_with_server(domain, dns_server=None):
    """使用指定DNS服务器解析域名"""
    try:
        start_time = time.time()
        
        if dns_server:
            # 使用nslookup命令指定DNS服务器
            if platform.system() == "Windows":
                cmd = ['nslookup', domain, dns_server]
            else:
                cmd = ['nslookup', domain, dns_server]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=DNS_TIMEOUT)
                dns_time = (time.time() - start_time) * 1000
                
                if result.returncode == 0:
                    # 解析nslookup输出获取IP地址
                    output = result.stdout
                    ip_addresses = []
                    
                    # 查找IP地址
                    for line in output.split('\n'):
                        if 'Address:' in line and not line.startswith('Server:'):
                            parts = line.split(':')
                            if len(parts) > 1:
                                ip = parts[1].strip()
                                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
                                    ip_addresses.append(ip)
                    
                    if ip_addresses:
                        return f"{dns_time:.1f}", ip_addresses[0], "SUCCESS", ip_addresses
                    else:
                        return f"{dns_time:.1f}", "N/A", "NO_IP_FOUND", []
                else:
                    dns_time = (time.time() - start_time) * 1000
                    error_msg = result.stderr.strip() if result.stderr.strip() else "Unknown nslookup error"
                    return f"{dns_time:.1f}", "N/A", f"NSLOOKUP_ERROR: {error_msg}", []
                    
            except subprocess.TimeoutExpired:
                dns_time = DNS_TIMEOUT * 1000
                return f"{dns_time:.1f}", "N/A", "TIMEOUT", []
            except Exception as e:
                dns_time = (time.time() - start_time) * 1000
                return f"{dns_time:.1f}", "N/A", f"ERROR: {str(e)}", []
        else:
            # 使用系统默认DNS
            resolved_ip = socket.gethostbyname(domain)
            dns_time = (time.time() - start_time) * 1000
            
            # 获取所有IP地址
            try:
                addr_info = socket.getaddrinfo(domain, None)
                ip_addresses = list(set([addr[4][0] for addr in addr_info if addr[0] == socket.AF_INET]))
            except:
                ip_addresses = [resolved_ip]
            
            return f"{dns_time:.1f}", resolved_ip, "SUCCESS", ip_addresses
            
    except socket.gaierror as e:
        dns_time = (time.time() - start_time) * 1000
        return f"{dns_time:.1f}", "N/A", f"DNS_ERROR: {str(e)}", []
    except Exception as e:
        dns_time = (time.time() - start_time) * 1000
        return f"{dns_time:.1f}", "N/A", f"ERROR: {str(e)}", []

def setup_logging(dns_server):
    """配置日志记录器"""
    # 清理DNS服务器名称用于文件名
    if dns_server:
        clean_dns = re.sub(r'[^\w\-.]', '_', dns_server)
        log_filename = f"dns_monitor_{TARGET_DOMAIN}_{clean_dns}.log"
    else:
        log_filename = f"dns_monitor_{TARGET_DOMAIN}_system.log"
    
    logger = logging.getLogger('DNSMonitor')
    logger.setLevel(logging.INFO)
    
    # 清除已有的处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 创建文件处理器
    fh = logging.FileHandler(log_filename, encoding='utf-8')
    fh.setLevel(logging.INFO)
    
    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)
    
    # 添加处理器到记录器
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
        system_dns = get_system_dns_servers()
        
        logger.info(f"=== DNS 解析监控日志 ===")
        logger.info(f"目标域名: {TARGET_DOMAIN}")
        logger.info(f"DNS 服务器: {dns_server if dns_server else '系统默认'}")
        if not dns_server and system_dns:
            logger.info(f"系统 DNS 服务器: {', '.join(system_dns)}")
        logger.info(f"服务器源公网 IP: {source_ip}")
        logger.info(f"监控启动于: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"测量间隔: {INTERVAL_SECONDS} 秒")
        logger.info(f"DNS 超时: {DNS_TIMEOUT} 秒")
        logger.info("-" * 100)
        logger.info("解析时间(ms) | 解析IP | 所有IP地址 | 状态")
        logger.info("-" * 100)
    
    return logger, log_filename

def validate_dns_server(dns_server):
    """验证DNS服务器地址格式"""
    if not dns_server:
        return True
    
    # 检查是否为有效的IP地址
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not ip_pattern.match(dns_server):
        return False
    
    # 检查IP地址范围
    parts = dns_server.split('.')
    for part in parts:
        if int(part) > 255:
            return False
    
    return True

def test_dns_server_connectivity(dns_server):
    """测试DNS服务器连通性"""
    if not dns_server:
        return True, "使用系统默认DNS"
    
    try:
        # 尝试连接DNS服务器的53端口
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.connect((dns_server, 53))
        sock.close()
        return True, "DNS服务器连通性正常"
    except Exception as e:
        return False, f"DNS服务器连通性测试失败: {str(e)}"

def main():
    global keep_running
    
    print(f"DNS解析监控工具 - 目标域名: {TARGET_DOMAIN}")
    print("用法: python3 monitor_dns.py [DNS服务器IP]")
    print("示例:")
    print("  python3 monitor_dns.py                    # 使用系统默认DNS")
    print("  python3 monitor_dns.py 8.8.8.8           # 使用Google DNS")
    print("  python3 monitor_dns.py 1.1.1.1           # 使用Cloudflare DNS")
    print("  python3 monitor_dns.py 114.114.114.114    # 使用114 DNS")
    print()
    
    # 解析命令行参数
    dns_server = None
    if len(sys.argv) > 1:
        dns_server = sys.argv[1]
        
        # 验证DNS服务器地址
        if not validate_dns_server(dns_server):
            print(f"错误: 无效的DNS服务器地址: {dns_server}")
            print("请提供有效的IPv4地址，例如: 8.8.8.8")
            sys.exit(1)
        
        # 测试DNS服务器连通性
        is_reachable, message = test_dns_server_connectivity(dns_server)
        print(f"DNS服务器测试: {message}")
        if not is_reachable:
            print("警告: DNS服务器可能无法正常工作，但将继续尝试监控")
    
    print(f"开始DNS解析监控: {TARGET_DOMAIN}")
    print(f"使用DNS服务器: {dns_server if dns_server else '系统默认'}")
    
    # 显示系统DNS信息
    if not dns_server:
        system_dns = get_system_dns_servers()
        if system_dns:
            print(f"系统DNS服务器: {', '.join(system_dns)}")
    
    logger, log_filename = setup_logging(dns_server)
    print(f"日志将记录在: {log_filename}")
    print("按 Ctrl+C 停止监控.")
    print()
    
    # 注册信号处理函数
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 统计信息
    total_queries = 0
    successful_queries = 0
    failed_queries = 0
    total_time = 0.0
    
    while keep_running:
        start_time = time.time()
        
        # DNS解析
        dns_time, resolved_ip, status, all_ips = resolve_dns_with_server(TARGET_DOMAIN, dns_server)
        
        # 更新统计
        total_queries += 1
        if status == "SUCCESS":
            successful_queries += 1
            if dns_time != "N/A":
                total_time += float(dns_time)
        else:
            failed_queries += 1
        
        # 格式化所有IP地址
        all_ips_str = ", ".join(all_ips) if all_ips else "N/A"
        
        # 显示结果
        if status == "SUCCESS":
            print(f"✓ DNS解析: {dns_time}ms | 主IP: {resolved_ip} | 所有IP: [{all_ips_str}] | 状态: {status}")
        else:
            print(f"✗ DNS解析: {dns_time}ms | 主IP: {resolved_ip} | 状态: {status}")
        
        # 记录日志
        log_message = (
            f"{str(dns_time):>13} | "
            f"{str(resolved_ip):>15} | "
            f"{all_ips_str:>30} | "
            f"{status}"
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
    
    # 显示统计信息
    print("\n=== 监控统计 ===")
    print(f"总查询次数: {total_queries}")
    print(f"成功次数: {successful_queries}")
    print(f"失败次数: {failed_queries}")
    if total_queries > 0:
        success_rate = (successful_queries / total_queries) * 100
        print(f"成功率: {success_rate:.2f}%")
    if successful_queries > 0:
        avg_time = total_time / successful_queries
        print(f"平均解析时间: {avg_time:.1f}ms")
    
    # 清理
    print("\nDNS监控已停止.")
    logger.info(f"监控停止于: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"统计信息 - 总查询: {total_queries}, 成功: {successful_queries}, 失败: {failed_queries}")
    if total_queries > 0:
        success_rate = (successful_queries / total_queries) * 100
        logger.info(f"成功率: {success_rate:.2f}%")
    if successful_queries > 0:
        avg_time = total_time / successful_queries
        logger.info(f"平均解析时间: {avg_time:.1f}ms")
    logging.shutdown()

if __name__ == "__main__":
    main()