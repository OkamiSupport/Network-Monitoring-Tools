# 网络监控工具集合

这是一个功能完整的网络监控工具集合，包含多种网络连通性和性能监控脚本，适用于网络诊断、性能分析和故障排查。

## 功能特色

- **多协议支持**: ICMP Ping、HTTP/HTTPS (cURL)、DNS解析、UDP Ping
- **智能分析**: 动态阈值计算、问题时段识别、统计分析
- **详细日志**: 结构化日志记录，支持长期监控
- **跨平台**: 支持 macOS、Linux、Windows
- **灵活配置**: 可自定义监控参数、间隔、超时等
- **多格式输出**: 支持纯文本和 Markdown 格式报告

## 项目结构

```
/
├── README.md                    # 项目说明文档
├── icmp_ping/                   # ICMP Ping 监控工具
│   ├── monitor_ping.py          # ICMP ping 监控脚本
│   └── analyze_network_log.py   # ICMP ping 日志分析脚本
├── curl_ping/                   # HTTP/HTTPS 监控工具
│   ├── monitor_curl.py          # cURL 网站连通性监控脚本
│   └── analyze_curl_log.py      # cURL 日志分析脚本
├── dns_lookup/                  # DNS 解析监控工具
│   ├── monitor_dns.py           # DNS 解析监控脚本
│   └── analyze_dns_log.py       # DNS 日志分析脚本
└── udp_ping/                    # UDP Ping 监控工具
    ├── ping_udp.py              # UDP ping 监控脚本
    ├── analyze_udp_ping_log.py  # UDP ping 日志分析脚本
    └── 使用说明.txt              # UDP ping 使用说明
```

## 工具详细介绍

### 1. ICMP Ping 监控 (`icmp_ping/`)

**功能**: 传统的 ICMP ping 监控，检测网络连通性和延迟

**特点**:
- 自动获取公网 IP 地址
- 支持多平台 ping 命令
- 实时显示 ping 结果和统计信息
- 详细的网络延迟分析

**使用方法**:
```bash
# 基本使用
python3 monitor_ping.py google.com

# 自定义参数
python3 monitor_ping.py google.com --interval 5 --timeout 10

# 分析日志
python3 analyze_network_log.py ping_google.com.log
python3 analyze_network_log.py ping_google.com.log --markdown
```

### 2. HTTP/HTTPS 监控 (`curl_ping/`)

**功能**: 使用 cURL 监控网站的 HTTP/HTTPS 连通性

**特点**:
- DNS 解析结果显示
- HTTP 状态码和响应时间记录
- 支持 HTTPS 和重定向
- 详细的错误信息记录

**使用方法**:
```bash
# 监控网站
python3 monitor_curl.py https://github.com
python3 monitor_curl.py http://example.com --interval 10

# 分析日志
python3 analyze_curl_log.py curl_monitor_github.com.log
python3 analyze_curl_log.py curl_monitor_example.com.log --markdown
```

### 3. DNS 解析监控 (`dns_lookup/`)

**功能**: 专门监控 DNS 解析性能和可靠性

**特点**:
- 固定解析 google.com 域名
- 支持自定义 DNS 服务器
- DNS 解析时间统计
- IP 地址变化追踪

**使用方法**:
```bash
# 使用系统默认 DNS
python3 monitor_dns.py

# 使用指定 DNS 服务器
python3 monitor_dns.py --dns-server 8.8.8.8
python3 monitor_dns.py --dns-server 1.1.1.1 --interval 5

# 分析日志
python3 analyze_dns_log.py dns_monitor_google.com_8.8.8.8.log
python3 analyze_dns_log.py dns_monitor_google.com_1.1.1.1.log --markdown
```

### 4. UDP Ping 监控 (`udp_ping/`)

**功能**: UDP 协议的连通性测试

**特点**:
- UDP 端口连通性检测
- 支持自定义端口
- 超时和错误处理
- 详细的 UDP 连接统计

**使用方法**:
```bash
# 基本 UDP ping
python3 ping_udp.py target_host 53

# 分析日志
python3 analyze_udp_ping_log.py udp_ping_log.txt
```

## 日志分析功能

所有监控脚本都配备了对应的日志分析工具，提供以下分析功能：

### 智能分析特性
- **动态阈值计算**: 基于历史数据自动计算性能阈值
- **问题时段识别**: 自动识别网络异常时间段
- **统计分析**: 成功率、平均延迟、最大/最小值等
- **趋势分析**: 网络性能变化趋势
- **错误分类**: 智能分类不同类型的网络错误

### 报告格式
- **纯文本格式**: 适合终端查看和日志记录
- **Markdown 格式**: 适合文档生成和分享

## 系统要求

### 基本要求
- Python 3.6+
- 网络连接

### 系统工具依赖
- **ping**: 系统自带 (ICMP ping 监控)
- **curl**: 系统自带或需安装 (HTTP/HTTPS 监控)
- **nslookup**: 系统自带 (DNS 监控)
- **nc (netcat)**: 系统自带或需安装 (UDP ping 监控)

### 支持的操作系统
- macOS
- Linux (Ubuntu, CentOS, Debian 等)
- Windows (需要相应的命令行工具)

## 快速开始

1. **克隆或下载项目**
   ```bash
   # 如果是 git 仓库
   git clone <repository_url>
   cd ai_written_tools
   ```

2. **选择监控工具**
   ```bash
   # ICMP Ping 监控
   cd icmp_ping
   python3 monitor_ping.py google.com
   
   # HTTP/HTTPS 监控
   cd curl_ping
   python3 monitor_curl.py https://github.com
   
   # DNS 解析监控
   cd dns_lookup
   python3 monitor_dns.py --dns-server 8.8.8.8
   ```

3. **分析监控结果**
   ```bash
   # 等待一段时间后，分析生成的日志
   python3 analyze_*.py <日志文件名> --markdown
   ```

## 使用场景

### 网络故障排查
- 使用 ICMP ping 检测基本连通性
- 使用 HTTP 监控检测 Web 服务可用性
- 使用 DNS 监控检测域名解析问题

### 性能监控
- 长期监控网络延迟变化
- 监控 DNS 解析性能
- 监控 Web 服务响应时间

### 网络质量评估
- 评估网络稳定性
- 分析网络性能趋势
- 生成网络质量报告

## 高级配置

### 自定义监控参数
大部分脚本支持以下通用参数：
- `--interval`: 监控间隔（秒）
- `--timeout`: 超时时间（秒）
- `--output`: 自定义日志文件名

### 环境变量
某些脚本支持通过环境变量进行配置：
```bash
export MONITOR_INTERVAL=30
export MONITOR_TIMEOUT=10
```

## 故障排除

### 常见问题

1. **权限问题**
   - 某些系统可能需要管理员权限执行 ping 命令
   - 解决方案: 使用 `sudo` 运行脚本

2. **命令不存在**
   - 确保系统安装了必要的网络工具 (ping, curl, nslookup, nc)
   - macOS: 通常预装所有工具
   - Linux: 可能需要安装 `iputils-ping`, `curl`, `netcat`

3. **网络防火墙**
   - 某些网络环境可能阻止特定协议
   - 解决方案: 检查防火墙设置或使用其他监控方式


## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

**注意**: 这些工具主要用于网络诊断和监控，请合理使用，避免对目标服务器造成过大负载。