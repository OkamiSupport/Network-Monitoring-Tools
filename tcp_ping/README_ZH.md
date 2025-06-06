# TCP Ping 监控工具

一个全面的TCP连接监控工具，用于测试端口连通性和测量连接性能指标。

## 功能特性

- **TCP连接测试**: 测试TCP端口连通性而非ICMP ping
- **并发连接**: 使用多线程进行更快的测量
- **详细指标**: 测量连接成功率、延迟和抖动
- **持续监控**: 以可配置的间隔持续运行
- **全面日志**: 带时间戳和统计信息的详细日志
- **信号处理**: 通过Ctrl+C优雅关闭
- **域名解析**: 支持IP地址和域名
- **日志分析**: 包含性能报告的分析工具

## 文件说明

- `monitor_tcp_ping.py` - 主监控脚本
- `analyze_tcp_ping_log.py` - 日志分析和报告工具
- `README.md` - 英文文档
- `README_ZH.md` - 中文文档（本文件）

## 系统要求

- Python 3.6 或更高版本
- 无外部依赖（仅使用标准库）

## 使用方法

### 基础监控

```bash
# 监控特定IP和端口
python3 monitor_tcp_ping.py 8.8.8.8 53

# 监控域名（使用默认端口80）
python3 monitor_tcp_ping.py google.com

# 监控域名的特定端口
python3 monitor_tcp_ping.py google.com 443
```

### 配置选项

编辑 `monitor_tcp_ping.py` 中的配置部分：

```python
# --- 配置选项 ---
TCP_CONNECT_COUNT = 10   # 每个周期的TCP连接尝试次数
INTERVAL_SECONDS = 5     # 测量间隔（秒）
TCP_TIMEOUT = 2          # 单次连接超时时间（秒）
DEFAULT_PORT = 80        # 未指定时的默认端口
MAX_CONCURRENT = 5       # 最大并发连接数
```

### 日志分析

```bash
# 生成Markdown报告
python3 analyze_tcp_ping_log.py tcp_monitor_google_com_80.log

# 生成纯文本报告
python3 analyze_tcp_ping_log.py tcp_monitor_google_com_80.log text
```

## 日志格式

监控工具生成以下格式的日志：

```
=== TCP连接监控日志 ===
目标主机: google.com
目标端口: 80
服务器源公网IP: xxx.xxx.xxx.xxx
监控开始时间: 2024-01-01 12:00:00
每次测量的TCP连接尝试次数: 10
测量间隔: 5秒
TCP连接超时时间: 2秒
--------------------------------------------------------------------------------
尝试次数 | 成功次数 | 失败次数 | 成功率(%) | 最小RTT(ms) | 平均RTT(ms) | 最大RTT(ms) | RTT标准差(ms)
--------------------------------------------------------------------------------
10        | 10      | 0       |      100.0 |       15.23 |       18.45 |       25.67 |          3.21
10        | 9       | 1       |       90.0 |       16.12 |       19.33 |       28.91 |          4.15
```

## 指标说明

- **尝试次数**: 该周期内的总连接尝试次数
- **成功次数**: 成功连接的次数
- **失败次数**: 失败连接的次数
- **成功率(%)**: 成功连接的百分比
- **最小RTT**: 最小连接时间（毫秒）
- **平均RTT**: 平均连接时间（毫秒）
- **最大RTT**: 最大连接时间（毫秒）
- **RTT标准差**: 连接时间的标准差（抖动）

## 分析功能

分析工具提供：

- **动态阈值**: 自动计算性能基线
- **违规检测**: 识别性能不佳的时段
- **统计摘要**: 整体性能统计
- **多种格式**: Markdown和纯文本报告
- **趋势分析**: 随时间变化的性能趋势

### 分析阈值

- **成功率**: 默认阈值95%
- **延迟**: 基于基线 + 50% + 10ms的动态阈值
- **抖动**: 基于基线标准差的动态阈值
- **最大/平均比率**: 固定阈值3.0

## 使用场景

1. **Web服务监控**: 监控HTTP/HTTPS端点
2. **数据库连通性**: 测试数据库端口可访问性
3. **API端点测试**: 验证API服务可用性
4. **网络故障排除**: 诊断连接问题
5. **性能基线**: 建立网络性能基线
6. **SLA监控**: 跟踪服务级别协议合规性

## 相比ICMP Ping的优势

- **端口特定测试**: 测试实际服务端口，而非仅主机可达性
- **防火墙友好**: 可通过阻止ICMP的防火墙工作
- **服务级监控**: 验证实际服务是否响应
- **真实连接指标**: 测量实际TCP握手性能
- **应用层测试**: 对应用监控更相关

## 示例输出

```bash
$ python3 monitor_tcp_ping.py google.com 443
将监控域名: google.com (解析到IP: 142.250.191.14) 端口 443
开始持续TCP连接监控 google.com:443 (IP: 142.250.191.14) ...
日志将记录在: tcp_monitor_google_com_443.log
按Ctrl+C停止监控。
```

## 故障排除

### 常见问题

1. **连接被拒绝**: 目标端口关闭或服务停止
2. **超时错误**: 网络延迟高或数据包丢失
3. **DNS解析错误**: 无法解析域名
4. **权限错误**: 某些系统可能需要提升权限

### 使用技巧

- 使用较短的超时时间以更快检测问题
- 增加并发连接数以获得更好的统计数据
- 使用单独实例同时监控多个端口
- 使用分析工具识别连接问题的模式

## 许可证

此工具按原样提供，用于网络监控和故障排除目的。