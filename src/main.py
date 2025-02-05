import argparse
from src.collector.log_parser import XrayLogParser
from src.collector.network_collector import NetworkCollector
from src.processor.traffic_analyzer import TrafficAnalyzer
from src.display.result_formatter import ResultFormatter

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Xray流量统计分析工具')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--log-path', help='Xray日志文件路径')
    group.add_argument('--interface', help='网络接口名称')
    parser.add_argument('--port', type=int, default=443, help='监听端口（默认：443）')
    parser.add_argument('--duration', type=int, default=60, help='捕获持续时间（秒）（默认：60）')
    parser.add_argument('-n', '--top-n', type=int, default=10,
                        help='显示流量最大的前N个域名（默认：10）')
    parser.add_argument('-f', '--format', choices=['table', 'json'],
                        default='table', help='输出格式（默认：table）')
    return parser.parse_args()

def main():
    """主程序入口"""
    args = parse_args()

    # 根据参数选择数据源
    if args.log_path:
        # 从日志文件获取数据
        parser = XrayLogParser(args.log_path)
        traffic_data = parser.process_log_file()
        domain_traffic = parser.get_domain_total_traffic()
    else:
        # 从网络接口获取数据
        collector = NetworkCollector(args.interface, args.port)
        traffic_data = collector.start_capture(args.duration)
        domain_traffic = collector.get_domain_total_traffic()

    # 对域名按流量排序
    analyzer = TrafficAnalyzer()
    sorted_domains = analyzer.sort_domain_by_traffic(domain_traffic, args.top_n)

    # 格式化输出结果
    formatter = ResultFormatter()
    if args.format == 'json':
        result = formatter.format_json(sorted_domains)
    else:
        result = formatter.format_table(sorted_domains)

    print(result)

if __name__ == '__main__':
    main()