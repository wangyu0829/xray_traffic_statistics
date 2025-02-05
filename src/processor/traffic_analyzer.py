from typing import Dict, List, Tuple
from src.collector.log_parser import TrafficRecord

class TrafficAnalyzer:
    """流量数据分析器"""

    @staticmethod
    def sort_domain_by_traffic(domain_traffic: Dict[str, int], top_n: int = 10) -> List[Tuple[str, int]]:
        """按流量大小对域名进行排序

        Args:
            domain_traffic: 域名流量数据字典
            top_n: 返回流量最大的前N个域名

        Returns:
            List[Tuple[str, int]]: 排序后的域名和流量列表
        """
        sorted_domains = sorted(
            domain_traffic.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_domains[:top_n]

    @staticmethod
    def calculate_traffic_stats(traffic_data: Dict[str, List[TrafficRecord]]) -> Dict[str, Dict[str, int]]:
        """计算流量统计数据

        Args:
            traffic_data: 域名流量记录数据

        Returns:
            Dict[str, Dict[str, int]]: 域名流量统计信息
        """
        stats = {}
        for domain, records in traffic_data.items():
            total_sent = sum(record.bytes_sent for record in records)
            total_received = sum(record.bytes_received for record in records)
            total_traffic = total_sent + total_received

            stats[domain] = {
                'bytes_sent': total_sent,
                'bytes_received': total_received,
                'total_bytes': total_traffic
            }

        return stats