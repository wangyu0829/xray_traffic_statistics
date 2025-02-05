from typing import List, Tuple, Dict
from tabulate import tabulate
import json

class ResultFormatter:
    """结果展示格式化器"""

    @staticmethod
    def format_table(domain_traffic: List[Tuple[str, int]], show_units: bool = True) -> str:
        """将域名流量数据格式化为表格形式

        Args:
            domain_traffic: 域名流量数据列表
            show_units: 是否显示流量单位

        Returns:
            str: 格式化后的表格字符串
        """
        headers = ['域名', '流量']
        rows = []

        for domain, traffic in domain_traffic:
            if show_units:
                traffic_str = ResultFormatter._format_bytes(traffic)
            else:
                traffic_str = str(traffic)
            rows.append([domain, traffic_str])

        return tabulate(rows, headers=headers, tablefmt='grid')

    @staticmethod
    def format_json(domain_traffic: List[Tuple[str, int]]) -> str:
        """将域名流量数据格式化为JSON字符串

        Args:
            domain_traffic: 域名流量数据列表

        Returns:
            str: JSON格式的字符串
        """
        result = {
            'domains': [
                {'domain': domain, 'traffic': traffic}
                for domain, traffic in domain_traffic
            ]
        }
        return json.dumps(result, ensure_ascii=False, indent=2)

    @staticmethod
    def _format_bytes(bytes_count: int) -> str:
        """将字节数格式化为人类可读的形式

        Args:
            bytes_count: 字节数

        Returns:
            str: 格式化后的字符串
        """
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        size = float(bytes_count)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        return f"{size:.2f} {units[unit_index]}"