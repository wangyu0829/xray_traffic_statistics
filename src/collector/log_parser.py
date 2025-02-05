from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import re
import json

@dataclass
class TrafficRecord:
    """流量记录数据类"""
    domain: str
    bytes_sent: int
    bytes_received: int
    timestamp: datetime

    @property
    def total_bytes(self) -> int:
        """计算总流量"""
        return self.bytes_sent + self.bytes_received

class XrayLogParser:
    """Xray日志解析器"""
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._traffic_data: Dict[str, List[TrafficRecord]] = {}

    def parse_log_line(self, line: str) -> Optional[TrafficRecord]:
        """解析单行日志

        Args:
            line: 日志行内容

        Returns:
            Optional[TrafficRecord]: 解析成功返回流量记录，失败返回None
        """
        try:
            log_data = json.loads(line)
            if 'domain' not in log_data or 'bytes_sent' not in log_data or 'bytes_received' not in log_data:
                return None

            return TrafficRecord(
                domain=log_data['domain'],
                bytes_sent=int(log_data['bytes_sent']),
                bytes_received=int(log_data['bytes_received']),
                timestamp=datetime.fromtimestamp(log_data.get('timestamp', datetime.now().timestamp()))
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    def process_log_file(self) -> Dict[str, List[TrafficRecord]]:
        """处理日志文件

        Returns:
            Dict[str, List[TrafficRecord]]: 按域名分组的流量记录
        """
        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    record = self.parse_log_line(line.strip())
                    if record:
                        if record.domain not in self._traffic_data:
                            self._traffic_data[record.domain] = []
                        self._traffic_data[record.domain].append(record)
        except FileNotFoundError:
            print(f"日志文件不存在: {self.log_path}")
        except Exception as e:
            print(f"处理日志文件时发生错误: {str(e)}")

        return self._traffic_data

    def get_domain_total_traffic(self) -> Dict[str, int]:
        """获取每个域名的总流量

        Returns:
            Dict[str, int]: 域名和对应的总流量（字节数）
        """
        domain_traffic = {}
        for domain, records in self._traffic_data.items():
            domain_traffic[domain] = sum(record.total_bytes for record in records)
        return domain_traffic