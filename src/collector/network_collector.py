from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import subprocess
import re
from .log_parser import TrafficRecord

class NetworkCollector:
    """网络流量采集器"""
    def __init__(self, interface: str, port: int):
        self.interface = interface
        self.port = port
        self._traffic_data: Dict[str, List[TrafficRecord]] = {}

    def start_capture(self, duration: int = 60) -> Dict[str, List[TrafficRecord]]:
        """开始捕获网络流量

        Args:
            duration: 捕获持续时间（秒）

        Returns:
            Dict[str, List[TrafficRecord]]: 按域名分组的流量记录
        """
        try:
            # 使用tcpdump捕获指定接口和端口的流量
            cmd = [
                'sudo', 'tcpdump',
                '-i', self.interface,
                '-nn',  # 不解析主机名和端口号
                '-q',   # 简化输出
                f'port {self.port}',
                '-t',   # 不打印时间戳
                '-l',   # 行缓冲模式
                '-s', '0',  # 捕获完整数据包
                '-w', '-'   # 输出到标准输出
            ]

            # 启动tcpdump进程
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # 等待指定时间
            try:
                process.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                process.terminate()

            # 解析捕获的数据
            self._parse_capture_data(process.stdout)

        except subprocess.CalledProcessError as e:
            print(f"执行tcpdump命令失败: {str(e)}")
        except Exception as e:
            print(f"捕获网络流量时发生错误: {str(e)}")

        return self._traffic_data

    def _parse_capture_data(self, capture_data):
        """解析捕获的网络数据

        Args:
            capture_data: tcpdump捕获的原始数据
        """
        # 使用tshark解析tcpdump输出的数据
        cmd = [
            'tshark',
            '-r', '-',  # 从标准输入读取
            '-T', 'fields',  # 字段格式输出
            '-e', 'frame.len',  # 数据包长度
            '-e', 'tls.handshake.extensions_server_name'  # SNI字段（域名）
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdin=capture_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # 处理tshark输出
            for line in process.stdout:
                fields = line.decode().strip().split('\t')
                if len(fields) == 2:
                    packet_len, domain = fields
                    if domain:  # 只处理包含域名的记录
                        record = TrafficRecord(
                            domain=domain,
                            bytes_sent=int(packet_len),
                            bytes_received=0,
                            timestamp=datetime.now()
                        )
                        if domain not in self._traffic_data:
                            self._traffic_data[domain] = []
                        self._traffic_data[domain].append(record)

        except subprocess.CalledProcessError as e:
            print(f"解析捕获数据失败: {str(e)}")
        except Exception as e:
            print(f"处理捕获数据时发生错误: {str(e)}")

    def get_domain_total_traffic(self) -> Dict[str, int]:
        """获取每个域名的总流量

        Returns:
            Dict[str, int]: 域名和对应的总流量（字节数）
        """
        domain_traffic = {}
        for domain, records in self._traffic_data.items():
            domain_traffic[domain] = sum(record.total_bytes for record in records)
        return domain_traffic