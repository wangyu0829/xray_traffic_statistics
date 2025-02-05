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
        print(f"开始在接口 {self.interface} 上捕获端口 {self.port} 的流量数据...")
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
            print(f"执行命令: {' '.join(cmd)}")

            # 启动tcpdump进程
            tcpdump_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1024*1024  # 设置较大的缓冲区
            )
            print("tcpdump进程已启动")

            # 准备tshark进程
            tshark_cmd = [
                'tshark',
                '-r', '-',  # 从标准输入读取
                '-T', 'fields',  # 字段格式输出
                '-e', 'frame.len',  # 数据包长度
                '-e', 'tls.handshake.extensions_server_name',  # SNI字段（域名）
                '-2'  # 使用Wireshark 2.x 版本的解析引擎
            ]
            tshark_process = subprocess.Popen(
                tshark_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1024*1024  # 设置较大的缓冲区
            )
            print("tshark进程已准备就绪")

            # 创建管道线程
            from threading import Thread
            import time
            
            def pipe_data():
                try:
                    while True:
                        data = tcpdump_process.stdout.read1(1024*1024)
                        if not data:
                            break
                        tshark_process.stdin.write(data)
                        tshark_process.stdin.flush()
                except Exception as e:
                    print(f"数据传输过程中发生错误: {str(e)}")
                finally:
                    tshark_process.stdin.close()

            pipe_thread = Thread(target=pipe_data)
            pipe_thread.start()

            # 显示进度
            start_time = time.time()
            while pipe_thread.is_alive() and time.time() - start_time < duration:
                elapsed = int(time.time() - start_time)
                remaining = duration - elapsed
                print(f"\r正在捕获数据: {elapsed}秒/{duration}秒 [{elapsed*'#'}{remaining*'.'}]", end='', flush=True)
                time.sleep(1)
            print("\n")

            # 停止tcpdump进程
            print("捕获时间结束，正在终止进程...")
            tcpdump_process.terminate()
            pipe_thread.join(timeout=5)

            # 等待tshark处理完所有数据
            tshark_stdout, tshark_stderr = tshark_process.communicate()
            if tshark_stderr:
                print(f"tshark错误输出: {tshark_stderr.decode()}")

            # 处理tshark输出
            self._process_tshark_output(tshark_stdout)

        except subprocess.CalledProcessError as e:
            print(f"执行tcpdump命令失败: {str(e)}")
            stderr_output = e.stderr.decode() if e.stderr else "无错误输出"
            print(f"错误输出: {stderr_output}")
        except Exception as e:
            print(f"捕获网络流量时发生错误: {str(e)}")

        return self._traffic_data

    def _process_tshark_output(self, stdout_data):
        print("处理tshark输出数据...")
        record_count = 0
        try:
            for line in stdout_data.splitlines():
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
                        record_count += 1

            print(f"解析完成，共处理 {record_count} 条记录")
            if record_count == 0:
                print("警告：未发现任何有效的流量记录")

        except Exception as e:
            print(f"处理tshark输出数据时发生错误: {str(e)}")

    def get_domain_total_traffic(self) -> Dict[str, int]:
        """获取每个域名的总流量

        Returns:
            Dict[str, int]: 域名和对应的总流量（字节数）
        """
        domain_traffic = {}
        for domain, records in self._traffic_data.items():
            domain_traffic[domain] = sum(record.total_bytes for record in records)
        return domain_traffic