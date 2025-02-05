from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import subprocess
import time
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
            retry_count = 3
            retry_delay = 2
            
            for attempt in range(retry_count):
                try:
                    tcpdump_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        bufsize=1024*1024,  # 设置较大的缓冲区
                        start_new_session=True  # 在新会话中启动进程
                    )
                    print("tcpdump进程已启动")
                    break
                except subprocess.TimeoutExpired:
                    if attempt < retry_count - 1:
                        print(f"启动tcpdump进程超时，{retry_delay}秒后重试...")
                        time.sleep(retry_delay)
                        continue
                    print("启动tcpdump进程多次尝试均超时")
                    return self._traffic_data
                except Exception as e:
                    if "Operation not permitted" in str(e):
                        print("错误：需要sudo权限运行tcpdump")
                    else:
                        print(f"启动tcpdump进程失败: {str(e)}")
                    return self._traffic_data
            else:
                print("无法启动tcpdump进程，已达到最大重试次数")
                return self._traffic_data

            # 准备tshark进程
            tshark_cmd = [
                'tshark',
                '-r', '-',  # 从标准输入读取
                '-T', 'fields',  # 字段格式输出
                '-e', 'frame.len',  # 数据包长度
                '-e', 'ip.dst',  # 目标IP
                '-e', 'ip.src',  # 源IP
                '-e', 'tcp.dstport',  # 目标端口
                '-e', 'tcp.srcport',  # 源端口
                '-e', 'udp.dstport',  # UDP目标端口
                '-e', 'udp.srcport',  # UDP源端口
                '-e', 'tls.handshake.extensions_server_name',  # SNI字段（域名）
                '-e', 'http.host',  # HTTP主机名
                '-e', 'http.request.uri',  # HTTP请求URI
                '-e', 'ftp.request.command',  # FTP命令
                '-E', 'separator=\t',  # 设置字段分隔符
                '-l',  # 行缓冲模式
                '-n',  # 不解析主机名
                '-Q',  # 安静模式
                '-o', 'tcp.desegment_tcp_streams:TRUE'  # 启用TCP流重组
            ]
            tshark_process = subprocess.Popen(
                tshark_cmd,
                stdin=tcpdump_process.stdout,  # 直接连接到tcpdump的输出
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1024*1024  # 设置较大的缓冲区
            )
            print("tshark进程已准备就绪")

            # 关闭tcpdump的stdout，避免文件描述符泄漏
            tcpdump_process.stdout.close()

            # 显示进度
            start_time = time.time()
            while time.time() - start_time < duration:
                elapsed = int(time.time() - start_time)
                remaining = duration - elapsed
                print(f"\r正在捕获数据: {elapsed}秒/{duration}秒 [{elapsed*'#'}{remaining*'.'}]", end='', flush=True)
                time.sleep(1)

                # 检查进程状态
                if tcpdump_process.poll() is not None or tshark_process.poll() is not None:
                    print("\n进程意外终止")
                    break

            print("\n")

            # 停止tcpdump进程
            print("捕获时间结束，正在终止进程...")
            tcpdump_process.terminate()
            tcpdump_process.wait(timeout=5)

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
                if len(fields) >= 11:  # 确保有足够的字段
                    packet_len = fields[0]
                    ip_dst = fields[1]
                    ip_src = fields[2]
                    tcp_dstport = fields[3]
                    tcp_srcport = fields[4]
                    udp_dstport = fields[5]
                    udp_srcport = fields[6]
                    sni = fields[7]
                    http_host = fields[8]
                    http_uri = fields[9]
                    ftp_cmd = fields[10]
                    
                    # 尝试从不同协议中获取域名信息
                    domain = None
                    if sni:  # HTTPS流量
                        domain = sni
                    elif http_host:  # HTTP流量
                        domain = http_host
                    elif ftp_cmd:  # FTP流量
                        domain = ip_dst  # FTP使用IP地址作为标识
                    elif tcp_dstport == str(self.port) or udp_dstport == str(self.port):
                        domain = ip_dst  # 目标端口匹配时使用目标IP
                    elif tcp_srcport == str(self.port) or udp_srcport == str(self.port):
                        domain = ip_src  # 源端口匹配时使用源IP
                    
                    if domain and packet_len.isdigit():  # 确保域名和数据包长度有效
                        bytes_len = int(packet_len)
                        record = TrafficRecord(
                            domain=domain,
                            bytes_sent=bytes_len if tcp_srcport == str(self.port) or udp_srcport == str(self.port) else 0,
                            bytes_received=bytes_len if tcp_dstport == str(self.port) or udp_dstport == str(self.port) else 0,
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