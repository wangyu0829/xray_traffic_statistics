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
            tcpdump_process = None
            
            for attempt in range(retry_count):
                try:
                    print(f"正在启动tcpdump进程，第{attempt + 1}次尝试...")
                    tcpdump_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        bufsize=1024*1024*4,  # 增加缓冲区大小到4MB
                        start_new_session=True  # 在新会话中启动进程
                    )
                    print("tcpdump进程已启动，等待数据输出...")
                    # 检查tcpdump是否正常启动
                    time.sleep(2)  # 增加等待时间
                    if tcpdump_process.poll() is not None:
                        print(f"tcpdump进程意外退出，退出码: {tcpdump_process.poll()}")
                        stderr = tcpdump_process.stderr.read().decode()
                        if stderr:
                            print(f"tcpdump错误信息: {stderr}")
                        if attempt < retry_count - 1:
                            print(f"等待{retry_delay}秒后进行下一次尝试...")
                            time.sleep(retry_delay)
                            continue
                    break
                except subprocess.TimeoutExpired:
                    if attempt < retry_count - 1:
                        print(f"启动tcpdump进程超时，{retry_delay}秒后重试...")
                        if tcpdump_process:
                            try:
                                tcpdump_process.terminate()
                                tcpdump_process.wait(timeout=3)
                            except:
                                pass
                        time.sleep(retry_delay)
                        continue
                    print("启动tcpdump进程多次尝试均超时")
                    return self._traffic_data
                except Exception as e:
                    if "Operation not permitted" in str(e):
                        print("错误：需要sudo权限运行tcpdump")
                    else:
                        print(f"启动tcpdump进程失败: {str(e)}")
                    if tcpdump_process:
                        try:
                            tcpdump_process.terminate()
                            tcpdump_process.wait(timeout=3)
                        except:
                            pass
                    return self._traffic_data
            else:
                print("无法启动tcpdump进程，已达到最大重试次数")
                return self._traffic_data

            if not tcpdump_process or tcpdump_process.poll() is not None:
                print("tcpdump进程未能成功启动")
                return self._traffic_data

            # 准备tshark进程
            # 优化tshark命令参数
            tshark_cmd = [
                'tshark',
                '-r', '-',  # 从标准输入读取
                '-T', 'fields',  # 字段格式输出
                '-e', 'frame.len',  # 数据包长度
                '-e', 'ip.dst',  # 目标IP
                '-e', 'ip.src',  # 源IP
                '-e', 'tcp.dstport',  # TCP目标端口
                '-e', 'tcp.srcport',  # TCP源端口
                '-e', 'udp.dstport',  # UDP目标端口
                '-e', 'udp.srcport',  # UDP源端口
                '-e', 'tls.handshake.extensions_server_name',  # SNI字段（域名）
                '-e', 'http.host',  # HTTP主机名
                '-e', 'dns.qry.name',  # DNS查询名称
                '-e', 'quic.tag.sni',  # QUIC SNI
                '-e', 'http2.headers.authority',  # HTTP2主机名
                '-e', 'http2.stream.header.value',  # HTTP2头部值
                '-E', 'separator=\t',  # 设置字段分隔符
                '-E', 'header=n',  # 不显示字段头
                '-E', 'quote=n',  # 禁用字段引号
                '-E', 'occurrence=f',  # 只显示第一个匹配项
                '-l',  # 行缓冲模式
                '-n',  # 不解析主机名
                '-Y', f'ip && (tcp.port=={self.port} || udp.port=={self.port} || quic)',  # 过滤条件
                '-o', 'tcp.desegment_tcp_streams:TRUE',  # 启用TCP流重组
                '-o', 'tls.desegment_ssl_records:TRUE',  # 启用TLS记录重组
                '-o', 'tls.desegment_ssl_application_data:TRUE',  # 启用TLS应用数据重组
                '-o', 'http2.reassemble_stream:TRUE',  # 启用HTTP2流重组
                '-o', 'quic.max_stream_data:4294967295',  # 增加QUIC流数据限制
                '-o', 'quic.desegment_streaming_data:TRUE'  # 启用QUIC流数据重组
            ]
            print(f"执行tshark命令: {' '.join(tshark_cmd)}")
            # 直接将tcpdump输出连接到tshark输入
            try:
                tshark_process = subprocess.Popen(
                    tshark_cmd,
                    stdin=tcpdump_process.stdout,  # 直接连接到tcpdump的输出
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1024*1024*8  # 增加缓冲区大小到8MB
                )
                print("tshark进程已准备就绪")
            except Exception as e:
                print(f"启动tshark进程失败: {str(e)}")
                tcpdump_process.terminate()
                tcpdump_process.wait(timeout=3)
                return self._traffic_data
            
            # 关闭父进程中的tcpdump stdout副本
            tcpdump_process.stdout.close()

            # 显示进度
            start_time = time.time()
            while time.time() - start_time < duration:
                elapsed = int(time.time() - start_time)
                remaining = duration - elapsed
                print(f"\r正在捕获数据: {elapsed}秒/{duration}秒 [{elapsed*'#'}{remaining*'.'}]", end='', flush=True)
                
                # 检查tcpdump进程状态
                tcpdump_poll = tcpdump_process.poll()
                if tcpdump_poll is not None:
                    print(f"\ntcpdump进程已终止，退出码: {tcpdump_poll}")
                    tcpdump_stderr = tcpdump_process.stderr.read().decode()
                    if tcpdump_stderr:
                        print(f"tcpdump错误输出: {tcpdump_stderr}")
                    break
                
                # 检查tshark进程状态
                tshark_poll = tshark_process.poll()
                if tshark_poll is not None:
                    print(f"\ntshark进程已终止，退出码: {tshark_poll}")
                    tshark_stderr = tshark_process.stderr.read().decode()
                    if tshark_stderr:
                        print(f"tshark错误输出: {tshark_stderr}")
                    break
                
                time.sleep(1)

            print("\n")

            # 停止tcpdump进程
            print("捕获时间结束，正在终止进程...")
            try:
                tcpdump_process.terminate()
                tcpdump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("警告：tcpdump进程未能在超时时间内终止")
                try:
                    tcpdump_process.kill()
                    tcpdump_process.wait(timeout=2)
                except:
                    print("错误：无法强制终止tcpdump进程")

            # 等待tshark处理完所有数据
            try:
                tshark_stdout, tshark_stderr = tshark_process.communicate(timeout=10)
                if tshark_stderr:
                    print(f"tshark错误输出: {tshark_stderr.decode()}")
            except subprocess.TimeoutExpired:
                print("警告：tshark进程未能在超时时间内完成数据处理")
                tshark_process.kill()
                try:
                    tshark_stdout, _ = tshark_process.communicate(timeout=2)
                except:
                    print("错误：无法获取tshark进程的输出数据")
                    return self._traffic_data

            # 处理tshark输出
            if tshark_stdout:
                self._process_tshark_output(tshark_stdout)
            else:
                print("警告：未收到tshark的输出数据")

        except subprocess.CalledProcessError as e:
            print(f"执行命令失败: {str(e)}")
            stderr_output = e.stderr.decode() if e.stderr else "无错误输出"
            print(f"错误输出: {stderr_output}")
        except Exception as e:
            print(f"捕获网络流量时发生错误: {str(e)}")
            import traceback
            print(f"错误堆栈: {traceback.format_exc()}")

        return self._traffic_data

    def _process_tshark_output(self, stdout_data):
        print("\n开始处理tshark输出数据...")
        record_count = 0
        try:
            print(f"接收到的原始数据大小: {len(stdout_data)} 字节")
            lines = stdout_data.splitlines()
            print(f"总行数: {len(lines)}")
            
            for line_num, line in enumerate(lines, 1):
                print(f"\n处理第 {line_num} 行数据:")
                try:
                    decoded_line = line.decode()
                    print(f"解码后的数据行: {decoded_line}")
                    fields = decoded_line.strip().split('\t')
                    print(f"解析出字段数量: {len(fields)}")
                    
                    # 打印每个字段的值，方便调试
                    field_names = ['packet_len', 'ip_dst', 'ip_src', 'tcp_dstport', 'tcp_srcport',
                                'udp_dstport', 'udp_srcport', 'sni', 'http_host', 'dns_name',
                                'quic_sni', 'http2_authority', 'http2_header']
                    print("字段详细信息:")
                    for i, name in enumerate(field_names):
                        value = fields[i] if i < len(fields) else "<未提供>"
                        print(f"  {name:15} = {value}")
                    
                    # 修改字段数量检查逻辑，只要求基本字段存在
                    if len(fields) < 3:  # 只需要包长度和IP地址信息
                        print(f"警告: 基本字段数量不足 (至少需要3个，实际{len(fields)}个)")
                        continue
                        
                    if not fields[0].strip():
                        print("警告: 数据包长度为空，跳过此记录")
                        continue

                    # 安全地获取字段值，避免索引越界
                    packet_len = fields[0]
                    ip_dst = fields[1]
                    ip_src = fields[2]
                    tcp_dstport = fields[3] if len(fields) > 3 else ""
                    tcp_srcport = fields[4] if len(fields) > 4 else ""
                    udp_dstport = fields[5] if len(fields) > 5 else ""
                    udp_srcport = fields[6] if len(fields) > 6 else ""
                    sni = fields[7] if len(fields) > 7 else ""
                    http_host = fields[8] if len(fields) > 8 else ""
                    dns_name = fields[9] if len(fields) > 9 else ""
                    quic_sni = fields[10] if len(fields) > 10 else ""
                    http2_authority = fields[11] if len(fields) > 11 else ""
                    http2_header = fields[12] if len(fields) > 12 else ""
                    
                    # 尝试从多个字段中获取域名信息
                    domain = None
                    # 按优先级尝试不同的域名来源
                    for domain_source in [sni, quic_sni, http2_authority, http_host, dns_name]:
                        if domain_source and domain_source.strip():
                            domain = domain_source.strip()
                            break
                    
                    # 如果没有域名信息，使用IP地址
                    if not domain:
                        # 检查端口是否匹配
                        is_target_port = (
                            tcp_dstport == str(self.port) or
                            tcp_srcport == str(self.port) or
                            udp_dstport == str(self.port) or
                            udp_srcport == str(self.port)
                        )
                        if is_target_port:
                            domain = ip_dst if tcp_dstport == str(self.port) or udp_dstport == str(self.port) else ip_src
                        else:
                            domain = ip_dst  # 默认使用目标IP
                    
                    if domain and packet_len.isdigit():  # 确保域名和数据包长度有效
                        bytes_len = int(packet_len)
                        # 判断数据包方向
                        is_incoming = False
                        if tcp_dstport == str(self.port) or udp_dstport == str(self.port):
                            is_incoming = True
                        
                        record = TrafficRecord(
                            domain=domain,
                            bytes_sent=0 if is_incoming else bytes_len,
                            bytes_received=bytes_len if is_incoming else 0,
                            timestamp=datetime.now()
                        )
                        if domain not in self._traffic_data:
                            self._traffic_data[domain] = []
                        self._traffic_data[domain].append(record)
                        record_count += 1

                except Exception as e:
                    print(f"处理第 {line_num} 行数据时发生错误: {str(e)}")
                    import traceback
                    print(f"错误堆栈: {traceback.format_exc()}")
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