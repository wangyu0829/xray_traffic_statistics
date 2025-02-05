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
        # 定义字段名列表
        self.field_names = [
            'packet_len',      # 数据包长度
            'ip_dst',          # 目标IP
            'ip_src',          # 源IP
            'tcp_dstport',     # TCP目标端口
            'tcp_srcport',     # TCP源端口
            'udp_dstport',     # UDP目标端口
            'udp_srcport',     # UDP源端口
            'sni',             # TLS SNI
            'http_host',       # HTTP主机名
            'dns_name',        # DNS查询名称
            'http_uri',        # HTTP URI
            'http_content_type', # HTTP内容类型
            'http_user_agent',  # HTTP User Agent
            'frame_protocols'   # 协议栈
        ]

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
                '-e', 'http.request.uri',  # HTTP请求URI
                '-e', 'http.content_type',  # HTTP内容类型
                '-e', 'http.user_agent',  # HTTP User Agent
                '-e', 'frame.protocols',  # 协议栈
                '-E', 'separator=\t',  # 设置字段分隔符
                '-E', 'header=n',  # 不显示字段头
                '-E', 'quote=n',  # 禁用字段引号
                '-E', 'occurrence=f',  # 只显示第一个匹配项
                '-l',  # 行缓冲模式
                '-n',  # 不解析主机名
                '-Y', f'ip',  # 只过滤IP数据包，不限制端口，以捕获所有流量
                '-o', 'tcp.desegment_tcp_streams:TRUE',  # 启用TCP流重组
                '-o', 'tls.desegment_ssl_records:TRUE',  # 启用TLS记录重组
                '-o', 'tls.desegment_ssl_application_data:TRUE'  # 启用TLS应用数据重组
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
        traffic_type_stats = {}  # 用于统计各类型流量数量
        
        try:
            print(f"接收到的原始数据大小: {len(stdout_data)} 字节")
            lines = stdout_data.splitlines()
            print(f"总行数: {len(lines)}")
            
            for line_num, line in enumerate(lines, 1):
                try:
                    decoded_line = line.decode()
                    fields = decoded_line.strip().split('\t')
                    
                    # 使用类的 field_names
                    values = {}
                    for i, name in enumerate(self.field_names):
                        values[name] = fields[i].strip() if i < len(fields) and fields[i].strip() else ""
                    
                    traffic_type = self._determine_traffic_type(values)
                    traffic_type_stats[traffic_type] = traffic_type_stats.get(traffic_type, 0) + 1
                    
                    domain = self._get_domain(values)
                    if domain:
                        print(f"\n处理记录 {line_num}:")
                        print(f"域名: {domain}")
                        print(f"流量类型: {traffic_type}")
                        print(f"数据包大小: {values['packet_len']} 字节")
                    
                    if domain and values['packet_len'].isdigit():
                        bytes_len = int(values['packet_len'])
                        is_incoming = self._is_incoming_traffic(values)
                        
                        record = TrafficRecord(
                            domain=f"{domain} [{traffic_type}]",
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
                    continue

            print("\n=== 流量类型统计 ===")
            for traffic_type, count in traffic_type_stats.items():
                print(f"{traffic_type}: {count} 条记录")
            print(f"\n总计处理记录数: {record_count}")

        except Exception as e:
            print(f"处理tshark输出数据时发生错误: {str(e)}")

    def _determine_traffic_type(self, values):
        """确定流量类型"""
        protocols = values.get('frame_protocols', '').lower()
        content_type = values.get('http_content_type', '').lower()
        uri = values.get('http_uri', '').lower()
        user_agent = values.get('http_user_agent', '').lower()
        
        print("\n--- 流量类型判断详情 ---")
        print(f"协议栈: {protocols}")
        print(f"内容类型: {content_type}")
        print(f"URI: {uri}")
        print(f"User Agent: {user_agent}")
        
        # 视频流量特征
        video_signatures = [
            'video/', 'mpegurl', 'mp4', 'm3u8', 'dash',  # 内容类型
            'youtube.com', 'youku.com', 'netflix.com',    # 常见视频网站
            '/hls/', '/dash/', '/video/', '/stream/',     # URL特征
            'mediaplayer', 'videoplayback'                # URI特征
        ]
        
        # 音频流量特征
        audio_signatures = [
            'audio/', 'mpeg', 'mp3', 'aac', 'ogg',       # 内容类型
            'spotify.com', 'music.163.com',              # 常见音频网站
            '/audio/', '/music/', '/stream/'             # URL特征
        ]
        
        # 检查视频流量
        for sig in video_signatures:
            if sig in content_type:
                print(f"发现视频特征(内容类型): {sig}")
                return 'VIDEO'
            if sig in uri:
                print(f"发现视频特征(URI): {sig}")
                return 'VIDEO'
            if values.get('http_host', '') and sig in values.get('http_host', '').lower():
                print(f"发现视频特征(域名): {sig}")
                return 'VIDEO'
            
        # 检查音频流量
        for sig in audio_signatures:
            if sig in content_type:
                print(f"发现音频特征(内容类型): {sig}")
                return 'AUDIO'
            if sig in uri:
                print(f"发现音频特征(URI): {sig}")
                return 'AUDIO'
            if values.get('http_host', '') and sig in values.get('http_host', '').lower():
                print(f"发现音频特征(域名): {sig}")
                return 'AUDIO'
            
        # 检查流媒体协议
        streaming_protocols = ['rtsp', 'rtp', 'rtcp', 'quic']
        for proto in streaming_protocols:
            if proto in protocols:
                print(f"发现流媒体协议: {proto}")
                return 'STREAM'
            
        # 检查实时通信
        realtime_protocols = ['webrtc', 'stun', 'turn']
        for proto in realtime_protocols:
            if proto in protocols:
                print(f"发现实时通信协议: {proto}")
                return 'REALTIME'
            
        # Web流量
        if 'http' in protocols:
            print("发现HTTP协议")
            return 'WEB'
        if values.get('http_uri', ''):
            print("发现HTTP URI")
            return 'WEB'
            
        # DNS流量
        if 'dns' in protocols:
            print("发现DNS协议")
            return 'DNS'
        if values.get('dns_name', ''):
            print("发现DNS查询")
            return 'DNS'
            
        # TLS/加密流量
        if 'tls' in protocols:
            print("发现TLS协议")
            return 'TLS'
        if values.get('sni', ''):
            print("发现SNI字段")
            return 'TLS'
            
        # 根据端口判断常见应用类型
        port = values.get('tcp_dstport', '') or values.get('tcp_srcport', '') or \
               values.get('udp_dstport', '') or values.get('udp_srcport', '')
        
        if port:
            try:
                port = int(port)
                print(f"端口号: {port}")
                if port in [80, 443]:
                    print("Web端口")
                    return 'WEB'
                elif port in [53]:
                    print("DNS端口")
                    return 'DNS'
                elif port in [1935, 554]:  # RTMP, RTSP
                    print("流媒体端口")
                    return 'STREAM'
                elif port in [3478, 3479]:  # STUN
                    print("实时通信端口")
                    return 'REALTIME'
            except ValueError:
                pass
        
        print("未能识别特定类型，标记为OTHER")
        return 'OTHER'

    def _get_domain(self, values):
        """从各个字段中提取域名"""
        # 按优先级尝试不同的域名来源
        domain_sources = [
            values.get('sni', ''),
            values.get('http_host', ''),
            values.get('dns_name', ''),
            values.get('ip_dst', '')
        ]
        
        for domain in domain_sources:
            if domain and domain.strip():
                return domain.strip()
        return None

    def _is_incoming_traffic(self, values):
        """判断是否为入站流量"""
        return any([
            values.get('tcp_dstport', '') == str(self.port),
            values.get('udp_dstport', '') == str(self.port)
        ])

    def get_domain_total_traffic(self) -> Dict[str, int]:
        """获取每个域名的总流量

        Returns:
            Dict[str, int]: 域名和对应的总流量（字节数）
        """
        domain_traffic = {}
        for domain, records in self._traffic_data.items():
            domain_traffic[domain] = sum(record.total_bytes for record in records)
        return domain_traffic