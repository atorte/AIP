#!/usr/bin/env python3
"""
Adaptive Internet Protocol (AIP) - 核心实现
自适应互联网协议的Python实现，包含包头处理、智能路由和安全机制
"""

import struct
import socket
import hashlib
import time
import threading
import json
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import numpy as np

class AddressType(Enum):
    """地址类型枚举"""
    IPV4_COMPAT = 0x0
    IPV6_COMPAT = 0x1
    GEOGRAPHIC = 0x2
    SERVICE_ID = 0x3
    HYBRID = 0x4

class ServiceClass(Enum):
    """服务类型枚举"""
    BEST_EFFORT = 0x00
    REAL_TIME_VIDEO = 0x01
    REAL_TIME_AUDIO = 0x02
    ONLINE_GAMING = 0x03
    FILE_TRANSFER = 0x04
    IOT_SENSOR = 0x05

class AIPFlags(Enum):
    """AIP协议标志位"""
    ENCRYPTED = 0x01
    AUTHENTICATED = 0x02
    COMPRESSED = 0x04
    FRAGMENTED = 0x08
    URGENT = 0x10

@dataclass
class GeographicAddress:
    """地理位置地址结构"""
    continent: int  # 4 bits
    country: int    # 8 bits
    region: int     # 12 bits
    city: int       # 16 bits
    area: int       # 24 bits
    
    def to_bytes(self) -> bytes:
        """转换为字节序列"""
        addr = (self.continent << 60) | (self.country << 52) | \
               (self.region << 40) | (self.city << 24) | self.area
        return struct.pack('>Q', addr)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'GeographicAddress':
        """从字节序列创建"""
        addr = struct.unpack('>Q', data)[0]
        return cls(
            continent=(addr >> 60) & 0xF,
            country=(addr >> 52) & 0xFF,
            region=(addr >> 40) & 0xFFF,
            city=(addr >> 24) & 0xFFFF,
            area=addr & 0xFFFFFF
        )

@dataclass
class ServiceAddress:
    """服务标识地址结构"""
    service_type: int     # 16 bits
    provider_id: int      # 16 bits
    instance_id: int      # 32 bits
    
    def to_bytes(self) -> bytes:
        """转换为字节序列"""
        return struct.pack('>HHI', self.service_type, self.provider_id, self.instance_id)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ServiceAddress':
        """从字节序列创建"""
        service_type, provider_id, instance_id = struct.unpack('>HHI', data)
        return cls(service_type, provider_id, instance_id)

class AIPAddress:
    """AIP协议地址类"""
    
    def __init__(self, addr_type: AddressType, address_data: Any):
        self.addr_type = addr_type
        self.address_data = address_data
    
    def to_bytes(self) -> bytes:
        """转换为字节序列"""
        if self.addr_type == AddressType.GEOGRAPHIC:
            return self.address_data.to_bytes()
        elif self.addr_type == AddressType.SERVICE_ID:
            return self.address_data.to_bytes()
        elif self.addr_type in [AddressType.IPV4_COMPAT, AddressType.IPV6_COMPAT]:
            return socket.inet_pton(
                socket.AF_INET if self.addr_type == AddressType.IPV4_COMPAT else socket.AF_INET6,
                self.address_data
            )
        else:
            return b''
    
    def __str__(self) -> str:
        """字符串表示"""
        if self.addr_type == AddressType.GEOGRAPHIC:
            return f"geo://{self.address_data.continent}.{self.address_data.country}.{self.address_data.region}.{self.address_data.city}.{self.address_data.area}"
        elif self.addr_type == AddressType.SERVICE_ID:
            return f"srv://{self.address_data.service_type}:{self.address_data.provider_id}:{self.address_data.instance_id}"
        else:
            return str(self.address_data)

class AIPPacket:
    """AIP协议包类"""
    
    HEADER_SIZE = 32  # 基础包头大小
    
    def __init__(self):
        self.version = 1
        self.addr_type = AddressType.IPV4_COMPAT
        self.flags = 0
        self.service_class = ServiceClass.BEST_EFFORT
        self.hop_limit = 64
        self.payload_length = 0
        self.header_length = self.HEADER_SIZE
        self.flow_id = 0
        self.timestamp = int(time.time() * 1000000)  # 微秒级时间戳
        self.source_addr = None
        self.dest_addr = None
        self.payload = b''
        self.extensions = []
    
    def pack(self) -> bytes:
        """打包为字节序列"""
        # 构建基础包头
        header = struct.pack(
            '>BBBBHHQQQ',
            (self.version << 4) | self.addr_type.value,
            self.flags,
            self.service_class.value,
            self.hop_limit,
            self.payload_length,
            self.header_length,
            self.flow_id,
            self.timestamp,
            0  # 占位符
        )
        
        # 添加地址信息
        src_bytes = self.source_addr.to_bytes() if self.source_addr else b''
        dst_bytes = self.dest_addr.to_bytes() if self.dest_addr else b''
        
        # 计算实际包头长度
        actual_header_len = len(header) + len(src_bytes) + len(dst_bytes)
        
        # 重新打包包头（更新header_length）
        header = struct.pack(
            '>BBBBHHQQQ',
            (self.version << 4) | self.addr_type.value,
            self.flags,
            self.service_class.value,
            self.hop_limit,
            len(self.payload),
            actual_header_len,
            self.flow_id,
            self.timestamp,
            0
        )
        
        return header + src_bytes + dst_bytes + self.payload
    
    @classmethod
    def unpack(cls, data: bytes) -> 'AIPPacket':
        """从字节序列解包"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("数据长度不足")
        
        packet = cls()
        
        # 解析基础包头
        fields = struct.unpack('>BBBBHHQQQ', data[:cls.HEADER_SIZE])
        
        packet.version = (fields[0] >> 4) & 0xF
        packet.addr_type = AddressType(fields[0] & 0xF)
        packet.flags = fields[1]
        packet.service_class = ServiceClass(fields[2])
        packet.hop_limit = fields[3]
        packet.payload_length = fields[4]
        packet.header_length = fields[5]
        packet.flow_id = fields[6]
        packet.timestamp = fields[7]
        
        # 解析地址（简化处理）
        addr_start = cls.HEADER_SIZE
        # 这里需要根据addr_type解析具体的地址格式
        
        # 提取载荷
        payload_start = packet.header_length
        packet.payload = data[payload_start:payload_start + packet.payload_length]
        
        return packet

@dataclass
class RouteMetrics:
    """路由度量信息"""
    latency: float      # 延迟 (ms)
    bandwidth: float    # 带宽 (Mbps)  
    packet_loss: float  # 丢包率
    cost: float         # 成本
    reliability: float  # 可靠性

class NetworkPath:
    """网络路径信息"""
    
    def __init__(self, path_id: str, next_hop: str):
        self.path_id = path_id
        self.next_hop = next_hop
        self.metrics = RouteMetrics(0, 0, 0, 0, 1.0)
        self.last_updated = time.time()
        self.usage_count = 0
    
    def update_metrics(self, latency: float, bandwidth: float, packet_loss: float):
        """更新路径度量"""
        self.metrics.latency = latency
        self.metrics.bandwidth = bandwidth
        self.metrics.packet_loss = packet_loss
        self.metrics.reliability = 1.0 - packet_loss
        self.last_updated = time.time()

class IntelligentRouter:
    """智能路由器类"""
    
    def __init__(self, router_id: str):
        self.router_id = router_id
        self.routing_table: Dict[str, List[NetworkPath]] = {}
        self.path_cache: Dict[str, str] = {}  # 缓存最优路径
        self.traffic_history: List[Dict] = []
        self.lock = threading.Lock()
    
    def add_path(self, destination: str, path: NetworkPath):
        """添加路径到路由表"""
        with self.lock:
            if destination not in self.routing_table:
                self.routing_table[destination] = []
            self.routing_table[destination].append(path)
    
    def calculate_path_score(self, path: NetworkPath, service_class: ServiceClass) -> float:
        """计算路径得分"""
        metrics = path.metrics
        
        # 基础得分计算
        latency_score = 1.0 / (1.0 + metrics.latency / 1000.0)  # 归一化延迟
        bandwidth_score = min(metrics.bandwidth / 100.0, 1.0)   # 归一化带宽
        reliability_score = metrics.reliability
        cost_score = 1.0 / (1.0 + metrics.cost)
        
        # 根据服务类型调整权重
        if service_class in [ServiceClass.REAL_TIME_VIDEO, ServiceClass.REAL_TIME_AUDIO]:
            # 实时服务优先考虑延迟和可靠性
            score = 0.4 * latency_score + 0.1 * bandwidth_score + \
                   0.3 * reliability_score + 0.2 * cost_score
        elif service_class == ServiceClass.FILE_TRANSFER:
            # 文件传输优先考虑带宽
            score = 0.1 * latency_score + 0.5 * bandwidth_score + \
                   0.2 * reliability_score + 0.2 * cost_score
        else:
            # 默认均衡权重
            score = 0.3 * latency_score + 0.25 * bandwidth_score + \
                   0.25 * reliability_score + 0.2 * cost_score
        
        return score
    
    def select_best_path(self, destination: str, service_class: ServiceClass) -> Optional[NetworkPath]:
        """选择最佳路径"""
        with self.lock:
            if destination not in self.routing_table:
                return None
            
            paths = self.routing_table[destination]
            if not paths:
                return None
            
            best_path = None
            best_score = -1
            
            for path in paths:
                score = self.calculate_path_score(path, service_class)
                if score > best_score:
                    best_score = score
                    best_path = path
            
            # 更新缓存
            if best_path:
                cache_key = f"{destination}:{service_class.value}"
                self.path_cache[cache_key] = best_path.path_id
                best_path.usage_count += 1
            
            return best_path
    
    def route_packet(self, packet: AIPPacket) -> Optional[str]:
        """路由数据包"""
        if not packet.dest_addr:
            return None
        
        destination = str(packet.dest_addr)
        best_path = self.select_best_path(destination, packet.service_class)
        
        if best_path:
            # 更新跳数
            packet.hop_limit -= 1
            return best_path.next_hop
        
        return None

class AIPSecurity:
    """AIP安全模块"""
    
    def __init__(self):
        # 生成密钥对
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.session_keys: Dict[str, bytes] = {}
    
    def generate_session_key(self, peer_id: str) -> bytes:
        """生成会话密钥"""
        key = hashlib.sha256(f"{peer_id}{time.time()}".encode()).digest()
        self.session_keys[peer_id] = key
        return key
    
    def encrypt_payload(self, payload: bytes, peer_id: str) -> bytes:
        """加密载荷"""
        if peer_id not in self.session_keys:
            self.generate_session_key(peer_id)
        
        key = self.session_keys[peer_id]
        iv = hashlib.sha256(str(time.time()).encode()).digest()[:16]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # 添加填充
        padding_len = 16 - (len(payload) % 16)
        padded_payload = payload + bytes([padding_len] * padding_len)
        
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        return iv + encrypted
    
    def decrypt_payload(self, encrypted_data: bytes, peer_id: str) -> bytes:
        """解密载荷"""
        if peer_id not in self.session_keys:
            raise ValueError("没有找到会话密钥")
        
        key = self.session_keys[peer_id]
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 移除填充
        padding_len = decrypted[-1]
        return decrypted[:-padding_len]
    
    def sign_packet(self, packet: AIPPacket) -> bytes:
        """对包进行数字签名"""
        packet_data = packet.pack()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(packet_data)
        packet_hash = digest.finalize()
        
        signature = self.private_key.sign(packet_hash, ec.ECDSA(hashes.SHA256()))
        return signature

class AIPProtocolStack:
    """AIP协议栈主类"""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.router = IntelligentRouter(node_id)
        self.security = AIPSecurity()
        self.interfaces: Dict[str, socket.socket] = {}
        self.running = False
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'packets_forwarded': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }
    
    def add_interface(self, interface_name: str, sock: socket.socket):
        """添加网络接口"""
        self.interfaces[interface_name] = sock
    
    def send_packet(self, packet: AIPPacket, interface: str = None) -> bool:
        """发送数据包"""
        try:
            # 路由决策
            if interface is None:
                next_hop = self.router.route_packet(packet)
                if not next_hop:
                    return False
                interface = next_hop
            
            # 安全处理
            if packet.flags & AIPFlags.ENCRYPTED.value:
                peer_id = str(packet.dest_addr)
                packet.payload = self.security.encrypt_payload(packet.payload, peer_id)
            
            if packet.flags & AIPFlags.AUTHENTICATED.value:
                signature = self.security.sign_packet(packet)
                # 将签名添加到扩展头中
                packet.extensions.append(('signature', signature))
            
            # 发送包
            if interface in self.interfaces:
                sock = self.interfaces[interface]
                packet_data = packet.pack()
                sock.send(packet_data)
                
                # 更新统计
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet_data)
                
                return True
        
        except Exception as e:
            print(f"发送包时出错: {e}")
        
        return False
    
    def receive_packet(self, interface: str) -> Optional[AIPPacket]:
        """接收数据包"""
        try:
            if interface not in self.interfaces:
                return None
            
            sock = self.interfaces[interface]
            data = sock.recv(65536)  # 最大包大小
            
            if not data:
                return None
            
            packet = AIPPacket.unpack(data)
            
            # 更新统计
            self.stats['packets_received'] += 1
            self.stats['bytes_received'] += len(data)
            
            # 安全验证
            if packet.flags & AIPFlags.AUTHENTICATED.value:
                # 验证数字签名
                pass  # 简化处理
            
            if packet.flags & AIPFlags.ENCRYPTED.value:
                peer_id = str(packet.source_addr)
                packet.payload = self.security.decrypt_payload(packet.payload, peer_id)
            
            return packet
        
        except Exception as e:
            print(f"接收包时出错: {e}")
        
        return None
    
    def forward_packet(self, packet: AIPPacket) -> bool:
        """转发数据包"""
        if packet.hop_limit <= 0:
            return False  # TTL耗尽，丢弃包
        
        next_hop = self.router.route_packet(packet)
        if next_hop:
            self.stats['packets_forwarded'] += 1
            return self.send_packet(packet, next_hop)
        
        return False
    
    def start_service(self):
        """启动协议栈服务"""
        self.running = True
        print(f"AIP协议栈 {self.node_id} 已启动")
    
    def stop_service(self):
        """停止协议栈服务"""
        self.running = False
        for sock in self.interfaces.values():
            sock.close()
        print(f"AIP协议栈 {self.node_id} 已停止")
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()

# 使用示例
def example_usage():
    """AIP协议使用示例"""
    
    # 创建协议栈实例
    stack = AIPProtocolStack("node1")
    
    # 创建地理位置地址
    geo_addr = GeographicAddress(continent=1, country=86, region=110, city=1, area=100001)
    source_addr = AIPAddress(AddressType.GEOGRAPHIC, geo_addr)
    
    # 创建服务地址  
    svc_addr = ServiceAddress(service_type=1, provider_id=100, instance_id=1001)
    dest_addr = AIPAddress(AddressType.SERVICE_ID, svc_addr)
    
    # 创建AIP包
    packet = AIPPacket()
    packet.source_addr = source_addr
    packet.dest_addr = dest_addr
    packet.service_class = ServiceClass.REAL_TIME_VIDEO
    packet.flags = AIPFlags.ENCRYPTED.value | AIPFlags.AUTHENTICATED.value
    packet.payload = b"Hello, AIP Protocol!"
    
    print("=== AIP协议包信息 ===")
    print(f"源地址: {packet.source_addr}")
    print(f"目标地址: {packet.dest_addr}")
    print(f"服务类型: {packet.service_class}")
    print(f"载荷: {packet.payload.decode()}")
    print(f"包大小: {len(packet.pack())} bytes")
    
    # 添加路径到路由表
    path1 = NetworkPath("path1", "interface1")
    path1.update_metrics(latency=10.5, bandwidth=100.0, packet_loss=0.001)
    
    path2 = NetworkPath("path2", "interface2")  
    path2.update_metrics(latency=15.2, bandwidth=80.0, packet_loss=0.002)
    
    stack.router.add_path(str(dest_addr), path1)
    stack.router.add_path(str(dest_addr), path2)
    
    # 路径选择
    best_path = stack.router.select_best_path(str(dest_addr), packet.service_class)
    if best_path:
        print(f"\n=== 最佳路径选择 ===")
        print(f"路径ID: {best_path.path_id}")
        print(f"下一跳: {best_path.next_hop}")
        print(f"延迟: {best_path.metrics.latency}ms")
        print(f"带宽: {best_path.metrics.bandwidth}Mbps")
        print(f"可靠性: {best_path.metrics.reliability}")
    
    # 启动协议栈
    stack.start_service()
    
    # 获取统计信息
    stats = stack.get_statistics()
    print(f"\n=== 协议栈统计 ===")
    print(f"已发送包: {stats['packets_sent']}")
    print(f"已接收包: {stats['packets_received']}")
    print(f"已转发包: {stats['packets_forwarded']}")
    
    # 停止协议栈
    stack.stop_service()

if __name__ == "__main__":
    example_usage()
