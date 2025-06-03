#!/usr/bin/env python3
"""
AIP协议网络仿真器
用于测试和演示自适应互联网协议的功能
"""

import time
import random
import threading
import matplotlib.pyplot as plt
import networkx as nx
from typing import List, Dict, Tuple
from dataclasses import dataclass
import json

# 导入AIP协议模块（假设在同一目录）
from aip_protocol_implementation import (
    AIPProtocolStack, AIPPacket, AIPAddress, AddressType,
    ServiceClass, AIPFlags, GeographicAddress, ServiceAddress,
    NetworkPath, RouteMetrics
)

@dataclass
class SimulationConfig:
    """仿真配置"""
    num_nodes: int = 10
    simulation_time: int = 60  # 秒
    packet_interval: float = 0.1  # 包发送间隔
    network_delay_range: Tuple[float, float] = (5.0, 50.0)  # 延迟范围(ms)
    bandwidth_range: Tuple[float, float] = (10.0, 1000.0)  # 带宽范围(Mbps)
    packet_loss_range: Tuple[float, float] = (0.001, 0.01)  # 丢包率范围

class SimulatedNode:
    """仿真节点类"""
    
    def __init__(self, node_id: str, position: Tuple[float, float]):
        self.node_id = node_id
        self.position = position  # (x, y) 坐标
        self.protocol_stack = AIPProtocolStack(node_id)
        self.neighbors: List['SimulatedNode'] = []
        self.message_queue: List[AIPPacket] = []
        self.active = True
        
        # 性能指标
        self.metrics = {
            'packets_generated': 0,
            'packets_delivered': 0,
            'total_latency': 0.0,
            'delivery_ratio': 0.0
        }
    
    def add_neighbor(self, neighbor: 'SimulatedNode', link_quality: RouteMetrics):
        """添加邻居节点"""
        self.neighbors.append(neighbor)
        
        # 创建到邻居的路径
        path = NetworkPath(f"link_{self.node_id}_{neighbor.node_id}", neighbor.node_id)
        path.metrics = link_quality
        
        # 添加到路由表
        self.protocol_stack.router.add_path(neighbor.node_id, path)
    
    def generate_traffic(self, dest_node: 'SimulatedNode', service_class: ServiceClass, size: int = 1024):
        """生成测试流量"""
        # 创建AIP包
        packet = AIPPacket()
        
        # 设置地址
        src_geo = GeographicAddress(1, random.randint(1, 255), random.randint(1, 4095), 
                                  random.randint(1, 65535), random.randint(1, 16777215))
        dst_geo = GeographicAddress(1, random.randint(1, 255), random.randint(1, 4095),
                                  random.randint(1, 65535), random.randint(1, 16777215))
        
        packet.source_addr = AIPAddress(AddressType.GEOGRAPHIC, src_geo)
        packet.dest_addr = AIPAddress(AddressType.GEOGRAPHIC, dst_geo)
        packet.service_class = service_class
        packet.payload = b'X' * size  # 模拟数据
        packet.flow_id = random.randint(1, 1000000)
        
        # 设置标志
        if service_class in [ServiceClass.REAL_TIME_VIDEO, ServiceClass.REAL_TIME_AUDIO]:
            packet.flags = AIPFlags.URGENT.value
        
        # 添加到消息队列
        packet.generation_time = time.time()  # 记录生成时间
        packet.destination_node = dest_node.node_id  # 记录目标节点
        self.message_queue.append(packet)
        self.metrics['packets_generated'] += 1
    
    def process_packet(self, packet: AIPPacket) -> bool:
        """处理接收到的包"""
        # 检查是否为本节点的包
        if hasattr(packet, 'destination_node') and packet.destination_node == self.node_id:
            # 包到达目标
            if hasattr(packet, 'generation_time'):
                latency = (time.time() - packet.generation_time) * 1000  # 转换为毫秒
                self.metrics['total_latency'] += latency
                self.metrics['packets_delivered'] += 1
                self.metrics['delivery_ratio'] = self.metrics['packets_delivered'] / max(1, self.metrics['packets_generated'])
            return True
        else:
            # 转发包
            return self.protocol_stack.forward_packet(packet)
    
    def send_queued_packets(self):
        """发送队列中的包"""
        packets_to_remove = []
        
        for i, packet in enumerate(self.message_queue):
            if self.protocol_stack.send_packet(packet):
                packets_to_remove.append(i)
        
        # 移除已发送的包
        for i in reversed(packets_to_remove):
            del self.message_queue[i]

class NetworkTopology:
    """网络拓扑生成器"""
    
    @staticmethod
    def generate_random_topology(num_nodes: int, connectivity: float = 0.3) -> List[Tuple[int, int, RouteMetrics]]:
        """生成随机网络拓扑"""
        edges = []
        
        for i in range(num_nodes):
            for j in range(i + 1, num_nodes):
                if random.random() < connectivity:
                    # 随机生成链路质量
                    metrics = RouteMetrics(
                        latency=random.uniform(5.0, 50.0),
                        bandwidth=random.uniform(10.0, 1000.0),
                        packet_loss=random.uniform(0.001, 0.01),
                        cost=random.uniform(1.0, 10.0),
                        reliability=1.0 - random.uniform(0.001, 0.01)
                    )
                    edges.append((i, j, metrics))
        
        return edges
    
    @staticmethod
    def generate_mesh_topology(num_nodes: int) -> List[Tuple[int, int, RouteMetrics]]:
        """生成网格拓扑"""
        edges = []
        grid_size = int(num_nodes ** 0.5)
        
        for i in range(grid_size):
            for j in range(grid_size):
                node_id = i * grid_size + j
                if node_id >= num_nodes:
                    break
                
                # 连接右边的节点
                if j + 1 < grid_size and node_id + 1 < num_nodes:
                    metrics = RouteMetrics(
                        latency=random.uniform(10.0, 20.0),
                        bandwidth=random.uniform(100.0, 500.0),
                        packet_loss=random.uniform(0.001, 0.005),
                        cost=1.0,
                        reliability=0.99
                    )
                    edges.append((node_id, node_id + 1, metrics))
                
                # 连接下面的节点
                if i + 1 < grid_size and node_id + grid_size < num_nodes:
                    metrics = RouteMetrics(
                        latency=random.uniform(10.0, 20.0),
                        bandwidth=random.uniform(100.0, 500.0),
                        packet_loss=random.uniform(0.001, 0.005),
                        cost=1.0,
                        reliability=0.99
                    )
                    edges.append((node_id, node_id + grid_size, metrics))
        
        return edges

class AIPNetworkSimulator:
    """AIP网络仿真器主类"""
    
    def __init__(self, config: SimulationConfig):
        self.config = config
        self.nodes: List[SimulatedNode] = []
        self.topology_edges: List[Tuple[int, int, RouteMetrics]] = []
        self.simulation_thread = None
        self.running = False
        self.results = {
            'timestamps': [],
            'throughput': [],
            'latency': [],
            'delivery_ratio': [],
            'node_metrics': {}
        }
    
    def create_network(self, topology_type: str = "random"):
        """创建网络拓扑"""
        # 创建节点
        self.nodes = []
        for i in range(self.config.num_nodes):
            position = (random.uniform(0, 100), random.uniform(0, 100))
            node = SimulatedNode(f"node_{i}", position)
            self.nodes.append(node)
        
        # 生成拓扑
        if topology_type == "random":
            self.topology_edges = NetworkTopology.generate_random_topology(self.config.num_nodes)
        elif topology_type == "mesh":
            self.topology_edges = NetworkTopology.generate_mesh_topology(self.config.num_nodes)
        
        # 建立连接
        for edge in self.topology_edges:
            node1_idx, node2_idx, metrics = edge
            node1 = self.nodes[node1_idx]
            node2 = self.nodes[node2_idx]
            
            # 双向连接
            node1.add_neighbor(node2, metrics)
            node2.add_neighbor(node1, metrics)
        
        print(f"创建了包含 {len(self.nodes)} 个节点和 {len(self.topology_edges)} 条链路的网络")
    
    def generate_traffic_patterns(self):
        """生成流量模式"""
        # 随机选择源和目标节点
        for _ in range(10):  # 生成10个流量流
            src_node = random.choice(self.nodes)
            dst_node = random.choice([n for n in self.nodes if n != src_node])
            service_class = random.choice(list(ServiceClass))
            
            # 根据服务类型生成不同大小的包
            if service_class == ServiceClass.REAL_TIME_VIDEO:
                size = random.randint(1024, 8192)
            elif service_class == ServiceClass.FILE_TRANSFER:
                size = random.randint(8192, 65536)
            else:
                size = random.randint(64, 1024)
            
            src_node.generate_traffic(dst_node, service_class, size)
    
    def simulate_network_dynamics(self):
        """模拟网络动态变化"""
        # 随机改变链路质量
        for edge in self.topology_edges:
            node1_idx, node2_idx, metrics = edge
            
            # 添加随机波动
            metrics.latency *= random.uniform(0.8, 1.2)
            metrics.bandwidth *= random.uniform(0.9, 1.1)
            metrics.packet_loss = min(0.1, metrics.packet_loss * random.uniform(0.5, 2.0))
            metrics.reliability = 1.0 - metrics.packet_loss
    
    def collect_metrics(self):
        """收集性能指标"""
        timestamp = time.time()
        total_throughput = 0
        total_latency = 0
        total_delivery_ratio = 0
        active_nodes = 0
        
        for node in self.nodes:
            if node.active:
                active_nodes += 1
                total_throughput += node.protocol_stack.stats['bytes_sent']
                
                if node.metrics['packets_delivered'] > 0:
                    avg_latency = node.metrics['total_latency'] / node.metrics['packets_delivered']
                    total_latency += avg_latency
                
                total_delivery_ratio += node.metrics['delivery_ratio']
                
                # 记录每个节点的详细指标
                self.results['node_metrics'][node.node_id] = {
                    'packets_generated': node.metrics['packets_generated'],
                    'packets_delivered': node.metrics['packets_delivered'],
                    'delivery_ratio': node.metrics['delivery_ratio'],
                    'avg_latency': node.metrics['total_latency'] / max(1, node.metrics['packets_delivered'])
                }
        
        # 计算平均值
        if active_nodes > 0:
            avg_throughput = total_throughput / active_nodes
            avg_latency = total_latency / active_nodes
            avg_delivery_ratio = total_delivery_ratio / active_nodes
        else:
            avg_throughput = avg_latency = avg_delivery_ratio = 0
        
        # 记录结果
        self.results['timestamps'].append(timestamp)
        self.results['throughput'].append(avg_throughput)
        self.results['latency'].append(avg_latency)
        self.results['delivery_ratio'].append(avg_delivery_ratio)
    
    def simulation_loop(self):
        """仿真主循环"""
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < self.config.simulation_time:
            # 生成流量
            if random.random() < 0.3:  # 30%概率生成新流量
                self.generate_traffic_patterns()
            
            # 处理包传输
            for node in self.nodes:
                if node.active:
                    # 发送队列中的包
                    node.send_queued_packets()
                    
                    # 模拟包的接收和处理
                    # 这里简化处理，实际中需要网络传输仿真
                    for neighbor in node.neighbors:
                        if neighbor.message_queue and random.random() < 0.1:  # 10%概率接收邻居的包
                            packet = neighbor.message_queue.pop(0)
                            node.process_packet(packet)
            
            # 模拟网络动态变化
            if random.random() < 0.05:  # 5%概率改变网络状态
                self.simulate_network_dynamics()
            
            # 收集指标
            self.collect_metrics()
            
            # 控制仿真速度
            time.sleep(self.config.packet_interval)
        
        print("仿真完成")
    
    def start_simulation(self):
        """启动仿真"""
        if self.running:
            print("仿真已在运行中")
            return
        
        self.running = True
        print("启动AIP网络仿真...")
        
        # 启动所有节点的协议栈
        for node in self.nodes:
            node.protocol_stack.start_service()
        
        # 启动仿真线程
        self.simulation_thread = threading.Thread(target=self.simulation_loop)
        self.simulation_thread.start()
    
    def stop_simulation(self):
        """停止仿真"""
        if not self.running:
            print("仿真未在运行")
            return
        
        print("停止仿真...")
        self.running = False
        
        if self.simulation_thread:
            self.simulation_thread.join()
        
        # 停止所有节点的协议栈
        for node in self.nodes:
            node.protocol_stack.stop_service()
    
    def visualize_network(self):
        """可视化网络拓扑"""
        try:
            # 创建网络图
            G = nx.Graph()
            
            # 添加节点
            for i, node in enumerate(self.nodes):
                G.add_node(i, pos=node.position, label=node.node_id)
            
            # 添加边
            for edge in self.topology_edges:
                node1_idx, node2_idx, metrics = edge
                G.add_edge(node1_idx, node2_idx, weight=metrics.latency)
            
            # 绘制网络图
            plt.figure(figsize=(12, 8))
            pos = nx.get_node_attributes(G, 'pos')
            
            # 绘制节点
            nx.draw_nodes(G, pos, node_color='lightblue', node_size=500)
            
            # 绘制边，颜色表示延迟
            edges = G.edges()
            weights = [G[u][v]['weight'] for u, v in edges]
            nx.draw_networkx_edges(G, pos, edge_color=weights, edge_cmap=plt.cm.Reds)
            
            # 添加标签
            labels = {i: f"N{i}" for i in range(len(self.nodes))}
            nx.draw_networkx_labels(G, pos, labels, font_size=8)
            
            plt.title("AIP网络拓扑")
            plt.colorbar(plt.cm.ScalarMappable(cmap=plt.cm.Reds), label='延迟 (ms)')
            plt.axis('off')
            plt.tight_layout()
            plt.show()
            
        except ImportError:
            print("需要安装matplotlib和networkx库来可视化网络")
    
    def plot_performance_metrics(self):
        """绘制性能指标图表"""
        try:
            if not self.results['timestamps']:
                print("没有可用的性能数据")
                return
            
            # 转换时间戳为相对时间
            start_time = self.results['timestamps'][0]
            relative_times = [(t - start_time) for t in self.results['timestamps']]
            
            # 创建子图
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
            
            # 吞吐量图
            ax1.plot(relative_times, self.results['throughput'], 'b-', linewidth=2)
            ax1.set_title('网络吞吐量')
            ax1.set_xlabel('时间 (秒)')
            ax1.set_ylabel('吞吐量 (Bytes/s)')
            ax1.grid(True)
            
            # 延迟图
            ax2.plot(relative_times, self.results['latency'], 'r-', linewidth=2)
            ax2.set_title('平均延迟')
            ax2.set_xlabel('时间 (秒)')
            ax2.set_ylabel('延迟 (ms)')
            ax2.grid(True)
            
            # 投递率图
            ax3.plot(relative_times, self.results['delivery_ratio'], 'g-', linewidth=2)
            ax3.set_title('包投递率')
            ax3.set_xlabel('时间 (秒)')
            ax3.set_ylabel('投递率')
            ax3.set_ylim(0, 1)
            ax3.grid(True)
            
            # 节点性能对比
            node_names = list(self.results['node_metrics'].keys())
            delivery_ratios = [self.results['node_metrics'][node]['delivery_ratio'] 
                             for node in node_names]
            
            ax4.bar(range(len(node_names)), delivery_ratios)
            ax4.set_title('各节点投递率对比')
            ax4.set_xlabel('节点')
            ax4.set_ylabel('投递率')
            ax4.set_xticks(range(len(node_names)))
            ax4.set_xticklabels([f"N{i}" for i in range(len(node_names))], rotation=45)
            
            plt.tight_layout()
            plt.show()
            
        except ImportError:
            print("需要安装matplotlib库来绘制性能图表")
    
    def export_results(self, filename: str = "aip_simulation_results.json"):
        """导出仿真结果"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"仿真结果已导出到 {filename}")
        except Exception as e:
            print(f"导出结果时出错: {e}")
    
    def print_summary(self):
        """打印仿真摘要"""
        if not self.results['timestamps']:
            print("没有可用的仿真数据")
            return
        
        print("\n" + "="*50)
        print("AIP网络仿真结果摘要")
        print("="*50)
        
        # 网络基本信息
        print(f"节点数量: {len(self.nodes)}")
        print(f"链路数量: {len(self.topology_edges)}")
        print(f"仿真时间: {self.config.simulation_time} 秒")
        
        # 性能统计
        if self.results['throughput']:
            avg_throughput = sum(self.results['throughput']) / len(self.results['throughput'])
            max_throughput = max(self.results['throughput'])
            print(f"\n吞吐量统计:")
            print(f"  平均吞吐量: {avg_throughput:.2f} Bytes/s")
            print(f"  峰值吞吐量: {max_throughput:.2f} Bytes/s")
        
        if self.results['latency']:
            avg_latency = sum(self.results['latency']) / len(self.results['latency'])
            min_latency = min(self.results['latency'])
            max_latency = max(self.results['latency'])
            print(f"\n延迟统计:")
            print(f"  平均延迟: {avg_latency:.2f} ms")
            print(f"  最小延迟: {min_latency:.2f} ms")
            print(f"  最大延迟: {max_latency:.2f} ms")
        
        if self.results['delivery_ratio']:
            avg_delivery = sum(self.results['delivery_ratio']) / len(self.results['delivery_ratio'])
            print(f"\n投递率统计:")
            print(f"  平均投递率: {avg_delivery:.3f}")
        
        # 节点统计
        total_generated = sum(metrics['packets_generated'] 
                            for metrics in self.results['node_metrics'].values())
        total_delivered = sum(metrics['packets_delivered'] 
                            for metrics in self.results['node_metrics'].values())
        
        print(f"\n包传输统计:")
        print(f"  总生成包数: {total_generated}")
        print(f"  总投递包数: {total_delivered}")
        print(f"  整体投递率: {total_delivered/max(1, total_generated):.3f}")

def main():
    """主函数 - 运行仿真示例"""
    print("AIP协议网络仿真器")
    print("==================")
    
    # 创建仿真配置
    config = SimulationConfig(
        num_nodes=8,
        simulation_time=30,
        packet_interval=0.1
    )
    
    # 创建仿真器
    simulator = AIPNetworkSimulator(config)
    
    # 创建网络拓扑
    print("创建网络拓扑...")
    simulator.create_network("random")
    
    # 可视化网络（如果有相关库）
    try:
        simulator.visualize_network()
    except:
        print("跳过网络可视化（需要matplotlib和networkx）")
    
    # 启动仿真
    simulator.start_simulation()
    
    # 等待仿真完成
    if simulator.simulation_thread:
        simulator.simulation_thread.join()
    
    # 打印结果摘要
    simulator.print_summary()
    
    # 绘制性能图表
    try:
        simulator.plot_performance_metrics()
    except:
        print("跳过性能图表绘制（需要matplotlib）")
    
    # 导出结果
    simulator.export_results()
    
    print("\n仿真完成！")

if __name__ == "__main__":
    main()