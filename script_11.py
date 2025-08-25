# Create traffic generator for background legitimate traffic
traffic_generator_content = '''"""
Traffic Generator for SDN DDoS Protection Testing
Generates legitimate background traffic to test system under normal conditions
"""

import threading
import time
import random
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from utils.logger import simulation_logger

@dataclass
class TrafficPattern:
    """Defines a traffic generation pattern"""
    name: str
    source_hosts: List[str]
    target_hosts: List[str]
    traffic_type: str  # web, file_transfer, video, mixed
    duration: int
    intensity: str  # low, medium, high
    protocols: List[str]  # tcp, udp, icmp
    ports: List[int]
    packet_sizes: List[int]

class TrafficGenerator:
    """
    Generates realistic background traffic for testing
    """
    
    def __init__(self, network):
        self.network = network
        self.active_generators = []
        self.traffic_threads = []
        
        # Traffic patterns for different scenarios
        self.patterns = {
            'web_browsing': {
                'protocols': ['tcp'],
                'ports': [80, 443, 8080],
                'packet_sizes': [64, 128, 256, 512, 1024],
                'rate_range': (1, 10)  # requests per second
            },
            'file_transfer': {
                'protocols': ['tcp'],
                'ports': [21, 22, 80, 443],
                'packet_sizes': [1024, 1460],
                'rate_range': (10, 100)  # packets per second
            },
            'video_streaming': {
                'protocols': ['udp', 'tcp'],
                'ports': [1935, 8080, 443],
                'packet_sizes': [1024, 1460],
                'rate_range': (50, 200)  # packets per second
            },
            'dns_queries': {
                'protocols': ['udp'],
                'ports': [53],
                'packet_sizes': [64, 128],
                'rate_range': (0.1, 2)  # queries per second
            },
            'email': {
                'protocols': ['tcp'],
                'ports': [25, 110, 143, 993, 995],
                'packet_sizes': [64, 256, 1024],
                'rate_range': (0.1, 1)  # messages per second
            },
            'database': {
                'protocols': ['tcp'],
                'ports': [3306, 5432, 1433, 27017],
                'packet_sizes': [128, 512, 1024],
                'rate_range': (1, 20)  # queries per second
            }
        }
        
        simulation_logger.info("Traffic Generator initialized")
    
    def generate_background_traffic(self, pattern_name: str = 'mixed', 
                                  duration: int = 300, intensity: str = 'medium') -> bool:
        """
        Generate background traffic based on specified pattern
        
        Args:
            pattern_name: Type of traffic pattern
            duration: Duration in seconds
            intensity: Traffic intensity (low, medium, high)
            
        Returns:
            True if traffic generation started successfully
        """
        try:
            hosts = self.network.net.hosts
            if len(hosts) < 2:
                simulation_logger.warning("Need at least 2 hosts for traffic generation")
                return False
            
            simulation_logger.info(
                f"Starting background traffic generation: {pattern_name}, "
                f"duration: {duration}s, intensity: {intensity}"
            )
            
            # Split hosts into clients and servers
            num_servers = max(1, len(hosts) // 4)
            servers = hosts[:num_servers]
            clients = hosts[num_servers:]
            
            # Start traffic generation based on pattern
            if pattern_name == 'mixed':
                return self._generate_mixed_traffic(servers, clients, duration, intensity)
            else:
                return self._generate_pattern_traffic(pattern_name, servers, clients, 
                                                    duration, intensity)
                
        except Exception as e:
            simulation_logger.error(f"Error starting background traffic: {e}")
            return False
    
    def _generate_mixed_traffic(self, servers: List, clients: List, 
                               duration: int, intensity: str) -> bool:
        """Generate mixed traffic with multiple patterns"""
        try:
            # Start different traffic patterns simultaneously
            patterns = ['web_browsing', 'file_transfer', 'video_streaming', 'dns_queries']
            
            for pattern in patterns:
                # Assign subset of hosts to each pattern
                pattern_servers = random.sample(servers, max(1, len(servers) // len(patterns)))
                pattern_clients = random.sample(clients, max(1, len(clients) // len(patterns)))
                
                thread = threading.Thread(
                    target=self._run_traffic_pattern,
                    args=(pattern, pattern_servers, pattern_clients, duration, intensity)
                )
                thread.daemon = True
                thread.start()
                self.traffic_threads.append(thread)
            
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error generating mixed traffic: {e}")
            return False
    
    def _generate_pattern_traffic(self, pattern_name: str, servers: List, 
                                 clients: List, duration: int, intensity: str) -> bool:
        """Generate traffic for specific pattern"""
        try:
            thread = threading.Thread(
                target=self._run_traffic_pattern,
                args=(pattern_name, servers, clients, duration, intensity)
            )
            thread.daemon = True
            thread.start()
            self.traffic_threads.append(thread)
            
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error generating pattern traffic: {e}")
            return False
    
    def _run_traffic_pattern(self, pattern_name: str, servers: List, 
                            clients: List, duration: int, intensity: str):
        """Run specific traffic pattern"""
        try:
            if pattern_name not in self.patterns:
                simulation_logger.warning(f"Unknown pattern: {pattern_name}")
                return
            
            pattern = self.patterns[pattern_name]
            
            # Start servers
            server_processes = self._start_servers(servers, pattern)
            
            # Wait for servers to start
            time.sleep(2)
            
            # Start clients
            client_threads = self._start_clients(clients, servers, pattern, 
                                                duration, intensity)
            
            # Wait for traffic to complete
            for thread in client_threads:
                thread.join()
            
            # Stop servers
            self._stop_servers(server_processes)
            
            simulation_logger.debug(f"Traffic pattern {pattern_name} completed")
            
        except Exception as e:
            simulation_logger.error(f"Error running traffic pattern {pattern_name}: {e}")
    
    def _start_servers(self, servers: List, pattern: Dict) -> List[Dict]:
        """Start servers for traffic pattern"""
        server_processes = []
        
        try:
            for i, server in enumerate(servers):
                for protocol in pattern['protocols']:
                    for port in pattern['ports']:
                        server_info = {
                            'host': server,
                            'protocol': protocol,
                            'port': port,
                            'processes': []
                        }
                        
                        if protocol == 'tcp':
                            # Start iperf server for TCP traffic
                            cmd = f'iperf -s -p {port} -D'
                            server.cmd(cmd)
                            server_info['processes'].append('iperf')
                            
                            # Start simple HTTP server for web traffic
                            if port in [80, 8080]:
                                cmd = f'python -m SimpleHTTPServer {port} > /dev/null 2>&1 &'
                                server.cmd(cmd)
                                server_info['processes'].append('python')
                        
                        elif protocol == 'udp':
                            # Start iperf server for UDP traffic
                            cmd = f'iperf -s -u -p {port} -D'
                            server.cmd(cmd)
                            server_info['processes'].append('iperf')
                            
                            # Start netcat server for UDP
                            cmd = f'nc -u -l -p {port} > /dev/null 2>&1 &'
                            server.cmd(cmd)
                            server_info['processes'].append('nc')
                        
                        server_processes.append(server_info)
                        
                        simulation_logger.debug(
                            f"Started {protocol} server on {server.name}:{port}"
                        )
            
            return server_processes
            
        except Exception as e:
            simulation_logger.error(f"Error starting servers: {e}")
            return server_processes
    
    def _start_clients(self, clients: List, servers: List, pattern: Dict, 
                      duration: int, intensity: str) -> List[threading.Thread]:
        """Start clients for traffic generation"""
        client_threads = []
        
        try:
            # Intensity multipliers
            intensity_multipliers = {'low': 0.3, 'medium': 1.0, 'high': 3.0}
            multiplier = intensity_multipliers.get(intensity, 1.0)
            
            for client in clients:
                for server in servers:
                    thread = threading.Thread(
                        target=self._client_worker,
                        args=(client, server, pattern, duration, multiplier)
                    )
                    thread.daemon = True
                    thread.start()
                    client_threads.append(thread)
            
            return client_threads
            
        except Exception as e:
            simulation_logger.error(f"Error starting clients: {e}")
            return client_threads
    
    def _client_worker(self, client, server, pattern: Dict, 
                      duration: int, multiplier: float):
        """Worker thread for client traffic generation"""
        try:
            start_time = time.time()
            requests_sent = 0
            
            server_ip = server.IP()
            rate_min, rate_max = pattern['rate_range']
            rate = random.uniform(rate_min * multiplier, rate_max * multiplier)
            
            while time.time() - start_time < duration:
                try:
                    # Choose random parameters
                    protocol = random.choice(pattern['protocols'])
                    port = random.choice(pattern['ports'])
                    packet_size = random.choice(pattern['packet_sizes'])
                    
                    if protocol == 'tcp':
                        self._send_tcp_traffic(client, server_ip, port, packet_size)
                    elif protocol == 'udp':
                        self._send_udp_traffic(client, server_ip, port, packet_size)
                    
                    requests_sent += 1
                    
                    # Rate limiting
                    if rate > 0:
                        time.sleep(1.0 / rate)
                    else:
                        time.sleep(1.0)
                
                except Exception as e:
                    simulation_logger.debug(f"Client traffic error: {e}")
            
            simulation_logger.debug(
                f"Client {client.name} sent {requests_sent} requests to {server.name}"
            )
            
        except Exception as e:
            simulation_logger.error(f"Client worker error: {e}")
    
    def _send_tcp_traffic(self, client, server_ip: str, port: int, size: int):
        """Send TCP traffic"""
        try:
            # Use different methods based on port
            if port in [80, 8080]:
                # HTTP request
                cmd = f'curl -s -m 1 http://{server_ip}:{port}/ > /dev/null 2>&1'
            else:
                # Generic TCP with iperf
                cmd = f'iperf -c {server_ip} -p {port} -t 1 -b {size*8}bps > /dev/null 2>&1'
            
            client.cmd(cmd)
            
        except Exception as e:
            simulation_logger.debug(f"TCP traffic error: {e}")
    
    def _send_udp_traffic(self, client, server_ip: str, port: int, size: int):
        """Send UDP traffic"""
        try:
            if port == 53:
                # DNS query
                cmd = f'nslookup google.com {server_ip} > /dev/null 2>&1'
            else:
                # Generic UDP with iperf
                cmd = f'iperf -c {server_ip} -p {port} -u -t 1 -b {size*8}bps > /dev/null 2>&1'
            
            client.cmd(cmd)
            
        except Exception as e:
            simulation_logger.debug(f"UDP traffic error: {e}")
    
    def _stop_servers(self, server_processes: List[Dict]):
        """Stop all server processes"""
        try:
            for server_info in server_processes:
                host = server_info['host']
                
                # Kill server processes
                for process in server_info['processes']:
                    host.cmd(f'killall {process} > /dev/null 2>&1')
            
            simulation_logger.debug("All servers stopped")
            
        except Exception as e:
            simulation_logger.error(f"Error stopping servers: {e}")
    
    def generate_web_traffic(self, duration: int = 300, intensity: str = 'medium') -> bool:
        """Generate realistic web browsing traffic"""
        try:
            hosts = self.network.net.hosts
            servers = hosts[:2]  # First 2 hosts as web servers
            clients = hosts[2:]  # Rest as clients
            
            # Start web servers
            for i, server in enumerate(servers):
                port = 80 + i
                cmd = f'python -m SimpleHTTPServer {port} > /dev/null 2>&1 &'
                server.cmd(cmd)
                simulation_logger.debug(f"Started web server on {server.name}:{port}")
            
            time.sleep(2)  # Let servers start
            
            # Generate web traffic
            for client in clients:
                thread = threading.Thread(
                    target=self._web_traffic_worker,
                    args=(client, servers, duration, intensity)
                )
                thread.daemon = True
                thread.start()
                self.traffic_threads.append(thread)
            
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error generating web traffic: {e}")
            return False
    
    def _web_traffic_worker(self, client, servers: List, duration: int, intensity: str):
        """Worker for web traffic generation"""
        try:
            start_time = time.time()
            requests = 0
            
            # Web pages to request
            pages = ['/', '/index.html', '/about.html', '/contact.html', '/products.html']
            
            # Request rate based on intensity
            rates = {'low': 0.5, 'medium': 2.0, 'high': 5.0}
            rate = rates.get(intensity, 2.0)
            
            while time.time() - start_time < duration:
                try:
                    server = random.choice(servers)
                    page = random.choice(pages)
                    port = 80 if servers.index(server) == 0 else 81
                    
                    # Send HTTP request
                    cmd = f'curl -s -m 2 http://{server.IP()}:{port}{page} > /dev/null 2>&1'
                    client.cmd(cmd)
                    
                    requests += 1
                    
                    # Random delay between requests
                    delay = random.exponential(1.0 / rate)
                    time.sleep(min(delay, 10))  # Cap delay at 10 seconds
                
                except Exception as e:
                    simulation_logger.debug(f"Web traffic error: {e}")
            
            simulation_logger.debug(f"Web client {client.name} made {requests} requests")
            
        except Exception as e:
            simulation_logger.error(f"Web traffic worker error: {e}")
    
    def generate_file_transfer(self, duration: int = 300, intensity: str = 'medium') -> bool:
        """Generate file transfer traffic"""
        try:
            hosts = self.network.net.hosts
            servers = hosts[:1]  # First host as file server
            clients = hosts[1:]  # Rest as clients
            
            # Start FTP-like server (using iperf for simplicity)
            for server in servers:
                cmd = 'iperf -s -p 21 -D'
                server.cmd(cmd)
                simulation_logger.debug(f"Started file server on {server.name}:21")
            
            time.sleep(2)
            
            # Generate file transfer traffic
            for client in clients:
                thread = threading.Thread(
                    target=self._file_transfer_worker,
                    args=(client, servers[0], duration, intensity)
                )
                thread.daemon = True
                thread.start()
                self.traffic_threads.append(thread)
            
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error generating file transfer traffic: {e}")
            return False
    
    def _file_transfer_worker(self, client, server, duration: int, intensity: str):
        """Worker for file transfer traffic"""
        try:
            start_time = time.time()
            transfers = 0
            
            # Transfer sizes based on intensity
            sizes = {
                'low': ['10K', '100K', '1M'],
                'medium': ['1M', '10M', '50M'],
                'high': ['50M', '100M', '500M']
            }
            
            file_sizes = sizes.get(intensity, ['1M', '10M'])
            
            while time.time() - start_time < duration:
                try:
                    size = random.choice(file_sizes)
                    
                    # Simulate file transfer with iperf
                    cmd = f'iperf -c {server.IP()} -p 21 -n {size} > /dev/null 2>&1'
                    client.cmd(cmd)
                    
                    transfers += 1
                    
                    # Delay between transfers
                    time.sleep(random.uniform(5, 30))
                
                except Exception as e:
                    simulation_logger.debug(f"File transfer error: {e}")
            
            simulation_logger.debug(f"Client {client.name} completed {transfers} transfers")
            
        except Exception as e:
            simulation_logger.error(f"File transfer worker error: {e}")
    
    def stop_all_traffic(self):
        """Stop all traffic generation"""
        try:
            simulation_logger.info("Stopping all traffic generation")
            
            # Kill common traffic processes
            for host in self.network.net.hosts:
                host.cmd('killall iperf > /dev/null 2>&1')
                host.cmd('killall python > /dev/null 2>&1')
                host.cmd('killall curl > /dev/null 2>&1')
                host.cmd('killall nc > /dev/null 2>&1')
            
            # Clear thread list
            self.traffic_threads.clear()
            
            simulation_logger.info("Traffic generation stopped")
            
        except Exception as e:
            simulation_logger.error(f"Error stopping traffic: {e}")
    
    def get_traffic_statistics(self) -> Dict:
        """Get traffic generation statistics"""
        return {
            'active_threads': len([t for t in self.traffic_threads if t.is_alive()]),
            'total_threads': len(self.traffic_threads),
            'patterns_available': list(self.patterns.keys())
        }

def run_realistic_simulation(network, duration: int = 600):
    """Run realistic traffic simulation with mixed patterns"""
    try:
        generator = TrafficGenerator(network)
        
        simulation_logger.info(f"Starting realistic traffic simulation for {duration}s")
        
        # Phase 1: Light web traffic (first 30% of time)
        phase1_duration = int(duration * 0.3)
        generator.generate_web_traffic(phase1_duration, 'low')
        time.sleep(phase1_duration)
        
        # Phase 2: Mixed traffic (middle 40% of time)
        phase2_duration = int(duration * 0.4)
        generator.generate_background_traffic('mixed', phase2_duration, 'medium')
        time.sleep(phase2_duration)
        
        # Phase 3: Heavy traffic (last 30% of time)
        phase3_duration = int(duration * 0.3)
        generator.generate_file_transfer(phase3_duration, 'high')
        time.sleep(phase3_duration)
        
        # Stop all traffic
        generator.stop_all_traffic()
        
        simulation_logger.info("Realistic traffic simulation completed")
        
    except Exception as e:
        simulation_logger.error(f"Error in realistic simulation: {e}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Traffic Generator for SDN Testing')
    parser.add_argument('--pattern', '-p',
                       choices=['web_browsing', 'file_transfer', 'video_streaming', 
                               'dns_queries', 'email', 'database', 'mixed'],
                       default='mixed',
                       help='Traffic pattern to generate')
    parser.add_argument('--duration', '-d',
                       type=int,
                       default=300,
                       help='Duration in seconds')
    parser.add_argument('--intensity', '-i',
                       choices=['low', 'medium', 'high'],
                       default='medium',
                       help='Traffic intensity')
    
    args = parser.parse_args()
    
    print(f"Traffic Generator - {args.pattern}")
    print(f"Duration: {args.duration}s")
    print(f"Intensity: {args.intensity}")
    print("\\nNote: This script requires an active Mininet network.")
    print("Use topology.py to create network first.")
'''

with open('sdn_ddos_protection/mininet_simulation/traffic_generator.py', 'w') as f:
    f.write(traffic_generator_content)

print("Traffic generator created successfully!")