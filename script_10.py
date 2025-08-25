# Create attack simulator for DDoS testing
attack_simulator_content = '''"""
DDoS Attack Simulator for SDN Testing
Simulates various types of DDoS attacks using hping3 and custom scripts
"""

import subprocess
import threading
import time
import random
import argparse
from typing import Dict, List, Optional
from dataclasses import dataclass

from utils.logger import simulation_logger
from utils.config import CONFIG, ATTACK_SIGNATURES

@dataclass
class AttackConfig:
    """Attack configuration parameters"""
    attack_type: str
    source_hosts: List[str]
    target_host: str
    duration: int  # seconds
    intensity: str  # low, medium, high
    protocol: str
    packet_size: int = 64
    delay: float = 0.0  # delay between packets in milliseconds
    randomize_source: bool = False
    custom_params: Dict = None

class DDoSAttackSimulator:
    """
    Simulates various DDoS attacks for testing SDN protection systems
    """
    
    def __init__(self, network):
        self.network = network
        self.active_attacks = []
        self.attack_threads = []
        
        # Attack intensity parameters
        self.intensity_params = {
            'low': {'rate': 10, 'threads': 1},
            'medium': {'rate': 100, 'threads': 3},
            'high': {'rate': 1000, 'threads': 5}
        }
        
        simulation_logger.info("DDoS Attack Simulator initialized")
    
    def launch_attack(self, config: AttackConfig) -> bool:
        """
        Launch a DDoS attack based on configuration
        
        Args:
            config: Attack configuration
            
        Returns:
            True if attack launched successfully
        """
        try:
            simulation_logger.info(
                f"Launching {config.attack_type} attack: "
                f"{len(config.source_hosts)} sources -> {config.target_host}, "
                f"duration: {config.duration}s, intensity: {config.intensity}"
            )
            
            # Choose attack method based on type
            if config.attack_type == 'syn_flood':
                return self._launch_syn_flood(config)
            elif config.attack_type == 'udp_flood':
                return self._launch_udp_flood(config)
            elif config.attack_type == 'icmp_flood':
                return self._launch_icmp_flood(config)
            elif config.attack_type == 'http_flood':
                return self._launch_http_flood(config)
            elif config.attack_type == 'volumetric':
                return self._launch_volumetric_attack(config)
            elif config.attack_type == 'port_scan':
                return self._launch_port_scan(config)
            elif config.attack_type == 'slowloris':
                return self._launch_slowloris(config)
            else:
                simulation_logger.error(f"Unknown attack type: {config.attack_type}")
                return False
                
        except Exception as e:
            simulation_logger.error(f"Error launching attack: {e}")
            return False
    
    def _launch_syn_flood(self, config: AttackConfig) -> bool:
        """Launch SYN flood attack"""
        try:
            target_ip = self._get_host_ip(config.target_host)
            if not target_ip:
                return False
            
            params = self.intensity_params[config.intensity]
            
            # Launch attack from each source host
            for source_host in config.source_hosts:
                for thread_id in range(params['threads']):
                    attack_thread = threading.Thread(
                        target=self._syn_flood_worker,
                        args=(source_host, target_ip, config, params, thread_id)
                    )
                    attack_thread.daemon = True
                    attack_thread.start()
                    self.attack_threads.append(attack_thread)
            
            # Schedule attack stop
            stop_thread = threading.Thread(
                target=self._stop_attack_after_duration,
                args=(config,)
            )
            stop_thread.daemon = True
            stop_thread.start()
            
            self.active_attacks.append(config)
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error launching SYN flood: {e}")
            return False
    
    def _syn_flood_worker(self, source_host: str, target_ip: str, 
                         config: AttackConfig, params: Dict, thread_id: int):
        """Worker thread for SYN flood attack"""
        try:
            host = self.network.net.get(source_host)
            if not host:
                simulation_logger.error(f"Host {source_host} not found")
                return
            
            # Randomize target ports
            target_ports = [80, 443, 22, 21, 25, 53, 8080, 3389]
            
            start_time = time.time()
            packet_count = 0
            
            while time.time() - start_time < config.duration:
                try:
                    port = random.choice(target_ports)
                    
                    # Use hping3 for SYN flood
                    cmd = (
                        f'hping3 -S -p {port} -c 1 --faster '
                        f'{"--rand-source" if config.randomize_source else ""} '
                        f'{target_ip} > /dev/null 2>&1'
                    )
                    
                    host.cmd(cmd)
                    packet_count += 1
                    
                    # Rate limiting
                    if params['rate'] < 1000:
                        time.sleep(1.0 / params['rate'])
                    
                except Exception as e:
                    simulation_logger.debug(f"SYN flood packet error: {e}")
            
            simulation_logger.debug(
                f"SYN flood worker {source_host}-{thread_id} sent {packet_count} packets"
            )
            
        except Exception as e:
            simulation_logger.error(f"SYN flood worker error: {e}")
    
    def _launch_udp_flood(self, config: AttackConfig) -> bool:
        """Launch UDP flood attack"""
        try:
            target_ip = self._get_host_ip(config.target_host)
            if not target_ip:
                return False
            
            params = self.intensity_params[config.intensity]
            
            for source_host in config.source_hosts:
                for thread_id in range(params['threads']):
                    attack_thread = threading.Thread(
                        target=self._udp_flood_worker,
                        args=(source_host, target_ip, config, params, thread_id)
                    )
                    attack_thread.daemon = True
                    attack_thread.start()
                    self.attack_threads.append(attack_thread)
            
            # Schedule attack stop
            stop_thread = threading.Thread(
                target=self._stop_attack_after_duration,
                args=(config,)
            )
            stop_thread.daemon = True
            stop_thread.start()
            
            self.active_attacks.append(config)
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error launching UDP flood: {e}")
            return False
    
    def _udp_flood_worker(self, source_host: str, target_ip: str, 
                         config: AttackConfig, params: Dict, thread_id: int):
        """Worker thread for UDP flood attack"""
        try:
            host = self.network.net.get(source_host)
            if not host:
                return
            
            start_time = time.time()
            packet_count = 0
            
            # Common UDP ports to target
            target_ports = [53, 123, 161, 1900, 5353, 11211]
            
            while time.time() - start_time < config.duration:
                try:
                    port = random.choice(target_ports)
                    packet_size = config.packet_size or random.randint(64, 1024)
                    
                    # Use hping3 for UDP flood
                    cmd = (
                        f'hping3 -2 -p {port} -d {packet_size} -c 1 --faster '
                        f'{"--rand-source" if config.randomize_source else ""} '
                        f'{target_ip} > /dev/null 2>&1'
                    )
                    
                    host.cmd(cmd)
                    packet_count += 1
                    
                    # Rate limiting
                    if params['rate'] < 1000:
                        time.sleep(1.0 / params['rate'])
                        
                except Exception as e:
                    simulation_logger.debug(f"UDP flood packet error: {e}")
            
            simulation_logger.debug(
                f"UDP flood worker {source_host}-{thread_id} sent {packet_count} packets"
            )
            
        except Exception as e:
            simulation_logger.error(f"UDP flood worker error: {e}")
    
    def _launch_icmp_flood(self, config: AttackConfig) -> bool:
        """Launch ICMP flood attack"""
        try:
            target_ip = self._get_host_ip(config.target_host)
            if not target_ip:
                return False
            
            params = self.intensity_params[config.intensity]
            
            for source_host in config.source_hosts:
                for thread_id in range(params['threads']):
                    attack_thread = threading.Thread(
                        target=self._icmp_flood_worker,
                        args=(source_host, target_ip, config, params, thread_id)
                    )
                    attack_thread.daemon = True
                    attack_thread.start()
                    self.attack_threads.append(attack_thread)
            
            # Schedule attack stop
            stop_thread = threading.Thread(
                target=self._stop_attack_after_duration,
                args=(config,)
            )
            stop_thread.daemon = True
            stop_thread.start()
            
            self.active_attacks.append(config)
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error launching ICMP flood: {e}")
            return False
    
    def _icmp_flood_worker(self, source_host: str, target_ip: str,
                          config: AttackConfig, params: Dict, thread_id: int):
        """Worker thread for ICMP flood attack"""
        try:
            host = self.network.net.get(source_host)
            if not host:
                return
            
            start_time = time.time()
            packet_count = 0
            
            while time.time() - start_time < config.duration:
                try:
                    packet_size = config.packet_size or random.randint(64, 1024)
                    
                    # Use hping3 for ICMP flood
                    cmd = (
                        f'hping3 -1 -d {packet_size} -c 1 --faster '
                        f'{"--rand-source" if config.randomize_source else ""} '
                        f'{target_ip} > /dev/null 2>&1'
                    )
                    
                    host.cmd(cmd)
                    packet_count += 1
                    
                    # Rate limiting
                    if params['rate'] < 1000:
                        time.sleep(1.0 / params['rate'])
                        
                except Exception as e:
                    simulation_logger.debug(f"ICMP flood packet error: {e}")
            
            simulation_logger.debug(
                f"ICMP flood worker {source_host}-{thread_id} sent {packet_count} packets"
            )
            
        except Exception as e:
            simulation_logger.error(f"ICMP flood worker error: {e}")
    
    def _launch_http_flood(self, config: AttackConfig) -> bool:
        """Launch HTTP flood attack"""
        try:
            target_ip = self._get_host_ip(config.target_host)
            if not target_ip:
                return False
            
            params = self.intensity_params[config.intensity]
            
            for source_host in config.source_hosts:
                for thread_id in range(params['threads']):
                    attack_thread = threading.Thread(
                        target=self._http_flood_worker,
                        args=(source_host, target_ip, config, params, thread_id)
                    )
                    attack_thread.daemon = True
                    attack_thread.start()
                    self.attack_threads.append(attack_thread)
            
            # Schedule attack stop
            stop_thread = threading.Thread(
                target=self._stop_attack_after_duration,
                args=(config,)
            )
            stop_thread.daemon = True
            stop_thread.start()
            
            self.active_attacks.append(config)
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error launching HTTP flood: {e}")
            return False
    
    def _http_flood_worker(self, source_host: str, target_ip: str,
                          config: AttackConfig, params: Dict, thread_id: int):
        """Worker thread for HTTP flood attack"""
        try:
            host = self.network.net.get(source_host)
            if not host:
                return
            
            start_time = time.time()
            request_count = 0
            
            # HTTP endpoints to target
            endpoints = ['/', '/index.html', '/home', '/login', '/api/data', '/search']
            
            while time.time() - start_time < config.duration:
                try:
                    endpoint = random.choice(endpoints)
                    
                    # Use curl for HTTP requests
                    cmd = (
                        f'curl -s -m 1 --max-time 1 '
                        f'http://{target_ip}{endpoint} > /dev/null 2>&1'
                    )
                    
                    host.cmd(cmd)
                    request_count += 1
                    
                    # Rate limiting
                    if params['rate'] < 100:
                        time.sleep(1.0 / params['rate'])
                        
                except Exception as e:
                    simulation_logger.debug(f"HTTP flood request error: {e}")
            
            simulation_logger.debug(
                f"HTTP flood worker {source_host}-{thread_id} sent {request_count} requests"
            )
            
        except Exception as e:
            simulation_logger.error(f"HTTP flood worker error: {e}")
    
    def _launch_port_scan(self, config: AttackConfig) -> bool:
        """Launch port scanning attack"""
        try:
            target_ip = self._get_host_ip(config.target_host)
            if not target_ip:
                return False
            
            for source_host in config.source_hosts:
                attack_thread = threading.Thread(
                    target=self._port_scan_worker,
                    args=(source_host, target_ip, config)
                )
                attack_thread.daemon = True
                attack_thread.start()
                self.attack_threads.append(attack_thread)
            
            # Schedule attack stop
            stop_thread = threading.Thread(
                target=self._stop_attack_after_duration,
                args=(config,)
            )
            stop_thread.daemon = True
            stop_thread.start()
            
            self.active_attacks.append(config)
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error launching port scan: {e}")
            return False
    
    def _port_scan_worker(self, source_host: str, target_ip: str, config: AttackConfig):
        """Worker thread for port scanning attack"""
        try:
            host = self.network.net.get(source_host)
            if not host:
                return
            
            start_time = time.time()
            scan_count = 0
            
            # Define port ranges to scan
            common_ports = list(range(1, 1024))  # Well-known ports
            random.shuffle(common_ports)
            
            while time.time() - start_time < config.duration and scan_count < len(common_ports):
                try:
                    port = common_ports[scan_count % len(common_ports)]
                    
                    # Use nmap for port scanning (if available) or hping3
                    cmd = f'hping3 -S -p {port} -c 1 {target_ip} > /dev/null 2>&1'
                    
                    host.cmd(cmd)
                    scan_count += 1
                    
                    # Small delay between scans
                    time.sleep(0.01)
                        
                except Exception as e:
                    simulation_logger.debug(f"Port scan error: {e}")
            
            simulation_logger.debug(
                f"Port scan worker {source_host} scanned {scan_count} ports"
            )
            
        except Exception as e:
            simulation_logger.error(f"Port scan worker error: {e}")
    
    def _launch_slowloris(self, config: AttackConfig) -> bool:
        """Launch Slowloris attack"""
        try:
            target_ip = self._get_host_ip(config.target_host)
            if not target_ip:
                return False
            
            for source_host in config.source_hosts:
                attack_thread = threading.Thread(
                    target=self._slowloris_worker,
                    args=(source_host, target_ip, config)
                )
                attack_thread.daemon = True
                attack_thread.start()
                self.attack_threads.append(attack_thread)
            
            # Schedule attack stop
            stop_thread = threading.Thread(
                target=self._stop_attack_after_duration,
                args=(config,)
            )
            stop_thread.daemon = True
            stop_thread.start()
            
            self.active_attacks.append(config)
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error launching Slowloris: {e}")
            return False
    
    def _slowloris_worker(self, source_host: str, target_ip: str, config: AttackConfig):
        """Worker thread for Slowloris attack"""
        try:
            host = self.network.net.get(source_host)
            if not host:
                return
            
            start_time = time.time()
            connection_count = 0
            
            # Create slow HTTP connections
            while time.time() - start_time < config.duration:
                try:
                    # Create partial HTTP request
                    cmd = (
                        f'echo "GET / HTTP/1.1\\r\\nHost: {target_ip}\\r\\n" | '
                        f'nc {target_ip} 80 &'
                    )
                    
                    host.cmd(cmd)
                    connection_count += 1
                    
                    # Create connections slowly
                    time.sleep(1)
                        
                except Exception as e:
                    simulation_logger.debug(f"Slowloris connection error: {e}")
            
            simulation_logger.debug(
                f"Slowloris worker {source_host} created {connection_count} connections"
            )
            
        except Exception as e:
            simulation_logger.error(f"Slowloris worker error: {e}")
    
    def _launch_volumetric_attack(self, config: AttackConfig) -> bool:
        """Launch generic volumetric attack"""
        try:
            # Mix of different protocols
            protocols = ['syn_flood', 'udp_flood', 'icmp_flood']
            
            for protocol in protocols:
                protocol_config = AttackConfig(
                    attack_type=protocol,
                    source_hosts=config.source_hosts,
                    target_host=config.target_host,
                    duration=config.duration,
                    intensity=config.intensity,
                    protocol=protocol
                )
                
                if protocol == 'syn_flood':
                    self._launch_syn_flood(protocol_config)
                elif protocol == 'udp_flood':
                    self._launch_udp_flood(protocol_config)
                elif protocol == 'icmp_flood':
                    self._launch_icmp_flood(protocol_config)
            
            self.active_attacks.append(config)
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error launching volumetric attack: {e}")
            return False
    
    def _get_host_ip(self, host_name: str) -> Optional[str]:
        """Get IP address of a host"""
        try:
            host = self.network.net.get(host_name)
            if host:
                return host.IP()
            else:
                simulation_logger.error(f"Host {host_name} not found")
                return None
        except Exception as e:
            simulation_logger.error(f"Error getting host IP: {e}")
            return None
    
    def _stop_attack_after_duration(self, config: AttackConfig):
        """Stop attack after specified duration"""
        time.sleep(config.duration)
        self.stop_attack(config.attack_type)
    
    def stop_attack(self, attack_type: Optional[str] = None):
        """Stop specific attack or all attacks"""
        try:
            if attack_type:
                self.active_attacks = [a for a in self.active_attacks if a.attack_type != attack_type]
                simulation_logger.info(f"Stopped {attack_type} attack")
            else:
                self.active_attacks.clear()
                simulation_logger.info("Stopped all attacks")
            
        except Exception as e:
            simulation_logger.error(f"Error stopping attack: {e}")
    
    def cleanup(self):
        """Clean up attack processes and threads"""
        try:
            # Stop all attacks
            self.stop_attack()
            
            # Kill any remaining attack processes
            for host in self.network.net.hosts:
                host.cmd('killall hping3 > /dev/null 2>&1')
                host.cmd('killall curl > /dev/null 2>&1')
                host.cmd('killall nc > /dev/null 2>&1')
            
            simulation_logger.info("Attack simulator cleanup completed")
            
        except Exception as e:
            simulation_logger.error(f"Error during cleanup: {e}")
    
    def get_active_attacks(self) -> List[Dict]:
        """Get information about active attacks"""
        return [
            {
                'type': attack.attack_type,
                'sources': attack.source_hosts,
                'target': attack.target_host,
                'duration': attack.duration,
                'intensity': attack.intensity
            }
            for attack in self.active_attacks
        ]

def create_attack_config(attack_type: str, sources: List[str], target: str,
                        duration: int = 60, intensity: str = 'medium') -> AttackConfig:
    """Helper function to create attack configuration"""
    return AttackConfig(
        attack_type=attack_type,
        source_hosts=sources,
        target_host=target,
        duration=duration,
        intensity=intensity,
        protocol='mixed'
    )

def run_attack_simulation(network, attack_scenarios: List[AttackConfig]):
    """Run multiple attack scenarios"""
    try:
        simulator = DDoSAttackSimulator(network)
        
        for i, scenario in enumerate(attack_scenarios):
            simulation_logger.info(f"Running attack scenario {i+1}/{len(attack_scenarios)}")
            
            if simulator.launch_attack(scenario):
                simulation_logger.info(f"Attack {scenario.attack_type} launched successfully")
                
                # Wait for attack to complete
                time.sleep(scenario.duration + 5)
            else:
                simulation_logger.error(f"Failed to launch attack {scenario.attack_type}")
        
        # Cleanup
        simulator.cleanup()
        
    except Exception as e:
        simulation_logger.error(f"Error running attack simulation: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DDoS Attack Simulator')
    parser.add_argument('--attack', '-a', 
                       choices=['syn_flood', 'udp_flood', 'icmp_flood', 'http_flood', 
                               'port_scan', 'slowloris', 'volumetric'],
                       required=True,
                       help='Attack type to simulate')
    parser.add_argument('--sources', '-s',
                       nargs='+',
                       default=['h1', 'h2'],
                       help='Source hosts for attack')
    parser.add_argument('--target', '-t',
                       default='h8',
                       help='Target host')
    parser.add_argument('--duration', '-d',
                       type=int,
                       default=60,
                       help='Attack duration in seconds')
    parser.add_argument('--intensity', '-i',
                       choices=['low', 'medium', 'high'],
                       default='medium',
                       help='Attack intensity')
    
    args = parser.parse_args()
    
    print(f"Attack Simulator - {args.attack}")
    print(f"Sources: {args.sources}")
    print(f"Target: {args.target}")
    print(f"Duration: {args.duration}s")
    print(f"Intensity: {args.intensity}")
    print("\\nNote: This script requires an active Mininet network.")
    print("Use topology.py to create network first.")
'''

with open('sdn_ddos_protection/mininet_simulation/attack_simulator.py', 'w') as f:
    f.write(attack_simulator_content)

print("Attack simulator created successfully!")