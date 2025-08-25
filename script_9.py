# Create Mininet topology for SDN simulation
topology_content = '''"""
Mininet Network Topology for SDN DDoS Protection Testing
Creates various network topologies for simulation and testing
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import argparse

from utils.config import CONFIG, TOPOLOGY_TEMPLATES
from utils.logger import simulation_logger

class DDoSTestTopology(Topo):
    """Custom topology for DDoS testing"""
    
    def __init__(self, topo_type="simple", **opts):
        super(DDoSTestTopology, self).__init__(**opts)
        self.topo_type = topo_type
        self.build_topology()
    
    def build_topology(self):
        """Build the network topology based on configuration"""
        if self.topo_type == "simple":
            self._build_simple_topology()
        elif self.topo_type == "tree":
            self._build_tree_topology()
        elif self.topo_type == "mesh":
            self._build_mesh_topology()
        elif self.topo_type == "datacenter":
            self._build_datacenter_topology()
        else:
            simulation_logger.warning(f"Unknown topology type: {self.topo_type}, using simple")
            self._build_simple_topology()
    
    def _build_simple_topology(self):
        """Build simple topology with one switch and multiple hosts"""
        simulation_logger.info("Building simple topology")
        
        # Add switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
        # Add hosts
        hosts = []
        for i in range(1, 9):  # 8 hosts
            host = self.addHost(f'h{i}', 
                              ip=f'10.0.0.{i}/24',
                              mac=f'00:00:00:00:00:{i:02x}')
            hosts.append(host)
            
            # Add link with bandwidth and delay constraints
            self.addLink(host, s1, 
                        bw=CONFIG.mininet.link_bandwidth,
                        delay=CONFIG.mininet.link_delay,
                        loss=0)
    
    def _build_tree_topology(self):
        """Build tree topology with multiple switches"""
        simulation_logger.info("Building tree topology")
        
        # Add root switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
        # Add leaf switches
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        
        # Connect switches
        self.addLink(s1, s2, bw=50, delay='5ms')
        self.addLink(s1, s3, bw=50, delay='5ms')
        
        # Add hosts to s2
        for i in range(1, 5):
            host = self.addHost(f'h{i}', 
                              ip=f'10.0.1.{i}/24',
                              mac=f'00:00:00:01:00:{i:02x}')
            self.addLink(host, s2, 
                        bw=CONFIG.mininet.link_bandwidth,
                        delay=CONFIG.mininet.link_delay)
        
        # Add hosts to s3
        for i in range(5, 9):
            host = self.addHost(f'h{i}', 
                              ip=f'10.0.2.{i-4}/24',
                              mac=f'00:00:00:02:00:{i-4:02x}')
            self.addLink(host, s3, 
                        bw=CONFIG.mininet.link_bandwidth,
                        delay=CONFIG.mininet.link_delay)
    
    def _build_mesh_topology(self):
        """Build mesh topology with interconnected switches"""
        simulation_logger.info("Building mesh topology")
        
        # Add switches
        switches = []
        for i in range(1, 5):  # 4 switches
            switch = self.addSwitch(f's{i}', protocols='OpenFlow13')
            switches.append(switch)
        
        # Create mesh connections between switches
        for i, s1 in enumerate(switches):
            for j, s2 in enumerate(switches[i+1:], i+1):
                self.addLink(s1, s2, bw=100, delay='2ms')
        
        # Add hosts to switches
        for i, switch in enumerate(switches):
            for j in range(1, 3):  # 2 hosts per switch
                host_id = i * 2 + j
                host = self.addHost(f'h{host_id}', 
                                  ip=f'10.0.{i+1}.{j}/24',
                                  mac=f'00:00:00:0{i+1}:00:{j:02x}')
                self.addLink(host, switch, 
                            bw=CONFIG.mininet.link_bandwidth,
                            delay=CONFIG.mininet.link_delay)
    
    def _build_datacenter_topology(self):
        """Build data center topology (Fat-Tree inspired)"""
        simulation_logger.info("Building datacenter topology")
        
        # Core switches
        core1 = self.addSwitch('c1', protocols='OpenFlow13')
        core2 = self.addSwitch('c2', protocols='OpenFlow13')
        
        # Aggregation switches
        agg1 = self.addSwitch('a1', protocols='OpenFlow13')
        agg2 = self.addSwitch('a2', protocols='OpenFlow13')
        
        # Edge switches
        edge1 = self.addSwitch('e1', protocols='OpenFlow13')
        edge2 = self.addSwitch('e2', protocols='OpenFlow13')
        edge3 = self.addSwitch('e3', protocols='OpenFlow13')
        edge4 = self.addSwitch('e4', protocols='OpenFlow13')
        
        # Core to aggregation links
        self.addLink(core1, agg1, bw=100, delay='1ms')
        self.addLink(core1, agg2, bw=100, delay='1ms')
        self.addLink(core2, agg1, bw=100, delay='1ms')
        self.addLink(core2, agg2, bw=100, delay='1ms')
        
        # Aggregation to edge links
        self.addLink(agg1, edge1, bw=50, delay='2ms')
        self.addLink(agg1, edge2, bw=50, delay='2ms')
        self.addLink(agg2, edge3, bw=50, delay='2ms')
        self.addLink(agg2, edge4, bw=50, delay='2ms')
        
        # Add hosts to edge switches
        edges = [edge1, edge2, edge3, edge4]
        for i, edge in enumerate(edges):
            for j in range(1, 3):  # 2 hosts per edge switch
                host_id = i * 2 + j
                host = self.addHost(f'h{host_id}', 
                                  ip=f'10.0.{i+1}.{j}/24',
                                  mac=f'00:00:00:0{i+1}:00:{j:02x}')
                self.addLink(host, edge, 
                            bw=CONFIG.mininet.link_bandwidth,
                            delay=CONFIG.mininet.link_delay)

class SDNNetwork:
    """SDN Network manager for testing"""
    
    def __init__(self, topology_type="simple", controller_ip="127.0.0.1", controller_port=6653):
        self.topology_type = topology_type
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.net = None
        self.topo = None
        
        simulation_logger.info(f"SDN Network initialized with {topology_type} topology")
    
    def create_network(self):
        """Create and configure the Mininet network"""
        try:
            # Create topology
            self.topo = DDoSTestTopology(topo_type=self.topology_type)
            
            # Create network with remote controller
            self.net = Mininet(
                topo=self.topo,
                controller=RemoteController('c0', ip=self.controller_ip, port=self.controller_port),
                switch=OVSSwitch,
                link=TCLink,
                autoSetMacs=True,
                autoStaticArp=True
            )
            
            simulation_logger.info("Network created successfully")
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error creating network: {e}")
            return False
    
    def start_network(self):
        """Start the Mininet network"""
        try:
            if not self.net:
                self.create_network()
            
            self.net.start()
            simulation_logger.info("Network started successfully")
            
            # Wait for switches to connect to controller
            time.sleep(5)
            
            # Test connectivity
            self.test_connectivity()
            
            return True
            
        except Exception as e:
            simulation_logger.error(f"Error starting network: {e}")
            return False
    
    def stop_network(self):
        """Stop the Mininet network"""
        try:
            if self.net:
                self.net.stop()
                simulation_logger.info("Network stopped successfully")
                return True
            
        except Exception as e:
            simulation_logger.error(f"Error stopping network: {e}")
            return False
    
    def test_connectivity(self):
        """Test basic network connectivity"""
        try:
            simulation_logger.info("Testing network connectivity...")
            
            # Get all hosts
            hosts = self.net.hosts
            
            if len(hosts) >= 2:
                # Test ping between first two hosts
                h1, h2 = hosts[0], hosts[1]
                result = self.net.ping([h1, h2], timeout='1')
                
                if result == 0:
                    simulation_logger.info("Connectivity test passed")
                else:
                    simulation_logger.warning("Connectivity test failed")
            else:
                simulation_logger.warning("Not enough hosts for connectivity test")
                
        except Exception as e:
            simulation_logger.error(f"Error testing connectivity: {e}")
    
    def get_network_info(self):
        """Get information about the network"""
        if not self.net:
            return {}
        
        info = {
            'topology_type': self.topology_type,
            'num_switches': len(self.net.switches),
            'num_hosts': len(self.net.hosts),
            'num_links': len(self.net.links),
            'switches': {},
            'hosts': {},
            'links': []
        }
        
        # Switch information
        for switch in self.net.switches:
            info['switches'][switch.name] = {
                'name': switch.name,
                'dpid': switch.dpid,
                'ports': [port.name for port in switch.ports.values()]
            }
        
        # Host information
        for host in self.net.hosts:
            info['hosts'][host.name] = {
                'name': host.name,
                'ip': host.IP(),
                'mac': host.MAC(),
                'intf': host.defaultIntf().name
            }
        
        # Link information
        for link in self.net.links:
            info['links'].append({
                'node1': link.intf1.node.name,
                'node2': link.intf2.node.name,
                'intf1': link.intf1.name,
                'intf2': link.intf2.name
            })
        
        return info
    
    def run_cli(self):
        """Run Mininet CLI for interactive testing"""
        if self.net:
            simulation_logger.info("Starting Mininet CLI...")
            CLI(self.net)
        else:
            simulation_logger.error("Network not started")
    
    def execute_command(self, host_name, command):
        """Execute command on a specific host"""
        try:
            host = self.net.get(host_name)
            if host:
                result = host.cmd(command)
                simulation_logger.debug(f"Command '{command}' on {host_name}: {result}")
                return result
            else:
                simulation_logger.error(f"Host {host_name} not found")
                return None
                
        except Exception as e:
            simulation_logger.error(f"Error executing command: {e}")
            return None
    
    def generate_background_traffic(self, duration=60):
        """Generate background traffic between hosts"""
        try:
            hosts = self.net.hosts
            if len(hosts) < 2:
                simulation_logger.warning("Not enough hosts for background traffic")
                return
            
            simulation_logger.info(f"Generating background traffic for {duration} seconds")
            
            # Start iperf servers on some hosts
            servers = hosts[:len(hosts)//2]
            clients = hosts[len(hosts)//2:]
            
            # Start servers
            for i, server in enumerate(servers):
                port = 5001 + i
                server.cmd(f'iperf -s -p {port} -D')  # Daemon mode
                simulation_logger.debug(f"Started iperf server on {server.name}:{port}")
            
            # Start clients
            for i, client in enumerate(clients):
                if i < len(servers):
                    server = servers[i]
                    port = 5001 + i
                    client.cmd(f'iperf -c {server.IP()} -p {port} -t {duration} -i 1 &')
                    simulation_logger.debug(f"Started iperf client {client.name} -> {server.name}")
            
            time.sleep(duration + 5)  # Wait for traffic to complete
            
            # Stop servers
            for server in servers:
                server.cmd('killall iperf')
            
            simulation_logger.info("Background traffic generation completed")
            
        except Exception as e:
            simulation_logger.error(f"Error generating background traffic: {e}")

def create_and_run_network(topology_type="simple", run_cli=True):
    """Create and run SDN network"""
    try:
        # Create network
        sdn_net = SDNNetwork(topology_type=topology_type)
        
        # Start network
        if not sdn_net.start_network():
            return None
        
        # Print network information
        info = sdn_net.get_network_info()
        print(f"\\nNetwork Information:")
        print(f"Topology: {info['topology_type']}")
        print(f"Switches: {info['num_switches']}")
        print(f"Hosts: {info['num_hosts']}")
        print(f"Links: {info['num_links']}")
        
        # Run CLI if requested
        if run_cli:
            sdn_net.run_cli()
        
        # Clean up
        sdn_net.stop_network()
        
        return sdn_net
        
    except Exception as e:
        simulation_logger.error(f"Error running network: {e}")
        return None

if __name__ == '__main__':
    # Set up logging
    setLogLevel('info')
    
    # Parse arguments
    parser = argparse.ArgumentParser(description='SDN DDoS Protection Network Topology')
    parser.add_argument('--topology', '-t', 
                       choices=['simple', 'tree', 'mesh', 'datacenter'],
                       default='simple',
                       help='Network topology type')
    parser.add_argument('--controller', '-c',
                       default='127.0.0.1:6653',
                       help='Controller IP:Port')
    parser.add_argument('--no-cli', 
                       action='store_true',
                       help='Don\'t start CLI')
    
    args = parser.parse_args()
    
    # Parse controller address
    controller_parts = args.controller.split(':')
    controller_ip = controller_parts[0]
    controller_port = int(controller_parts[1]) if len(controller_parts) > 1 else 6653
    
    # Create and run network
    print(f"Creating {args.topology} topology...")
    print(f"Controller: {controller_ip}:{controller_port}")
    
    sdn_net = SDNNetwork(
        topology_type=args.topology,
        controller_ip=controller_ip,
        controller_port=controller_port
    )
    
    try:
        if sdn_net.start_network():
            print("\\nNetwork started successfully!")
            print("\\nUse 'help' command in CLI for available commands")
            print("Example commands:")
            print("  pingall - Test connectivity between all hosts")
            print("  iperf h1 h2 - Test bandwidth between h1 and h2")
            print("  h1 ping -c 3 h2 - Ping from h1 to h2")
            print("  exit - Exit Mininet CLI")
            
            if not args.no_cli:
                sdn_net.run_cli()
        else:
            print("Failed to start network")
    
    finally:
        sdn_net.stop_network()
        print("\\nNetwork stopped")
'''

with open('sdn_ddos_protection/mininet_simulation/topology.py', 'w') as f:
    f.write(topology_content)

print("Network topology module created successfully!")