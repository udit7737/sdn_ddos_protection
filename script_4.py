# Create the main Ryu SDN controller
ryu_controller_content = '''"""
Main Ryu SDN Controller for DDoS Protection System
Handles OpenFlow events, traffic monitoring, and attack mitigation
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub
from ryu.app.wsgi import ControllerWSGI, WSGIApplication
from ryu.app.ofctl import api as ofctl_api

import json
import time
import threading
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional

from utils.config import CONFIG
from utils.logger import controller_logger
from controller.statistics_collector import StatisticsCollector
from controller.ddos_detection import DDoSDetector
from controller.flow_manager import FlowManager

class SDNDDoSController(app_manager.RyuApp):
    """
    Main SDN Controller for DDoS Protection
    Integrates traffic monitoring, attack detection, and mitigation
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": ControllerWSGI}
    
    def __init__(self, *args, **kwargs):
        super(SDNDDoSController, self).__init__(*args, **kwargs)
        
        # Initialize components
        self.mac_to_port = {}
        self.datapaths = {}
        self.switches = {}
        self.hosts = {}
        self.links = {}
        
        # Initialize system components
        self.stats_collector = StatisticsCollector(self)
        self.ddos_detector = DDoSDetector()
        self.flow_manager = FlowManager(self)
        
        # Traffic monitoring data
        self.flow_stats = defaultdict(dict)
        self.port_stats = defaultdict(dict)
        self.packet_counts = defaultdict(int)
        self.byte_counts = defaultdict(int)
        
        # Attack detection state
        self.attack_detected = False
        self.blocked_ips = set()
        self.mitigation_rules = {}
        
        # Start monitoring threads
        self.monitor_thread = hub.spawn(self._monitor)
        self.detection_thread = hub.spawn(self._detection_loop)
        
        # Web API setup
        wsgi = kwargs["wsgi"]
        wsgi.register(SDNWebAPI, {"sdn_controller": self})
        
        controller_logger.info("SDN DDoS Controller initialized successfully")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and install default flows"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install default miss-match flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.flow_manager.add_flow(datapath, 0, match, actions)
        
        # Register switch
        self.datapaths[datapath.id] = datapath
        self.switches[datapath.id] = {
            'dpid': datapath.id,
            'connected_at': time.time(),
            'ports': {}
        }
        
        controller_logger.info(f"Switch {datapath.id} connected")
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Handle switch connection state changes"""
        datapath = ev.datapath
        
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                controller_logger.info(f"Register datapath: {datapath.id}")
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                controller_logger.info(f"Unregister datapath: {datapath.id}")
                del self.datapaths[datapath.id]
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming packets"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Extract packet information
        packet_info = self._extract_packet_info(pkt, in_port)
        
        # Update packet statistics
        self.packet_counts[datapath.id] += 1
        self.byte_counts[datapath.id] += len(msg.data)
        
        # Check if packet is part of DDoS attack
        if self._is_suspicious_packet(packet_info):
            controller_logger.warning(f"Suspicious packet detected: {packet_info}")
            # Add to detection queue
            self.ddos_detector.add_packet_sample(packet_info)
        
        # Handle the packet (learning switch functionality)
        self._handle_packet(msg, pkt, eth, in_port)
    
    def _extract_packet_info(self, pkt, in_port):
        """Extract relevant information from packet for analysis"""
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        info = {
            'timestamp': time.time(),
            'in_port': in_port,
            'src_mac': eth.src,
            'dst_mac': eth.dst,
            'eth_type': eth.ethertype
        }
        
        # Extract IP information
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            info.update({
                'src_ip': ipv4_pkt.src,
                'dst_ip': ipv4_pkt.dst,
                'protocol': ipv4_pkt.proto,
                'ttl': ipv4_pkt.ttl,
                'tos': ipv4_pkt.tos,
                'total_length': ipv4_pkt.total_length
            })
            
            # Extract TCP information
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                info.update({
                    'src_port': tcp_pkt.src_port,
                    'dst_port': tcp_pkt.dst_port,
                    'tcp_flags': tcp_pkt.bits,
                    'seq_num': tcp_pkt.seq,
                    'ack_num': tcp_pkt.ack,
                    'window_size': tcp_pkt.window_size
                })
            
            # Extract UDP information
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt:
                info.update({
                    'src_port': udp_pkt.src_port,
                    'dst_port': udp_pkt.dst_port,
                    'udp_length': udp_pkt.total_length
                })
            
            # Extract ICMP information
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt:
                info.update({
                    'icmp_type': icmp_pkt.type,
                    'icmp_code': icmp_pkt.code
                })
        
        return info
    
    def _is_suspicious_packet(self, packet_info):
        """Quick check for suspicious packet patterns"""
        # Check for known attack signatures
        if packet_info.get('protocol') == 6:  # TCP
            # SYN flood detection
            if packet_info.get('tcp_flags', 0) & 0x02:  # SYN flag
                return True
        
        elif packet_info.get('protocol') == 17:  # UDP
            # High rate UDP packets
            return True
        
        elif packet_info.get('protocol') == 1:  # ICMP
            # ICMP flood detection
            return True
        
        return False
    
    def _handle_packet(self, msg, pkt, eth, in_port):
        """Standard learning switch packet handling"""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        # Learn MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.flow_manager.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def _monitor(self):
        """Main monitoring loop"""
        while True:
            try:
                # Collect statistics from all switches
                for dp in self.datapaths.values():
                    self.stats_collector.request_stats(dp)
                
                hub.sleep(CONFIG.controller.statistics_interval)
                
            except Exception as e:
                controller_logger.error(f"Error in monitoring loop: {e}")
                hub.sleep(5)
    
    def _detection_loop(self):
        """Main detection loop"""
        while True:
            try:
                # Run DDoS detection
                attack_detected = self.ddos_detector.detect_attacks()
                
                if attack_detected and not self.attack_detected:
                    self._handle_attack_detected(attack_detected)
                elif not attack_detected and self.attack_detected:
                    self._handle_attack_cleared()
                
                hub.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                controller_logger.error(f"Error in detection loop: {e}")
                hub.sleep(5)
    
    def _handle_attack_detected(self, attack_info):
        """Handle detected DDoS attack"""
        self.attack_detected = True
        
        controller_logger.warning(
            f"DDoS attack detected: {attack_info['type']} from {attack_info['source_ip']}"
        )
        
        # Apply mitigation measures
        for dp in self.datapaths.values():
            self.flow_manager.install_mitigation_rules(dp, attack_info)
        
        # Add to blocked IPs
        if attack_info.get('source_ip'):
            self.blocked_ips.add(attack_info['source_ip'])
        
        # Log attack for audit
        from utils.logger import security_logger
        security_logger.log_attack_attempt(attack_info)
    
    def _handle_attack_cleared(self):
        """Handle attack cleared"""
        self.attack_detected = False
        controller_logger.info("DDoS attack cleared")
        
        # Schedule removal of mitigation rules
        hub.spawn_after(CONFIG.detection.mitigation_timeout, 
                       self._remove_mitigation_rules)
    
    def _remove_mitigation_rules(self):
        """Remove mitigation rules after timeout"""
        for dp in self.datapaths.values():
            self.flow_manager.remove_mitigation_rules(dp)
        
        self.blocked_ips.clear()
        controller_logger.info("Mitigation rules removed")
    
    def get_network_stats(self):
        """Get current network statistics"""
        return {
            'switches': len(self.datapaths),
            'flows': sum(len(stats) for stats in self.flow_stats.values()),
            'packets': sum(self.packet_counts.values()),
            'bytes': sum(self.byte_counts.values()),
            'attack_detected': self.attack_detected,
            'blocked_ips': list(self.blocked_ips),
            'timestamp': time.time()
        }
    
    def get_topology(self):
        """Get network topology information"""
        return {
            'switches': self.switches,
            'hosts': self.hosts,
            'links': self.links,
            'timestamp': time.time()
        }

class SDNWebAPI:
    """Web API for SDN Controller"""
    
    def __init__(self, req, link, data, **config):
        super(SDNWebAPI, self).__init__(req, link, data, **config)
        self.sdn_controller = data["sdn_controller"]
    
    def get_stats(self, req, **kwargs):
        """Get network statistics"""
        stats = self.sdn_controller.get_network_stats()
        return json.dumps(stats)
    
    def get_topology(self, req, **kwargs):
        """Get network topology"""
        topology = self.sdn_controller.get_topology()
        return json.dumps(topology)
    
    def get_attacks(self, req, **kwargs):
        """Get attack information"""
        attacks = self.sdn_controller.ddos_detector.get_attack_history()
        return json.dumps(attacks)
    
    def block_ip(self, req, **kwargs):
        """Manually block an IP address"""
        body = req.json if req.json else {}
        ip_address = body.get('ip_address')
        
        if not ip_address:
            return json.dumps({'error': 'IP address required'})
        
        # Add manual mitigation
        attack_info = {'source_ip': ip_address, 'type': 'manual_block'}
        
        for dp in self.sdn_controller.datapaths.values():
            self.sdn_controller.flow_manager.install_mitigation_rules(dp, attack_info)
        
        return json.dumps({'success': f'IP {ip_address} blocked'})

# Register API endpoints
def create_wsgi_app():
    """Create WSGI application with API endpoints"""
    app = WSGIApplication()
    app.add_route('stats', '/api/stats', SDNWebAPI.get_stats, methods=['GET'])
    app.add_route('topology', '/api/topology', SDNWebAPI.get_topology, methods=['GET'])
    app.add_route('attacks', '/api/attacks', SDNWebAPI.get_attacks, methods=['GET'])
    app.add_route('block', '/api/block', SDNWebAPI.block_ip, methods=['POST'])
    return app
'''

with open('sdn_ddos_protection/controller/ryu_controller.py', 'w') as f:
    f.write(ryu_controller_content)

print("Main Ryu Controller created successfully!")