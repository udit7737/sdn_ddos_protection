# Create the statistics collector for gathering OpenFlow data
statistics_collector_content = '''"""
Statistics Collector for SDN DDoS Protection System
Collects flow, port, and table statistics from OpenFlow switches
"""

import time
from collections import defaultdict
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from utils.logger import controller_logger
from utils.config import CONFIG

@dataclass
class FlowStats:
    """Flow statistics data structure"""
    dpid: int
    table_id: int
    duration_sec: int
    duration_nsec: int
    priority: int
    idle_timeout: int
    hard_timeout: int
    flags: int
    cookie: int
    packet_count: int
    byte_count: int
    match: dict
    actions: list
    timestamp: float

@dataclass  
class PortStats:
    """Port statistics data structure"""
    dpid: int
    port_no: int
    rx_packets: int
    tx_packets: int
    rx_bytes: int
    tx_bytes: int
    rx_dropped: int
    tx_dropped: int
    rx_errors: int
    tx_errors: int
    rx_frame_err: int
    rx_over_err: int
    rx_crc_err: int
    collisions: int
    duration_sec: int
    duration_nsec: int
    timestamp: float

class StatisticsCollector:
    """
    Collects and manages OpenFlow statistics from switches
    Provides data for DDoS detection and network monitoring
    """
    
    def __init__(self, controller):
        self.controller = controller
        
        # Statistics storage
        self.flow_stats = defaultdict(list)
        self.port_stats = defaultdict(list)
        self.table_stats = defaultdict(dict)
        
        # Statistics history for trend analysis
        self.flow_history = defaultdict(list)
        self.port_history = defaultdict(list)
        
        # Performance metrics
        self.stats_collection_time = {}
        self.stats_requests_sent = defaultdict(int)
        self.stats_responses_received = defaultdict(int)
        
        controller_logger.info("Statistics Collector initialized")
    
    def request_stats(self, datapath):
        """Request all types of statistics from a switch"""
        try:
            # Request flow statistics
            self._request_flow_stats(datapath)
            
            # Request port statistics  
            self._request_port_stats(datapath)
            
            # Request table statistics
            self._request_table_stats(datapath)
            
            self.stats_requests_sent[datapath.id] += 3
            
        except Exception as e:
            controller_logger.error(f"Error requesting stats from {datapath.id}: {e}")
    
    def _request_flow_stats(self, datapath):
        """Request flow statistics from switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    def _request_port_stats(self, datapath):
        """Request port statistics from switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    def _request_table_stats(self, datapath):
        """Request table statistics from switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPTableStatsRequest(datapath, 0)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, 'MAIN')
    def _flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply"""
        timestamp = time.time()
        datapath = ev.msg.datapath
        dpid = datapath.id
        
        # Clear previous stats for this switch
        self.flow_stats[dpid] = []
        
        # Process each flow entry
        for stat in ev.msg.body:
            flow_stat = FlowStats(
                dpid=dpid,
                table_id=stat.table_id,
                duration_sec=stat.duration_sec,
                duration_nsec=stat.duration_nsec,
                priority=stat.priority,
                idle_timeout=stat.idle_timeout,
                hard_timeout=stat.hard_timeout,
                flags=stat.flags,
                cookie=stat.cookie,
                packet_count=stat.packet_count,
                byte_count=stat.byte_count,
                match=self._parse_match(stat.match),
                actions=self._parse_actions(stat.instructions),
                timestamp=timestamp
            )
            
            self.flow_stats[dpid].append(flow_stat)
        
        # Store in history for trend analysis
        self.flow_history[dpid].append({
            'timestamp': timestamp,
            'flow_count': len(self.flow_stats[dpid]),
            'total_packets': sum(f.packet_count for f in self.flow_stats[dpid]),
            'total_bytes': sum(f.byte_count for f in self.flow_stats[dpid])
        })
        
        # Keep only recent history (last 100 entries)
        if len(self.flow_history[dpid]) > 100:
            self.flow_history[dpid] = self.flow_history[dpid][-100:]
        
        self.stats_responses_received[dpid] += 1
        
        controller_logger.debug(
            f"Flow stats received from {dpid}: {len(self.flow_stats[dpid])} flows"
        )
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, 'MAIN')
    def _port_stats_reply_handler(self, ev):
        """Handle port statistics reply"""
        timestamp = time.time()
        datapath = ev.msg.datapath
        dpid = datapath.id
        
        # Clear previous stats for this switch
        self.port_stats[dpid] = []
        
        # Process each port
        for stat in ev.msg.body:
            if stat.port_no != 0xfffffffe:  # Skip local port
                port_stat = PortStats(
                    dpid=dpid,
                    port_no=stat.port_no,
                    rx_packets=stat.rx_packets,
                    tx_packets=stat.tx_packets,
                    rx_bytes=stat.rx_bytes,
                    tx_bytes=stat.tx_bytes,
                    rx_dropped=stat.rx_dropped,
                    tx_dropped=stat.tx_dropped,
                    rx_errors=stat.rx_errors,
                    tx_errors=stat.tx_errors,
                    rx_frame_err=stat.rx_frame_err,
                    rx_over_err=stat.rx_over_err,
                    rx_crc_err=stat.rx_crc_err,
                    collisions=stat.collisions,
                    duration_sec=stat.duration_sec,
                    duration_nsec=stat.duration_nsec,
                    timestamp=timestamp
                )
                
                self.port_stats[dpid].append(port_stat)
        
        # Store in history for trend analysis
        total_rx_packets = sum(p.rx_packets for p in self.port_stats[dpid])
        total_tx_packets = sum(p.tx_packets for p in self.port_stats[dpid])
        total_rx_bytes = sum(p.rx_bytes for p in self.port_stats[dpid])
        total_tx_bytes = sum(p.tx_bytes for p in self.port_stats[dpid])
        
        self.port_history[dpid].append({
            'timestamp': timestamp,
            'total_rx_packets': total_rx_packets,
            'total_tx_packets': total_tx_packets,
            'total_rx_bytes': total_rx_bytes,
            'total_tx_bytes': total_tx_bytes,
            'total_dropped': sum(p.rx_dropped + p.tx_dropped for p in self.port_stats[dpid]),
            'total_errors': sum(p.rx_errors + p.tx_errors for p in self.port_stats[dpid])
        })
        
        # Keep only recent history (last 100 entries)
        if len(self.port_history[dpid]) > 100:
            self.port_history[dpid] = self.port_history[dpid][-100:]
        
        self.stats_responses_received[dpid] += 1
        
        controller_logger.debug(
            f"Port stats received from {dpid}: {len(self.port_stats[dpid])} ports"
        )
    
    @set_ev_cls(ofp_event.EventOFPTableStatsReply, 'MAIN')
    def _table_stats_reply_handler(self, ev):
        """Handle table statistics reply"""
        timestamp = time.time()
        datapath = ev.msg.datapath
        dpid = datapath.id
        
        self.table_stats[dpid] = {}
        
        for stat in ev.msg.body:
            self.table_stats[dpid][stat.table_id] = {
                'table_id': stat.table_id,
                'active_count': stat.active_count,
                'lookup_count': stat.lookup_count,
                'matched_count': stat.matched_count,
                'timestamp': timestamp
            }
        
        self.stats_responses_received[dpid] += 1
        
        controller_logger.debug(f"Table stats received from {dpid}")
    
    def _parse_match(self, match):
        """Parse OpenFlow match fields into dictionary"""
        match_dict = {}
        
        for field, value in match.items():
            match_dict[field] = str(value)
        
        return match_dict
    
    def _parse_actions(self, instructions):
        """Parse OpenFlow instructions into action list"""
        actions = []
        
        for instruction in instructions:
            if hasattr(instruction, 'actions'):
                for action in instruction.actions:
                    actions.append({
                        'type': action.__class__.__name__,
                        'params': str(action)
                    })
        
        return actions
    
    def get_flow_features(self, dpid: int, time_window: int = 60) -> Dict[str, Any]:
        """
        Extract flow-based features for DDoS detection
        
        Args:
            dpid: Switch datapath ID
            time_window: Time window in seconds for feature extraction
            
        Returns:
            Dictionary containing flow features
        """
        current_time = time.time()
        recent_flows = [
            f for f in self.flow_stats.get(dpid, [])
            if current_time - f.timestamp <= time_window
        ]
        
        if not recent_flows:
            return {}
        
        # Calculate basic flow features
        features = {
            'flow_count': len(recent_flows),
            'total_packets': sum(f.packet_count for f in recent_flows),
            'total_bytes': sum(f.byte_count for f in recent_flows),
            'avg_packet_count': sum(f.packet_count for f in recent_flows) / len(recent_flows),
            'avg_byte_count': sum(f.byte_count for f in recent_flows) / len(recent_flows),
            'avg_duration': sum(f.duration_sec for f in recent_flows) / len(recent_flows),
        }
        
        # Calculate packet and byte rates
        if time_window > 0:
            features['packets_per_second'] = features['total_packets'] / time_window
            features['bytes_per_second'] = features['total_bytes'] / time_window
            features['flows_per_second'] = features['flow_count'] / time_window
        
        # Protocol distribution
        protocol_counts = defaultdict(int)
        for flow in recent_flows:
            protocol = flow.match.get('ip_proto', 'unknown')
            protocol_counts[protocol] += 1
        
        features['protocol_distribution'] = dict(protocol_counts)
        
        # Port distribution
        dst_ports = defaultdict(int)
        src_ports = defaultdict(int)
        
        for flow in recent_flows:
            if 'tcp_dst' in flow.match:
                dst_ports[flow.match['tcp_dst']] += 1
            if 'udp_dst' in flow.match:
                dst_ports[flow.match['udp_dst']] += 1
            if 'tcp_src' in flow.match:
                src_ports[flow.match['tcp_src']] += 1
            if 'udp_src' in flow.match:
                src_ports[flow.match['udp_src']] += 1
        
        features['unique_dst_ports'] = len(dst_ports)
        features['unique_src_ports'] = len(src_ports)
        
        # IP address diversity
        src_ips = set()
        dst_ips = set()
        
        for flow in recent_flows:
            if 'ipv4_src' in flow.match:
                src_ips.add(flow.match['ipv4_src'])
            if 'ipv4_dst' in flow.match:
                dst_ips.add(flow.match['ipv4_dst'])
        
        features['unique_src_ips'] = len(src_ips)
        features['unique_dst_ips'] = len(dst_ips)
        
        return features
    
    def get_port_features(self, dpid: int) -> Dict[str, Any]:
        """Extract port-based features for DDoS detection"""
        ports = self.port_stats.get(dpid, [])
        
        if not ports:
            return {}
        
        features = {
            'total_rx_packets': sum(p.rx_packets for p in ports),
            'total_tx_packets': sum(p.tx_packets for p in ports),
            'total_rx_bytes': sum(p.rx_bytes for p in ports),
            'total_tx_bytes': sum(p.tx_bytes for p in ports),
            'total_rx_dropped': sum(p.rx_dropped for p in ports),
            'total_tx_dropped': sum(p.tx_dropped for p in ports),
            'total_rx_errors': sum(p.rx_errors for p in ports),
            'total_tx_errors': sum(p.tx_errors for p in ports),
            'active_ports': len(ports)
        }
        
        return features
    
    def get_traffic_trends(self, dpid: int, time_window: int = 300) -> Dict[str, List[float]]:
        """
        Get traffic trends for a switch over time
        
        Args:
            dpid: Switch datapath ID
            time_window: Time window in seconds
            
        Returns:
            Dictionary containing trend data
        """
        current_time = time.time()
        
        # Get recent flow history
        recent_flow_history = [
            h for h in self.flow_history.get(dpid, [])
            if current_time - h['timestamp'] <= time_window
        ]
        
        # Get recent port history
        recent_port_history = [
            h for h in self.port_history.get(dpid, [])
            if current_time - h['timestamp'] <= time_window
        ]
        
        trends = {
            'timestamps': [],
            'flow_counts': [],
            'packet_rates': [],
            'byte_rates': [],
            'drop_rates': [],
            'error_rates': []
        }
        
        # Calculate flow trends
        for i, entry in enumerate(recent_flow_history):
            trends['timestamps'].append(entry['timestamp'])
            trends['flow_counts'].append(entry['flow_count'])
            
            # Calculate rates
            if i > 0:
                time_diff = entry['timestamp'] - recent_flow_history[i-1]['timestamp']
                if time_diff > 0:
                    packet_diff = entry['total_packets'] - recent_flow_history[i-1]['total_packets']
                    byte_diff = entry['total_bytes'] - recent_flow_history[i-1]['total_bytes']
                    
                    trends['packet_rates'].append(packet_diff / time_diff)
                    trends['byte_rates'].append(byte_diff / time_diff)
                else:
                    trends['packet_rates'].append(0)
                    trends['byte_rates'].append(0)
            else:
                trends['packet_rates'].append(0)
                trends['byte_rates'].append(0)
        
        # Calculate port trends
        for i, entry in enumerate(recent_port_history):
            if i > 0:
                time_diff = entry['timestamp'] - recent_port_history[i-1]['timestamp']
                if time_diff > 0:
                    drop_diff = entry['total_dropped'] - recent_port_history[i-1]['total_dropped']
                    error_diff = entry['total_errors'] - recent_port_history[i-1]['total_errors']
                    
                    trends['drop_rates'].append(drop_diff / time_diff)
                    trends['error_rates'].append(error_diff / time_diff)
                else:
                    trends['drop_rates'].append(0)
                    trends['error_rates'].append(0)
            else:
                trends['drop_rates'].append(0)
                trends['error_rates'].append(0)
        
        return trends
    
    def get_statistics_summary(self) -> Dict[str, Any]:
        """Get summary of all collected statistics"""
        summary = {
            'switches_monitored': len(self.flow_stats),
            'total_flows': sum(len(flows) for flows in self.flow_stats.values()),
            'total_requests_sent': sum(self.stats_requests_sent.values()),
            'total_responses_received': sum(self.stats_responses_received.values()),
            'collection_success_rate': 0.0,
            'switch_details': {}
        }
        
        # Calculate success rate
        total_requests = sum(self.stats_requests_sent.values())
        if total_requests > 0:
            summary['collection_success_rate'] = (
                sum(self.stats_responses_received.values()) / total_requests
            ) * 100
        
        # Per-switch details
        for dpid in self.flow_stats:
            summary['switch_details'][dpid] = {
                'flows': len(self.flow_stats.get(dpid, [])),
                'ports': len(self.port_stats.get(dpid, [])),
                'requests_sent': self.stats_requests_sent[dpid],
                'responses_received': self.stats_responses_received[dpid]
            }
        
        return summary
'''

with open('sdn_ddos_protection/controller/statistics_collector.py', 'w') as f:
    f.write(statistics_collector_content)

print("Statistics Collector created successfully!")