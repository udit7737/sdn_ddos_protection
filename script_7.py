# Create the feature extractor for ML models
feature_extractor_content = '''"""
Feature Extractor for DDoS Detection
Processes network traffic data into meaningful features for machine learning models
"""

import numpy as np
import pandas as pd
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import math

from utils.logger import ml_logger
from utils.config import CONFIG

class FeatureExtractor:
    """
    Extracts features from network traffic data for DDoS detection
    """
    
    def __init__(self):
        self.feature_cache = {}
        self.temporal_windows = [5, 10, 30, 60]  # seconds
        ml_logger.info("Feature Extractor initialized")
    
    def extract_features(self, packets: List[Dict], flows: List[Dict]) -> Dict[str, Any]:
        """
        Extract comprehensive features from packet and flow data
        
        Args:
            packets: List of packet information dictionaries
            flows: List of flow information dictionaries
            
        Returns:
            Dictionary containing extracted features
        """
        features = {}
        
        try:
            # Basic traffic features
            features.update(self._extract_basic_features(packets))
            
            # Protocol-based features
            features.update(self._extract_protocol_features(packets))
            
            # Statistical features
            features.update(self._extract_statistical_features(packets))
            
            # Temporal features
            features.update(self._extract_temporal_features(packets))
            
            # Network diversity features
            features.update(self._extract_diversity_features(packets))
            
            # Flow-based features
            features.update(self._extract_flow_features(flows))
            
            # Behavioral features
            features.update(self._extract_behavioral_features(packets))
            
            # Entropy-based features
            features.update(self._extract_entropy_features(packets))
            
            ml_logger.debug(f"Extracted {len(features)} features from {len(packets)} packets")
            
        except Exception as e:
            ml_logger.error(f"Error extracting features: {e}")
        
        return features
    
    def _extract_basic_features(self, packets: List[Dict]) -> Dict[str, Any]:
        """Extract basic traffic volume features"""
        if not packets:
            return {}
        
        features = {}
        
        # Basic counts
        features['packet_count'] = len(packets)
        features['byte_count'] = sum(p.get('total_length', 64) for p in packets)
        features['avg_packet_size'] = features['byte_count'] / features['packet_count']
        
        # Time span
        timestamps = [p.get('timestamp', 0) for p in packets if p.get('timestamp')]
        if timestamps:
            time_span = max(timestamps) - min(timestamps)
            features['time_span'] = max(time_span, 1.0)  # Avoid division by zero
            
            # Rate calculations
            features['packets_per_second'] = features['packet_count'] / features['time_span']
            features['bytes_per_second'] = features['byte_count'] / features['time_span']
        else:
            features['time_span'] = 1.0
            features['packets_per_second'] = 0.0
            features['bytes_per_second'] = 0.0
        
        # Packet size distribution
        packet_sizes = [p.get('total_length', 64) for p in packets]
        features['packet_size_min'] = min(packet_sizes) if packet_sizes else 0
        features['packet_size_max'] = max(packet_sizes) if packet_sizes else 0
        features['packet_size_std'] = np.std(packet_sizes) if packet_sizes else 0
        features['packet_size_variance'] = np.var(packet_sizes) if packet_sizes else 0
        
        return features
    
    def _extract_protocol_features(self, packets: List[Dict]) -> Dict[str, Any]:
        """Extract protocol distribution features"""
        features = {}
        
        if not packets:
            return features
        
        # Protocol counts
        protocol_counts = Counter()
        tcp_flags = Counter()
        port_counts = defaultdict(int)
        
        for packet in packets:
            protocol = packet.get('protocol', 0)
            protocol_counts[protocol] += 1
            
            # TCP-specific features
            if protocol == 6:  # TCP
                flags = packet.get('tcp_flags', 0)
                if flags & 0x02:  # SYN
                    tcp_flags['syn'] += 1
                if flags & 0x10:  # ACK
                    tcp_flags['ack'] += 1
                if flags & 0x01:  # FIN
                    tcp_flags['fin'] += 1
                if flags & 0x04:  # RST
                    tcp_flags['rst'] += 1
                
                # Port information
                src_port = packet.get('src_port', 0)
                dst_port = packet.get('dst_port', 0)
                port_counts[dst_port] += 1
        
        total_packets = len(packets)
        
        # Protocol ratios
        features['tcp_ratio'] = protocol_counts.get(6, 0) / total_packets
        features['udp_ratio'] = protocol_counts.get(17, 0) / total_packets
        features['icmp_ratio'] = protocol_counts.get(1, 0) / total_packets
        features['other_protocol_ratio'] = (total_packets - protocol_counts.get(6, 0) - 
                                          protocol_counts.get(17, 0) - protocol_counts.get(1, 0)) / total_packets
        
        # TCP flag ratios
        tcp_total = protocol_counts.get(6, 1)  # Avoid division by zero
        features['syn_ratio'] = tcp_flags.get('syn', 0) / tcp_total
        features['ack_ratio'] = tcp_flags.get('ack', 0) / tcp_total
        features['fin_ratio'] = tcp_flags.get('fin', 0) / tcp_total
        features['rst_ratio'] = tcp_flags.get('rst', 0) / tcp_total
        
        # Port distribution
        features['unique_dst_ports'] = len(set(p.get('dst_port', 0) for p in packets 
                                              if p.get('dst_port')))
        features['unique_src_ports'] = len(set(p.get('src_port', 0) for p in packets 
                                              if p.get('src_port')))
        
        # Well-known port ratios
        well_known_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
        well_known_count = sum(1 for p in packets if p.get('dst_port', 0) in well_known_ports)
        features['well_known_port_ratio'] = well_known_count / total_packets
        
        return features
    
    def _extract_statistical_features(self, packets: List[Dict]) -> Dict[str, Any]:
        """Extract statistical features from traffic patterns"""
        features = {}
        
        if len(packets) < 2:
            return features
        
        # Inter-arrival times
        timestamps = sorted([p.get('timestamp', 0) for p in packets if p.get('timestamp')])
        if len(timestamps) > 1:
            inter_arrivals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            features['inter_arrival_mean'] = np.mean(inter_arrivals)
            features['inter_arrival_std'] = np.std(inter_arrivals)
            features['inter_arrival_variance'] = np.var(inter_arrivals)
            features['inter_arrival_min'] = min(inter_arrivals)
            features['inter_arrival_max'] = max(inter_arrivals)
            
            # Coefficient of variation
            if features['inter_arrival_mean'] > 0:
                features['inter_arrival_cv'] = features['inter_arrival_std'] / features['inter_arrival_mean']
            else:
                features['inter_arrival_cv'] = 0
        
        # Packet size statistics
        sizes = [p.get('total_length', 64) for p in packets]
        if sizes:
            features['size_mean'] = np.mean(sizes)
            features['size_median'] = np.median(sizes)
            features['size_std'] = np.std(sizes)
            features['size_skew'] = self._calculate_skewness(sizes)
            features['size_kurtosis'] = self._calculate_kurtosis(sizes)
        
        # TTL statistics (for IP spoofing detection)
        ttls = [p.get('ttl', 64) for p in packets if p.get('ttl')]
        if ttls:
            features['ttl_mean'] = np.mean(ttls)
            features['ttl_std'] = np.std(ttls)
            features['ttl_unique_count'] = len(set(ttls))
        
        return features
    
    def _extract_temporal_features(self, packets: List[Dict]) -> Dict[str, Any]:
        """Extract temporal pattern features"""
        features = {}
        
        timestamps = [p.get('timestamp', 0) for p in packets if p.get('timestamp')]
        if not timestamps:
            return features
        
        # Sort timestamps
        timestamps.sort()
        current_time = max(timestamps)
        
        # Traffic volume in different time windows
        for window in self.temporal_windows:
            window_start = current_time - window
            window_packets = [t for t in timestamps if t >= window_start]
            
            features[f'packets_last_{window}s'] = len(window_packets)
            features[f'rate_last_{window}s'] = len(window_packets) / window
        
        # Burst detection
        if len(timestamps) > 10:
            # Calculate packet inter-arrival times
            inter_arrivals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            # Detect bursts (inter-arrival time < 0.1s)
            burst_threshold = 0.1
            burst_packets = sum(1 for ia in inter_arrivals if ia < burst_threshold)
            features['burst_ratio'] = burst_packets / len(inter_arrivals)
        
        return features
    
    def _extract_diversity_features(self, packets: List[Dict]) -> Dict[str, Any]:
        """Extract network diversity features"""
        features = {}
        
        if not packets:
            return features
        
        # IP address diversity
        src_ips = [p.get('src_ip', '') for p in packets if p.get('src_ip')]
        dst_ips = [p.get('dst_ip', '') for p in packets if p.get('dst_ip')]
        
        features['unique_src_ips'] = len(set(src_ips))
        features['unique_dst_ips'] = len(set(dst_ips))
        
        # Source IP concentration
        if src_ips:
            src_ip_counts = Counter(src_ips)
            most_common_src = src_ip_counts.most_common(1)[0][1]
            features['src_ip_concentration'] = most_common_src / len(src_ips)
        
        # Destination IP concentration
        if dst_ips:
            dst_ip_counts = Counter(dst_ips)
            most_common_dst = dst_ip_counts.most_common(1)[0][1]
            features['dst_ip_concentration'] = most_common_dst / len(dst_ips)
        
        # MAC address diversity
        src_macs = [p.get('src_mac', '') for p in packets if p.get('src_mac')]
        dst_macs = [p.get('dst_mac', '') for p in packets if p.get('dst_mac')]
        
        features['unique_src_macs'] = len(set(src_macs))
        features['unique_dst_macs'] = len(set(dst_macs))
        
        # Port diversity
        src_ports = [p.get('src_port', 0) for p in packets if p.get('src_port')]
        dst_ports = [p.get('dst_port', 0) for p in packets if p.get('dst_port')]
        
        features['port_diversity_src'] = len(set(src_ports)) / max(len(src_ports), 1)
        features['port_diversity_dst'] = len(set(dst_ports)) / max(len(dst_ports), 1)
        
        return features
    
    def _extract_flow_features(self, flows: List[Dict]) -> Dict[str, Any]:
        """Extract flow-based features"""
        features = {}
        
        if not flows:
            return features
        
        features['flow_count'] = len(flows)
        
        # Flow duration statistics
        durations = [f.get('duration', 0) for f in flows]
        if durations:
            features['flow_duration_mean'] = np.mean(durations)
            features['flow_duration_std'] = np.std(durations)
            features['flow_duration_max'] = max(durations)
            features['flow_duration_min'] = min(durations)
        
        # Flows per second
        timestamps = [f.get('timestamp', 0) for f in flows if f.get('timestamp')]
        if timestamps and len(timestamps) > 1:
            time_span = max(timestamps) - min(timestamps)
            features['flows_per_second'] = len(flows) / max(time_span, 1.0)
        else:
            features['flows_per_second'] = 0.0
        
        # Flow size distribution
        flow_packets = [f.get('packet_count', 1) for f in flows]
        flow_bytes = [f.get('byte_count', 64) for f in flows]
        
        if flow_packets:
            features['avg_packets_per_flow'] = np.mean(flow_packets)
            features['avg_bytes_per_flow'] = np.mean(flow_bytes)
        
        return features
    
    def _extract_behavioral_features(self, packets: List[Dict]) -> Dict[str, Any]:
        """Extract behavioral pattern features"""
        features = {}
        
        if not packets:
            return features
        
        # Port scanning behavior
        features['port_scan_score'] = self._calculate_port_scan_score(packets)
        
        # Connection patterns
        connections = defaultdict(set)
        for packet in packets:
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            dst_port = packet.get('dst_port', 0)
            
            if src_ip and dst_ip:
                connections[src_ip].add((dst_ip, dst_port))
        
        # Calculate connection diversity
        if connections:
            connection_counts = [len(targets) for targets in connections.values()]
            features['max_connections_per_src'] = max(connection_counts)
            features['avg_connections_per_src'] = np.mean(connection_counts)
        
        # Scanning behavior detection
        features['potential_scanners'] = sum(1 for count in connection_counts 
                                           if count > 10) if 'connection_counts' in locals() else 0
        
        return features
    
    def _extract_entropy_features(self, packets: List[Dict]) -> Dict[str, Any]:
        """Extract entropy-based features for randomness detection"""
        features = {}
        
        if not packets:
            return features
        
        # Source IP entropy
        src_ips = [p.get('src_ip', '') for p in packets if p.get('src_ip')]
        features['entropy_src_ip'] = self._calculate_entropy(src_ips)
        
        # Destination IP entropy
        dst_ips = [p.get('dst_ip', '') for p in packets if p.get('dst_ip')]
        features['entropy_dst_ip'] = self._calculate_entropy(dst_ips)
        
        # Source port entropy
        src_ports = [p.get('src_port', 0) for p in packets if p.get('src_port')]
        features['entropy_src_port'] = self._calculate_entropy(src_ports)
        
        # Destination port entropy
        dst_ports = [p.get('dst_port', 0) for p in packets if p.get('dst_port')]
        features['entropy_dst_port'] = self._calculate_entropy(dst_ports)
        
        # Packet size entropy
        sizes = [p.get('total_length', 64) for p in packets]
        features['entropy_packet_size'] = self._calculate_entropy(sizes)
        
        return features
    
    def _calculate_port_scan_score(self, packets: List[Dict]) -> float:
        """Calculate port scanning score"""
        try:
            # Group packets by source IP
            src_connections = defaultdict(set)
            
            for packet in packets:
                src_ip = packet.get('src_ip', '')
                dst_ip = packet.get('dst_ip', '')
                dst_port = packet.get('dst_port', 0)
                
                if src_ip and dst_ip and dst_port:
                    src_connections[src_ip].add((dst_ip, dst_port))
            
            if not src_connections:
                return 0.0
            
            # Calculate scanning behavior
            max_targets = max(len(targets) for targets in src_connections.values())
            
            # Port scan indicators:
            # - High number of unique destination ports
            # - Multiple destination IPs
            # - Few packets per connection
            
            scan_scores = []
            for src_ip, targets in src_connections.items():
                unique_ports = len(set(port for _, port in targets))
                unique_ips = len(set(ip for ip, _ in targets))
                
                # Normalize by total targets
                port_diversity = unique_ports / len(targets) if targets else 0
                ip_diversity = unique_ips / len(targets) if targets else 0
                
                # Scanning score based on diversity and volume
                score = (port_diversity + ip_diversity) * (len(targets) / 100)
                scan_scores.append(min(score, 1.0))  # Cap at 1.0
            
            return max(scan_scores) if scan_scores else 0.0
            
        except Exception as e:
            ml_logger.error(f"Error calculating port scan score: {e}")
            return 0.0
    
    def _calculate_entropy(self, values: List[Any]) -> float:
        """Calculate Shannon entropy of a list of values"""
        try:
            if not values:
                return 0.0
            
            # Count occurrences
            counts = Counter(values)
            total = len(values)
            
            # Calculate entropy
            entropy = 0.0
            for count in counts.values():
                probability = count / total
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            ml_logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    def _calculate_skewness(self, values: List[float]) -> float:
        """Calculate skewness of a distribution"""
        try:
            if len(values) < 3:
                return 0.0
            
            mean = np.mean(values)
            std = np.std(values)
            
            if std == 0:
                return 0.0
            
            skewness = np.mean([((x - mean) / std) ** 3 for x in values])
            return skewness
            
        except Exception:
            return 0.0
    
    def _calculate_kurtosis(self, values: List[float]) -> float:
        """Calculate kurtosis of a distribution"""
        try:
            if len(values) < 4:
                return 0.0
            
            mean = np.mean(values)
            std = np.std(values)
            
            if std == 0:
                return 0.0
            
            kurtosis = np.mean([((x - mean) / std) ** 4 for x in values]) - 3
            return kurtosis
            
        except Exception:
            return 0.0
    
    def get_feature_importance(self, model, feature_names: List[str]) -> Dict[str, float]:
        """Get feature importance from trained model"""
        try:
            if hasattr(model, 'feature_importances_'):
                importance_dict = dict(zip(feature_names, model.feature_importances_))
                # Sort by importance
                return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
            else:
                return {}
        except Exception as e:
            ml_logger.error(f"Error calculating feature importance: {e}")
            return {}
    
    def select_top_features(self, features: Dict[str, Any], top_n: int = 20) -> Dict[str, Any]:
        """Select top N most important features"""
        # This is a simplified feature selection based on variance
        # In practice, you might use more sophisticated methods
        
        numeric_features = {k: v for k, v in features.items() 
                          if isinstance(v, (int, float)) and not math.isnan(v)}
        
        if len(numeric_features) <= top_n:
            return numeric_features
        
        # Sort by absolute value (simple heuristic)
        sorted_features = sorted(numeric_features.items(), 
                               key=lambda x: abs(x[1]), reverse=True)
        
        return dict(sorted_features[:top_n])
'''

with open('sdn_ddos_protection/ml_models/feature_extractor.py', 'w') as f:
    f.write(feature_extractor_content)

print("Feature Extractor created successfully!")