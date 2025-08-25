# Create the configuration file
config_content = '''"""
Configuration file for SDN DDoS Protection System
Contains all system settings and parameters
"""

import os
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class ControllerConfig:
    """Configuration for Ryu SDN Controller"""
    controller_host: str = "127.0.0.1"
    controller_port: int = 6653
    web_api_host: str = "127.0.0.1"
    web_api_port: int = 8080
    openflow_version: str = "1.3"
    statistics_interval: int = 10  # seconds
    
@dataclass
class MLConfig:
    """Configuration for Machine Learning models"""
    # Feature extraction parameters
    flow_timeout: int = 60  # seconds
    feature_window: int = 30  # seconds
    
    # ML model parameters
    svm_kernel: str = "rbf"
    svm_gamma: str = "scale"
    svm_c: float = 1.0
    
    rf_n_estimators: int = 100
    rf_max_depth: int = 10
    rf_random_state: int = 42
    
    kmeans_n_clusters: int = 2
    kmeans_random_state: int = 42
    
    # Model training parameters
    test_size: float = 0.2
    cross_validation_folds: int = 5
    model_save_path: str = "ml_models/models/"
    
@dataclass 
class DetectionConfig:
    """Configuration for DDoS detection"""
    # Detection thresholds
    packet_rate_threshold: int = 1000  # packets per second
    byte_rate_threshold: int = 1000000  # bytes per second (1MB)
    flow_rate_threshold: int = 100  # new flows per second
    
    # Anomaly detection thresholds
    anomaly_threshold: float = 0.7
    consecutive_anomalies: int = 3
    
    # Mitigation parameters
    mitigation_timeout: int = 300  # seconds
    block_duration: int = 600  # seconds
    
@dataclass
class DashboardConfig:
    """Configuration for Web Dashboard"""
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5000
    debug_mode: bool = True
    secret_key: str = "your-secret-key-here"
    
@dataclass
class DatabaseConfig:
    """Configuration for Database"""
    db_type: str = "sqlite"
    db_path: str = "data/ddos_protection.db"
    mongo_host: str = "localhost"
    mongo_port: int = 27017
    mongo_db: str = "sdn_ddos"
    
@dataclass
class MinnetConfig:
    """Configuration for Mininet simulation"""
    topology_type: str = "tree"
    num_hosts: int = 8
    num_switches: int = 3
    link_bandwidth: int = 10  # Mbps
    link_delay: str = "10ms"
    
    # Attack simulation parameters
    attack_types: List[str] = None
    attack_duration: int = 60  # seconds
    attack_intensity: str = "medium"  # low, medium, high
    
    def __post_init__(self):
        if self.attack_types is None:
            self.attack_types = ["syn_flood", "udp_flood", "icmp_flood"]

@dataclass
class SystemConfig:
    """Main system configuration"""
    controller: ControllerConfig = ControllerConfig()
    ml: MLConfig = MLConfig()
    detection: DetectionConfig = DetectionConfig()
    dashboard: DashboardConfig = DashboardConfig()
    database: DatabaseConfig = DatabaseConfig()
    mininet: MinnetConfig = MinnetConfig()
    
    # Logging configuration
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_file: str = "logs/sdn_ddos.log"
    
    # System paths
    project_root: str = os.path.dirname(os.path.abspath(__file__))
    data_dir: str = "data"
    logs_dir: str = "logs"
    
    def __post_init__(self):
        """Create necessary directories"""
        for directory in [self.data_dir, self.logs_dir, self.ml.model_save_path]:
            os.makedirs(directory, exist_ok=True)

# Global configuration instance
CONFIG = SystemConfig()

# Network topology templates
TOPOLOGY_TEMPLATES = {
    "simple": {
        "switches": 1,
        "hosts": 4,
        "links": [("s1", "h1"), ("s1", "h2"), ("s1", "h3"), ("s1", "h4")]
    },
    "tree": {
        "switches": 3,
        "hosts": 8, 
        "links": [
            ("s1", "s2"), ("s1", "s3"),
            ("s2", "h1"), ("s2", "h2"), ("s2", "h3"), ("s2", "h4"),
            ("s3", "h5"), ("s3", "h6"), ("s3", "h7"), ("s3", "h8")
        ]
    },
    "mesh": {
        "switches": 4,
        "hosts": 8,
        "links": [
            ("s1", "s2"), ("s1", "s3"), ("s1", "s4"),
            ("s2", "s3"), ("s2", "s4"), ("s3", "s4"),
            ("s1", "h1"), ("s1", "h2"), ("s2", "h3"), ("s2", "h4"),
            ("s3", "h5"), ("s3", "h6"), ("s4", "h7"), ("s4", "h8")
        ]
    }
}

# ML feature definitions
FEATURE_DEFINITIONS = {
    "flow_features": [
        "duration", "protocol_type", "packet_count", "byte_count",
        "src_port", "dst_port", "flags", "packet_size_avg",
        "packet_size_std", "inter_arrival_time_avg", "inter_arrival_time_std"
    ],
    "port_features": [
        "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
        "rx_dropped", "tx_dropped", "rx_errors", "tx_errors",
        "rx_frame_err", "rx_over_err", "rx_crc_err", "collisions"
    ],
    "switch_features": [
        "flow_count", "packet_count", "byte_count", "duration_avg",
        "flows_per_second", "packets_per_second", "bytes_per_second"
    ]
}

# Attack signatures and patterns
ATTACK_SIGNATURES = {
    "syn_flood": {
        "protocol": "TCP",
        "flags": ["SYN"],
        "packet_size_range": (40, 60),
        "rate_threshold": 1000,
        "pattern": "high_syn_rate"
    },
    "udp_flood": {
        "protocol": "UDP", 
        "packet_size_range": (64, 1500),
        "rate_threshold": 5000,
        "pattern": "high_udp_rate"
    },
    "icmp_flood": {
        "protocol": "ICMP",
        "packet_size_range": (64, 1024),
        "rate_threshold": 2000,
        "pattern": "high_icmp_rate"  
    },
    "http_flood": {
        "protocol": "TCP",
        "dst_port": [80, 443, 8080],
        "rate_threshold": 500,
        "pattern": "high_http_rate"
    }
}
'''

with open('sdn_ddos_protection/utils/config.py', 'w') as f:
    f.write(config_content)

print("Configuration file created successfully!")