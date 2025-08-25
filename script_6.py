# Create the DDoS detection module with machine learning
ddos_detection_content = '''"""
DDoS Detection Module for SDN Protection System
Uses machine learning algorithms to detect distributed denial of service attacks
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple
import pickle
import os
import time

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from utils.logger import ml_logger
from utils.config import CONFIG, ATTACK_SIGNATURES
from ml_models.feature_extractor import FeatureExtractor

class DDoSDetector:
    """
    Main DDoS detection engine using multiple ML algorithms
    """
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        
        # ML models
        self.models = {
            'random_forest': None,
            'svm': None,
            'isolation_forest': None,
            'kmeans': None
        }
        
        # Scalers for feature normalization
        self.scalers = {
            'standard': StandardScaler(),
            'minmax': MinMaxScaler()
        }
        
        # Detection state
        self.packet_buffer = deque(maxlen=10000)
        self.flow_buffer = deque(maxlen=1000)
        self.attack_history = []
        self.current_features = {}
        
        # Thresholds and parameters
        self.detection_threshold = CONFIG.detection.anomaly_threshold
        self.consecutive_anomalies = CONFIG.detection.consecutive_anomalies
        self.anomaly_counter = defaultdict(int)
        
        # Initialize models
        self._initialize_models()
        
        ml_logger.info("DDoS Detector initialized")
    
    def _initialize_models(self):
        """Initialize all ML models with default parameters"""
        try:
            # Random Forest for supervised learning (if training data available)
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=CONFIG.ml.rf_n_estimators,
                max_depth=CONFIG.ml.rf_max_depth,
                random_state=CONFIG.ml.rf_random_state,
                n_jobs=-1
            )
            
            # One-Class SVM for anomaly detection
            self.models['svm'] = OneClassSVM(
                kernel=CONFIG.ml.svm_kernel,
                gamma=CONFIG.ml.svm_gamma,
                nu=0.1  # Expected fraction of outliers
            )
            
            # Isolation Forest for anomaly detection
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1,  # Expected fraction of outliers
                random_state=CONFIG.ml.rf_random_state,
                n_jobs=-1
            )
            
            # K-Means for clustering-based detection
            self.models['kmeans'] = KMeans(
                n_clusters=CONFIG.ml.kmeans_n_clusters,
                random_state=CONFIG.ml.kmeans_random_state,
                n_init=10
            )
            
            ml_logger.info("ML models initialized successfully")
            
        except Exception as e:
            ml_logger.error(f"Error initializing ML models: {e}")
    
    def add_packet_sample(self, packet_info: Dict[str, Any]):
        """Add packet sample to detection buffer"""
        packet_info['timestamp'] = time.time()
        self.packet_buffer.append(packet_info)
        
        # Extract features if buffer is full enough
        if len(self.packet_buffer) >= 100:
            self._update_features()
    
    def add_flow_sample(self, flow_info: Dict[str, Any]):
        """Add flow sample to detection buffer"""
        flow_info['timestamp'] = time.time()
        self.flow_buffer.append(flow_info)
    
    def _update_features(self):
        """Update current features from packet and flow buffers"""
        try:
            # Convert recent packets to DataFrame
            recent_packets = list(self.packet_buffer)[-500:]  # Last 500 packets
            
            if not recent_packets:
                return
            
            # Extract features
            self.current_features = self.feature_extractor.extract_features(
                recent_packets, list(self.flow_buffer)
            )
            
        except Exception as e:
            ml_logger.error(f"Error updating features: {e}")
    
    def detect_attacks(self) -> Optional[Dict[str, Any]]:
        """
        Main detection method using ensemble of ML algorithms
        
        Returns:
            Attack information if detected, None otherwise
        """
        if not self.current_features:
            return None
        
        try:
            # Prepare feature vector
            feature_vector = self._prepare_feature_vector(self.current_features)
            
            if feature_vector is None:
                return None
            
            # Run ensemble detection
            detection_results = self._run_ensemble_detection(feature_vector)
            
            # Rule-based detection
            rule_based_result = self._rule_based_detection(self.current_features)
            
            # Combine results
            attack_detected = self._combine_detection_results(
                detection_results, rule_based_result
            )
            
            if attack_detected:
                attack_info = self._analyze_attack(self.current_features)
                self._log_attack(attack_info)
                return attack_info
            
            return None
            
        except Exception as e:
            ml_logger.error(f"Error in attack detection: {e}")
            return None
    
    def _prepare_feature_vector(self, features: Dict[str, Any]) -> Optional[np.ndarray]:
        """Prepare feature vector for ML models"""
        try:
            # Define feature order for consistent vector creation
            feature_names = [
                'packet_count', 'byte_count', 'flow_count', 'avg_packet_size',
                'packets_per_second', 'bytes_per_second', 'flows_per_second',
                'unique_src_ips', 'unique_dst_ips', 'unique_src_ports', 'unique_dst_ports',
                'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'syn_ratio', 'ack_ratio',
                'packet_size_variance', 'inter_arrival_variance', 'port_scan_score',
                'entropy_src_ip', 'entropy_dst_ip'
            ]
            
            vector = []
            for feature_name in feature_names:
                value = features.get(feature_name, 0)
                # Handle non-numeric values
                if isinstance(value, (int, float)):
                    vector.append(float(value))
                else:
                    vector.append(0.0)
            
            if len(vector) != len(feature_names):
                ml_logger.warning(f"Feature vector size mismatch: {len(vector)} vs {len(feature_names)}")
                return None
            
            return np.array(vector).reshape(1, -1)
            
        except Exception as e:
            ml_logger.error(f"Error preparing feature vector: {e}")
            return None
    
    def _run_ensemble_detection(self, feature_vector: np.ndarray) -> Dict[str, bool]:
        """Run ensemble of ML models for detection"""
        results = {}
        
        try:
            # Normalize features
            normalized_features = self.scalers['standard'].fit_transform(feature_vector)
            
            # One-Class SVM detection
            if self.models['svm'] is not None:
                try:
                    # Fit model with recent normal samples (unsupervised)
                    self.models['svm'].fit(normalized_features)
                    svm_prediction = self.models['svm'].predict(normalized_features)[0]
                    results['svm'] = svm_prediction == -1  # -1 indicates anomaly
                except:
                    results['svm'] = False
            
            # Isolation Forest detection
            if self.models['isolation_forest'] is not None:
                try:
                    self.models['isolation_forest'].fit(normalized_features)
                    iso_prediction = self.models['isolation_forest'].predict(normalized_features)[0]
                    results['isolation_forest'] = iso_prediction == -1  # -1 indicates anomaly
                except:
                    results['isolation_forest'] = False
            
            # K-Means clustering detection
            if self.models['kmeans'] is not None:
                try:
                    self.models['kmeans'].fit(normalized_features)
                    cluster_center = self.models['kmeans'].cluster_centers_[0]
                    distance = np.linalg.norm(normalized_features[0] - cluster_center)
                    results['kmeans'] = distance > 2.0  # Threshold for anomaly
                except:
                    results['kmeans'] = False
            
            # Random Forest (if trained)
            if self.models['random_forest'] is not None:
                try:
                    # This would require pre-trained model with labeled data
                    # For now, skip or use unsupervised approach
                    results['random_forest'] = False
                except:
                    results['random_forest'] = False
            
        except Exception as e:
            ml_logger.error(f"Error in ensemble detection: {e}")
        
        return results
    
    def _rule_based_detection(self, features: Dict[str, Any]) -> Dict[str, bool]:
        """Rule-based detection using statistical thresholds"""
        results = {}
        
        try:
            # High packet rate detection
            pps = features.get('packets_per_second', 0)
            results['high_packet_rate'] = pps > CONFIG.detection.packet_rate_threshold
            
            # High byte rate detection
            bps = features.get('bytes_per_second', 0)
            results['high_byte_rate'] = bps > CONFIG.detection.byte_rate_threshold
            
            # High flow rate detection
            fps = features.get('flows_per_second', 0)
            results['high_flow_rate'] = fps > CONFIG.detection.flow_rate_threshold
            
            # SYN flood detection
            syn_ratio = features.get('syn_ratio', 0)
            results['syn_flood'] = syn_ratio > 0.7 and pps > 500
            
            # UDP flood detection
            udp_ratio = features.get('udp_ratio', 0)
            results['udp_flood'] = udp_ratio > 0.8 and pps > 1000
            
            # ICMP flood detection
            icmp_ratio = features.get('icmp_ratio', 0)
            results['icmp_flood'] = icmp_ratio > 0.5 and pps > 200
            
            # Port scan detection
            port_scan_score = features.get('port_scan_score', 0)
            results['port_scan'] = port_scan_score > 0.8
            
            # IP spoofing detection (low entropy in source IPs with high traffic)
            entropy_src = features.get('entropy_src_ip', 1.0)
            results['ip_spoofing'] = entropy_src < 0.3 and pps > 100
            
        except Exception as e:
            ml_logger.error(f"Error in rule-based detection: {e}")
        
        return results
    
    def _combine_detection_results(self, ml_results: Dict[str, bool], 
                                 rule_results: Dict[str, bool]) -> bool:
        """Combine ML and rule-based detection results"""
        try:
            # Count ML model detections
            ml_detections = sum(1 for result in ml_results.values() if result)
            ml_total = len(ml_results)
            
            # Count rule-based detections
            rule_detections = sum(1 for result in rule_results.values() if result)
            
            # Decision logic: either majority of ML models agree OR multiple rules triggered
            ml_consensus = (ml_detections / ml_total) >= 0.5 if ml_total > 0 else False
            rule_consensus = rule_detections >= 2
            
            # Final decision
            attack_detected = ml_consensus or rule_consensus
            
            ml_logger.debug(
                f"Detection results - ML: {ml_detections}/{ml_total}, "
                f"Rules: {rule_detections}, Decision: {attack_detected}"
            )
            
            return attack_detected
            
        except Exception as e:
            ml_logger.error(f"Error combining detection results: {e}")
            return False
    
    def _analyze_attack(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze detected attack and determine type and characteristics"""
        attack_info = {
            'timestamp': datetime.now(),
            'type': 'unknown',
            'severity': 'medium',
            'source_ip': None,
            'target_ip': None,
            'characteristics': {},
            'features': features
        }
        
        try:
            # Determine attack type based on features
            syn_ratio = features.get('syn_ratio', 0)
            udp_ratio = features.get('udp_ratio', 0)
            icmp_ratio = features.get('icmp_ratio', 0)
            pps = features.get('packets_per_second', 0)
            
            if syn_ratio > 0.7:
                attack_info['type'] = 'syn_flood'
                attack_info['severity'] = 'high' if pps > 2000 else 'medium'
            elif udp_ratio > 0.8:
                attack_info['type'] = 'udp_flood'
                attack_info['severity'] = 'high' if pps > 5000 else 'medium'
            elif icmp_ratio > 0.5:
                attack_info['type'] = 'icmp_flood'
                attack_info['severity'] = 'medium'
            elif features.get('port_scan_score', 0) > 0.8:
                attack_info['type'] = 'port_scan'
                attack_info['severity'] = 'low'
            else:
                attack_info['type'] = 'volumetric'
                attack_info['severity'] = 'high' if pps > 10000 else 'medium'
            
            # Extract source and target information from recent packets
            if self.packet_buffer:
                recent_packets = list(self.packet_buffer)[-100:]
                src_ips = [p.get('src_ip') for p in recent_packets if p.get('src_ip')]
                dst_ips = [p.get('dst_ip') for p in recent_packets if p.get('dst_ip')]
                
                if src_ips:
                    # Find most common source (potential attacker)
                    from collections import Counter
                    src_counter = Counter(src_ips)
                    attack_info['source_ip'] = src_counter.most_common(1)[0][0]
                
                if dst_ips:
                    # Find most common target
                    dst_counter = Counter(dst_ips)
                    attack_info['target_ip'] = dst_counter.most_common(1)[0][0]
            
            # Add characteristics
            attack_info['characteristics'] = {
                'packets_per_second': pps,
                'bytes_per_second': features.get('bytes_per_second', 0),
                'flows_per_second': features.get('flows_per_second', 0),
                'protocol_distribution': {
                    'tcp': features.get('tcp_ratio', 0),
                    'udp': features.get('udp_ratio', 0),
                    'icmp': features.get('icmp_ratio', 0)
                },
                'diversity_metrics': {
                    'unique_src_ips': features.get('unique_src_ips', 0),
                    'unique_dst_ips': features.get('unique_dst_ips', 0),
                    'entropy_src_ip': features.get('entropy_src_ip', 0)
                }
            }
            
        except Exception as e:
            ml_logger.error(f"Error analyzing attack: {e}")
        
        return attack_info
    
    def _log_attack(self, attack_info: Dict[str, Any]):
        """Log detected attack"""
        self.attack_history.append(attack_info)
        
        # Keep only recent attacks (last 100)
        if len(self.attack_history) > 100:
            self.attack_history = self.attack_history[-100:]
        
        ml_logger.warning(
            f"DDoS attack detected - Type: {attack_info['type']}, "
            f"Severity: {attack_info['severity']}, "
            f"Source: {attack_info.get('source_ip', 'Unknown')}"
        )
    
    def train_supervised_model(self, training_data: pd.DataFrame, labels: np.ndarray):
        """Train supervised model with labeled data"""
        try:
            # Prepare features
            X = training_data.select_dtypes(include=[np.number])
            y = labels
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=CONFIG.ml.test_size, random_state=42
            )
            
            # Normalize features
            X_train_scaled = self.scalers['standard'].fit_transform(X_train)
            X_test_scaled = self.scalers['standard'].transform(X_test)
            
            # Train Random Forest
            self.models['random_forest'].fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.models['random_forest'].predict(X_test_scaled)
            accuracy = (y_pred == y_test).mean()
            
            ml_logger.info(f"Random Forest trained with accuracy: {accuracy:.4f}")
            
            # Save model
            model_path = os.path.join(CONFIG.ml.model_save_path, 'random_forest.pkl')
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            with open(model_path, 'wb') as f:
                pickle.dump({
                    'model': self.models['random_forest'],
                    'scaler': self.scalers['standard'],
                    'accuracy': accuracy
                }, f)
            
            return accuracy
            
        except Exception as e:
            ml_logger.error(f"Error training supervised model: {e}")
            return 0.0
    
    def load_trained_model(self, model_name: str) -> bool:
        """Load pre-trained model"""
        try:
            model_path = os.path.join(CONFIG.ml.model_save_path, f'{model_name}.pkl')
            
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    model_data = pickle.load(f)
                
                self.models[model_name] = model_data['model']
                if 'scaler' in model_data:
                    self.scalers['standard'] = model_data['scaler']
                
                ml_logger.info(f"Model {model_name} loaded successfully")
                return True
            
            return False
            
        except Exception as e:
            ml_logger.error(f"Error loading model {model_name}: {e}")
            return False
    
    def get_attack_history(self) -> List[Dict[str, Any]]:
        """Get history of detected attacks"""
        return [
            {
                'timestamp': attack['timestamp'].isoformat(),
                'type': attack['type'],
                'severity': attack['severity'],
                'source_ip': attack.get('source_ip'),
                'target_ip': attack.get('target_ip'),
                'characteristics': attack.get('characteristics', {})
            }
            for attack in self.attack_history
        ]
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        total_attacks = len(self.attack_history)
        
        if total_attacks == 0:
            return {'total_attacks': 0}
        
        # Count by type
        attack_types = {}
        severities = {}
        
        for attack in self.attack_history:
            attack_type = attack['type']
            severity = attack['severity']
            
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
        
        return {
            'total_attacks': total_attacks,
            'attack_types': attack_types,
            'severities': severities,
            'recent_attacks': len([
                a for a in self.attack_history 
                if (datetime.now() - a['timestamp']).seconds < 3600
            ])
        }
'''

with open('sdn_ddos_protection/controller/ddos_detection.py', 'w') as f:
    f.write(ddos_detection_content)

print("DDoS Detection module created successfully!")