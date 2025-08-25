# Create the logger utility
logger_content = '''"""
Logging utility for SDN DDoS Protection System
Provides centralized logging with different levels and formats
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from typing import Optional
import coloredlogs

class SDNLogger:
    """Enhanced logger for SDN DDoS Protection System"""
    
    def __init__(self, name: str, log_level: str = "INFO", 
                 log_file: Optional[str] = None, 
                 console_output: bool = True):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler with colored output
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            
            # Add colored logs for better readability
            coloredlogs.install(
                level=log_level.upper(),
                logger=self.logger,
                fmt='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
        
        # File handler
        if log_file:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            # Rotating file handler (max 10MB, keep 5 files)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10*1024*1024, backupCount=5
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def get_logger(self):
        """Return the logger instance"""
        return self.logger
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(message, **kwargs)
    
    def log_attack_detected(self, attack_type: str, source_ip: str, 
                          target_ip: str, severity: str = "HIGH"):
        """Log DDoS attack detection"""
        self.logger.warning(
            f"DDoS ATTACK DETECTED - Type: {attack_type}, "
            f"Source: {source_ip}, Target: {target_ip}, Severity: {severity}"
        )
    
    def log_mitigation_applied(self, action: str, target: str, duration: int):
        """Log mitigation action"""
        self.logger.info(
            f"MITIGATION APPLIED - Action: {action}, "
            f"Target: {target}, Duration: {duration}s"
        )
    
    def log_flow_stats(self, dpid: str, flow_count: int, packet_count: int):
        """Log flow statistics"""
        self.logger.debug(
            f"FLOW STATS - DPID: {dpid}, Flows: {flow_count}, "
            f"Packets: {packet_count}"
        )
    
    def log_ml_training(self, model_name: str, accuracy: float, training_time: float):
        """Log ML model training results"""
        self.logger.info(
            f"ML TRAINING - Model: {model_name}, "
            f"Accuracy: {accuracy:.4f}, Time: {training_time:.2f}s"
        )
    
    def log_system_startup(self, component: str, config: dict):
        """Log system component startup"""
        self.logger.info(
            f"SYSTEM STARTUP - Component: {component}, Config: {config}"
        )

class SecurityAuditLogger:
    """Specialized logger for security events and audit trails"""
    
    def __init__(self, log_file: str = "logs/security_audit.log"):
        self.logger = SDNLogger("SecurityAudit", log_file=log_file).get_logger()
        
        # Create security-specific formatter
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Update all handlers with security formatter
        for handler in self.logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                handler.setFormatter(security_formatter)
    
    def log_attack_attempt(self, attack_info: dict):
        """Log attack attempt with full details"""
        self.logger.critical(
            f"ATTACK_ATTEMPT - Type: {attack_info.get('type', 'Unknown')}, "
            f"Source: {attack_info.get('source_ip', 'Unknown')}, "
            f"Target: {attack_info.get('target_ip', 'Unknown')}, "
            f"Packets: {attack_info.get('packet_count', 0)}, "
            f"Duration: {attack_info.get('duration', 0)}s, "
            f"Detected: {attack_info.get('detection_time', datetime.now())}"
        )
    
    def log_mitigation_action(self, action_info: dict):
        """Log mitigation action taken"""
        self.logger.warning(
            f"MITIGATION_ACTION - Action: {action_info.get('action', 'Unknown')}, "
            f"Target: {action_info.get('target', 'Unknown')}, "
            f"Rule: {action_info.get('rule_id', 'Unknown')}, "
            f"Applied: {action_info.get('timestamp', datetime.now())}"
        )
    
    def log_system_access(self, user: str, action: str, resource: str):
        """Log system access attempts"""
        self.logger.info(
            f"SYSTEM_ACCESS - User: {user}, Action: {action}, Resource: {resource}"
        )

# Factory function for creating loggers
def create_logger(name: str, log_level: str = "INFO", 
                 log_file: Optional[str] = None) -> logging.Logger:
    """Create a standard logger instance"""
    return SDNLogger(name, log_level, log_file).get_logger()

# Pre-configured logger instances
controller_logger = SDNLogger(
    "SDNController", 
    log_file="logs/controller.log"
).get_logger()

ml_logger = SDNLogger(
    "MachineLearning",
    log_file="logs/ml_models.log" 
).get_logger()

dashboard_logger = SDNLogger(
    "Dashboard",
    log_file="logs/dashboard.log"
).get_logger()

simulation_logger = SDNLogger(
    "Simulation", 
    log_file="logs/simulation.log"
).get_logger()

security_logger = SecurityAuditLogger()
'''

with open('sdn_ddos_protection/utils/logger.py', 'w') as f:
    f.write(logger_content)

print("Logger utility created successfully!")