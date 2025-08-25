# Create Flask dashboard for SDN monitoring
dashboard_app_content = '''"""
Flask Dashboard for SDN DDoS Protection System
Provides REST API and web interface for monitoring and control
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from utils.config import CONFIG
from utils.logger import dashboard_logger
from controller.ryu_controller import SDNDDoSController

class SDNDashboard:
    """
    Web dashboard for SDN DDoS protection monitoring and control
    """
    
    def __init__(self, controller: Optional[SDNDDoSController] = None):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = CONFIG.dashboard.secret_key
        
        # Enable CORS for all routes
        CORS(self.app, origins="*")
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Store reference to SDN controller
        self.controller = controller
        
        # Dashboard state
        self.connected_clients = 0
        self.last_update = time.time()
        
        # Setup routes and websocket handlers
        self._setup_routes()
        self._setup_websocket_handlers()
        
        # Start background task for real-time updates
        self.update_thread = threading.Thread(target=self._real_time_updates)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        dashboard_logger.info("SDN Dashboard initialized")
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('index.html')
        
        @self.app.route('/api/status')
        def api_status():
            """Get system status"""
            try:
                status = {
                    'system_status': 'running',
                    'controller_connected': self.controller is not None,
                    'timestamp': datetime.now().isoformat(),
                    'uptime': time.time() - self.last_update,
                    'connected_clients': self.connected_clients
                }
                
                if self.controller:
                    controller_stats = self.controller.get_network_stats()
                    status.update({
                        'network_stats': controller_stats,
                        'switches_count': controller_stats.get('switches', 0),
                        'attack_detected': controller_stats.get('attack_detected', False)
                    })
                
                return jsonify(status)
                
            except Exception as e:
                dashboard_logger.error(f"Error getting system status: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/network/topology')
        def api_network_topology():
            """Get network topology"""
            try:
                if not self.controller:
                    return jsonify({'error': 'Controller not connected'}), 503
                
                topology = self.controller.get_topology()
                
                # Convert to format suitable for frontend visualization
                nodes = []
                links = []
                
                # Add switches as nodes
                for switch_id, switch_info in topology.get('switches', {}).items():
                    nodes.append({
                        'id': f's{switch_id}',
                        'name': f'Switch {switch_id}',
                        'type': 'switch',
                        'status': 'active',
                        'dpid': switch_id
                    })
                
                # Add hosts as nodes
                for host_id, host_info in topology.get('hosts', {}).items():
                    nodes.append({
                        'id': host_id,
                        'name': host_id,
                        'type': 'host',
                        'status': 'active',
                        'ip': host_info.get('ip', ''),
                        'mac': host_info.get('mac', '')
                    })
                
                # Add links
                for link in topology.get('links', []):
                    links.append({
                        'source': link['node1'],
                        'target': link['node2'],
                        'type': 'ethernet'
                    })
                
                return jsonify({
                    'nodes': nodes,
                    'links': links,
                    'timestamp': topology.get('timestamp', time.time())
                })
                
            except Exception as e:
                dashboard_logger.error(f"Error getting topology: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/network/statistics')
        def api_network_statistics():
            """Get network statistics"""
            try:
                if not self.controller:
                    return jsonify({'error': 'Controller not connected'}), 503
                
                stats = self.controller.get_network_stats()
                
                # Add additional statistics
                enhanced_stats = {
                    'basic_stats': stats,
                    'flow_stats': {},
                    'port_stats': {},
                    'performance_metrics': {
                        'throughput': 0,
                        'latency': 0,
                        'packet_loss': 0
                    }
                }
                
                # Get per-switch statistics if available
                if hasattr(self.controller, 'stats_collector'):
                    collector = self.controller.stats_collector
                    
                    for dpid in self.controller.datapaths.keys():
                        flow_features = collector.get_flow_features(dpid)
                        port_features = collector.get_port_features(dpid)
                        
                        enhanced_stats['flow_stats'][dpid] = flow_features
                        enhanced_stats['port_stats'][dpid] = port_features
                
                return jsonify(enhanced_stats)
                
            except Exception as e:
                dashboard_logger.error(f"Error getting network statistics: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/attacks/current')
        def api_current_attacks():
            """Get current attack status"""
            try:
                if not self.controller:
                    return jsonify({'error': 'Controller not connected'}), 503
                
                attacks = {
                    'active_attacks': [],
                    'attack_detected': self.controller.attack_detected,
                    'blocked_ips': list(self.controller.blocked_ips),
                    'mitigation_rules': len(self.controller.mitigation_rules)
                }
                
                # Get attack history from detector
                if hasattr(self.controller, 'ddos_detector'):
                    attacks['attack_history'] = self.controller.ddos_detector.get_attack_history()
                    attacks['detection_stats'] = self.controller.ddos_detector.get_detection_stats()
                
                return jsonify(attacks)
                
            except Exception as e:
                dashboard_logger.error(f"Error getting attack info: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/attacks/history')
        def api_attack_history():
            """Get attack history with pagination"""
            try:
                page = request.args.get('page', 1, type=int)
                per_page = request.args.get('per_page', 50, type=int)
                
                if not self.controller or not hasattr(self.controller, 'ddos_detector'):
                    return jsonify({'error': 'Attack detection not available'}), 503
                
                history = self.controller.ddos_detector.get_attack_history()
                
                # Pagination
                start = (page - 1) * per_page
                end = start + per_page
                paginated_history = history[start:end]
                
                return jsonify({
                    'attacks': paginated_history,
                    'pagination': {
                        'page': page,
                        'per_page': per_page,
                        'total': len(history),
                        'pages': (len(history) + per_page - 1) // per_page
                    }
                })
                
            except Exception as e:
                dashboard_logger.error(f"Error getting attack history: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/mitigation/rules')
        def api_mitigation_rules():
            """Get active mitigation rules"""
            try:
                if not self.controller or not hasattr(self.controller, 'flow_manager'):
                    return jsonify({'error': 'Flow manager not available'}), 503
                
                rules = self.controller.flow_manager.get_active_rules()
                stats = self.controller.flow_manager.get_rule_statistics()
                
                return jsonify({
                    'active_rules': rules,
                    'statistics': stats
                })
                
            except Exception as e:
                dashboard_logger.error(f"Error getting mitigation rules: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/mitigation/block', methods=['POST'])
        def api_block_ip():
            """Manually block an IP address"""
            try:
                data = request.get_json()
                if not data or 'ip_address' not in data:
                    return jsonify({'error': 'IP address required'}), 400
                
                ip_address = data['ip_address']
                duration = data.get('duration', 600)  # Default 10 minutes
                
                if not self.controller:
                    return jsonify({'error': 'Controller not connected'}), 503
                
                # Block IP on all switches
                blocked_switches = []
                for dpid, datapath in self.controller.datapaths.items():
                    self.controller.flow_manager.block_ip_address(datapath, ip_address, duration)
                    blocked_switches.append(dpid)
                
                dashboard_logger.info(f"IP {ip_address} blocked manually for {duration}s")
                
                return jsonify({
                    'success': True,
                    'message': f'IP {ip_address} blocked for {duration} seconds',
                    'blocked_switches': blocked_switches
                })
                
            except Exception as e:
                dashboard_logger.error(f"Error blocking IP: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/mitigation/unblock', methods=['POST'])
        def api_unblock_ip():
            """Manually unblock an IP address"""
            try:
                data = request.get_json()
                if not data or 'ip_address' not in data:
                    return jsonify({'error': 'IP address required'}), 400
                
                ip_address = data['ip_address']
                
                if not self.controller:
                    return jsonify({'error': 'Controller not connected'}), 503
                
                # Unblock IP from all switches
                unblocked_switches = []
                for dpid, datapath in self.controller.datapaths.items():
                    self.controller.flow_manager.unblock_ip_address(datapath, ip_address)
                    unblocked_switches.append(dpid)
                
                dashboard_logger.info(f"IP {ip_address} unblocked manually")
                
                return jsonify({
                    'success': True,
                    'message': f'IP {ip_address} unblocked',
                    'unblocked_switches': unblocked_switches
                })
                
            except Exception as e:
                dashboard_logger.error(f"Error unblocking IP: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/ml/status')
        def api_ml_status():
            """Get machine learning model status"""
            try:
                if not self.controller or not hasattr(self.controller, 'ddos_detector'):
                    return jsonify({'error': 'ML detector not available'}), 503
                
                detector = self.controller.ddos_detector
                
                ml_status = {
                    'models_loaded': {
                        'random_forest': detector.models['random_forest'] is not None,
                        'svm': detector.models['svm'] is not None,
                        'isolation_forest': detector.models['isolation_forest'] is not None,
                        'kmeans': detector.models['kmeans'] is not None
                    },
                    'detection_threshold': detector.detection_threshold,
                    'packet_buffer_size': len(detector.packet_buffer),
                    'flow_buffer_size': len(detector.flow_buffer),
                    'current_features_count': len(detector.current_features)
                }
                
                return jsonify(ml_status)
                
            except Exception as e:
                dashboard_logger.error(f"Error getting ML status: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/config')
        def api_config():
            """Get system configuration"""
            try:
                config_dict = {
                    'controller': {
                        'host': CONFIG.controller.controller_host,
                        'port': CONFIG.controller.controller_port,
                        'statistics_interval': CONFIG.controller.statistics_interval
                    },
                    'detection': {
                        'packet_rate_threshold': CONFIG.detection.packet_rate_threshold,
                        'byte_rate_threshold': CONFIG.detection.byte_rate_threshold,
                        'anomaly_threshold': CONFIG.detection.anomaly_threshold
                    },
                    'ml': {
                        'feature_window': CONFIG.ml.feature_window,
                        'flow_timeout': CONFIG.ml.flow_timeout
                    }
                }
                
                return jsonify(config_dict)
                
            except Exception as e:
                dashboard_logger.error(f"Error getting config: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Static file serving
        @self.app.route('/static/<path:filename>')
        def static_files(filename):
            return send_from_directory('static', filename)
    
    def _setup_websocket_handlers(self):
        """Setup WebSocket event handlers for real-time communication"""
        
        @self.socketio.on('connect')
        def handle_connect():
            self.connected_clients += 1
            dashboard_logger.info(f"Client connected. Total clients: {self.connected_clients}")
            emit('connected', {'message': 'Connected to SDN Dashboard'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            self.connected_clients = max(0, self.connected_clients - 1)
            dashboard_logger.info(f"Client disconnected. Total clients: {self.connected_clients}")
        
        @self.socketio.on('get_real_time_stats')
        def handle_real_time_stats():
            """Send real-time statistics to client"""
            try:
                if self.controller:
                    stats = self.controller.get_network_stats()
                    emit('real_time_stats', stats)
                else:
                    emit('error', {'message': 'Controller not connected'})
            except Exception as e:
                emit('error', {'message': str(e)})
        
        @self.socketio.on('request_topology_update')
        def handle_topology_update():
            """Send topology update to client"""
            try:
                if self.controller:
                    topology = self.controller.get_topology()
                    emit('topology_update', topology)
                else:
                    emit('error', {'message': 'Controller not connected'})
            except Exception as e:
                emit('error', {'message': str(e)})
    
    def _real_time_updates(self):
        """Background thread for sending real-time updates"""
        while True:
            try:
                if self.connected_clients > 0 and self.controller:
                    # Get current statistics
                    stats = self.controller.get_network_stats()
                    
                    # Broadcast to all connected clients
                    self.socketio.emit('stats_update', stats)
                    
                    # Check for attacks
                    if stats.get('attack_detected'):
                        attack_info = {
                            'timestamp': datetime.now().isoformat(),
                            'type': 'attack_detected',
                            'blocked_ips': stats.get('blocked_ips', [])
                        }
                        self.socketio.emit('attack_alert', attack_info)
                
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                dashboard_logger.error(f"Error in real-time updates: {e}")
                time.sleep(10)
    
    def run(self, host: str = None, port: int = None, debug: bool = None):
        """Run the Flask dashboard"""
        try:
            host = host or CONFIG.dashboard.dashboard_host
            port = port or CONFIG.dashboard.dashboard_port
            debug = debug if debug is not None else CONFIG.dashboard.debug_mode
            
            dashboard_logger.info(f"Starting dashboard on {host}:{port}")
            
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=debug,
                use_reloader=False  # Disable reloader to prevent issues with threading
            )
            
        except Exception as e:
            dashboard_logger.error(f"Error running dashboard: {e}")
    
    def set_controller(self, controller: SDNDDoSController):
        """Set the SDN controller reference"""
        self.controller = controller
        dashboard_logger.info("Controller reference set in dashboard")

def create_dashboard(controller: Optional[SDNDDoSController] = None) -> SDNDashboard:
    """Factory function to create dashboard instance"""
    return SDNDashboard(controller)

def run_dashboard_server(controller: Optional[SDNDDoSController] = None,
                        host: str = "127.0.0.1", port: int = 5000):
    """Standalone function to run dashboard server"""
    try:
        dashboard = create_dashboard(controller)
        dashboard.run(host=host, port=port)
    except KeyboardInterrupt:
        dashboard_logger.info("Dashboard server stopped by user")
    except Exception as e:
        dashboard_logger.error(f"Dashboard server error: {e}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SDN DDoS Protection Dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Dashboard host')
    parser.add_argument('--port', type=int, default=5000, help='Dashboard port')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    print(f"Starting SDN Dashboard on {args.host}:{args.port}")
    print("Access dashboard at: http://{args.host}:{args.port}")
    
    run_dashboard_server(
        controller=None,  # Will connect when controller is available
        host=args.host,
        port=args.port
    )
'''

with open('sdn_ddos_protection/dashboard/app.py', 'w') as f:
    f.write(dashboard_app_content)

print("Dashboard Flask app created successfully!")