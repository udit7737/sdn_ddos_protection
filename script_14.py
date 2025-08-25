# Create comprehensive README file
readme_content = '''# SDN DDoS Protection System

A comprehensive Software-Defined Networking (SDN) DDoS protection system that uses machine learning algorithms to detect and mitigate distributed denial of service attacks in real-time.

## 🚀 Features

### Core Features
- **Real-time DDoS Detection**: Uses multiple ML algorithms (Random Forest, SVM, K-Means, Isolation Forest)
- **Automatic Mitigation**: Installs OpenFlow rules to block malicious traffic
- **Multi-Attack Support**: Detects SYN flood, UDP flood, ICMP flood, port scanning, and volumetric attacks
- **Web Dashboard**: Real-time monitoring and control interface
- **Network Simulation**: Complete Mininet-based testing environment

### Machine Learning Models
- **Random Forest**: Supervised learning for labeled attack data
- **One-Class SVM**: Anomaly detection for unknown attacks
- **K-Means Clustering**: Behavioral pattern analysis
- **Isolation Forest**: Outlier detection for traffic anomalies

### SDN Controller Features
- **Ryu-based Controller**: OpenFlow 1.3 support
- **Flow Statistics Collection**: Real-time traffic monitoring
- **Dynamic Rule Installation**: Automatic mitigation rule deployment
- **REST API**: Programmatic control and monitoring

### Dashboard Features
- **Network Topology Visualization**: Interactive network diagram
- **Real-time Traffic Analysis**: Live charts and statistics
- **Attack Monitoring**: Attack history and current status
- **Manual Controls**: Block/unblock IPs and manage rules

## 📋 Prerequisites

### System Requirements
- **Operating System**: Ubuntu 18.04+ (recommended) or similar Linux distribution
- **Python**: 3.8 or higher
- **Memory**: At least 4GB RAM
- **CPU**: Multi-core processor recommended

### Required Software
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev
sudo apt-get install -y build-essential libssl-dev libffi-dev
sudo apt-get install -y git wget curl

# Install Mininet
sudo apt-get install -y mininet

# Install network tools
sudo apt-get install -y hping3 iperf nmap tcpdump wireshark-common
```

## 🔧 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/sdn-ddos-protection.git
cd sdn-ddos-protection
```

### 2. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 3. Setup Directory Structure
```bash
mkdir -p logs data ml_models/models
```

### 4. Configure the System
```bash
# Edit configuration if needed
nano utils/config.py
```

## 🚀 Quick Start

### Method 1: All-in-One Startup Script
```bash
# Make scripts executable
chmod +x scripts/start_system.sh
chmod +x scripts/stop_system.sh

# Start the complete system
sudo ./scripts/start_system.sh

# Stop the system
sudo ./scripts/stop_system.sh
```

### Method 2: Manual Component Startup

#### Step 1: Start the SDN Controller
```bash
# Terminal 1 - Start Ryu controller
cd sdn_ddos_protection
ryu-manager --verbose controller/ryu_controller.py
```

#### Step 2: Start the Network Topology
```bash
# Terminal 2 - Start Mininet network
cd sdn_ddos_protection
sudo python3 mininet_simulation/topology.py --topology tree
```

#### Step 3: Start the Dashboard
```bash
# Terminal 3 - Start web dashboard
cd sdn_ddos_protection
python3 dashboard/app.py
```

#### Step 4: Access the Dashboard
Open your web browser and go to: http://localhost:5000

## 📊 Usage Examples

### Basic Network Testing
```bash
# Test connectivity between hosts
mininet> pingall

# Check switch connections
mininet> net

# View flow tables
mininet> sh ovs-ofctl dump-flows s1
```

### Attack Simulation
```bash
# Terminal 4 - Generate background traffic
cd sdn_ddos_protection
python3 mininet_simulation/traffic_generator.py --pattern mixed --duration 300

# Terminal 5 - Launch DDoS attacks
python3 mininet_simulation/attack_simulator.py --attack syn_flood --sources h1 h2 h3 --target h8 --duration 60 --intensity high
```

### Manual IP Blocking
```bash
# Block an IP address via REST API
curl -X POST http://localhost:5000/api/mitigation/block \\
  -H "Content-Type: application/json" \\
  -d '{"ip_address": "10.0.0.1", "duration": 600}'

# Unblock an IP address
curl -X POST http://localhost:5000/api/mitigation/unblock \\
  -H "Content-Type: application/json" \\
  -d '{"ip_address": "10.0.0.1"}'
```

## 🏗️ System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   SDN Controller │    │   ML Detection  │
│                 │◄──►│                  │◄──►│     Engine      │
│  - Monitoring   │    │  - Flow Mgmt     │    │  - Anomaly Det  │
│  - Controls     │    │  - Statistics    │    │  - Feature Ext  │
│  - Alerts       │    │  - Mitigation    │    │  - Training     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   OpenFlow       │
                       │   Switches       │
                       │                  │
                       │  - Traffic Fwd   │
                       │  - Rule Install  │
                       │  - Stats Report  │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Network Hosts  │
                       │                  │
                       │  - Clients       │
                       │  - Servers       │
                       │  - Attackers     │
                       └──────────────────┘
```

## 📡 REST API Reference

### System Status
- `GET /api/status` - Get system status
- `GET /api/config` - Get configuration

### Network Management
- `GET /api/network/topology` - Get network topology
- `GET /api/network/statistics` - Get traffic statistics

### Attack Monitoring
- `GET /api/attacks/current` - Get current attacks
- `GET /api/attacks/history` - Get attack history

### Mitigation Control
- `GET /api/mitigation/rules` - Get active rules
- `POST /api/mitigation/block` - Block IP address
- `POST /api/mitigation/unblock` - Unblock IP address

### Machine Learning
- `GET /api/ml/status` - Get ML model status

## 🧪 Testing Scenarios

### Scenario 1: SYN Flood Attack
```bash
# Start network with tree topology
sudo python3 mininet_simulation/topology.py --topology tree

# Generate background traffic
python3 mininet_simulation/traffic_generator.py --pattern web_browsing &

# Launch SYN flood attack
python3 mininet_simulation/attack_simulator.py \\
  --attack syn_flood \\
  --sources h1 h2 h3 \\
  --target h7 \\
  --duration 120 \\
  --intensity high

# Monitor detection in dashboard
# URL: http://localhost:5000
```

### Scenario 2: Mixed Attack Simulation
```bash
# Launch multiple attack types simultaneously
python3 mininet_simulation/attack_simulator.py --attack volumetric --sources h1 h2 --target h8 --duration 60 &
python3 mininet_simulation/attack_simulator.py --attack port_scan --sources h3 --target h7 --duration 30 &
```

### Scenario 3: Performance Testing
```bash
# Generate high-intensity legitimate traffic
python3 mininet_simulation/traffic_generator.py --pattern mixed --intensity high --duration 600

# Monitor system performance
watch -n 1 'ps aux | grep ryu'
watch -n 1 'free -h'
```

## 🔍 Monitoring and Debugging

### Log Files
- `logs/controller.log` - SDN controller logs
- `logs/ml_models.log` - Machine learning logs
- `logs/dashboard.log` - Web dashboard logs
- `logs/simulation.log` - Network simulation logs
- `logs/security_audit.log` - Security events

### Debug Commands
```bash
# Check OpenFlow connections
sudo ovs-vsctl show

# View flow tables
sudo ovs-ofctl dump-flows s1 -O OpenFlow13

# Monitor network traffic
sudo tcpdump -i s1-eth1

# Check controller connectivity
netstat -tlnp | grep 6653
```

### Performance Monitoring
```bash
# Monitor system resources
htop

# Monitor network interfaces
sudo iftop

# Check disk usage
df -h logs/
```

## ⚙️ Configuration

### Controller Configuration (`utils/config.py`)
```python
@dataclass
class ControllerConfig:
    controller_host: str = "127.0.0.1"
    controller_port: int = 6653
    statistics_interval: int = 10

@dataclass
class DetectionConfig:
    packet_rate_threshold: int = 1000
    byte_rate_threshold: int = 1000000
    anomaly_threshold: float = 0.7
```

### Network Topology Configuration
```python
# Edit mininet_simulation/topology.py
TOPOLOGY_TEMPLATES = {
    "simple": {"switches": 1, "hosts": 4},
    "tree": {"switches": 3, "hosts": 8},
    "mesh": {"switches": 4, "hosts": 8}
}
```

## 🤖 Machine Learning Training

### Training with Custom Data
```bash
# Prepare training data (CSV format)
# Columns: packet_count, byte_count, flow_count, ..., label

# Train supervised models
python3 -c "
from controller.ddos_detection import DDoSDetector
import pandas as pd

detector = DDoSDetector()
data = pd.read_csv('training_data.csv')
labels = data['label'].values
features = data.drop('label', axis=1)

accuracy = detector.train_supervised_model(features, labels)
print(f'Model accuracy: {accuracy:.4f}')
"
```

### Feature Engineering
```bash
# Extract features from packet captures
python3 -c "
from ml_models.feature_extractor import FeatureExtractor
import json

extractor = FeatureExtractor()
# Load your packet data
packets = [...]  # Your packet data
features = extractor.extract_features(packets, [])
print(json.dumps(features, indent=2))
"
```

## 🚨 Troubleshooting

### Common Issues

#### Controller Connection Issues
```bash
# Check if controller is running
ps aux | grep ryu

# Check port availability
netstat -tlnp | grep 6653

# Restart controller
pkill -f ryu-manager
ryu-manager controller/ryu_controller.py
```

#### Mininet Network Issues
```bash
# Clean up previous Mininet state
sudo mn -c

# Check Open vSwitch
sudo systemctl status openvswitch-switch

# Restart network
sudo systemctl restart openvswitch-switch
```

#### Dashboard Access Issues
```bash
# Check if dashboard is running
ps aux | grep "dashboard/app.py"

# Check port 5000
netstat -tlnp | grep 5000

# Check firewall
sudo ufw status
```

#### Permission Issues
```bash
# Fix file permissions
chmod +x scripts/*.sh
sudo chown -R $USER:$USER logs/ data/

# Mininet requires root
sudo python3 mininet_simulation/topology.py
```

### Performance Optimization

#### For High Traffic Scenarios
```python
# Increase buffer sizes in config.py
CONFIG.ml.feature_window = 60
CONFIG.controller.statistics_interval = 5

# Use faster detection algorithms
CONFIG.detection.consecutive_anomalies = 2
```

#### For Resource-Constrained Systems
```python
# Reduce ML model complexity
CONFIG.ml.rf_n_estimators = 50
CONFIG.ml.rf_max_depth = 5

# Increase update intervals
CONFIG.controller.statistics_interval = 30
```

## 📝 Development

### Project Structure
```
sdn_ddos_protection/
├── controller/               # SDN controller components
│   ├── ryu_controller.py    # Main Ryu application
│   ├── ddos_detection.py    # DDoS detection logic
│   ├── flow_manager.py      # OpenFlow rule management
│   └── statistics_collector.py # Traffic statistics
├── ml_models/               # Machine learning components
│   ├── anomaly_detector.py  # ML models
│   ├── feature_extractor.py # Feature engineering
│   └── model_trainer.py     # Model training
├── dashboard/               # Web dashboard
│   ├── app.py              # Flask application
│   └── templates/          # HTML templates
├── mininet_simulation/      # Network simulation
│   ├── topology.py         # Network topologies
│   ├── attack_simulator.py # Attack generation
│   └── traffic_generator.py # Legitimate traffic
├── utils/                   # Utilities
│   ├── config.py           # Configuration
│   ├── logger.py           # Logging utilities
│   └── database.py         # Database operations
└── requirements.txt         # Python dependencies
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Running Tests
```bash
# Install test dependencies
pip3 install pytest pytest-cov

# Run tests
python3 -m pytest tests/

# Run with coverage
python3 -m pytest --cov=. tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Ryu Controller**: SDN framework
- **Mininet**: Network emulation platform
- **Scikit-learn**: Machine learning library
- **Flask**: Web framework
- **D3.js**: Data visualization
- **Bootstrap**: UI framework

## 📞 Support

For questions and support:
- Create an issue on GitHub
- Email: support@example.com
- Documentation: [Wiki](https://github.com/your-username/sdn-ddos-protection/wiki)

## 🔮 Future Enhancements

- [ ] Deep learning models (LSTM, CNN)
- [ ] Distributed controller support
- [ ] Integration with external threat intelligence
- [ ] Mobile dashboard app
- [ ] Advanced visualization features
- [ ] Performance optimization
- [ ] Multi-tenant support
- [ ] Cloud deployment support

---

**Note**: This system is for educational and research purposes. Always test in isolated environments before deploying in production networks.
'''

with open('sdn_ddos_protection/README.md', 'w') as f:
    f.write(readme_content)

print("README.md created successfully!")