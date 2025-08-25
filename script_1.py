# Let's create the requirements.txt file with all necessary dependencies
requirements_content = """
# SDN Controller Dependencies
ryu>=4.34
eventlet>=0.33.3
oslo.config>=9.1.1

# Machine Learning Dependencies
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
tensorflow>=2.13.0
torch>=2.0.0
matplotlib>=3.7.0
seaborn>=0.12.0
joblib>=1.3.0

# Web Framework Dependencies
Flask>=2.3.0
Flask-CORS>=4.0.0
Flask-SocketIO>=5.3.0
python-socketio>=5.8.0

# Database Dependencies
sqlite3
sqlalchemy>=2.0.0
pymongo>=4.4.0

# Networking Dependencies
netifaces>=0.11.0
psutil>=5.9.0
scapy>=2.5.0

# Utility Dependencies
pyyaml>=6.0
python-dotenv>=1.0.0
requests>=2.31.0
schedule>=1.2.0
coloredlogs>=15.0.1

# Development Dependencies
pytest>=7.4.0
pytest-cov>=4.1.0
black>=23.7.0
flake8>=6.0.0

# Mininet Dependencies (for simulation)
# Note: Mininet should be installed separately following official instructions
# These are Python packages that work with Mininet
mininet>=2.3.0
"""

with open('sdn_ddos_protection/requirements.txt', 'w') as f:
    f.write(requirements_content.strip())

print("Requirements.txt created successfully!")