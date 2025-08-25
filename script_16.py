# Fix the setup script with proper string escaping
setup_script_content = '''#!/usr/bin/env python3
"""
Setup script for SDN DDoS Protection System
Installs dependencies and configures the system
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(command, check=True):
    """Run a shell command"""
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, check=check, 
                              capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        return False
    print(f"Python version: {sys.version}")
    return True

def check_system():
    """Check system requirements"""
    print("Checking system requirements...")
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check if running on Linux
    if os.name != 'posix':
        print("Warning: This system is designed for Linux environments")
    
    # Check available memory
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if 'MemTotal' in line:
                    mem_kb = int(line.split()[1])
                    mem_gb = mem_kb / 1024 / 1024
                    print(f"Available memory: {mem_gb:.1f} GB")
                    if mem_gb < 2:
                        print("Warning: Less than 2GB memory available")
                    break
    except FileNotFoundError:
        print("Cannot check memory (not on Linux)")
    
    return True

def install_system_dependencies():
    """Install system-level dependencies"""
    print("Installing system dependencies...")
    
    dependencies = [
        "python3-dev",
        "python3-pip", 
        "build-essential",
        "libssl-dev",
        "libffi-dev",
        "git",
        "wget",
        "curl"
    ]
    
    # Update package list
    if not run_command("sudo apt-get update"):
        print("Warning: Could not update package list")
    
    # Install dependencies
    deps_str = " ".join(dependencies)
    return run_command(f"sudo apt-get install -y {deps_str}")

def install_mininet():
    """Install Mininet network emulator"""
    print("Installing Mininet...")
    
    # Check if Mininet is already installed
    if run_command("which mn", check=False):
        print("Mininet is already installed")
        return True
    
    # Install Mininet
    if not run_command("sudo apt-get install -y mininet"):
        print("Failed to install Mininet via apt, trying alternative method...")
        
        # Clone and install from source
        if run_command("git clone https://github.com/mininet/mininet.git /tmp/mininet"):
            return run_command("cd /tmp/mininet && sudo ./util/install.sh -a")
    
    return True

def install_network_tools():
    """Install network testing tools"""
    print("Installing network tools...")
    
    tools = [
        "hping3",
        "iperf",
        "nmap", 
        "tcpdump",
        "wireshark-common"
    ]
    
    tools_str = " ".join(tools)
    return run_command(f"sudo apt-get install -y {tools_str}")

def install_python_dependencies():
    """Install Python packages"""
    print("Installing Python dependencies...")
    
    # Upgrade pip first
    run_command(f"{sys.executable} -m pip install --upgrade pip")
    
    # Install from requirements.txt
    if os.path.exists("requirements.txt"):
        return run_command(f"{sys.executable} -m pip install -r requirements.txt")
    else:
        print("requirements.txt not found, installing essential packages...")
        
        packages = [
            "ryu>=4.34",
            "flask>=2.3.0",
            "flask-cors>=4.0.0", 
            "flask-socketio>=5.3.0",
            "scikit-learn>=1.3.0",
            "pandas>=2.0.0",
            "numpy>=1.24.0",
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
            "requests>=2.31.0"
        ]
        
        for package in packages:
            if not run_command(f"{sys.executable} -m pip install {package}"):
                print(f"Warning: Failed to install {package}")
        
        return True

def create_directories():
    """Create necessary directories"""
    print("Creating directories...")
    
    directories = [
        "logs",
        "data",
        "ml_models/models",
        "dashboard/static/css",
        "dashboard/static/js", 
        "dashboard/static/images"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {directory}")
    
    return True

def set_permissions():
    """Set proper file permissions"""
    print("Setting file permissions...")
    
    # Make Python files executable
    python_files = [
        "controller/ryu_controller.py",
        "dashboard/app.py",
        "mininet_simulation/topology.py",
        "mininet_simulation/attack_simulator.py",
        "mininet_simulation/traffic_generator.py"
    ]
    
    for file_path in python_files:
        if os.path.exists(file_path):
            os.chmod(file_path, 0o755)
            print(f"Made executable: {file_path}")
    
    # Create startup scripts
    create_startup_scripts()
    
    return True

def create_startup_scripts():
    """Create convenience startup scripts"""
    print("Creating startup scripts...")
    
    # Create scripts directory
    Path("scripts").mkdir(exist_ok=True)
    
    # Start system script
    start_script = """#!/bin/bash
echo "Starting SDN DDoS Protection System..."

# Check if running as root (needed for Mininet)
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (needed for Mininet)"
    echo "Usage: sudo ./scripts/start_system.sh"
    exit 1
fi

# Kill any existing processes
pkill -f ryu-manager
pkill -f "python.*app.py"
mn -c

echo "Starting Ryu controller..."
cd $(dirname $0)/..
ryu-manager --verbose controller/ryu_controller.py &
CONTROLLER_PID=$!

echo "Waiting for controller to start..."
sleep 5

echo "Starting Mininet network..."
python3 mininet_simulation/topology.py --topology tree --no-cli &
MININET_PID=$!

echo "Waiting for network to initialize..."
sleep 10

echo "Starting web dashboard..."
python3 dashboard/app.py &
DASHBOARD_PID=$!

echo ""
echo "=== SDN DDoS Protection System Started ==="
echo "Controller PID: $CONTROLLER_PID"
echo "Mininet PID: $MININET_PID" 
echo "Dashboard PID: $DASHBOARD_PID"
echo ""
echo "Access dashboard at: http://localhost:5000"
echo "Press Ctrl+C to stop all components"
echo ""

# Wait for interrupt
wait
"""

    # Stop system script
    stop_script = """#!/bin/bash
echo "Stopping SDN DDoS Protection System..."

# Kill processes
echo "Stopping controller..."
pkill -f ryu-manager

echo "Stopping dashboard..."
pkill -f "python.*app.py"

echo "Stopping Mininet..."
mn -c

echo "Cleaning up..."
pkill -f hping3
pkill -f iperf
pkill -f python3

echo "System stopped."
"""

    # Demo script
    demo_script = """#!/bin/bash
echo "Running SDN DDoS Protection Demo..."

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./scripts/demo.sh"
    exit 1
fi

cd $(dirname $0)/..

echo "1. Starting system components..."
./scripts/start_system.sh &
SYSTEM_PID=$!

echo "2. Waiting for system to initialize..."
sleep 20

echo "3. Generating background traffic..."
python3 mininet_simulation/traffic_generator.py --pattern web_browsing --duration 60 --intensity low &

echo "4. Waiting 10 seconds..."
sleep 10

echo "5. Launching SYN flood attack..."
python3 mininet_simulation/attack_simulator.py --attack syn_flood --sources h1 h2 h3 --target h7 --duration 60 --intensity medium &

echo ""
echo "=== Demo Running ==="
echo "Monitor the dashboard at: http://localhost:5000"
echo "Attack should be detected and mitigated automatically"
echo "Demo will run for 2 minutes..."
echo ""

sleep 120

echo "6. Stopping demo..."
pkill -f attack_simulator
pkill -f traffic_generator
./scripts/stop_system.sh

echo "Demo completed!"
"""

    # Write scripts
    with open("scripts/start_system.sh", "w") as f:
        f.write(start_script)
    
    with open("scripts/stop_system.sh", "w") as f:
        f.write(stop_script)
        
    with open("scripts/demo.sh", "w") as f:
        f.write(demo_script)
    
    # Make scripts executable
    os.chmod("scripts/start_system.sh", 0o755)
    os.chmod("scripts/stop_system.sh", 0o755)
    os.chmod("scripts/demo.sh", 0o755)
    
    print("Created startup scripts in scripts/ directory")

def verify_installation():
    """Verify that installation was successful"""
    print("Verifying installation...")
    
    # Check Python packages
    try:
        import ryu
        print(f"✓ Ryu controller: {ryu.__version__}")
    except ImportError:
        print("✗ Ryu controller not found")
        return False
    
    try:
        import flask
        print(f"✓ Flask: {flask.__version__}")
    except ImportError:
        print("✗ Flask not found")
        return False
    
    try:
        import sklearn
        print(f"✓ Scikit-learn: {sklearn.__version__}")
    except ImportError:
        print("✗ Scikit-learn not found")
        return False
    
    # Check system tools
    tools_check = [
        ("mn", "Mininet"),
        ("hping3", "hping3"),
        ("iperf", "iperf"),
        ("ovs-vsctl", "Open vSwitch")
    ]
    
    for cmd, name in tools_check:
        if run_command(f"which {cmd}", check=False):
            print(f"✓ {name}")
        else:
            print(f"✗ {name} not found")
    
    # Check directories
    for directory in ["logs", "data", "ml_models/models"]:
        if os.path.exists(directory):
            print(f"✓ Directory: {directory}")
        else:
            print(f"✗ Directory missing: {directory}")
    
    print("\\nInstallation verification completed!")
    return True

def print_next_steps():
    """Print next steps for the user"""
    print("\\n" + "="*60)
    print("SDN DDoS Protection System Setup Complete!")
    print("="*60)
    print("\\nNext steps:")
    print("\\n1. Start the system:")
    print("   sudo ./scripts/start_system.sh")
    print("\\n2. Access the dashboard:")
    print("   http://localhost:5000")
    print("\\n3. Run a demo:")
    print("   sudo ./scripts/demo.sh")
    print("\\n4. Manual component startup:")
    print("   Terminal 1: ryu-manager --verbose controller/ryu_controller.py")
    print("   Terminal 2: sudo python3 mininet_simulation/topology.py")
    print("   Terminal 3: python3 dashboard/app.py")
    print("\\n5. Generate attacks:")
    print("   python3 mininet_simulation/attack_simulator.py --help")
    print("\\n6. View logs:")
    print("   tail -f logs/controller.log")
    print("   tail -f logs/security_audit.log")
    print("\\nFor more information, see README.md")
    print("="*60)

def main():
    """Main setup function"""
    print("SDN DDoS Protection System Setup")
    print("================================")
    
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"Working directory: {os.getcwd()}")
    
    # Check system requirements
    if not check_system():
        print("System requirements not met. Please fix issues and try again.")
        sys.exit(1)
    
    # Ask user for confirmation
    print("\\nThis will install system dependencies and Python packages.")
    choice = input("Continue? (y/N): ").strip().lower()
    if choice != 'y' and choice != 'yes':
        print("Setup cancelled.")
        sys.exit(0)
    
    success = True
    
    # Install system dependencies
    print("\\n" + "="*50)
    if not install_system_dependencies():
        print("Warning: System dependencies installation had issues")
        success = False
    
    # Install Mininet
    print("\\n" + "="*50)
    if not install_mininet():
        print("Warning: Mininet installation had issues")
        success = False
    
    # Install network tools
    print("\\n" + "="*50) 
    if not install_network_tools():
        print("Warning: Network tools installation had issues")
        success = False
    
    # Install Python dependencies
    print("\\n" + "="*50)
    if not install_python_dependencies():
        print("Warning: Python dependencies installation had issues")
        success = False
    
    # Create directories
    print("\\n" + "="*50)
    if not create_directories():
        print("Warning: Directory creation had issues")
        success = False
    
    # Set permissions
    print("\\n" + "="*50)
    if not set_permissions():
        print("Warning: Permission setting had issues")
        success = False
    
    # Verify installation
    print("\\n" + "="*50)
    verify_installation()
    
    # Print next steps
    print_next_steps()
    
    if success:
        print("\\n✓ Setup completed successfully!")
        sys.exit(0)
    else:
        print("\\n⚠ Setup completed with warnings. Check output above.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\nSetup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\\nSetup failed with error: {e}")
        sys.exit(1)
'''

with open('sdn_ddos_protection/setup.py', 'w') as f:
    f.write(setup_script_content)

# Make setup script executable
import os
os.chmod('sdn_ddos_protection/setup.py', 0o755)

print("Setup script created and made executable!")