# Let's start by creating the project structure and core files
import os
import json

# Create project directory structure
project_structure = {
    'sdn_ddos_protection': {
        'controller': {
            'ryu_controller.py': '',
            'ddos_detection.py': '',
            'flow_manager.py': '',
            'statistics_collector.py': ''
        },
        'ml_models': {
            'anomaly_detector.py': '',
            'feature_extractor.py': '',
            'model_trainer.py': '',
            'models': {}
        },
        'dashboard': {
            'app.py': '',
            'static': {
                'css': {},
                'js': {},
                'images': {}
            },
            'templates': {
                'index.html': ''
            }
        },
        'frontend': {
            'src': {
                'components': {
                    'Dashboard.js': '',
                    'NetworkTopology.js': '',
                    'TrafficMonitor.js': '',
                    'AlertSystem.js': ''
                },
                'services': {
                    'api.js': ''
                },
                'App.js': '',
                'index.js': ''
            },
            'package.json': ''
        },
        'mininet_simulation': {
            'topology.py': '',
            'attack_simulator.py': '',
            'traffic_generator.py': ''
        },
        'utils': {
            'config.py': '',
            'logger.py': '',
            'database.py': ''
        },
        'requirements.txt': '',
        'setup.py': '',
        'README.md': ''
    }
}

def create_directory_structure(structure, base_path=""):
    for name, content in structure.items():
        current_path = os.path.join(base_path, name)
        if isinstance(content, dict):
            # It's a directory
            os.makedirs(current_path, exist_ok=True)
            print(f"Created directory: {current_path}")
            create_directory_structure(content, current_path)
        else:
            # It's a file
            with open(current_path, 'w') as f:
                f.write(content)
            print(f"Created file: {current_path}")

create_directory_structure(project_structure)
print("Project structure created successfully!")