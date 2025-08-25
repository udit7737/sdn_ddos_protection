# Create HTML template for the dashboard
html_template_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SDN DDoS Protection Dashboard</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- D3.js for network visualization -->
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <!-- Socket.IO -->
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .dashboard-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .status-card {
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s;
        }
        
        .status-card:hover {
            transform: translateY(-2px);
        }
        
        .status-good { border-left: 5px solid #28a745; }
        .status-warning { border-left: 5px solid #ffc107; }
        .status-danger { border-left: 5px solid #dc3545; }
        
        .metric-value {
            font-size: 2rem;
            font-weight: bold;
            color: #495057;
        }
        
        .metric-label {
            font-size: 0.9rem;
            color: #6c757d;
            text-transform: uppercase;
        }
        
        .attack-alert {
            background: linear-gradient(135deg, #ff6b6b, #ffa500);
            color: white;
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        .network-topology {
            border: 1px solid #dee2e6;
            border-radius: 10px;
            background: white;
            min-height: 400px;
        }
        
        .topology-node {
            cursor: pointer;
        }
        
        .topology-node.switch {
            fill: #007bff;
        }
        
        .topology-node.host {
            fill: #28a745;
        }
        
        .topology-link {
            stroke: #6c757d;
            stroke-width: 2;
        }
        
        .logs-container {
            max-height: 300px;
            overflow-y: auto;
            background: #f8f9fa;
            border-radius: 5px;
            padding: 1rem;
        }
        
        .log-entry {
            padding: 0.5rem;
            margin-bottom: 0.5rem;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.9rem;
        }
        
        .log-info { background-color: #d1ecf1; color: #0c5460; }
        .log-warning { background-color: #fff3cd; color: #856404; }
        .log-error { background-color: #f8d7da; color: #721c24; }
        
        .control-panel {
            background: white;
            border-radius: 10px;
            padding: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .nav-tabs .nav-link.active {
            background-color: #667eea;
            border-color: #667eea;
            color: white;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            background: white;
            border-radius: 10px;
            padding: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="dashboard-header">
        <div class="container-fluid">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <h1><i class="fas fa-shield-alt"></i> SDN DDoS Protection Dashboard</h1>
                </div>
                <div class="col-md-6 text-end">
                    <div class="d-flex align-items-center justify-content-end">
                        <div class="me-3">
                            <span id="connection-status" class="badge bg-secondary">
                                <i class="fas fa-circle"></i> Connecting...
                            </span>
                        </div>
                        <div class="text-white-50">
                            Last Update: <span id="last-update">--:--:--</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Attack Alert -->
    <div class="container-fluid mt-3">
        <div id="attack-alert" class="attack-alert d-none">
            <div class="d-flex align-items-center">
                <i class="fas fa-exclamation-triangle fa-2x me-3"></i>
                <div>
                    <h5 class="mb-1">DDoS Attack Detected!</h5>
                    <p class="mb-0" id="attack-details">Attack in progress...</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Dashboard -->
    <div class="container-fluid mt-3">
        <!-- Status Cards -->
        <div class="row mb-4">
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card status-card status-good">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col">
                                <div class="metric-label">Network Status</div>
                                <div class="metric-value" id="network-status">Active</div>
                            </div>
                            <div class="col-auto">
                                <i class="fas fa-network-wired fa-2x text-success"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card status-card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col">
                                <div class="metric-label">Switches</div>
                                <div class="metric-value" id="switches-count">0</div>
                            </div>
                            <div class="col-auto">
                                <i class="fas fa-server fa-2x text-primary"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card status-card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col">
                                <div class="metric-label">Packets/sec</div>
                                <div class="metric-value" id="packets-rate">0</div>
                            </div>
                            <div class="col-auto">
                                <i class="fas fa-tachometer-alt fa-2x text-info"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card status-card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col">
                                <div class="metric-label">Blocked IPs</div>
                                <div class="metric-value" id="blocked-ips">0</div>
                            </div>
                            <div class="col-auto">
                                <i class="fas fa-ban fa-2x text-danger"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content Tabs -->
        <div class="card">
            <div class="card-header">
                <ul class="nav nav-tabs card-header-tabs" id="main-tabs">
                    <li class="nav-item">
                        <a class="nav-link active" href="#topology-tab" data-bs-toggle="tab">
                            <i class="fas fa-project-diagram"></i> Network Topology
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#traffic-tab" data-bs-toggle="tab">
                            <i class="fas fa-chart-line"></i> Traffic Analysis
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#attacks-tab" data-bs-toggle="tab">
                            <i class="fas fa-exclamation-triangle"></i> Attack Monitor
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#controls-tab" data-bs-toggle="tab">
                            <i class="fas fa-cogs"></i> Controls
                        </a>
                    </li>
                </ul>
            </div>
            <div class="card-body">
                <div class="tab-content">
                    <!-- Network Topology Tab -->
                    <div class="tab-pane fade show active" id="topology-tab">
                        <div class="row">
                            <div class="col-lg-8">
                                <div class="network-topology">
                                    <svg id="topology-svg" width="100%" height="400"></svg>
                                </div>
                            </div>
                            <div class="col-lg-4">
                                <div class="card">
                                    <div class="card-header">
                                        <h6><i class="fas fa-info-circle"></i> Topology Information</h6>
                                    </div>
                                    <div class="card-body">
                                        <div id="topology-info">
                                            <p>Select a node to view details</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="card mt-3">
                                    <div class="card-header">
                                        <h6><i class="fas fa-list"></i> Network Statistics</h6>
                                    </div>
                                    <div class="card-body">
                                        <div id="network-stats">
                                            <div class="d-flex justify-content-between">
                                                <span>Total Flows:</span>
                                                <span id="total-flows">0</span>
                                            </div>
                                            <div class="d-flex justify-content-between">
                                                <span>Total Packets:</span>
                                                <span id="total-packets">0</span>
                                            </div>
                                            <div class="d-flex justify-content-between">
                                                <span>Total Bytes:</span>
                                                <span id="total-bytes">0</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Traffic Analysis Tab -->
                    <div class="tab-pane fade" id="traffic-tab">
                        <div class="row">
                            <div class="col-lg-6 mb-3">
                                <div class="chart-container">
                                    <canvas id="traffic-chart"></canvas>
                                </div>
                            </div>
                            <div class="col-lg-6 mb-3">
                                <div class="chart-container">
                                    <canvas id="protocol-chart"></canvas>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-lg-6 mb-3">
                                <div class="chart-container">
                                    <canvas id="bandwidth-chart"></canvas>
                                </div>
                            </div>
                            <div class="col-lg-6 mb-3">
                                <div class="chart-container">
                                    <canvas id="flows-chart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Attack Monitor Tab -->
                    <div class="tab-pane fade" id="attacks-tab">
                        <div class="row">
                            <div class="col-lg-8">
                                <div class="card">
                                    <div class="card-header">
                                        <h6><i class="fas fa-history"></i> Attack History</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="table-responsive">
                                            <table class="table table-striped" id="attacks-table">
                                                <thead>
                                                    <tr>
                                                        <th>Timestamp</th>
                                                        <th>Type</th>
                                                        <th>Source</th>
                                                        <th>Target</th>
                                                        <th>Severity</th>
                                                        <th>Status</th>
                                                    </tr>
                                                </thead>
                                                <tbody id="attacks-tbody">
                                                    <tr>
                                                        <td colspan="6" class="text-center">No attacks detected</td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-lg-4">
                                <div class="card">
                                    <div class="card-header">
                                        <h6><i class="fas fa-chart-pie"></i> Attack Statistics</h6>
                                    </div>
                                    <div class="card-body">
                                        <canvas id="attack-types-chart" height="200"></canvas>
                                    </div>
                                </div>
                                <div class="card mt-3">
                                    <div class="card-header">
                                        <h6><i class="fas fa-shield-alt"></i> Detection Status</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="d-flex justify-content-between">
                                            <span>Detection Active:</span>
                                            <span class="badge bg-success" id="detection-status">Yes</span>
                                        </div>
                                        <div class="d-flex justify-content-between mt-2">
                                            <span>ML Models Loaded:</span>
                                            <span id="ml-models">0/4</span>
                                        </div>
                                        <div class="d-flex justify-content-between mt-2">
                                            <span>Buffer Size:</span>
                                            <span id="buffer-size">0</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Controls Tab -->
                    <div class="tab-pane fade" id="controls-tab">
                        <div class="row">
                            <div class="col-lg-6">
                                <div class="control-panel">
                                    <h6><i class="fas fa-ban"></i> IP Blocking</h6>
                                    <form id="block-ip-form">
                                        <div class="mb-3">
                                            <label for="ip-address" class="form-label">IP Address</label>
                                            <input type="text" class="form-control" id="ip-address" 
                                                   placeholder="192.168.1.100" required>
                                        </div>
                                        <div class="mb-3">
                                            <label for="block-duration" class="form-label">Duration (seconds)</label>
                                            <input type="number" class="form-control" id="block-duration" 
                                                   value="600" min="1" max="3600">
                                        </div>
                                        <div class="mb-3">
                                            <button type="submit" class="btn btn-danger me-2">
                                                <i class="fas fa-ban"></i> Block IP
                                            </button>
                                            <button type="button" class="btn btn-success" id="unblock-btn">
                                                <i class="fas fa-check"></i> Unblock IP
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                            <div class="col-lg-6">
                                <div class="control-panel">
                                    <h6><i class="fas fa-list"></i> Active Rules</h6>
                                    <div id="active-rules" style="max-height: 300px; overflow-y: auto;">
                                        <p class="text-muted">No active mitigation rules</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-12">
                                <div class="control-panel">
                                    <h6><i class="fas fa-terminal"></i> System Logs</h6>
                                    <div class="logs-container" id="system-logs">
                                        <div class="log-entry log-info">
                                            <i class="fas fa-info-circle"></i> System initialized
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Dashboard JavaScript -->
    <script>
        // Dashboard state
        let socket;
        let charts = {};
        let topologyData = { nodes: [], links: [] };
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeWebSocket();
            initializeCharts();
            initializeTopology();
            initializeControls();
            fetchInitialData();
        });
        
        // WebSocket connection
        function initializeWebSocket() {
            socket = io();
            
            socket.on('connect', function() {
                updateConnectionStatus('connected');
                addLog('Connected to dashboard server', 'info');
            });
            
            socket.on('disconnect', function() {
                updateConnectionStatus('disconnected');
                addLog('Disconnected from dashboard server', 'warning');
            });
            
            socket.on('stats_update', function(data) {
                updateDashboard(data);
            });
            
            socket.on('attack_alert', function(data) {
                showAttackAlert(data);
            });
            
            socket.on('topology_update', function(data) {
                updateTopology(data);
            });
            
            socket.on('error', function(data) {
                addLog('Error: ' + data.message, 'error');
            });
        }
        
        // Update connection status
        function updateConnectionStatus(status) {
            const statusElement = document.getElementById('connection-status');
            if (status === 'connected') {
                statusElement.innerHTML = '<i class="fas fa-circle text-success"></i> Connected';
                statusElement.className = 'badge bg-success';
            } else {
                statusElement.innerHTML = '<i class="fas fa-circle text-danger"></i> Disconnected';
                statusElement.className = 'badge bg-danger';
            }
        }
        
        // Update main dashboard
        function updateDashboard(data) {
            // Update metrics
            document.getElementById('switches-count').textContent = data.switches || 0;
            document.getElementById('total-flows').textContent = data.flows || 0;
            document.getElementById('total-packets').textContent = (data.packets || 0).toLocaleString();
            document.getElementById('total-bytes').textContent = formatBytes(data.bytes || 0);
            document.getElementById('blocked-ips').textContent = (data.blocked_ips || []).length;
            
            // Update network status
            const networkStatus = document.getElementById('network-status');
            if (data.attack_detected) {
                networkStatus.textContent = 'Under Attack';
                networkStatus.parentElement.parentElement.parentElement.className = 'card status-card status-danger';
            } else {
                networkStatus.textContent = 'Active';
                networkStatus.parentElement.parentElement.parentElement.className = 'card status-card status-good';
            }
            
            // Update last update time
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
            
            // Update charts
            updateTrafficChart(data);
        }
        
        // Show attack alert
        function showAttackAlert(data) {
            const alertElement = document.getElementById('attack-alert');
            const detailsElement = document.getElementById('attack-details');
            
            detailsElement.textContent = `Attack type: ${data.type || 'Unknown'} - Blocked IPs: ${(data.blocked_ips || []).length}`;
            alertElement.classList.remove('d-none');
            
            // Auto-hide after 10 seconds
            setTimeout(() => {
                alertElement.classList.add('d-none');
            }, 10000);
        }
        
        // Initialize charts
        function initializeCharts() {
            // Traffic chart
            const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
            charts.traffic = new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Packets/sec',
                        data: [],
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.1)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
            
            // Protocol distribution chart
            const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
            charts.protocol = new Chart(protocolCtx, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            'rgba(54, 162, 235, 0.8)',
                            'rgba(255, 99, 132, 0.8)',
                            'rgba(255, 205, 86, 0.8)',
                            'rgba(75, 192, 192, 0.8)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
        
        // Initialize network topology
        function initializeTopology() {
            const svg = d3.select("#topology-svg");
            const width = svg.node().getBoundingClientRect().width;
            const height = 400;
            
            svg.attr("width", width).attr("height", height);
            
            // Add zoom behavior
            const g = svg.append("g");
            svg.call(d3.zoom().on("zoom", (event) => {
                g.attr("transform", event.transform);
            }));
            
            // Initialize force simulation
            this.simulation = d3.forceSimulation()
                .force("link", d3.forceLink().id(d => d.id))
                .force("charge", d3.forceManyBody().strength(-300))
                .force("center", d3.forceCenter(width / 2, height / 2));
        }
        
        // Update topology
        function updateTopology(data) {
            if (!data || !data.nodes) return;
            
            topologyData = data;
            renderTopology();
        }
        
        // Render topology visualization
        function renderTopology() {
            const svg = d3.select("#topology-svg g");
            
            // Clear previous elements
            svg.selectAll("*").remove();
            
            // Create links
            const link = svg.append("g")
                .selectAll("line")
                .data(topologyData.links)
                .enter().append("line")
                .attr("class", "topology-link");
            
            // Create nodes
            const node = svg.append("g")
                .selectAll("circle")
                .data(topologyData.nodes)
                .enter().append("circle")
                .attr("class", d => `topology-node ${d.type}`)
                .attr("r", d => d.type === 'switch' ? 15 : 10)
                .on("click", function(event, d) {
                    showNodeDetails(d);
                });
            
            // Add labels
            const labels = svg.append("g")
                .selectAll("text")
                .data(topologyData.nodes)
                .enter().append("text")
                .text(d => d.name)
                .attr("font-size", "12px")
                .attr("text-anchor", "middle")
                .attr("dy", 4);
            
            // Update simulation
            this.simulation.nodes(topologyData.nodes);
            this.simulation.force("link").links(topologyData.links);
            
            this.simulation.on("tick", () => {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);
                
                node
                    .attr("cx", d => d.x)
                    .attr("cy", d => d.y);
                
                labels
                    .attr("x", d => d.x)
                    .attr("y", d => d.y + 25);
            });
        }
        
        // Show node details
        function showNodeDetails(node) {
            const infoDiv = document.getElementById('topology-info');
            infoDiv.innerHTML = `
                <h6>${node.name}</h6>
                <p><strong>Type:</strong> ${node.type}</p>
                <p><strong>Status:</strong> ${node.status}</p>
                ${node.ip ? `<p><strong>IP:</strong> ${node.ip}</p>` : ''}
                ${node.mac ? `<p><strong>MAC:</strong> ${node.mac}</p>` : ''}
                ${node.dpid ? `<p><strong>DPID:</strong> ${node.dpid}</p>` : ''}
            `;
        }
        
        // Initialize controls
        function initializeControls() {
            // Block IP form
            document.getElementById('block-ip-form').addEventListener('submit', function(e) {
                e.preventDefault();
                const ipAddress = document.getElementById('ip-address').value;
                const duration = document.getElementById('block-duration').value;
                
                blockIP(ipAddress, duration);
            });
            
            // Unblock IP button
            document.getElementById('unblock-btn').addEventListener('click', function() {
                const ipAddress = document.getElementById('ip-address').value;
                if (ipAddress) {
                    unblockIP(ipAddress);
                }
            });
        }
        
        // Block IP address
        function blockIP(ipAddress, duration) {
            fetch('/api/mitigation/block', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip_address: ipAddress,
                    duration: parseInt(duration)
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    addLog(`IP ${ipAddress} blocked for ${duration} seconds`, 'info');
                    refreshActiveRules();
                } else {
                    addLog(`Error blocking IP: ${data.error}`, 'error');
                }
            })
            .catch(error => {
                addLog(`Error blocking IP: ${error}`, 'error');
            });
        }
        
        // Unblock IP address
        function unblockIP(ipAddress) {
            fetch('/api/mitigation/unblock', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip_address: ipAddress
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    addLog(`IP ${ipAddress} unblocked`, 'info');
                    refreshActiveRules();
                } else {
                    addLog(`Error unblocking IP: ${data.error}`, 'error');
                }
            })
            .catch(error => {
                addLog(`Error unblocking IP: ${error}`, 'error');
            });
        }
        
        // Add log entry
        function addLog(message, type) {
            const logsContainer = document.getElementById('system-logs');
            const logEntry = document.createElement('div');
            logEntry.className = `log-entry log-${type}`;
            
            const timestamp = new Date().toLocaleTimeString();
            const icon = type === 'info' ? 'info-circle' : type === 'warning' ? 'exclamation-triangle' : 'times-circle';
            
            logEntry.innerHTML = `<i class="fas fa-${icon}"></i> [${timestamp}] ${message}`;
            
            logsContainer.appendChild(logEntry);
            logsContainer.scrollTop = logsContainer.scrollHeight;
            
            // Keep only last 50 log entries
            while (logsContainer.children.length > 50) {
                logsContainer.removeChild(logsContainer.firstChild);
            }
        }
        
        // Fetch initial data
        function fetchInitialData() {
            // Get topology
            fetch('/api/network/topology')
                .then(response => response.json())
                .then(data => updateTopology(data))
                .catch(error => console.error('Error fetching topology:', error));
            
            // Get initial stats
            fetch('/api/status')
                .then(response => response.json())
                .then(data => updateDashboard(data.network_stats || {}))
                .catch(error => console.error('Error fetching status:', error));
            
            // Get attack history
            refreshAttackHistory();
            
            // Get active rules
            refreshActiveRules();
        }
        
        // Refresh attack history
        function refreshAttackHistory() {
            fetch('/api/attacks/history')
                .then(response => response.json())
                .then(data => {
                    updateAttackHistory(data.attacks || []);
                })
                .catch(error => console.error('Error fetching attack history:', error));
        }
        
        // Update attack history table
        function updateAttackHistory(attacks) {
            const tbody = document.getElementById('attacks-tbody');
            tbody.innerHTML = '';
            
            if (attacks.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center">No attacks detected</td></tr>';
                return;
            }
            
            attacks.forEach(attack => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(attack.timestamp).toLocaleString()}</td>
                    <td><span class="badge bg-warning">${attack.type}</span></td>
                    <td>${attack.source_ip || 'Unknown'}</td>
                    <td>${attack.target_ip || 'Unknown'}</td>
                    <td><span class="badge bg-${attack.severity === 'high' ? 'danger' : attack.severity === 'medium' ? 'warning' : 'info'}">${attack.severity}</span></td>
                    <td><span class="badge bg-success">Mitigated</span></td>
                `;
                tbody.appendChild(row);
            });
        }
        
        // Refresh active rules
        function refreshActiveRules() {
            fetch('/api/mitigation/rules')
                .then(response => response.json())
                .then(data => {
                    updateActiveRules(data.active_rules || []);
                })
                .catch(error => console.error('Error fetching rules:', error));
        }
        
        // Update active rules display
        function updateActiveRules(rules) {
            const container = document.getElementById('active-rules');
            container.innerHTML = '';
            
            if (rules.length === 0) {
                container.innerHTML = '<p class="text-muted">No active mitigation rules</p>';
                return;
            }
            
            rules.forEach(rule => {
                const ruleElement = document.createElement('div');
                ruleElement.className = 'border rounded p-2 mb-2';
                ruleElement.innerHTML = `
                    <div class="d-flex justify-content-between">
                        <span><strong>${rule.rule_type}</strong></span>
                        <span class="badge bg-info">${Math.round(rule.remaining_time)}s</span>
                    </div>
                    <div class="text-muted small">Target: ${rule.target}</div>
                `;
                container.appendChild(ruleElement);
            });
        }
        
        // Update traffic chart
        function updateTrafficChart(data) {
            if (!charts.traffic) return;
            
            const now = new Date().toLocaleTimeString();
            const packetsPerSec = Math.round(data.packets / (data.time_span || 1));
            
            // Add new data point
            charts.traffic.data.labels.push(now);
            charts.traffic.data.datasets[0].data.push(packetsPerSec);
            
            // Keep only last 20 data points
            if (charts.traffic.data.labels.length > 20) {
                charts.traffic.data.labels.shift();
                charts.traffic.data.datasets[0].data.shift();
            }
            
            charts.traffic.update('none');
        }
        
        // Format bytes
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Auto-refresh data every 30 seconds
        setInterval(() => {
            fetchInitialData();
        }, 30000);
    </script>
</body>
</html>'''

with open('sdn_ddos_protection/dashboard/templates/index.html', 'w') as f:
    f.write(html_template_content)

print("Dashboard HTML template created successfully!")