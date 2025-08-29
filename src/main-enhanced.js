// src/main-enhanced.js
import './style.css';

// API Configuration
const API_BASE_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:3001' 
    : window.location.origin;

const WS_URL = window.location.hostname === 'localhost'
    ? 'ws://localhost:3001'
    : `wss://${window.location.host}`;

// Enhanced Network Analyzer with Backend Support
class EnhancedNetworkAnalyzer {
    constructor() {
        // Core properties
        this.isRunning = false;
        this.testResults = [];
        this.currentTarget = '';
        this.testCount = 0;
        this.successCount = 0;
        this.failCount = 0;
        this.chartData = [];
        this.maxDataPoints = 50;
        this.abortController = null;
        this.testHistory = [];
        this.gamingModeEnabled = false;
        this.comparisonResults = null;
        this.currentSort = 'avg';
        this.useBackend = true; // Flag to use backend when available
        this.ws = null; // WebSocket connection
        this.monitoringSessionId = null;
        this.db = null; // IndexedDB instance
        
        // Enhanced server locations database
        this.serverLocations = {
            '8.8.8.8': { name: 'Google DNS Primary', location: 'USA', flag: '🇺🇸', lat: 37.4192, lng: -122.0574, provider: 'Google' },
            '8.8.4.4': { name: 'Google DNS Secondary', location: 'USA', flag: '🇺🇸', lat: 37.4192, lng: -122.0574, provider: 'Google' },
            '1.1.1.1': { name: 'Cloudflare Primary', location: 'Global', flag: '🌍', lat: 37.7749, lng: -122.4194, provider: 'Cloudflare' },
            '1.0.0.1': { name: 'Cloudflare Secondary', location: 'Global', flag: '🌍', lat: 37.7749, lng: -122.4194, provider: 'Cloudflare' },
            '208.67.222.222': { name: 'OpenDNS Primary', location: 'USA', flag: '🇺🇸', lat: 37.7749, lng: -122.4194, provider: 'Cisco' },
            '208.67.220.220': { name: 'OpenDNS Secondary', location: 'USA', flag: '🇺🇸', lat: 37.7749, lng: -122.4194, provider: 'Cisco' },
            '9.9.9.9': { name: 'Quad9', location: 'Switzerland', flag: '🇨🇭', lat: 47.3769, lng: 8.5417, provider: 'Quad9' },
            '94.140.14.14': { name: 'AdGuard DNS', location: 'Cyprus', flag: '🇨🇾', lat: 35.1856, lng: 33.3823, provider: 'AdGuard' },
            '76.76.19.19': { name: 'Alternate DNS', location: 'USA', flag: '🇺🇸', lat: 40.7128, lng: -74.0060, provider: 'Alternate DNS' },
            '185.228.168.9': { name: 'CleanBrowsing', location: 'USA', flag: '🇺🇸', lat: 37.7749, lng: -122.4194, provider: 'CleanBrowsing' },
            'google.com': { name: 'Google', location: 'USA', flag: '🇺🇸', lat: 37.4192, lng: -122.0574, provider: 'Google' },
            'facebook.com': { name: 'Facebook', location: 'USA', flag: '🇺🇸', lat: 37.4852, lng: -122.1504, provider: 'Meta' },
            'youtube.com': { name: 'YouTube', location: 'USA', flag: '🇺🇸', lat: 37.4192, lng: -122.0574, provider: 'Google' },
            'twitter.com': { name: 'Twitter/X', location: 'USA', flag: '🇺🇸', lat: 37.7749, lng: -122.4194, provider: 'X Corp' }
        };
        
        // Enhanced configuration
        this.config = {
            alerts: {
                highLatency: 200,
                highLatencyGaming: 50,
                highJitter: 100,
                highJitterGaming: 20,
                packetLossThreshold: 5
            },
            defaults: {
                testCount: 10,
                interval: 1,
                timeout: 5000,
                testsPerBatch: 5
            },
            history: {
                maxItems: 100,
                autoSave: true
            },
            ui: {
                darkModeDefault: false,
                soundEnabled: true,
                notificationsEnabled: false,
                animationsEnabled: true
            },
            backend: {
                enabled: true,
                autoReconnect: true,
                reconnectInterval: 5000
            }
        };
        
        this.init();
    }

    async init() {
        await this.initIndexedDB();
        await this.checkBackendConnection();
        this.initWebSocket();
        this.initializeHistory();
        this.renderUI();
        this.bindEvents();
        this.initChart();
        this.checkPWASupport();
        this.initNotifications();
        this.loadSettings();
        console.log('Enhanced Network Analyzer v2.0 Initialized');
        
        // Show backend status
        this.updateBackendStatus();
    }

    // Initialize IndexedDB for better storage
    async initIndexedDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('NetworkAnalyzerDB', 1);
            
            request.onerror = () => {
                console.error('Failed to open IndexedDB');
                resolve(); // Continue without DB
            };
            
            request.onsuccess = (event) => {
                this.db = event.target.result;
                console.log('IndexedDB initialized');
                resolve();
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create object stores
                if (!db.objectStoreNames.contains('tests')) {
                    const testStore = db.createObjectStore('tests', { 
                        keyPath: 'id', 
                        autoIncrement: true 
                    });
                    testStore.createIndex('timestamp', 'timestamp');
                    testStore.createIndex('target', 'target');
                    testStore.createIndex('score', 'qualityScore');
                }
                
                if (!db.objectStoreNames.contains('history')) {
                    const historyStore = db.createObjectStore('history', { 
                        keyPath: 'id', 
                        autoIncrement: true 
                    });
                    historyStore.createIndex('timestamp', 'timestamp');
                }
                
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings', { keyPath: 'key' });
                }
            };
        });
    }

    // Check if backend server is available
    async checkBackendConnection() {
        if (!this.config.backend.enabled) {
            this.useBackend = false;
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/api/network-stats`, {
                method: 'GET',
                signal: AbortSignal.timeout(2000)
            });
            
            this.useBackend = response.ok;
            console.log(`Backend server ${this.useBackend ? 'connected' : 'not available'}`);
        } catch (error) {
            this.useBackend = false;
            console.log('Backend server not available, using fallback mode');
        }
    }

    // Initialize WebSocket connection
    initWebSocket() {
        if (!this.useBackend) return;

        try {
            this.ws = new WebSocket(WS_URL);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.updateBackendStatus();
            };
            
            this.ws.onmessage = (event) => {
                this.handleWebSocketMessage(event);
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateBackendStatus();
                
                // Auto-reconnect if enabled
                if (this.config.backend.autoReconnect && this.useBackend) {
                    setTimeout(() => this.initWebSocket(), this.config.backend.reconnectInterval);
                }
            };
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
        }
    }

    // Handle WebSocket messages
    handleWebSocketMessage(event) {
        try {
            const data = JSON.parse(event.data);
            
            switch (data.type) {
                case 'monitoring-update':
                    this.handleMonitoringUpdate(data.data);
                    break;
                    
                case 'monitoring-started':
                    this.addLog(`✅ Real-time monitoring started for ${data.host}`, 'success');
                    break;
                    
                case 'monitoring-stopped':
                    this.addLog(`⏹️ Monitoring stopped (Duration: ${(data.duration / 1000).toFixed(1)}s)`, 'info');
                    break;
                    
                case 'ping-result':
                    this.handlePingResult(data.data);
                    break;
                    
                default:
                    console.log('Unknown WebSocket message type:', data.type);
            }
        } catch (error) {
            console.error('Error handling WebSocket message:', error);
        }
    }

    // Handle real-time monitoring updates
    handleMonitoringUpdate(data) {
        if (!data.alive) {
            this.failCount++;
            this.testResults.push(null);
            this.addLog(`❌ Real-time: Host unreachable`, 'error');
        } else {
            this.successCount++;
            this.testResults.push(data.time);
            this.chartData.push({ x: this.testCount++, y: data.time });
            
            if (this.chartData.length > this.maxDataPoints) {
                this.chartData.shift();
            }
            
            this.updateMetrics();
            this.calculateAdvancedMetrics();
            this.drawChart();
            this.drawHistogram();
            this.updateQualityScore();
            this.updateGamingStats();
            
            const quality = this.getQuality(data.time);
            this.addLog(
                `✅ Real-time: ${data.time.toFixed(2)}ms - ${quality.label}`,
                quality.class
            );
        }
    }

    // Enhanced ping function using backend when available
    async performSingleTest() {
        this.testCount++;
        const testNumber = this.testCount;

        try {
            let latency;
            
            if (this.useBackend) {
                // Use backend for accurate ping
                latency = await this.backendPing();
            } else {
                // Fallback to browser-based measurement
                latency = await this.measureLatency();
            }
            
            if (latency !== null) {
                this.successCount++;
                this.testResults.push(latency);
                this.chartData.push({ x: testNumber, y: latency });

                if (this.chartData.length > this.maxDataPoints) {
                    this.chartData.shift();
                }

                this.updateMetrics();
                this.calculateAdvancedMetrics();
                this.drawChart();
                this.drawHistogram();
                this.updateQualityScore();
                this.generateSmartTips();
                this.updateGamingStats();
                this.checkAlerts(latency);

                const quality = this.getQuality(latency);
                this.addLog(
                    `✅ Test #${testNumber}: ${latency.toFixed(2)}ms - ${quality.label} ${this.useBackend ? '(Backend)' : '(Browser)'}`,
                    quality.class
                );
                
                // Save to IndexedDB
                await this.saveTestResult({
                    testNumber,
                    latency,
                    timestamp: Date.now(),
                    target: this.currentTarget,
                    method: this.useBackend ? 'backend' : 'browser'
                });
            }
        } catch (error) {
            this.failCount++;
            this.testResults.push(null);
            this.addLog(`❌ Test #${testNumber}: Failed - ${error.message}`, 'error');
            this.updateMetrics();
            this.calculateAdvancedMetrics();
        }
    }

    // Backend ping implementation
    async backendPing() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/ping`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    host: this.currentTarget,
                    count: 1,
                    timeout: 2
                }),
                signal: AbortSignal.timeout(5000)
            });
            
            if (!response.ok) {
                throw new Error(`Backend ping failed: ${response.statusText}`);
            }
            
            const data = await response.json();
            return data.alive ? data.time : null;
        } catch (error) {
            console.error('Backend ping error:', error);
            // Fallback to browser-based measurement
            return await this.measureLatency();
        }
    }

    // Enhanced traceroute functionality
    async performTraceroute() {
        if (!this.useBackend) {
            this.addLog('⚠️ Traceroute requires backend server', 'warning');
            return;
        }

        this.addLog(`🔍 Starting traceroute to ${this.currentTarget}...`, 'info');

        try {
            const response = await fetch(`${API_BASE_URL}/api/traceroute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    host: this.currentTarget,
                    maxHops: 30
                })
            });
            
            if (!response.ok) {
                throw new Error(`Traceroute failed: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.displayTraceroute(data.hops);
        } catch (error) {
            this.addLog(`❌ Traceroute failed: ${error.message}`, 'error');
        }
    }

    // Display traceroute results
    displayTraceroute(hops) {
        let html = `
            <div class="card traceroute-results">
                <h3>🔍 Traceroute Results</h3>
                <div class="traceroute-target">Target: ${this.currentTarget}</div>
                <div class="traceroute-hops">
        `;
        
        hops.forEach((hop) => {
            const avgTime = hop.avg ? hop.avg.toFixed(2) : 'N/A';
            html += `
                <div class="hop-item">
                    <span class="hop-number">${hop.hop}</span>
                    <span class="hop-ip">${hop.ip}</span>
                    <span class="hop-time">${avgTime}ms</span>
                </div>
            `;
        });
        
        html += `
                </div>
                <div class="traceroute-summary">
                    Total hops: ${hops.length}
                </div>
            </div>
        `;
        
        // Add to UI
        const container = document.getElementById('tracerouteContainer');
        if (container) {
            container.innerHTML = html;
        }
        
        this.addLog(`✅ Traceroute complete: ${hops.length} hops`, 'success');
    }

    // Enhanced batch testing with backend
    async compareAllDNS() {
        const dnsServers = [
            '8.8.8.8',
            '1.1.1.1',
            '9.9.9.9',
            '208.67.222.222',
            '94.140.14.14',
            '76.76.19.19',
            '185.228.168.9'
        ];

        this.addLog('🔄 Starting comprehensive DNS comparison...', 'info');

        if (this.useBackend) {
            // Use backend batch test for better performance
            try {
                const response = await fetch(`${API_BASE_URL}/api/batch-test`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        servers: dnsServers,
                        testsPerServer: 10
                    })
                });
                
                if (!response.ok) {
                    throw new Error(`Batch test failed: ${response.statusText}`);
                }
                
                const data = await response.json();
                this.processBackendBatchResults(data.results);
            } catch (error) {
                this.addLog(`⚠️ Backend batch test failed, using fallback`, 'warning');
                await this.fallbackDNSComparison(dnsServers);
            }
        } else {
            await this.fallbackDNSComparison(dnsServers);
        }
    }

    // Process backend batch test results
    processBackendBatchResults(results) {
        const processedResults = results.map(result => {
            if (!result.success) {
                return null;
            }
            
            const serverInfo = this.serverLocations[result.server] || {
                name: result.server,
                location: 'Unknown',
                flag: '🌐'
            };
            
            return {
                server: result.server,
                info: serverInfo,
                avg: result.avg,
                min: result.min,
                max: result.max,
                jitter: result.jitter,
                successRate: (result.successCount / result.totalCount) * 100,
                packetLoss: result.packetLoss,
                method: 'backend'
            };
        }).filter(r => r !== null);
        
        this.displayComparisonResults(processedResults);
    }

    // Fallback DNS comparison (browser-based)
    async fallbackDNSComparison(dnsServers) {
        const results = [];

        for (const server of dnsServers) {
            const serverInfo = this.serverLocations[server];
            this.addLog(`Testing ${serverInfo.flag} ${serverInfo.name}...`, 'info');
            
            const testResults = [];
            for (let i = 0; i < 10; i++) {
                try {
                    const startTime = performance.now();
                    await fetch(`https://${server}`, {
                        method: 'HEAD',
                        mode: 'no-cors',
                        cache: 'no-cache',
                        signal: AbortSignal.timeout(2000)
                    });
                    const latency = performance.now() - startTime;
                    testResults.push(latency);
                } catch (error) {
                    testResults.push(null);
                }
                await this.sleep(200);
            }

            const validResults = testResults.filter(r => r !== null);
            if (validResults.length > 0) {
                results.push({
                    server: server,
                    info: serverInfo,
                    avg: validResults.reduce((a, b) => a + b, 0) / validResults.length,
                    min: Math.min(...validResults),
                    max: Math.max(...validResults),
                    jitter: this.calculateJitter(validResults),
                    successRate: (validResults.length / testResults.length) * 100,
                    packetLoss: ((testResults.length - validResults.length) / testResults.length) * 100,
                    method: 'browser'
                });
            }
        }

        this.displayComparisonResults(results);
    }

    // Save test result to IndexedDB
    async saveTestResult(data) {
        if (!this.db) return;
        
        try {
            const transaction = this.db.transaction(['tests'], 'readwrite');
            const store = transaction.objectStore('tests');
            
            const testData = {
                ...data,
                qualityScore: this.calculateQualityScore(),
                sessionId: this.monitoringSessionId
            };
            
            await store.add(testData);
        } catch (error) {
            console.error('Failed to save test result:', error);
        }
    }

    // Load test history from IndexedDB
    async loadTestHistory(target = null, limit = 100) {
        if (!this.db) return [];
        
        try {
            const transaction = this.db.transaction(['tests'], 'readonly');
            const store = transaction.objectStore('tests');
            
            let results;
            if (target) {
                const index = store.index('target');
                results = await index.getAll(target, limit);
            } else {
                results = await store.getAll();
            }
            
            return results.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
        } catch (error) {
            console.error('Failed to load test history:', error);
            return [];
        }
    }

    // Save settings to IndexedDB
    async saveSettings() {
        if (!this.db) {
            localStorage.setItem('networkAnalyzerSettings', JSON.stringify(this.config));
            return;
        }
        
        try {
            const transaction = this.db.transaction(['settings'], 'readwrite');
            const store = transaction.objectStore('settings');
            
            await store.put({
                key: 'config',
                value: this.config,
                timestamp: Date.now()
            });
        } catch (error) {
            console.error('Failed to save settings:', error);
            localStorage.setItem('networkAnalyzerSettings', JSON.stringify(this.config));
        }
    }

    // Load settings from IndexedDB
    async loadSettings() {
        if (!this.db) {
            const saved = localStorage.getItem('networkAnalyzerSettings');
            if (saved) {
                this.config = { ...this.config, ...JSON.parse(saved) };
            }
            return;
        }
        
        try {
            const transaction = this.db.transaction(['settings'], 'readonly');
            const store = transaction.objectStore('settings');
            const result = await store.get('config');
            
            if (result) {
                this.config = { ...this.config, ...result.value };
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    // Update backend status indicator
    updateBackendStatus() {
        const statusEl = document.getElementById('backendStatus');
        if (!statusEl) return;
        
        if (this.useBackend && this.ws && this.ws.readyState === WebSocket.OPEN) {
            statusEl.innerHTML = `
                <span class="backend-indicator online">
                    <span class="pulse"></span>
                    Backend Connected
                </span>
            `;
        } else if (this.useBackend) {
            statusEl.innerHTML = `
                <span class="backend-indicator partial">
                    <span class="pulse"></span>
                    Backend Available (No WebSocket)
                </span>
            `;
        } else {
            statusEl.innerHTML = `
                <span class="backend-indicator offline">
                    <span class="pulse"></span>
                    Browser Mode Only
                </span>
            `;
        }
    }

    // Enhanced UI rendering with backend controls
    renderUI() {
        document.getElementById('app').innerHTML = `
            <div class="analyzer-container">
                <!-- Header -->
                <div class="header">
                    <h1>🌐 Network Latency Analyzer v2.0</h1>
                    <p>Professional Network Performance Analysis with Backend Support</p>
                    <div class="header-actions">
                        <div id="backendStatus" class="backend-status"></div>
                        <button class="mode-btn ${this.gamingModeEnabled ? 'active' : ''}" onclick="window.analyzer.toggleGamingMode()">
                            🎮 Gaming Mode
                        </button>
                        <button class="mode-btn" onclick="window.analyzer.toggleDarkMode()">
                            🌙 Dark Mode
                        </button>
                        <button class="mode-btn" onclick="window.analyzer.showSettings()">
                            ⚙️ Settings
                        </button>
                    </div>
                </div>

                <!-- Main Grid -->
                <div class="main-grid">
                    <!-- Control Panel -->
                    <div class="control-panel card">
                        <h2>
                            ⚙️ Control Panel
                            <span class="status-indicator idle" id="status">
                                <span class="pulse"></span>
                                Idle
                            </span>
                        </h2>

                        <div class="form-group">
                            <label>Target (IP or Domain):</label>
                            <div class="input-with-info">
                                <input type="text" id="target" value="8.8.8.8" placeholder="e.g., google.com">
                                <span class="server-info" id="serverInfo"></span>
                            </div>
                        </div>

                        <div class="preset-targets">
                            <button class="preset-btn" data-target="8.8.8.8" title="Google DNS Primary">
                                ${this.serverLocations['8.8.8.8'].flag} Google DNS
                            </button>
                            <button class="preset-btn" data-target="1.1.1.1" title="Cloudflare">
                                ${this.serverLocations['1.1.1.1'].flag} Cloudflare
                            </button>
                            <button class="preset-btn" data-target="9.9.9.9" title="Quad9">
                                ${this.serverLocations['9.9.9.9'].flag} Quad9
                            </button>
                            <button class="preset-btn" data-target="94.140.14.14" title="AdGuard">
                                ${this.serverLocations['94.140.14.14'].flag} AdGuard
                            </button>
                        </div>

                        <!-- Quick Actions -->
                        <div class="quick-actions">
                            <button class="quick-btn" onclick="window.analyzer.quickTest('fast')">
                                ⚡ Quick (5)
                            </button>
                            <button class="quick-btn" onclick="window.analyzer.quickTest('normal')">
                                🎯 Normal (10)
                            </button>
                            <button class="quick-btn" onclick="window.analyzer.quickTest('thorough')">
                                🔍 Thorough (25)
                            </button>
                            <button class="quick-btn gaming" onclick="window.analyzer.gamingTest()">
                                🎮 Gaming (50)
                            </button>
                        </div>

                        <div class="form-group">
                            <label>Number of Tests:</label>
                            <input type="number" id="testCount" value="${this.config.defaults.testCount}" min="1" max="100">
                        </div>

                        <div class="form-group">
                            <label>Interval (seconds):</label>
                            <input type="number" id="interval" value="${this.config.defaults.interval}" min="0.2" max="10" step="0.1">
                        </div>

                        <div class="checkbox-group">
                            <label>
                                <input type="checkbox" id="continuous">
                                Continuous Testing Mode
                            </label>
                        </div>

                        <div class="checkbox-group">
                            <label>
                                <input type="checkbox" id="realtimeMonitoring" ${this.useBackend ? '' : 'disabled'}>
                                Real-time WebSocket Monitoring ${!this.useBackend ? '(Backend Required)' : ''}
                            </label>
                        </div>

                        <div class="action-buttons">
                            <button class="btn btn-primary" id="startBtn">
                                ▶️ Start Test
                            </button>
                            <button class="btn btn-danger" id="stopBtn" style="display: none;">
                                ⏹️ Stop
                            </button>
                        </div>

                        <!-- Advanced Tools (Backend Required) -->
                        <div class="advanced-tools ${this.useBackend ? '' : 'disabled'}">
                            <h3>🔧 Advanced Tools</h3>
                            <button class="btn btn-secondary" onclick="window.analyzer.performTraceroute()" ${this.useBackend ? '' : 'disabled'}>
                                📍 Traceroute
                            </button>
                            <button class="btn btn-secondary" onclick="window.analyzer.performDNSLookup()" ${this.useBackend ? '' : 'disabled'}>
                                🔍 DNS Lookup
                            </button>
                            <button class="btn btn-secondary" onclick="window.analyzer.performPortCheck()" ${this.useBackend ? '' : 'disabled'}>
                                🔌 Port Check
                            </button>
                        </div>

                        <div class="export-options">
                            <button class="export-btn" onclick="window.analyzer.exportResults()">
                                📊 JSON
                            </button>
                            <button class="export-btn" onclick="window.analyzer.exportToCSV()">
                                📈 CSV
                            </button>
                            <button class="export-btn" onclick="window.analyzer.generatePDFReport()">
                                📄 Report
                            </button>
                        </div>

                        <button class="btn btn-secondary" onclick="window.analyzer.compareAllDNS()">
                            🔄 Compare All DNS Servers
                        </button>
                    </div>

                    <!-- Results Panel -->
                    <div class="results-panel">
                        <!-- Metrics Cards -->
                        <div class="metrics-grid">
                            <div class="metric-card" id="currentCard">
                                <div class="metric-label">Current Latency</div>
                                <div class="metric-value">
                                    <span id="currentLatency">--</span>
                                    <span class="metric-unit">ms</span>
                                </div>
                                <div class="metric-indicator" id="currentIndicator"></div>
                            </div>

                            <div class="metric-card" id="avgCard">
                                <div class="metric-label">Average</div>
                                <div class="metric-value">
                                    <span id="avgLatency">--</span>
                                    <span class="metric-unit">ms</span>
                                </div>
                                <div class="metric-indicator" id="avgIndicator"></div>
                            </div>

                            <div class="metric-card" id="jitterCard">
                                <div class="metric-label">Jitter</div>
                                <div class="metric-value">
                                    <span id="jitter">--</span>
                                    <span class="metric-unit">ms</span>
                                </div>
                                <div class="metric-indicator" id="jitterIndicator"></div>
                            </div>

                            <div class="metric-card" id="lossCard">
                                <div class="metric-label">Packet Loss</div>
                                <div class="metric-value">
                                    <span id="packetLoss">0</span>
                                    <span class="metric-unit">%</span>
                                </div>
                                <div class="metric-indicator" id="lossIndicator"></div>
                            </div>
                        </div>

                        <!-- Advanced Statistics Panel -->
                        <div class="card stats-panel">
                            <h3>📊 Advanced Statistics</h3>
                            <div class="stats-grid">
                                <div class="stat-item">
                                    <span class="stat-label">Min Latency:</span>
                                    <span class="stat-value" id="minLatency">--</span> ms
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Max Latency:</span>
                                    <span class="stat-value" id="maxLatency">--</span> ms
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Median:</span>
                                    <span class="stat-value" id="medianLatency">--</span> ms
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Std Dev:</span>
                                    <span class="stat-value" id="stdDev">--</span> ms
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Success Rate:</span>
                                    <span class="stat-value" id="successRate">--</span> %
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Total Tests:</span>
                                    <span class="stat-value" id="totalTests">0</span>
                                </div>
                            </div>
                        </div>

                        <!-- Quality Score Card -->
                        <div id="qualityScoreContainer"></div>

                        <!-- Smart Tips -->
                        <div id="smartTipsContainer"></div>

                        <!-- Traceroute Container -->
                        <div id="tracerouteContainer"></div>

                        <!-- Charts Container -->
                        <div class="charts-container">
                            <!-- Real-time Chart -->
                            <div class="card chart-container">
                                <h3>📈 Real-time Latency Graph</h3>
                                <canvas id="latencyChart"></canvas>
                            </div>

                            <!-- Histogram -->
                            <div class="card chart-container">
                                <h3>📊 Latency Distribution</h3>
                                <canvas id="histogramChart"></canvas>
                            </div>
                        </div>

                        <!-- Log -->
                        <div class="card log-container">
                            <div class="log-header">
                                <h3>📝 Results Log</h3>
                                <div class="log-actions">
                                    <select id="logFilter" onchange="window.analyzer.filterLogs()">
                                        <option value="all">All</option>
                                        <option value="success">Success</option>
                                        <option value="warning">Warning</option>
                                        <option value="error">Error</option>
                                    </select>
                                    <button class="btn-small" id="clearLogBtn">Clear</button>
                                </div>
                            </div>
                            <div class="log-entries" id="logEntries"></div>
                        </div>

                        <!-- History Panel -->
                        <div class="card history-panel">
                            <h3>📜 Test History</h3>
                            <div id="historyContainer"></div>
                        </div>

                        <!-- Comparison Results -->
                        <div id="comparisonContainer"></div>
                    </div>
                </div>
            </div>

            <!-- Gaming Mode Overlay -->
            <div id="gamingOverlay" class="gaming-overlay" style="display: none;">
                <div class="gaming-stats">
                    <div class="gaming-stat">
                        <span class="gaming-label">PING</span>
                        <span class="gaming-value" id="gamingPing">--</span>
                        <span class="gaming-unit">ms</span>
                    </div>
                    <div class="gaming-stat">
                        <span class="gaming-label">JITTER</span>
                        <span class="gaming-value" id="gamingJitter">--</span>
                        <span class="gaming-unit">ms</span>
                    </div>
                    <div class="gaming-stat">
                        <span class="gaming-label">LOSS</span>
                        <span class="gaming-value" id="gamingLoss">--</span>
                        <span class="gaming-unit">%</span>
                    </div>
                    <div class="gaming-stat">
                        <span class="gaming-label">STATUS</span>
                        <span class="gaming-value" id="gamingStatus">--</span>
                    </div>
                </div>
            </div>

            <!-- Settings Modal -->
            <div id="settingsModal" class="modal" style="display: none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h2>⚙️ Settings</h2>
                        <button class="modal-close" onclick="window.analyzer.closeSettings()">×</button>
                    </div>
                    <div class="modal-body">
                        <div class="settings-section">
                            <h3>Backend Configuration</h3>
                            <div class="setting-item">
                                <label>
                                    <input type="checkbox" id="backendEnabled" ${this.config.backend.enabled ? 'checked' : ''}>
                                    Enable Backend Server
                                </label>
                            </div>
                            <div class="setting-item">
                                <label>Backend URL:</label>
                                <input type="text" id="backendUrl" value="${API_BASE_URL}">
                            </div>
                        </div>
                        
                        <div class="settings-section">
                            <h3>Alert Thresholds</h3>
                            <div class="setting-item">
                                <label>High Latency (ms):</label>
                                <input type="number" id="highLatencyThreshold" value="${this.config.alerts.highLatency}">
                            </div>
                            <div class="setting-item">
                                <label>High Jitter (ms):</label>
                                <input type="number" id="highJitterThreshold" value="${this.config.alerts.highJitter}">
                            </div>
                        </div>
                        
                        <div class="settings-section">
                            <h3>UI Preferences</h3>
                            <div class="setting-item">
                                <label>
                                    <input type="checkbox" id="animationsEnabled" ${this.config.ui.animationsEnabled ? 'checked' : ''}>
                                    Enable Animations
                                </label>
                            </div>
                            <div class="setting-item">
                                <label>
                                    <input type="checkbox" id="soundEnabled" ${this.config.ui.soundEnabled ? 'checked' : ''}>
                                    Enable Sound Notifications
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary" onclick="window.analyzer.saveSettingsFromModal()">Save Settings</button>
                        <button class="btn btn-secondary" onclick="window.analyzer.closeSettings()">Cancel</button>
                    </div>
                </div>
            </div>
        `;
    }

    // Show settings modal
    showSettings() {
        document.getElementById('settingsModal').style.display = 'flex';
    }

    // Close settings modal
    closeSettings() {
        document.getElementById('settingsModal').style.display = 'none';
    }

    // Save settings from modal
    async saveSettingsFromModal() {
        this.config.backend.enabled = document.getElementById('backendEnabled').checked;
        this.config.alerts.highLatency = parseInt(document.getElementById('highLatencyThreshold').value);
        this.config.alerts.highJitter = parseInt(document.getElementById('highJitterThreshold').value);
        this.config.ui.animationsEnabled = document.getElementById('animationsEnabled').checked;
        this.config.ui.soundEnabled = document.getElementById('soundEnabled').checked;
        
        await this.saveSettings();
        this.closeSettings();
        this.addLog('✅ Settings saved successfully', 'success');
        
        // Reconnect if backend settings changed
        if (this.config.backend.enabled) {
            await this.checkBackendConnection();
            this.initWebSocket();
        }
        
        this.updateBackendStatus();
    }

    // Start real-time monitoring with WebSocket
    startRealtimeMonitoring() {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            this.addLog('⚠️ WebSocket not connected', 'warning');
            return;
        }
        
        this.monitoringSessionId = `session-${Date.now()}`;
        
        this.ws.send(JSON.stringify({
            action: 'start-monitoring',
            host: this.currentTarget,
            interval: parseFloat(document.getElementById('interval').value) * 1000,
            sessionId: this.monitoringSessionId
        }));
    }

    // Stop real-time monitoring
    stopRealtimeMonitoring() {
        if (!this.ws || !this.monitoringSessionId) return;
        
        this.ws.send(JSON.stringify({
            action: 'stop-monitoring',
            sessionId: this.monitoringSessionId
        }));
        
        this.monitoringSessionId = null;
    }

    // Enhanced start test with real-time monitoring option
    async startTest() {
        if (this.isRunning) return;

        this.currentTarget = document.getElementById('target').value.trim();
        if (!this.currentTarget) {
            this.addLog('⚠️ Please enter a target address', 'warning');
            return;
        }

        this.testResults = [];
        this.chartData = [];
        this.testCount = 0;
        this.successCount = 0;
        this.failCount = 0;
        this.isRunning = true;
        this.abortController = new AbortController();

        this.updateStatus('testing');
        this.addLog(`🚀 Starting test for ${this.currentTarget}`, 'success');

        const useRealtimeMonitoring = document.getElementById('realtimeMonitoring')?.checked;
        const count = parseInt(document.getElementById('testCount').value);
        const interval = parseFloat(document.getElementById('interval').value) * 1000;
        const continuous = document.getElementById('continuous').checked;

        if (useRealtimeMonitoring && this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.startRealtimeMonitoring();
        } else {
            if (continuous) {
                this.runContinuousTest(interval);
            } else {
                this.runLimitedTest(count, interval);
            }
        }
    }

    async runLimitedTest(count, interval) {
        for (let i = 0; i < count && this.isRunning; i++) {
            await this.performSingleTest();
            if (i < count - 1 && this.isRunning) {
                await this.sleep(interval);
            }
        }
        if (this.isRunning) {
            this.stopTest();
        }
    }

    async runContinuousTest(interval) {
        while (this.isRunning) {
            await this.performSingleTest();
            await this.sleep(interval);
        }
    }

    // DNS Lookup functionality
    async performDNSLookup() {
        if (!this.useBackend) {
            this.addLog('⚠️ DNS Lookup requires backend server', 'warning');
            return;
        }

        const target = this.currentTarget || document.getElementById('target').value.trim();
        if (!target) {
            this.addLog('⚠️ Please enter a target', 'warning');
            return;
        }

        this.addLog(`🔍 Performing DNS lookup for ${target}...`, 'info');

        try {
            const response = await fetch(`${API_BASE_URL}/api/dns-lookup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ hostname: target })
            });

            if (!response.ok) {
                throw new Error(`DNS lookup failed: ${response.statusText}`);
            }

            const data = await response.json();
            this.displayDNSResults(data);
        } catch (error) {
            this.addLog(`❌ DNS lookup failed: ${error.message}`, 'error');
        }
    }

    // Display DNS lookup results
    displayDNSResults(data) {
        const html = `
            <div class="card dns-results">
                <h3>🔍 DNS Lookup Results</h3>
                <div class="dns-info">
                    <div class="dns-item">
                        <span class="dns-label">Hostname:</span>
                        <span class="dns-value">${data.hostname}</span>
                    </div>
                    <div class="dns-item">
                        <span class="dns-label">IP Addresses:</span>
                        <span class="dns-value">${data.addresses.join(', ')}</span>
                    </div>
                    <div class="dns-item">
                        <span class="dns-label">Lookup Time:</span>
                        <span class="dns-value">${data.lookupTime}ms</span>
                    </div>
                    <div class="dns-item">
                        <span class="dns-label">DNS Servers:</span>
                        <span class="dns-value">${data.dnsServers.join(', ')}</span>
                    </div>
                </div>
            </div>
        `;

        const container = document.getElementById('tracerouteContainer');
        if (container) {
            container.innerHTML = html;
        }

        this.addLog(`✅ DNS lookup complete: ${data.addresses.length} addresses found`, 'success');
    }

    // Port check functionality
    async performPortCheck() {
        if (!this.useBackend) {
            this.addLog('⚠️ Port check requires backend server', 'warning');
            return;
        }

        const target = this.currentTarget || document.getElementById('target').value.trim();
        if (!target) {
            this.addLog('⚠️ Please enter a target', 'warning');
            return;
        }

        const port = prompt('Enter port number to check (e.g., 80, 443, 22):');
        if (!port) return;

        this.addLog(`🔌 Checking port ${port} on ${target}...`, 'info');

        try {
            const response = await fetch(`${API_BASE_URL}/api/port-check`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    host: target,
                    port: parseInt(port),
                    timeout: 3000
                })
            });

            if (!response.ok) {
                throw new Error(`Port check failed: ${response.statusText}`);
            }

            const data = await response.json();
            const status = data.open ? 'OPEN ✅' : 'CLOSED ❌';
            this.addLog(`Port ${port} on ${target} is ${status}`, data.open ? 'success' : 'warning');
        } catch (error) {
            this.addLog(`❌ Port check failed: ${error.message}`, 'error');
        }
    }

    // Original browser-based latency measurement (fallback)
    async measureLatency() {
        const startTime = performance.now();
        const timeout = this.config.defaults.timeout;

        try {
            const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(this.currentTarget);
            let url;

            if (isIP) {
                url = `https://${this.currentTarget}`;
            } else {
                url = this.currentTarget.startsWith('http') 
                    ? this.currentTarget 
                    : `https://${this.currentTarget}`;
            }

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            const response = await fetch(url, {
                method: 'HEAD',
                mode: 'no-cors',
                cache: 'no-cache',
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            const endTime = performance.now();
            return endTime - startTime;

        } catch (error) {
            const endTime = performance.now();
            const elapsed = endTime - startTime;
            
            if (elapsed < timeout) {
                return elapsed;
            }
            throw error;
        }
    }

    // Handle ping result from WebSocket
    handlePingResult(data) {
        if (!data.alive) {
            this.failCount++;
            this.testResults.push(null);
            this.addLog(`❌ Host unreachable`, 'error');
        } else {
            this.successCount++;
            this.testResults.push(data.time);
            this.updateMetrics();
        }
    }

    // Enhanced stop test
    stopTest() {
        this.isRunning = false;
        if (this.abortController) {
            this.abortController.abort();
        }
        
        // Stop real-time monitoring if active
        if (this.monitoringSessionId) {
            this.stopRealtimeMonitoring();
        }
        
        this.updateStatus('idle');
        
        const summary = this.generateSummary();
        this.addLog(summary, 'info');
        
        this.saveToHistory();
        
        if (document.getElementById('soundEnabled')?.checked || this.config.ui.soundEnabled) {
            this.playNotification('success');
        }
    }

    // All remaining original methods from main.js
    bindEvents() {
        document.getElementById('startBtn').addEventListener('click', () => this.startTest());
        document.getElementById('stopBtn').addEventListener('click', () => this.stopTest());
        document.getElementById('clearLogBtn').addEventListener('click', () => this.clearLog());

        document.getElementById('target').addEventListener('input', (e) => {
            this.updateServerInfo(e.target.value);
        });

        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const target = e.currentTarget.dataset.target;
                document.getElementById('target').value = target;
                document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
                e.currentTarget.classList.add('active');
                this.updateServerInfo(target);
            });
        });

        this.updateServerInfo(document.getElementById('target').value);
        this.displayHistory();
    }

    updateServerInfo(target) {
        const info = this.serverLocations[target];
        const infoEl = document.getElementById('serverInfo');
        
        if (info) {
            infoEl.innerHTML = `${info.flag} ${info.name} - ${info.location}`;
            infoEl.style.display = 'block';
        } else {
            infoEl.style.display = 'none';
        }
    }

    initChart() {
        const canvas = document.getElementById('latencyChart');
        const ctx = canvas.getContext('2d');
        canvas.width = canvas.offsetWidth;
        canvas.height = 200;
        this.chart = { ctx, width: canvas.width, height: canvas.height };
        
        const histCanvas = document.getElementById('histogramChart');
        const histCtx = histCanvas.getContext('2d');
        histCanvas.width = histCanvas.offsetWidth;
        histCanvas.height = 200;
        this.histogramChart = { ctx: histCtx, width: histCanvas.width, height: histCanvas.height };
        
        this.drawChart();
    }

    toggleGamingMode() {
        this.gamingModeEnabled = !this.gamingModeEnabled;
        const overlay = document.getElementById('gamingOverlay');
        const btn = document.querySelector('.mode-btn');
        
        if (this.gamingModeEnabled) {
            overlay.style.display = 'flex';
            btn.classList.add('active');
            document.body.classList.add('gaming-mode');
            this.showNotification('🎮 Gaming Mode Activated', 'info');
        } else {
            overlay.style.display = 'none';
            btn.classList.remove('active');
            document.body.classList.remove('gaming-mode');
        }
    }

    toggleDarkMode() {
        document.body.classList.toggle('dark-mode');
        localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
    }

    gamingTest() {
        document.getElementById('testCount').value = 50;
        document.getElementById('interval').value = 0.2;
        document.getElementById('continuous').checked = false;
        
        this.gamingModeEnabled = true;
        this.toggleGamingMode();
        this.startTest();
    }

    checkAlerts(latency) {
        const jitter = this.calculateJitter(this.testResults.filter(r => r !== null));
        const loss = (this.failCount / this.testCount * 100);

        if (this.gamingModeEnabled) {
            if (latency > this.config.alerts.highLatencyGaming) {
                this.showNotification('⚠️ High ping for gaming!', 'warning');
            }
            if (jitter > this.config.alerts.highJitterGaming) {
                this.showNotification('📶 Jitter too high for gaming!', 'warning');
            }
            if (loss > 0) {
                this.showNotification('❌ Packet loss detected!', 'error');
            }
        } else {
            if (latency > this.config.alerts.highLatency) {
                this.showNotification('⚠️ High latency detected!', 'warning');
            }
            if (jitter > this.config.alerts.highJitter) {
                this.showNotification('📶 Unstable connection!', 'warning');
            }
            if (loss > this.config.alerts.packetLossThreshold) {
                this.showNotification('❌ Significant packet loss!', 'error');
            }
        }
    }

    showNotification(message, type) {
        if (document.getElementById('desktopNotifications')?.checked && 'Notification' in window) {
            if (Notification.permission === 'granted') {
                new Notification('Network Analyzer', {
                    body: message,
                    icon: '/icon-192.png',
                    badge: '/icon-192.png'
                });
            }
        }

        if (document.getElementById('soundEnabled')?.checked || this.config.ui.soundEnabled) {
            this.playNotification(type === 'error' ? 'error' : 'warning');
        }
    }

    updateGamingStats() {
        if (!this.gamingModeEnabled) return;

        const validResults = this.testResults.filter(r => r !== null);
        if (validResults.length === 0) return;

        const current = validResults[validResults.length - 1];
        const jitter = this.calculateJitter(validResults);
        const loss = (this.failCount / this.testCount * 100);

        document.getElementById('gamingPing').textContent = current.toFixed(0);
        document.getElementById('gamingJitter').textContent = jitter.toFixed(0);
        document.getElementById('gamingLoss').textContent = loss.toFixed(1);

        let status = '';
        let statusColor = '';
        
        if (current < 30 && jitter < 10 && loss === 0) {
            status = 'EXCELLENT';
            statusColor = '#4ecdc4';
        } else if (current < 50 && jitter < 20 && loss < 1) {
            status = 'GOOD';
            statusColor = '#52c41a';
        } else if (current < 100 && jitter < 50 && loss < 3) {
            status = 'PLAYABLE';
            statusColor = '#ffd93d';
        } else {
            status = 'POOR';
            statusColor = '#ff6b6b';
        }

        const statusEl = document.getElementById('gamingStatus');
        statusEl.textContent = status;
        statusEl.style.color = statusColor;
    }

    generateSmartTips() {
        const tips = [];
        const validResults = this.testResults.filter(r => r !== null);
        
        if (validResults.length === 0) return;

        const avg = validResults.reduce((a, b) => a + b, 0) / validResults.length;
        const jitter = this.calculateJitter(validResults);
        const loss = (this.failCount / this.testCount * 100);

        if (avg > this.config.alerts.highLatency) {
            tips.push({
                icon: '💡',
                text: 'High latency detected. Try switching to a closer DNS server or check your internet connection.',
                severity: 'warning'
            });
        }

        if (jitter > 50) {
            tips.push({
                icon: '📶',
                text: 'High jitter detected. This may affect video calls and gaming. Try using a wired connection.',
                severity: 'warning'
            });
        }

        if (loss > 0) {
            tips.push({
                icon: '⚠️',
                text: `${loss.toFixed(1)}% packet loss detected. Check your network cables and router.`,
                severity: 'error'
            });
        }

        if (this.gamingModeEnabled && avg > this.config.alerts.highLatencyGaming) {
            tips.push({
                icon: '🎮',
                text: 'Ping is too high for competitive gaming. Consider upgrading your connection or using a gaming VPN.',
                severity: 'info'
            });
        }

        if (avg < 50 && jitter < 20 && loss === 0) {
            tips.push({
                icon: '✅',
                text: 'Excellent connection quality! Perfect for all online activities.',
                severity: 'success'
            });
        }

        const container = document.getElementById('smartTipsContainer');
        if (tips.length > 0) {
            container.innerHTML = `
                <div class="card smart-tips">
                    <h3>💡 Smart Tips & Recommendations</h3>
                    <div class="tips-list">
                        ${tips.map(tip => `
                            <div class="tip-item ${tip.severity}">
                                <span class="tip-icon">${tip.icon}</span>
                                <span class="tip-text">${tip.text}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
    }

    drawHistogram() {
        const ctx = this.histogramChart.ctx;
        const width = this.histogramChart.width;
        const height = this.histogramChart.height;

        ctx.clearRect(0, 0, width, height);

        const validResults = this.testResults.filter(r => r !== null);
        if (validResults.length < 2) return;

        const min = Math.min(...validResults);
        const max = Math.max(...validResults);
        const range = max - min;
        const binCount = Math.min(10, validResults.length);
        const binSize = range / binCount;

        const bins = Array(binCount).fill(0);
        validResults.forEach(value => {
            const binIndex = Math.min(Math.floor((value - min) / binSize), binCount - 1);
            bins[binIndex]++;
        });

        const maxBinValue = Math.max(...bins);
        const barWidth = width / binCount;

        bins.forEach((count, i) => {
            const barHeight = (count / maxBinValue) * (height - 30);
            const x = i * barWidth;
            const y = height - barHeight - 20;

            const gradient = ctx.createLinearGradient(0, y, 0, height - 20);
            gradient.addColorStop(0, '#667eea');
            gradient.addColorStop(1, '#764ba2');
            
            ctx.fillStyle = gradient;
            ctx.fillRect(x + 2, y, barWidth - 4, barHeight);

            ctx.fillStyle = '#666';
            ctx.font = '10px Arial';
            ctx.textAlign = 'center';
            const label = `${(min + i * binSize).toFixed(0)}-${(min + (i + 1) * binSize).toFixed(0)}`;
            ctx.fillText(label, x + barWidth / 2, height - 5);
        });
    }

    displayComparisonResults(results) {
        if (results.length === 0) {
            this.addLog('⚠️ No comparison results available', 'warning');
            return;
        }

        this.comparisonResults = results;
        
        results.sort((a, b) => {
            if (this.currentSort === 'successRate') return b[this.currentSort] - a[this.currentSort];
            return a[this.currentSort] - b[this.currentSort];
        });

        let html = `
            <div class="card comparison-results">
                <h3>🔄 DNS Server Comparison Results ${this.useBackend ? '(Backend)' : '(Browser)'}</h3>
                <div class="sort-buttons">
                    <button onclick="window.analyzer.sortComparison('avg')" class="sort-btn ${this.currentSort === 'avg' ? 'active' : ''}">Avg</button>
                    <button onclick="window.analyzer.sortComparison('jitter')" class="sort-btn ${this.currentSort === 'jitter' ? 'active' : ''}">Jitter</button>
                    <button onclick="window.analyzer.sortComparison('successRate')" class="sort-btn ${this.currentSort === 'successRate' ? 'active' : ''}">Success%</button>
                    <button onclick="window.analyzer.sortComparison('packetLoss')" class="sort-btn ${this.currentSort === 'packetLoss' ? 'active' : ''}">Loss</button>
                </div>
                <div class="comparison-grid">
        `;

        results.forEach((result, index) => {
            const barWidth = (result.avg / results[results.length - 1].avg) * 100;
            const quality = this.getQuality(result.avg);
            
            html += `
                <div class="comparison-item">
                    <div class="comparison-rank">#${index + 1}</div>
                    <div class="comparison-info">
                        <span class="comparison-target">
                            ${result.info.flag} ${result.info.name}
                        </span>
                        <span class="comparison-location">${result.info.location} - ${result.info.provider || ''}</span>
                    </div>
                    <div class="comparison-bar-container">
                        <div class="comparison-bar" style="width: ${barWidth}%; background: ${quality.class === 'success' ? '#4ecdc4' : quality.class === 'warning' ? '#ffd93d' : '#ff6b6b'}"></div>
                    </div>
                    <div class="comparison-stats">
                        <span class="comparison-value">${result.avg.toFixed(2)}ms</span>
                        <span class="comparison-jitter">Jitter: ${result.jitter.toFixed(1)}ms</span>
                        <span class="comparison-loss">Loss: ${result.packetLoss.toFixed(1)}%</span>
                    </div>
                    <button class="set-target-btn" onclick="window.analyzer.setAsTarget('${result.server}')">
                        Set as Target
                    </button>
                </div>
            `;
        });

        html += `
                </div>
                <div class="comparison-summary">
                    <div class="winner">
                        🏆 Best: ${results[0].info.flag} ${results[0].info.name} (${results[0].avg.toFixed(2)}ms)
                    </div>
                    <div class="recommendation">
                        💡 Recommendation: Use ${results[0].server} for optimal performance in your region.
                    </div>
                </div>
            </div>
        `;

        document.getElementById('comparisonContainer').innerHTML = html;
        this.addLog(`✅ Comparison complete. Best: ${results[0].info.name}`, 'success');
    }

    setAsTarget(server) {
        document.getElementById('target').value = server;
        this.updateServerInfo(server);
        this.addLog(`🎯 Target set to ${server}`, 'info');
        setTimeout(() => this.startTest(), 500);
    }

    sortComparison(key) {
        if (!this.comparisonResults) return;
        this.currentSort = key;
        this.displayComparisonResults(this.comparisonResults);
    }

    generatePDFReport() {
        const validResults = this.testResults.filter(r => r !== null);
        if (validResults.length === 0) {
            this.addLog('⚠️ No results to generate report', 'warning');
            return;
        }

        const report = {
            title: 'Network Analysis Report',
            version: '2.0',
            date: new Date().toLocaleString(),
            target: this.currentTarget,
            serverInfo: this.serverLocations[this.currentTarget] || { name: 'Unknown', location: 'Unknown' },
            testMethod: this.useBackend ? 'Backend Server (ICMP)' : 'Browser-based (HTTP)',
            summary: {
                totalTests: this.testCount,
                successful: this.successCount,
                failed: this.failCount,
                successRate: ((this.successCount / this.testCount) * 100).toFixed(1) + '%',
                qualityScore: this.calculateQualityScore()
            },
            statistics: {
                average: (validResults.reduce((a, b) => a + b, 0) / validResults.length).toFixed(2) + 'ms',
                min: Math.min(...validResults).toFixed(2) + 'ms',
                max: Math.max(...validResults).toFixed(2) + 'ms',
                median: this.getMedian(validResults).toFixed(2) + 'ms',
                stdDev: this.getStdDev(validResults).toFixed(2) + 'ms',
                jitter: this.calculateJitter(validResults).toFixed(2) + 'ms',
                packetLoss: ((this.failCount / this.testCount) * 100).toFixed(1) + '%',
                p95: this.percentile(validResults, 0.95).toFixed(2) + 'ms',
                p99: this.percentile(validResults, 0.99).toFixed(2) + 'ms'
            },
            recommendations: this.generateRecommendations(validResults)
        };

        const reportText = `
NETWORK ANALYSIS REPORT v2.0
============================
Generated: ${report.date}
Test Method: ${report.testMethod}

TARGET INFORMATION
------------------
Target: ${report.target}
Server: ${report.serverInfo.name}
Location: ${report.serverInfo.location}

TEST SUMMARY
------------
Total Tests: ${report.summary.totalTests}
Successful: ${report.summary.successful}
Failed: ${report.summary.failed}
Success Rate: ${report.summary.successRate}
Quality Score: ${report.summary.qualityScore}/100

STATISTICS
----------
Average Latency: ${report.statistics.average}
Minimum Latency: ${report.statistics.min}
Maximum Latency: ${report.statistics.max}
Median Latency: ${report.statistics.median}
P95 Latency: ${report.statistics.p95}
P99 Latency: ${report.statistics.p99}
Standard Deviation: ${report.statistics.stdDev}
Jitter: ${report.statistics.jitter}
Packet Loss: ${report.statistics.packetLoss}

RECOMMENDATIONS
---------------
${report.recommendations.join('\n')}

QUALITY SCORE FORMULA
--------------------
Score = 100 - (0.60×L + 0.25×J + 0.15×P)
L = avg/300ms, J = jitter/100ms, P = loss/10%

============================
Report generated by Network Latency Analyzer v2.0
${this.useBackend ? 'Backend Server Mode' : 'Browser Mode'}
        `;

        const blob = new Blob([reportText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `network-report-${Date.now()}.txt`;
        a.click();

        this.addLog('✅ Report generated successfully', 'success');
    }

    generateRecommendations(results) {
        const recommendations = [];
        const avg = results.reduce((a, b) => a + b, 0) / results.length;
        const jitter = this.calculateJitter(results);
        const loss = (this.failCount / this.testCount * 100);

        if (avg > this.config.alerts.highLatency) {
            recommendations.push('• Consider switching to a closer DNS server');
            recommendations.push('• Check for network congestion');
            recommendations.push('• Upgrade your internet plan if needed');
        }

        if (jitter > 50) {
            recommendations.push('• Use a wired connection instead of WiFi');
            recommendations.push('• Close bandwidth-heavy applications');
            recommendations.push('• Check for interference in WiFi channels');
        }

        if (loss > 0) {
            recommendations.push('• Check all network cables for damage');
            recommendations.push('• Restart your router and modem');
            recommendations.push('• Contact your ISP for line quality check');
        }

        if (avg < 50 && jitter < 20 && loss === 0) {
            recommendations.push('• Your connection is excellent!');
            recommendations.push('• Suitable for all online activities including gaming');
        }

        if (!this.useBackend) {
            recommendations.push('• Enable backend server for more accurate measurements');
        }

        return recommendations;
    }

    getMedian(values) {
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    getStdDev(values) {
        const avg = values.reduce((a, b) => a + b, 0) / values.length;
        const variance = values.reduce((acc, val) => acc + Math.pow(val - avg, 2), 0) / values.length;
        return Math.sqrt(variance);
    }

    percentile(values, p) {
        if (!values?.length) return NaN;
        const sorted = values.slice().sort((a, b) => a - b);
        const idx = (sorted.length - 1) * p;
        const lo = Math.floor(idx);
        const hi = Math.ceil(idx);
        return lo === hi ? sorted[lo] : sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
    }

    filterLogs() {
        const filter = document.getElementById('logFilter').value;
        const entries = document.querySelectorAll('.log-entry');
        
        entries.forEach(entry => {
            if (filter === 'all') {
                entry.style.display = 'block';
            } else {
                entry.style.display = entry.classList.contains(filter) ? 'block' : 'none';
            }
        });
    }
    
    updateMetrics() {
        const validResults = this.testResults.filter(r => r !== null);

        if (validResults.length > 0) {
            const current = validResults[validResults.length - 1];
            document.getElementById('currentLatency').textContent = current.toFixed(1);

            const avg = validResults.reduce((a, b) => a + b, 0) / validResults.length;
            document.getElementById('avgLatency').textContent = avg.toFixed(1);

            if (validResults.length > 1) {
                const jitter = this.calculateJitter(validResults);
                document.getElementById('jitter').textContent = jitter.toFixed(1);
            }

            const loss = (this.failCount / this.testCount * 100);
            document.getElementById('packetLoss').textContent = loss.toFixed(1);

            this.updateCardColors(current, avg, loss);
        }
    }

    updateCardColors(current, avg, loss) {
        const currentCard = document.getElementById('currentCard');
        currentCard.className = 'metric-card';
        const currentIndicator = document.getElementById('currentIndicator');
        
        if (current < 50) {
            currentCard.classList.add('good');
            currentIndicator.innerHTML = '🟢 Excellent';
        } else if (current < 150) {
            currentCard.classList.add('warning');
            currentIndicator.innerHTML = '🟡 Good';
        } else {
            currentCard.classList.add('bad');
            currentIndicator.innerHTML = '🔴 Poor';
        }
    }

    calculateAdvancedMetrics() {
        const validResults = this.testResults.filter(r => r !== null);
        
        if (validResults.length > 0) {
            document.getElementById('minLatency').textContent = Math.min(...validResults).toFixed(1);
            document.getElementById('maxLatency').textContent = Math.max(...validResults).toFixed(1);
            document.getElementById('medianLatency').textContent = this.getMedian(validResults).toFixed(1);
            document.getElementById('stdDev').textContent = this.getStdDev(validResults).toFixed(1);
            document.getElementById('successRate').textContent = ((this.successCount / this.testCount) * 100).toFixed(1);
            document.getElementById('totalTests').textContent = this.testCount;
        }
    }

    calculateJitter(values) {
        if (values.length < 2) return 0;
        const differences = [];
        for (let i = 1; i < values.length; i++) {
            differences.push(Math.abs(values[i] - values[i - 1]));
        }
        return differences.reduce((a, b) => a + b, 0) / differences.length;
    }

    drawChart() {
        const ctx = this.chart.ctx;
        const width = this.chart.width;
        const height = this.chart.height;
        ctx.clearRect(0, 0, width, height);

        if (this.chartData.length < 2) return;

        const maxY = Math.max(...this.chartData.map(d => d.y)) * 1.2;
        const minX = Math.min(...this.chartData.map(d => d.x));
        const maxX = Math.max(...this.chartData.map(d => d.x));

        // Grid lines
        ctx.strokeStyle = '#e0e0e0';
        ctx.lineWidth = 0.5;
        for (let i = 0; i <= 5; i++) {
            const y = (height / 5) * i;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }

        // Chart line
        ctx.strokeStyle = '#667eea';
        ctx.lineWidth = 2;
        ctx.beginPath();
        this.chartData.forEach((point, index) => {
            const x = ((point.x - minX) / (maxX - minX)) * width;
            const y = height - ((point.y / maxY) * height);
            if (index === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Data points
        this.chartData.forEach((point) => {
            const x = ((point.x - minX) / (maxX - minX)) * width;
            const y = height - ((point.y / maxY) * height);
            ctx.fillStyle = '#667eea';
            ctx.beginPath();
            ctx.arc(x, y, 3, 0, Math.PI * 2);
            ctx.fill();
        });
    }

    quickTest(mode) {
        const settings = {
            fast: { count: 5, interval: 0.5 },
            normal: { count: 10, interval: 1 },
            thorough: { count: 25, interval: 1.5 }
        };
        
        const config = settings[mode];
        document.getElementById('testCount').value = config.count;
        document.getElementById('interval').value = config.interval;
        document.getElementById('continuous').checked = false;
        
        this.startTest();
    }

    calculateQualityScore() {
        const validResults = this.testResults.filter(r => r !== null);
        if (validResults.length === 0) return 0;
        
        const avg = validResults.reduce((a, b) => a + b, 0) / validResults.length;
        const jitter = this.calculateJitter(validResults);
        const loss = this.failCount / this.testCount * 100;
        
        const Ln = Math.min(avg / 300, 1);
        const Jn = Math.min(jitter / 100, 1);
        const Pn = Math.min(loss / 10, 1);
        
        const score = Math.round(100 * (1 - (0.60 * Ln + 0.25 * Jn + 0.15 * Pn)));
        return Math.max(0, Math.min(score, 100));
    }

    getQualityGrade(score) {
        if (score >= 95) return { grade: 'A+', color: '#4ecdc4', label: 'Excellent' };
        if (score >= 90) return { grade: 'A', color: '#4ecdc4', label: 'Very Good' };
        if (score >= 75) return { grade: 'B', color: '#52c41a', label: 'Good' };
        if (score >= 60) return { grade: 'C', color: '#ffd93d', label: 'Fair' };
        if (score >= 40) return { grade: 'D', color: '#ff9800', label: 'Poor' };
        return { grade: 'F', color: '#ff6b6b', label: 'Very Poor' };
    }

    updateQualityScore() {
        const score = this.calculateQualityScore();
        const grade = this.getQualityGrade(score);
        
        document.getElementById('qualityScoreContainer').innerHTML = `
            <div class="quality-score-card" 
                 style="background: linear-gradient(135deg, ${grade.color}22, white);"
                 title="Score = 100 - (0.60×L + 0.25×J + 0.15×P)&#10;L = avg/300ms, J = jitter/100ms, P = loss/10%">
                <h3>Network Quality Score</h3>
                <div class="score-display">
                    <div class="score-circle" style="border-color: ${grade.color};">
                        <span class="score-grade">${grade.grade}</span>
                        <span class="score-value">${score}/100</span>
                    </div>
                    <div class="score-label">${grade.label}</div>
                    <div class="score-formula">Hover for formula</div>
                </div>
            </div>
        `;
    }

    exportToCSV() {
        if (this.testResults.length === 0) {
            this.addLog('⚠️ No results to export', 'warning');
            return;
        }
        
        let csv = 'Test Number,Latency (ms),Status,Method,Timestamp\n';
        
        this.testResults.forEach((latency, index) => {
            const timestamp = new Date(Date.now() - (this.testResults.length - index - 1) * 1000).toISOString();
            const status = latency !== null ? 'Success' : 'Failed';
            const value = latency !== null ? latency.toFixed(2) : 'N/A';
            const method = this.useBackend ? 'Backend' : 'Browser';
            csv += `${index + 1},${value},${status},${method},${timestamp}\n`;
        });
        
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `network-analysis-${this.currentTarget}-${Date.now()}.csv`;
        a.click();
        
        this.addLog('✅ Results exported as CSV', 'success');
    }

    exportResults() {
        if (this.testResults.length === 0) {
            this.addLog('⚠️ No results to export', 'warning');
            return;
        }

        const validResults = this.testResults.filter(r => r !== null);
        const data = {
            version: '2.0',
            target: this.currentTarget,
            serverInfo: this.serverLocations[this.currentTarget],
            testMethod: this.useBackend ? 'Backend Server' : 'Browser-based',
            timestamp: new Date().toISOString(),
            summary: {
                totalTests: this.testCount,
                successful: this.successCount,
                failed: this.failCount,
                packetLoss: (this.failCount / this.testCount * 100).toFixed(1) + '%',
                qualityScore: this.calculateQualityScore()
            },
            statistics: {
                average: document.getElementById('avgLatency').textContent,
                min: document.getElementById('minLatency').textContent,
                max: document.getElementById('maxLatency').textContent,
                median: document.getElementById('medianLatency').textContent,
                stdDev: document.getElementById('stdDev').textContent,
                jitter: document.getElementById('jitter').textContent,
                p95: this.percentile(validResults, 0.95).toFixed(2),
                p99: this.percentile(validResults, 0.99).toFixed(2)
            },
            results: this.testResults.map((latency, index) => ({
                test: index + 1,
                latency: latency ? latency.toFixed(2) + 'ms' : 'Failed'
            }))
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `network-analysis-${Date.now()}.json`;
        a.click();

        this.addLog('✅ Results exported successfully', 'success');
    }

    playNotification(type) {
        if (!this.config.ui.soundEnabled) return;
        
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            const frequencies = {
                success: 880,
                warning: 440,
                error: 220,
                info: 660
            };
            
            oscillator.frequency.value = frequencies[type] || 440;
            oscillator.type = 'sine';
            gainNode.gain.value = 0.1;
            
            oscillator.start();
            oscillator.stop(audioContext.currentTime + 0.2);
        } catch (e) {
            console.log('Audio not supported');
        }
    }

    async saveToHistory() {
        const validResults = this.testResults.filter(r => r !== null);
        if (validResults.length === 0) return;
        
        const historyEntry = {
            timestamp: new Date().toISOString(),
            target: this.currentTarget,
            serverInfo: this.serverLocations[this.currentTarget],
            testMethod: this.useBackend ? 'Backend' : 'Browser',
            summary: {
                avg: (validResults.reduce((a, b) => a + b, 0) / validResults.length).toFixed(2),
                min: Math.min(...validResults).toFixed(2),
                max: Math.max(...validResults).toFixed(2),
                jitter: this.calculateJitter(validResults).toFixed(2),
                packetLoss: (this.failCount / this.testCount * 100).toFixed(1),
                totalTests: this.testCount,
                qualityScore: this.calculateQualityScore()
            }
        };
        
        // Save to IndexedDB if available
        if (this.db) {
            try {
                const transaction = this.db.transaction(['history'], 'readwrite');
                const store = transaction.objectStore('history');
                await store.add(historyEntry);
            } catch (error) {
                console.error('Failed to save to IndexedDB:', error);
            }
        }
        
        // Also save to memory and localStorage
        this.testHistory.unshift(historyEntry);
        if (this.testHistory.length > this.config.history.maxItems) {
            this.testHistory.pop();
        }
        
        if (this.config.history.autoSave) {
            localStorage.setItem('networkTestHistory', JSON.stringify(this.testHistory));
        }
        
        this.displayHistory();
    }

    async displayHistory() {
        const container = document.getElementById('historyContainer');
        if (!container) return;
        
        // Load from IndexedDB if available
        if (this.db) {
            this.testHistory = await this.loadTestHistory(null, 10);
        }
        
        if (this.testHistory.length === 0) {
            container.innerHTML = '<p style="color: #999;">No test history available</p>';
            return;
        }
        
        let html = '';
        this.testHistory.slice(0, 5).forEach((entry) => {
            const date = new Date(entry.timestamp);
            const timeAgo = this.getTimeAgo(date);
            const info = entry.serverInfo || { flag: '🌐', name: entry.target };
            
            html += `
                <div class="history-item">
                    <div class="history-header">
                        <span class="history-target">${info.flag} ${entry.target}</span>
                        <span class="history-time">${timeAgo}</span>
                    </div>
                    <div class="history-stats">
                        <span class="history-stat">Avg: <strong>${entry.summary.avg}ms</strong></span>
                        <span class="history-stat">Loss: <strong>${entry.summary.packetLoss}%</strong></span>
                        <span class="history-stat">Score: <strong>${entry.summary.qualityScore}/100</strong></span>
                        <span class="history-method">${entry.testMethod || 'Browser'}</span>
                    </div>
                </div>
            `;
        });
        
        container.innerHTML = html;
    }

    getTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        
        if (seconds < 60) return 'just now';
        if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago';
        if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
        return Math.floor(seconds / 86400) + ' days ago';
    }

    generateSummary() {
        const validResults = this.testResults.filter(r => r !== null);
        if (validResults.length === 0) {
            return '📊 No valid results to display';
        }

        const avg = (validResults.reduce((a, b) => a + b, 0) / validResults.length).toFixed(2);
        const min = Math.min(...validResults).toFixed(2);
        const max = Math.max(...validResults).toFixed(2);
        const loss = (this.failCount / this.testCount * 100).toFixed(1);
        const score = this.calculateQualityScore();
        const method = this.useBackend ? 'Backend' : 'Browser';

        return `📊 Summary: Avg: ${avg}ms | Min: ${min}ms | Max: ${max}ms | Loss: ${loss}% | Score: ${score}/100 | Method: ${method}`;
    }

    addLog(message, type = 'info') {
        const logEntries = document.getElementById('logEntries');
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        
        const timestamp = new Date().toLocaleTimeString('en-US');
        entry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${message}`;
        
        logEntries.appendChild(entry);
        logEntries.scrollTop = logEntries.scrollHeight;
    }

    clearLog() {
        document.getElementById('logEntries').innerHTML = '';
        this.addLog('📋 Log cleared', 'info');
    }

    updateStatus(status) {
        const statusEl = document.getElementById('status');
        if (status === 'testing') {
            statusEl.className = 'status-indicator testing';
            statusEl.innerHTML = '<span class="pulse"></span> Testing';
            document.getElementById('startBtn').style.display = 'none';
            document.getElementById('stopBtn').style.display = 'block';
        } else {
            statusEl.className = 'status-indicator idle';
            statusEl.innerHTML = '<span class="pulse"></span> Idle';
            document.getElementById('startBtn').style.display = 'block';
            document.getElementById('stopBtn').style.display = 'none';
        }
    }

    getQuality(latency) {
        if (latency < 50) {
            return { label: 'Excellent', class: 'success' };
        } else if (latency < 150) {
            return { label: 'Good', class: 'warning' };
        } else {
            return { label: 'Poor', class: 'error' };
        }
    }

    checkPWASupport() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(() => {});
        }
    }

    initNotifications() {
        if (this.config.ui.notificationsEnabled && 'Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    initializeHistory() {
        try {
            this.testHistory = JSON.parse(localStorage.getItem('networkTestHistory') || '[]');
            if (this.testHistory.length > this.config.history.maxItems) {
                this.testHistory = this.testHistory.slice(0, this.config.history.maxItems);
                localStorage.setItem('networkTestHistory', JSON.stringify(this.testHistory));
            }
        } catch (e) {
            this.testHistory = [];
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.analyzer = new EnhancedNetworkAnalyzer();
    
    // Check for dark mode preference
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
    }
    
    // Show version in console
    console.log('%c Enhanced Network Latency Analyzer v2.0 ', 'background: #667eea; color: white; padding: 5px 10px; border-radius: 3px;');
    console.log('Features: Backend Support | WebSocket Real-time | IndexedDB Storage | Advanced Metrics');
});