const express = require('express');
const cors = require('cors');
const path = require('path');
const ping = require('ping');
const dns = require('dns').promises;
const { exec } = require('child_process');
const { promisify } = require('util');
const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');

const execAsync = promisify(exec);
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from the root directory
app.use(express.static(path.join(__dirname, '../')));

// Store active monitoring sessions
const monitoringSessions = new Map();

// ==================== REST API Endpoints ====================

// Root endpoint
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, '../index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Network Analyzer API</title>
                <style>
                    body { font-family: Arial, sans-serif; padding: 40px; background: #f5f5f5; }
                    h1 { color: #333; }
                    .endpoints { background: white; padding: 20px; border-radius: 8px; }
                    .endpoint { margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 3px solid #667eea; }
                    code { background: #e1e1e1; padding: 2px 6px; border-radius: 3px; }
                </style>
            </head>
            <body>
                <h1>Network Analyzer Backend API</h1>
                <div class="endpoints">
                    <h2>Available Endpoints:</h2>
                    <div class="endpoint">
                        <strong>GET /health</strong> - Health check
                    </div>
                    <div class="endpoint">
                        <strong>POST /api/ping</strong> - Ping a host
                        <br>Body: <code>{ "host": "google.com", "count": 4 }</code>
                    </div>
                    <div class="endpoint">
                        <strong>POST /api/dns-lookup</strong> - DNS lookup
                        <br>Body: <code>{ "hostname": "google.com" }</code>
                    </div>
                    <div class="endpoint">
                        <strong>POST /api/batch-test</strong> - Test multiple servers
                        <br>Body: <code>{ "servers": ["8.8.8.8", "1.1.1.1"] }</code>
                    </div>
                    <div class="endpoint">
                        <strong>WebSocket</strong> - ws://localhost:3001 for real-time monitoring
                    </div>
                </div>
            </body>
            </html>
        `);
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Network Analyzer API',
        version: '1.0.0'
    });
});

// Ping endpoint with detailed metrics
app.post('/api/ping', async (req, res) => {
    try {
        const { host, count = 4, timeout = 2 } = req.body;
        
        if (!host) {
            return res.status(400).json({ error: 'Host is required' });
        }

        console.log(`Pinging ${host}...`);
        
        // Try ICMP ping first (may not work on Render)
        try {
            const result = await ping.promise.probe(host, {
                min_reply: count,
                timeout: timeout,
                extra: ['-i', '0.2']
            });

            const detailedPing = await performDetailedPing(host, count);
            
            res.json({
                alive: result.alive,
                host: result.host,
                ip: result.numeric_host,
                time: result.time,
                min: result.min,
                max: result.max,
                avg: result.avg,
                stddev: result.stddev,
                packetLoss: result.packetLoss || detailedPing.packetLoss,
                times: detailedPing.times,
                jitter: calculateJitter(detailedPing.times),
                timestamp: new Date().toISOString()
            });
        } catch (icmpError) {
            // Fallback to HTTP ping if ICMP fails
            console.log('ICMP ping failed, using HTTP fallback');
            const httpPing = await performHttpPing(host, count);
            res.json(httpPing);
        }
    } catch (error) {
        console.error('Ping error:', error);
        res.status(500).json({ 
            error: 'Ping failed', 
            message: error.message 
        });
    }
});

// DNS lookup endpoint
app.post('/api/dns-lookup', async (req, res) => {
    try {
        const { hostname } = req.body;
        
        if (!hostname) {
            return res.status(400).json({ error: 'Hostname is required' });
        }
        
        const startTime = Date.now();
        const addresses = await dns.resolve4(hostname);
        const lookupTime = Date.now() - startTime;
        
        const servers = await dns.getServers();
        
        res.json({
            hostname,
            addresses,
            lookupTime,
            dnsServers: servers,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'DNS lookup failed', 
            message: error.message 
        });
    }
});

// Traceroute endpoint
app.post('/api/traceroute', async (req, res) => {
    try {
        const { host, maxHops = 30 } = req.body;
        
        if (!host) {
            return res.status(400).json({ error: 'Host is required' });
        }

        console.log(`Traceroute to ${host}...`);
        
        try {
            const hops = await performTraceroute(host, maxHops);
            res.json({
                host,
                hops,
                totalHops: hops.length,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            res.json({
                host,
                error: 'Traceroute not available in this environment',
                message: 'Running on a containerized platform that doesn\'t support traceroute',
                timestamp: new Date().toISOString()
            });
        }
    } catch (error) {
        console.error('Traceroute error:', error);
        res.status(500).json({ 
            error: 'Traceroute failed', 
            message: error.message 
        });
    }
});

// Port check endpoint
app.post('/api/port-check', async (req, res) => {
    try {
        const { host, port, timeout = 2000 } = req.body;
        
        if (!host || !port) {
            return res.status(400).json({ error: 'Host and port are required' });
        }
        
        const isOpen = await checkPort(host, port, timeout);
        
        res.json({
            host,
            port,
            open: isOpen,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'Port check failed', 
            message: error.message 
        });
    }
});

// Batch test multiple servers
app.post('/api/batch-test', async (req, res) => {
    try {
        const { servers, testsPerServer = 5 } = req.body;
        
        if (!Array.isArray(servers) || servers.length === 0) {
            return res.status(400).json({ error: 'Servers array is required' });
        }

        const results = await Promise.all(
            servers.map(async (server) => {
                try {
                    const pingResult = await performHttpPing(server, testsPerServer);
                    return {
                        server,
                        success: true,
                        ...pingResult
                    };
                } catch (error) {
                    return {
                        server,
                        success: false,
                        error: error.message
                    };
                }
            })
        );

        res.json({
            results,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'Batch test failed', 
            message: error.message 
        });
    }
});

// Network statistics endpoint
app.get('/api/network-stats', async (req, res) => {
    try {
        const stats = await getNetworkStatistics();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ 
            error: 'Failed to get network statistics', 
            message: error.message 
        });
    }
});

// Serve static files - Fixed for Node.js v22
app.get('/*', (req, res) => {
    const indexPath = path.join(__dirname, '../index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(404).json({ error: 'Page not found' });
    }
});

// ==================== WebSocket for Real-time Monitoring ====================

wss.on('connection', (ws) => {
    console.log('New WebSocket connection');
    
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            switch (data.action) {
                case 'start-monitoring':
                    startMonitoring(ws, data);
                    break;
                    
                case 'stop-monitoring':
                    stopMonitoring(ws, data.sessionId);
                    break;
                    
                case 'ping':
                    await handleWebSocketPing(ws, data);
                    break;
                    
                default:
                    ws.send(JSON.stringify({ 
                        error: 'Unknown action',
                        action: data.action 
                    }));
            }
        } catch (error) {
            console.error('WebSocket error:', error);
            ws.send(JSON.stringify({ 
                error: 'Processing failed',
                message: error.message 
            }));
        }
    });
    
    ws.on('close', () => {
        console.log('WebSocket connection closed');
        for (const [sessionId, session] of monitoringSessions.entries()) {
            if (session.ws === ws) {
                clearInterval(session.interval);
                monitoringSessions.delete(sessionId);
            }
        }
    });
});

// ==================== Helper Functions ====================

// HTTP-based ping for compatibility
async function performHttpPing(host, count = 4) {
    const times = [];
    let successCount = 0;
    
    // Ensure host has protocol
    if (!host.startsWith('http://') && !host.startsWith('https://')) {
        // Check if it's an IP address
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
            host = `http://${host}`;
        } else {
            host = `https://${host}`;
        }
    }
    
    for (let i = 0; i < count; i++) {
        const startTime = Date.now();
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            
            await fetch(host, {
                method: 'HEAD',
                mode: 'no-cors',
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            const latency = Date.now() - startTime;
            times.push(latency);
            successCount++;
        } catch (error) {
            times.push(null);
        }
        
        // Small delay between pings
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    
    const validTimes = times.filter(t => t !== null);
    
    return {
        alive: successCount > 0,
        host: host.replace(/^https?:\/\//, ''),
        times,
        successCount,
        totalCount: count,
        packetLoss: ((count - successCount) / count) * 100,
        min: validTimes.length > 0 ? Math.min(...validTimes) : null,
        max: validTimes.length > 0 ? Math.max(...validTimes) : null,
        avg: validTimes.length > 0 ? 
            validTimes.reduce((a, b) => a + b, 0) / validTimes.length : null,
        jitter: calculateJitter(validTimes),
        timestamp: new Date().toISOString(),
        method: 'HTTP'
    };
}

async function performDetailedPing(host, count = 4) {
    const times = [];
    let successCount = 0;
    
    for (let i = 0; i < count; i++) {
        try {
            const result = await ping.promise.probe(host, {
                timeout: 2,
                min_reply: 1
            });
            
            if (result.alive) {
                times.push(result.time);
                successCount++;
            } else {
                times.push(null);
            }
            
            await new Promise(resolve => setTimeout(resolve, 200));
        } catch (error) {
            times.push(null);
        }
    }
    
    const validTimes = times.filter(t => t !== null);
    
    return {
        times,
        successCount,
        totalCount: count,
        packetLoss: ((count - successCount) / count) * 100,
        min: validTimes.length > 0 ? Math.min(...validTimes) : null,
        max: validTimes.length > 0 ? Math.max(...validTimes) : null,
        avg: validTimes.length > 0 ? 
            validTimes.reduce((a, b) => a + b, 0) / validTimes.length : null,
        jitter: calculateJitter(validTimes)
    };
}

async function performTraceroute(host, maxHops = 30) {
    const platform = process.platform;
    let command;
    
    if (platform === 'win32') {
        command = `tracert -h ${maxHops} ${host}`;
    } else {
        command = `traceroute -m ${maxHops} ${host}`;
    }
    
    try {
        const { stdout } = await execAsync(command);
        return parseTraceroute(stdout, platform);
    } catch (error) {
        throw new Error(`Traceroute failed: ${error.message}`);
    }
}

function parseTraceroute(output, platform) {
    const lines = output.split('\n');
    const hops = [];
    
    const startIndex = platform === 'win32' ? 4 : 1;
    
    for (let i = startIndex; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        
        const hop = parseTracerouteHop(line, platform);
        if (hop) {
            hops.push(hop);
        }
    }
    
    return hops;
}

function parseTracerouteHop(line, platform) {
    const parts = line.split(/\s+/);
    
    if (parts.length < 2) return null;
    
    const hopNumber = parseInt(parts[0]);
    if (isNaN(hopNumber)) return null;
    
    const times = [];
    let ip = null;
    
    for (const part of parts.slice(1)) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(part)) {
            ip = part;
        } else if (/^\d+(\.\d+)?$/.test(part) || part.includes('ms')) {
            const time = parseFloat(part.replace('ms', ''));
            if (!isNaN(time)) {
                times.push(time);
            }
        }
    }
    
    return {
        hop: hopNumber,
        ip: ip || 'Unknown',
        times: times.length > 0 ? times : null,
        avg: times.length > 0 ? 
            times.reduce((a, b) => a + b, 0) / times.length : null
    };
}

async function checkPort(host, port, timeout) {
    return new Promise((resolve) => {
        const net = require('net');
        const socket = new net.Socket();
        
        socket.setTimeout(timeout);
        
        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', () => {
            resolve(false);
        });
        
        socket.connect(port, host);
    });
}

function calculateJitter(times) {
    if (!times || times.length < 2) return 0;
    
    const validTimes = times.filter(t => t !== null && t !== undefined);
    if (validTimes.length < 2) return 0;
    
    const differences = [];
    for (let i = 1; i < validTimes.length; i++) {
        differences.push(Math.abs(validTimes[i] - validTimes[i - 1]));
    }
    
    return differences.reduce((a, b) => a + b, 0) / differences.length;
}

async function getNetworkStatistics() {
    const platform = process.platform;
    let command;
    
    if (platform === 'win32') {
        command = 'netstat -s';
    } else if (platform === 'darwin') {
        command = 'netstat -s';
    } else {
        command = 'ss -s';
    }
    
    try {
        const { stdout } = await execAsync(command);
        return {
            raw: stdout,
            platform,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        return {
            error: error.message,
            platform,
            timestamp: new Date().toISOString()
        };
    }
}

function startMonitoring(ws, data) {
    const { host, interval = 1000, sessionId } = data;
    
    if (!host || !sessionId) {
        ws.send(JSON.stringify({ 
            error: 'Host and sessionId are required' 
        }));
        return;
    }
    
    if (monitoringSessions.has(sessionId)) {
        stopMonitoring(ws, sessionId);
    }
    
    console.log(`Starting monitoring session ${sessionId} for ${host}`);
    
    const monitorInterval = setInterval(async () => {
        try {
            const result = await performHttpPing(host, 1);
            
            ws.send(JSON.stringify({
                type: 'monitoring-update',
                sessionId,
                data: {
                    alive: result.alive,
                    time: result.avg,
                    timestamp: new Date().toISOString()
                }
            }));
        } catch (error) {
            ws.send(JSON.stringify({
                type: 'monitoring-error',
                sessionId,
                error: error.message
            }));
        }
    }, interval);
    
    monitoringSessions.set(sessionId, {
        ws,
        interval: monitorInterval,
        host,
        startTime: new Date()
    });
    
    ws.send(JSON.stringify({
        type: 'monitoring-started',
        sessionId,
        host,
        interval
    }));
}

function stopMonitoring(ws, sessionId) {
    const session = monitoringSessions.get(sessionId);
    
    if (session) {
        clearInterval(session.interval);
        monitoringSessions.delete(sessionId);
        
        ws.send(JSON.stringify({
            type: 'monitoring-stopped',
            sessionId,
            duration: new Date() - session.startTime
        }));
        
        console.log(`Stopped monitoring session ${sessionId}`);
    }
}

async function handleWebSocketPing(ws, data) {
    const { host } = data;
    
    if (!host) {
        ws.send(JSON.stringify({ 
            error: 'Host is required' 
        }));
        return;
    }
    
    try {
        const result = await performHttpPing(host, 1);
        
        ws.send(JSON.stringify({
            type: 'ping-result',
            data: {
                alive: result.alive,
                host: result.host,
                time: result.avg,
                timestamp: new Date().toISOString()
            }
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'ping-error',
            error: error.message
        }));
    }
}

// ==================== Server Initialization ====================

const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
    console.log(`
    ╔════════════════════════════════════════════╗
    ║   Network Analyzer Backend Server v1.0    ║
    ╠════════════════════════════════════════════╣
    ║   Server running on port ${PORT}             ║
    ║   WebSocket ready for connections         ║
    ║                                            ║
    ║   Endpoints:                               ║
    ║   POST /api/ping                           ║
    ║   POST /api/dns-lookup                     ║
    ║   POST /api/traceroute                     ║
    ║   POST /api/port-check                     ║
    ║   POST /api/batch-test                     ║
    ║   GET  /api/network-stats                  ║
    ║   GET  /health                             ║
    ║                                            ║
    ║   WebSocket: ws://localhost:${PORT}          ║
    ╚════════════════════════════════════════════╝
    `);
    
    console.log('Test the API at: http://localhost:' + PORT);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        
        wss.clients.forEach((ws) => {
            ws.close();
        });
        
        for (const [sessionId, session] of monitoringSessions.entries()) {
            clearInterval(session.interval);
        }
        
        process.exit(0);
    });
});