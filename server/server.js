import express from 'express';
import http from 'http';
import path from 'path';
import fs from 'fs';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { WebSocketServer } from 'ws';
import rateLimit from 'express-rate-limit';

import { config } from './config/config.js';
import { packetStreamManager } from './services/packetStreamService.js';

import healthRoutes from './routes/healthRoutes.js';
import authRoutes from './routes/authRoutes.js';
import trafficRoutes from './routes/trafficRoutes.js';
import firewallRoutes from './routes/firewallRoutes.js';
import fileRoutes from './routes/fileRoutes.js';
import aiRoutes from './routes/aiRoutes.js';
import incidentRoutes from './routes/incidentRoutes.js';

const app = express();
const server = http.createServer(app);

// 1. Hardened Security Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Allows flexible SPA inline assets & WebSockets
  crossOriginEmbedderPolicy: false
}));

// 2. CORS configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// 3. Request parsers & logging
app.use(morgan(config.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// 4. Rate Limiter for Auth / Sensitive Endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts from this IP, please try again in 15 minutes.' }
});

// 5. Mount API Routes
app.use('/api', healthRoutes);
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/traffic', trafficRoutes);
app.use('/api/firewall', firewallRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/incidents', incidentRoutes);

// 6. Production Static SPA Serving
if (fs.existsSync(config.DIST_DIR)) {
  console.log(`🌐 Serving production frontend bundle from: ${config.DIST_DIR}`);
  app.use(express.static(config.DIST_DIR));

  // SPA fallback for client-side routing
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/ws')) {
      return next();
    }
    res.sendFile(path.join(config.DIST_DIR, 'index.html'));
  });
} else {
  app.get('/', (req, res) => {
    res.json({
      service: 'SENTINEL AI SOC API Server',
      status: 'ONLINE',
      note: 'Frontend bundle not yet built in dist/. Run "npm run build" to enable combined SPA serving.',
      apiDocs: '/api/health',
      systemInfo: '/api/system/info'
    });
  });
}

// 7. WebSocket Server Initialization
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  console.log(`🔌 [WebSocket] SOC Client Connected from ${clientIp}`);

  packetStreamManager.addClient(ws);

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.action === 'INJECT_ATTACK') {
        packetStreamManager.injectAttack(msg.type || 'SQLI');
      } else if (msg.action === 'PING') {
        ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
      }
    } catch (e) {
      // Ignore malformed WS frames
    }
  });

  ws.on('close', () => {
    console.log(`🔌 [WebSocket] Client Disconnected: ${clientIp}`);
    packetStreamManager.removeClient(ws);
  });

  ws.on('error', (err) => {
    console.error('⚠️ [WebSocket] Error:', err.message);
    packetStreamManager.removeClient(ws);
  });
});

// 8. Start Background Services
packetStreamManager.startStreaming();

// 9. Start Server Listener
server.listen(config.PORT, config.HOST, () => {
  console.log('================================================================');
  console.log(`🛡️  CSTD SENTINEL AI SOC ENTERPRISE SERVER`);
  console.log(`🚀  HTTP API Gateway:   http://${config.HOST}:${config.PORT}`);
  console.log(`⚡  Live WebSocket:     ws://${config.HOST}:${config.PORT}/ws`);
  console.log(`📊  Telemetry Endpoint: http://${config.HOST}:${config.PORT}/api/system/info`);
  console.log(`🛡️  Environment:        ${config.NODE_ENV.toUpperCase()}`);
  console.log('================================================================');
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  server.close(() => process.exit(0));
});
