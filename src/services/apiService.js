/**
 * SENTINEL AI - Central API Client Service
 * Communicates with the real Node.js Backend API & gracefully falls back to offline mode.
 */

// Detect API base URL: auto-probes local backend at port 5000 if running on dev/preview server
let dynamicApiBase = import.meta.env.VITE_API_URL || '';

// If served on a dev/preview port (not 5000), default fallback to localhost:5000
if (!dynamicApiBase && typeof window !== 'undefined') {
  if (window.location.port !== '5000') {
    dynamicApiBase = `http://${window.location.hostname || 'localhost'}:5000`;
  }
}

const TOKEN_KEY = 'SENTINEL_JWT_TOKEN';

export const apiService = {
  getApiBase() {
    return dynamicApiBase;
  },

  setApiBase(url) {
    dynamicApiBase = url;
  },

  getToken() {
    return localStorage.getItem(TOKEN_KEY) || '';
  },

  setToken(token) {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  },

  async request(endpoint, options = {}) {
    const token = this.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(options.headers || {})
    };

    let url = endpoint;
    if (!url.startsWith('http')) {
      const base = this.getApiBase();
      url = `${base}${endpoint}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers
      });

      if (!response.ok) {
        let errData = {};
        try {
          errData = await response.json();
        } catch (e) {}
        throw new Error(errData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (err) {
      throw err;
    }
  },

  // Health & Server Telemetry with multi-target fallback
  async checkHealth() {
    // 1. Try currently configured dynamicApiBase
    const candidates = [];
    if (dynamicApiBase) candidates.push(dynamicApiBase);
    candidates.push(''); // Relative (for same-origin or proxy)
    if (typeof window !== 'undefined') {
      const explicitHost = `http://${window.location.hostname || 'localhost'}:5000`;
      if (!candidates.includes(explicitHost)) candidates.push(explicitHost);
      const fallbackLocal = 'http://localhost:5000';
      if (!candidates.includes(fallbackLocal)) candidates.push(fallbackLocal);
      const fallback127 = 'http://127.0.0.1:5000';
      if (!candidates.includes(fallback127)) candidates.push(fallback127);
    }

    for (const base of candidates) {
      try {
        const start = Date.now();
        const targetUrl = `${base}/api/health`;
        const res = await fetch(targetUrl, { method: 'GET', headers: { 'Content-Type': 'application/json' } });
        if (res.ok) {
          const data = await res.json();
          const latency = Date.now() - start;
          dynamicApiBase = base; // Lock in the discovered working API base
          return { online: true, latency, apiBase: base, ...data };
        }
      } catch (e) {
        // Try next candidate
      }
    }

    return { online: false, error: 'Server unreachable across local and proxy endpoints' };
  },

  async getSystemInfo() {
    return this.request('/api/system/info');
  },

  async getSystemMetrics() {
    return this.request('/api/system/metrics');
  },

  // Authentication
  async login(email, password) {
    const res = await this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    if (res.token) {
      this.setToken(res.token);
    }
    return res;
  },

  async register(name, email, password, role, badge) {
    const res = await this.request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, role, badge })
    });
    if (res.token) {
      this.setToken(res.token);
    }
    return res;
  },

  async getMe() {
    return this.request('/api/auth/me');
  },

  // Traffic & Packets
  async getRecentPackets() {
    return this.request('/api/traffic/packets');
  },

  async injectAttack(type) {
    return this.request('/api/traffic/inject', {
      method: 'POST',
      body: JSON.stringify({ type })
    });
  },

  async getQuarantinedIPs() {
    return this.request('/api/traffic/quarantined');
  },

  async quarantineIP(ip, reason) {
    return this.request('/api/traffic/quarantine', {
      method: 'POST',
      body: JSON.stringify({ ip, reason })
    });
  },

  async unbanIP(ip) {
    return this.request(`/api/traffic/quarantine/${encodeURIComponent(ip)}`, {
      method: 'DELETE'
    });
  },

  async toggleEmergencyLockdown() {
    return this.request('/api/traffic/lockdown', {
      method: 'POST'
    });
  },

  // Database Firewall
  async inspectQuery(query) {
    return this.request('/api/firewall/inspect', {
      method: 'POST',
      body: JSON.stringify({ query })
    });
  },

  async getFirewallRules() {
    return this.request('/api/firewall/rules');
  },

  async addFirewallRule(rule) {
    return this.request('/api/firewall/rules', {
      method: 'POST',
      body: JSON.stringify(rule)
    });
  },

  async deleteFirewallRule(id) {
    return this.request(`/api/firewall/rules/${id}`, {
      method: 'DELETE'
    });
  },

  async getFirewallLogs() {
    return this.request('/api/firewall/logs');
  },

  // Files & Dataset Sanitize
  async uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const token = this.getToken();
    const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

    const base = this.getApiBase();
    const res = await fetch(`${base}/api/files/upload`, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!res.ok) {
      throw new Error(`Upload failed: ${res.statusText}`);
    }

    return await res.json();
  },

  async sanitizeDatasetOnServer(rows, filename) {
    return this.request('/api/files/sanitize', {
      method: 'POST',
      body: JSON.stringify({ rows, filename })
    });
  },

  // AI Security Gateway
  async analyzeWithServerAI(datasetRecords, metadata, userApiKey) {
    return this.request('/api/ai/analyze', {
      method: 'POST',
      body: JSON.stringify({ datasetRecords, metadata, userApiKey })
    });
  },

  // Incidents
  async getIncidents() {
    return this.request('/api/incidents');
  },

  async logIncident(incident) {
    return this.request('/api/incidents', {
      method: 'POST',
      body: JSON.stringify(incident)
    });
  }
};
