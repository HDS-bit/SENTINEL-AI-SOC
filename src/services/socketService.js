/**
 * SENTINEL AI - WebSocket Client Service
 * Real-time event streaming for packets, attacks, alerts, and server metrics.
 * Production-hardened for HTTPS/WSS, real servers, mobile, and LAN edge runtime.
 */

class SocketService {
  constructor() {
    this.ws = null;
    this.listeners = new Map();
    this.isConnected = false;
    this.reconnectTimer = null;
    this.reconnectAttempts = 0;
    this.isManualClosed = false;
  }

  connect() {
    if (typeof window === 'undefined') return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      const isHttps = window.location.protocol === 'https:';
      const wsProtocol = isHttps ? 'wss:' : 'ws:';
      
      // Compute intelligent host target:
      // 1. If explicit env variable is provided
      let host = window.location.host;
      
      const hostname = window.location.hostname || 'localhost';
      const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
      
      // In local dev without proxy, default to port 5000
      if (isLocalhost && (window.location.port === '3000' || window.location.port === '5173')) {
        host = `${hostname}:5000`;
      }

      const wsUrl = `${wsProtocol}//${host}/ws`;
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.emit('connection_change', { isConnected: true });
        console.log('⚡ [SENTINEL WS] Connected to live server stream:', wsUrl);
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type) {
            this.emit(data.type, data);
            this.emit('*', data);
          }
        } catch (err) {
          // Ignore malformed WS payload
        }
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this.emit('connection_change', { isConnected: false });
        if (!this.isManualClosed) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        this.isConnected = false;
        this.emit('connection_change', { isConnected: false });
        // Error will trigger onclose which schedules reconnect
      };
    } catch (err) {
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectAttempts++;
    // Exponential backoff capped at 8 seconds to prevent console flood
    const delay = Math.min(8000, 2000 * Math.pow(1.3, Math.min(this.reconnectAttempts, 4)));
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);

    return () => {
      this.off(event, callback);
    };
  }

  off(event, callback) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).delete(callback);
    }
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(cb => {
        try {
          cb(data);
        } catch (e) {
          console.error(`Error in WS listener [${event}]:`, e);
        }
      });
    }
  }

  send(action, payload = {}) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ action, ...payload }));
      return true;
    }
    return false;
  }

  disconnect() {
    this.isManualClosed = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
  }
}

export const socketService = new SocketService();
