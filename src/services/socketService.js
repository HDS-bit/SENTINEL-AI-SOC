/**
 * SENTINEL AI - WebSocket Client Service
 * Real-time event streaming for packets, attacks, alerts, and server metrics.
 */

class SocketService {
  constructor() {
    this.ws = null;
    this.listeners = new Map();
    this.isConnected = false;
    this.reconnectTimer = null;
    this.reconnectAttempts = 0;
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      
      let host = window.location.host;
      // If we are running on any dev/preview port other than 5000, route WS to backend on 5000
      if (window.location.port !== '5000') {
        const hostname = window.location.hostname || 'localhost';
        host = `${hostname}:5000`;
      }

      const wsUrl = `${protocol}//${host}/ws`;
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
          console.warn('⚠️ Malformed WS message:', event.data);
        }
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this.emit('connection_change', { isConnected: false });
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.isConnected = false;
        this.emit('connection_change', { isConnected: false });
      };
    } catch (err) {
      console.warn('⚠️ WebSocket initialization error:', err.message);
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectAttempts++;
    const delay = Math.min(10000, 1500 * Math.pow(1.5, Math.min(this.reconnectAttempts, 4)));
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
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
  }
}

export const socketService = new SocketService();
