import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './', // Enables relative asset loading for direct file execution & local previews
  server: {
    port: 3000,
    open: true,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
        configure: (proxy, _options) => {
          proxy.on('error', (_err, _req, res) => {
            // Graceful response when backend is offline or starting
            if (res.writeHead && !res.headersSent) {
              res.writeHead(503, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ 
                error: 'Backend API server offline (standalone client mode active)',
                online: false 
              }));
            }
          });
        }
      },
      '/ws': {
        target: 'ws://localhost:5000',
        ws: true,
        configure: (proxy, _options) => {
          proxy.on('error', (_err, _req, _socket) => {
            // Silently handle WS proxy error when backend is offline
          });
        }
      }
    }
  },
  preview: {
    port: 4173,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
        configure: (proxy, _options) => {
          proxy.on('error', (_err, _req, res) => {
            if (res.writeHead && !res.headersSent) {
              res.writeHead(503, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ 
                error: 'Backend API server offline',
                online: false 
              }));
            }
          });
        }
      },
      '/ws': {
        target: 'ws://localhost:5000',
        ws: true,
        configure: (proxy, _options) => {
          proxy.on('error', (_err, _req, _socket) => {
            // Silently handle WS proxy error
          });
        }
      }
    }
  }
});
