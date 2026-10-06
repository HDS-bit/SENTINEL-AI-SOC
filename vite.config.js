import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import http from 'http';

// Custom silent proxy plugin to seamlessly forward to Node.js backend when running,
// or gracefully provide standalone fallback without any terminal console error spam
function silentBackendGateway() {
  const handleProxy = (req, res) => {
    const options = {
      hostname: '127.0.0.1',
      port: 5000,
      path: `/api${req.url}`,
      method: req.method,
      headers: { ...req.headers, host: '127.0.0.1:5000' },
      timeout: 1500
    };

    const proxyReq = http.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res, { end: true });
    });

    proxyReq.on('error', () => {
      // Backend is offline - gracefully respond with standalone mode without throwing terminal errors
      if (!res.headersSent) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          online: false,
          status: 'STANDALONE_SIMULATION',
          note: 'Edge Simulation Mode Active (Start backend with "npm run server" for live DB & REST API)'
        }));
      }
    });

    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      if (!res.headersSent) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ online: false, status: 'STANDALONE_SIMULATION' }));
      }
    });

    req.pipe(proxyReq, { end: true });
  };

  return {
    name: 'silent-backend-gateway',
    configureServer(server) {
      server.middlewares.use('/api', handleProxy);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api', handleProxy);
    }
  };
}

export default defineConfig({
  plugins: [react(), silentBackendGateway()],
  base: './', // Enables relative asset loading for direct file execution & local previews
  server: {
    port: 3000,
    open: true,
    host: true
  },
  preview: {
    port: 4173,
    host: true
  }
});
