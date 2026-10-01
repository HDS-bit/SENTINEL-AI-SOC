module.exports = {
  apps: [
    {
      name: 'sentinel-soc-backend',
      script: 'server/server.js',
      instances: 'max',
      exec_mode: 'cluster',
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: 5000,
        HOST: '0.0.0.0'
      }
    }
  ]
};
