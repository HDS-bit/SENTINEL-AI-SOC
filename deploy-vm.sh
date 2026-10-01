#!/bin/bash
# ==============================================================================
# CSTD SENTINEL AI SOC - Full-Stack Automated Cloud VM Deployment Script
# Supports: Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12, AWS EC2, DigitalOcean
# ==============================================================================

set -e

echo ""
echo "=================================================================="
echo "🛡️  STARTING CSTD SENTINEL AI SOC ENTERPRISE SERVER DEPLOYMENT"
echo "=================================================================="
echo ""

# 1. Update system packages
echo "📦 [1/7] Updating Linux system packages..."
sudo apt-get update -y
sudo apt-get install -y curl git nginx ufw build-essential

# 2. Install Node.js LTS (v20.x)
if ! command -v node &> /dev/null || [[ $(node -v | cut -d'.' -f1 | tr -d 'v') -lt 20 ]]; then
    echo "⚡ [2/7] Installing Node.js LTS (v20.x)..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
echo "   Node Version: $(node -v) | NPM Version: $(npm -v)"

# 3. Install Global Process Manager (PM2)
if ! command -v pm2 &> /dev/null; then
    echo "🔄 [3/7] Installing PM2 Process Manager..."
    sudo npm install -g pm2
fi

# 4. Install Project Dependencies & Build
echo "🔨 [4/7] Installing dependencies & compiling frontend..."
npm install
npm run build

echo "🔨 Installing backend server dependencies..."
cd server
npm install --omit=dev
cd ..

# 5. Setup PM2 Daemon for Backend Server
echo "🚀 [5/7] Starting SENTINEL Backend & WebSocket Engine under PM2..."
pm2 stop sentinel-backend 2>/dev/null || true
pm2 delete sentinel-backend 2>/dev/null || true
pm2 start server/server.js --name "sentinel-backend" --time
pm2 save
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u $USER --hp $HOME 2>/dev/null || true

# 6. Configure Nginx Web Server & Reverse Proxy
echo "⚙️ [6/7] Configuring Nginx Reverse Proxy for Web & WebSockets..."
sudo mkdir -p /var/www/sentinel
sudo cp -r dist/* /var/www/sentinel/
sudo chown -R www-data:www-data /var/www/sentinel

sudo cat << 'EOF' | sudo tee /etc/nginx/sites-available/sentinel
upstream sentinel_api_backend {
    server 127.0.0.1:5000;
    keepalive 32;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/sentinel;
    index index.html index.htm;

    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied expired no-cache no-store private auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml application/javascript application/json image/svg+xml;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # API Proxy
    location /api/ {
        proxy_pass http://sentinel_api_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;
    }

    # WebSocket Proxy
    location /ws {
        proxy_pass http://sentinel_api_backend/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # Static Assets Caching
    location ~* \.(?:ico|css|js|gif|jpe?g|png|woff2?|eot|ttf|svg|mp3|wav)$ {
        expires 6M;
        access_log off;
        add_header Cache-Control "public, max-age=15552000, immutable";
    }

    # SPA Fallback
    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/sentinel

sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx

# 7. Configure Linux Firewall (UFW)
echo "🛡️ [7/7] Hardening UFW Firewall..."
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable || true

PUBLIC_IP=$(curl -s -m 5 https://api.ipify.org || curl -s -m 5 ifconfig.me || echo "YOUR_SERVER_IP")

echo ""
echo "=================================================================="
echo "✅ SENTINEL ENTERPRISE SOC DEPLOYMENT SUCCESSFUL!"
echo "=================================================================="
echo ""
echo "🌐 Web Dashboard:        http://${PUBLIC_IP}"
echo "🚀 REST API Gateway:     http://${PUBLIC_IP}/api/health"
echo "⚡ Live WebSocket:       ws://${PUBLIC_IP}/ws"
echo "📊 Real-Time Telemetry:  http://${PUBLIC_IP}/api/system/info"
echo ""
echo "🔧 PM2 Management Commands:"
echo "   pm2 status            - View backend process status"
echo "   pm2 logs              - View live server logs"
echo "   pm2 restart all       - Restart backend service"
echo ""
echo "🔒 To attach a custom domain and Free SSL (HTTPS):"
echo "   sudo apt install -y certbot python3-certbot-nginx"
echo "   sudo certbot --nginx -d yourdomain.com"
echo "=================================================================="
