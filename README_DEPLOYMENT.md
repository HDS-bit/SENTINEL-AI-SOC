# 🛡️ CSTD SENTINEL AI SOC — Real Server Deployment Manual

SENTINEL is an enterprise-grade **AI Cybersecurity & SOC Threat Intelligence Platform** featuring real-time packet telemetry, dynamic database firewall, multi-model ML classifier zoo, server-side dataset sanitization, and hardware diagnostics.

---

## 🏛️ System Architecture

```
                               ┌──────────────────────────────────────────────┐
                               │            Client Browser (SOC)              │
                               └──────┬────────────────────────────────┬──────┘
                                      │ HTTPS (:443) / HTTP (:80)      │ WebSocket (:5000 / /ws)
                                      ▼                                ▼
                       ┌──────────────────────────────┐ ┌──────────────────────────────┐
                       │  Nginx Web Server & Proxy    │ │  Live WebSocket Stream       │
                       │  - SSL Termination           │ │  - Real-time Packet Engine   │
                       │  - SPA Static Asset Caching  │ │  - Threat Intercept Alerts   │
                       │  - Gzip / Security Headers   │ │  - Host Resource Telemetry   │
                       └──────────────┬───────────────┘ └──────────────┬───────────────┘
                                      │ /api/* Reverse Proxy           │
                                      ▼                                │
┌──────────────────────────────────────────────────────────────────────┴──────────────────────────────────┐
│                             SENTINEL Node.js Enterprise Server (:5000)                                   │
│  ┌─────────────────────────┬─────────────────────────┬─────────────────────────┬──────────────────────┐ │
│  │   REST API Gateway      │    Security Kernel      │   File Sanitizer Engine │ Hardware Telemetry   │ │
│  │   - /api/health         │   - SQLi AST Parser     │   - Multipart Uploads   │ - CPU Load %         │ │
│  │   - /api/auth (JWT)     │   - XSS Neutralizer     │   - Dataset Disinfection│ - Memory Allocation  │ │
│  │   - /api/traffic        │   - PII/Secret Masker   │   - Rectified Downloads │ - System Load / IPs  │ │
│  │   - /api/firewall       │   - Adversarial Guard   │   - Persistent Storage  │ - OS Architecture    │ │
│  └─────────────────────────┴─────────────────────────┴─────────────────────────┴──────────────────────┘ │
│                                      │                                                                  │
│                                      ▼                                                                  │
│                      ┌──────────────────────────────┐ ┌──────────────────────────────┐                  │
│                      │ Persistent DB (Atomic JSON)  │ │ Google Gemini 1.5 Gateway    │                  │
│                      │ (Users, Rules, Logs, Files)  │ │ (Cloud Threat Intelligence)  │                  │
│                      └──────────────────────────────┘ └──────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Deployment Options

### Option 1: Automated 1-Click Linux VM Deployment (Recommended)
**Tested on:** Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12, AWS EC2, DigitalOcean Droplets, Linode, Hetzner, GCP Compute Engine.

1. SSH into your remote server:
   ```bash
   ssh root@<YOUR_SERVER_IP>
   ```

2. Clone the repository and run the automated deployment script:
   ```bash
   git clone <YOUR_REPOSITORY_URL> sentinel
   cd sentinel
   chmod +x deploy-vm.sh
   ./deploy-vm.sh
   ```

3. **What the script does automatically:**
   - Installs Node.js 20 LTS, Nginx, UFW Firewall, and PM2.
   - Compiles the production React frontend bundle.
   - Launches the backend server under PM2 with automatic restart on boot.
   - Configures Nginx reverse proxy for `/api/`, `/ws`, and static SPA routing.
   - Configures UFW firewall for OpenSSH (22) and Nginx Full (80/443).
   - Outputs the public URL and diagnostic endpoints.

---

### Option 2: Docker & Docker Compose
Ideal for containerized cloud environments (AWS ECS, DigitalOcean App Platform, GCP Cloud Run, Docker Swarm):

1. **Single-Command Launch:**
   ```bash
   docker-compose up -d --build
   ```

2. **Access your instance:**
   - Web App: `http://<SERVER_IP>:5000` (or `http://<SERVER_IP>:80`)
   - Health Check: `http://<SERVER_IP>:5000/api/health`
   - Telemetry: `http://<SERVER_IP>:5000/api/system/info`

---

### Option 3: 1-Click Cloud Platforms (Render / Railway / Fly.io)

1. **Render.com / Railway.app:**
   - Create a **New Web Service** connected to your Git repository.
   - **Environment:** Docker
   - **Build Command:** *(Leave empty, uses Dockerfile)*
   - **Start Command:** *(Leave empty, uses Dockerfile CMD)*
   - **Port:** `5000`

---

### Option 4: Windows Server or Local Production Run

1. Simply double-click **`START_WEBSITE.bat`** (or `run.bat`).
2. The script will automatically build the assets and start the enterprise Node.js server on `http://localhost:5000`.

---

## 🔒 Custom Domain & Free SSL/HTTPS Setup (Let's Encrypt)

To secure your server with HTTPS using Certbot:

1. Point your domain's DNS `A Record` to your server's Public IP (e.g. `soc.yourcompany.com` -> `198.51.100.42`).
2. Run Certbot on your server:
   ```bash
   sudo apt update
   sudo apt install -y certbot python3-certbot-nginx
   sudo certbot --nginx -d soc.yourcompany.com
   ```
3. Certbot will automatically issue a free SSL certificate, configure Nginx with HTTP-to-HTTPS redirect, and setup automatic renewal!

---

## 🔑 Default Credentials & Operator Roles

| Role | Username / Email | Default Password | Access Level |
|---|---|---|---|
| **SOC Commander** | `commander@sentinel.defense.gov` | `Sentinel@2025!` | Full Root Access, Emergency Lockdown, Quarantine Control |
| **Threat Analyst** | `analyst@sentinel.defense.gov` | `Analyst@2025!` | Threat Ingestion, Model Zoo Retraining, Incident Audit |
| **Demo Operator** | `Sentinel_Admin` | *(6+ characters)* | Interactive Sandboxed SOC Session with 2FA |

---

## 📡 REST API & WebSocket Endpoints Reference

### Telemetry & Health
- `GET /api/health` — Service readiness & status check.
- `GET /api/system/metrics` — Real-time CPU Load %, Memory Used/Free MB, Load Average, Uptime.
- `GET /api/system/info` — Host OS, Architecture, Network Interface IPs, Node Runtime.

### Authentication & RBAC
- `POST /api/auth/login` — Authenticates credentials and returns JWT bearer token.
- `POST /api/auth/register` — Registers new SOC operator with password hashing.
- `GET /api/auth/me` — Decodes and verifies active JWT bearer session.

### Live Network Traffic & Packets
- `GET /api/traffic/packets` — Retrieves circular buffer of recent network packets.
- `POST /api/traffic/inject` — Injects live attack simulation (`SQLI`, `XSS`, `DDOS`, `POISONING`).
- `GET /api/traffic/quarantined` — Retrieves active IP quarantine list.
- `POST /api/traffic/quarantine` — Bans/quarantines a malicious IP.
- `DELETE /api/traffic/quarantine/:ip` — Unbans/releases an IP from quarantine.
- `POST /api/traffic/lockdown` — Toggles Level 1 Emergency SOC Lockdown.

### Database Firewall
- `POST /api/firewall/inspect` — Real-time AST query parser & threat evaluation.
- `GET /api/firewall/rules` — Lists active firewall rules and regexes.
- `POST /api/firewall/rules` — Adds dynamic security rule.
- `GET /api/firewall/logs` — Retrieves blocked queries history.

### File Processing & Dataset Sanitization
- `POST /api/files/upload` — Multipart dataset upload with automated threat scanning.
- `POST /api/files/sanitize` — Disinfects dataset records, neutralizes payloads, and masks PII.
- `GET /api/files/download/:filename` — Downloads sanitized dataset artifact.

### WebSocket Gateway
- `ws://<SERVER_IP>:5000/ws` (or `wss://yourdomain.com/ws`)
- **Broadcast Events:**
  - `INITIAL_STATE` — Initial packets, system metrics, and quarantined IPs.
  - `PACKET_STREAM` — Live packet telemetry streamed every 2 seconds.
  - `ATTACK_INJECTED` — High-priority attack alerts.
  - `IP_QUARANTINED` & `IP_UNBANNED` — Synchronized quarantine actions.
  - `FIREWALL_BLOCKED_QUERY` — Live firewall blocks.

---

## 🛠️ Management & Monitoring Commands

```bash
# Check PM2 backend status
pm2 status

# View live real-time server logs
pm2 logs sentinel-backend

# Restart server
pm2 restart sentinel-backend

# Test Nginx configuration
sudo nginx -t

# View Nginx error logs
sudo tail -f /var/log/nginx/error.log

# Check UFW Firewall Status
sudo ufw status verbose
```
