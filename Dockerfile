# ==============================================================================
# CSTD SENTINEL AI SOC - Unified Full-Stack Production Container
# Builds React Frontend SPA + Runs Express & WebSocket Server on Node.js 20 LTS
# ==============================================================================

# Stage 1: Build React Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install
COPY . .
RUN npm run build

# Stage 2: Install Backend Dependencies
FROM node:20-alpine AS backend-builder
WORKDIR /app/server
COPY server/package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

# Stage 3: Production Runtime
FROM node:20-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=5000
ENV HOST=0.0.0.0

# Copy backend dependencies and code
COPY --from=backend-builder /app/server/node_modules ./server/node_modules
COPY --from=backend-builder /app/server/package*.json ./server/
COPY server/ ./server/

# Copy built frontend assets to dist/
COPY --from=frontend-builder /app/dist ./dist

# Create persistent storage directories
RUN mkdir -p /app/server/data/uploads && chmod -R 777 /app/server/data

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/api/health || exit 1

# Launch Server
CMD ["node", "server/server.js"]
