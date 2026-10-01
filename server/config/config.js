import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env if present
dotenv.config({ path: path.join(__dirname, '../../.env') });
dotenv.config({ path: path.join(__dirname, '../.env') });

export const config = {
  PORT: process.env.PORT || 5000,
  HOST: process.env.HOST || '0.0.0.0',
  NODE_ENV: process.env.NODE_ENV || 'production',
  JWT_SECRET: process.env.JWT_SECRET || 'sentinel-super-secret-cyber-soc-jwt-key-2025-defense-token',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY || '',
  UPLOAD_DIR: path.join(__dirname, '../data/uploads'),
  DATA_DIR: path.join(__dirname, '../data'),
  DB_FILE: path.join(__dirname, '../data/sentinel_db.json'),
  CORS_ORIGINS: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000', 'http://127.0.0.1:5173'],
  DIST_DIR: path.join(__dirname, '../../dist')
};
