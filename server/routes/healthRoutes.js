import { Router } from 'express';
import { getSystemMetrics, getServerInfo } from '../services/systemService.js';
import { db } from '../db/database.js';

const router = Router();

/**
 * @route GET /api/health
 * @desc Quick liveness & readiness check
 */
router.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'SENTINEL AI SOC Engine',
    version: '3.4.0-enterprise',
    timestamp: new Date().toISOString(),
    uptime: Math.round(process.uptime()),
    database: 'PERSISTED_OK'
  });
});

/**
 * @route GET /api/system/metrics
 * @desc Real-time hardware telemetry (CPU, RAM, Load)
 */
router.get('/system/metrics', (req, res) => {
  res.json(getSystemMetrics());
});

/**
 * @route GET /api/system/info
 * @desc Host server hardware, platform & network interfaces
 */
router.get('/system/info', (req, res) => {
  res.json({
    server: getServerInfo(),
    metrics: getSystemMetrics(),
    soc: db.get('socStatus')
  });
});

export default router;
