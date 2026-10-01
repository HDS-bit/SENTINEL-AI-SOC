import { Router } from 'express';
import { db } from '../db/database.js';

const router = Router();

/**
 * @route GET /api/incidents
 * @desc Get all logged security incident events
 */
router.get('/', (req, res) => {
  res.json(db.get('incidentLogs'));
});

/**
 * @route POST /api/incidents
 * @desc Manually record a security incident
 */
router.post('/', (req, res) => {
  const { ip, type, payload, action = 'LOGGED', severity = 'MEDIUM' } = req.body;

  if (!ip || !type) {
    return res.status(400).json({ error: 'IP and incident type are required' });
  }

  const incident = {
    id: `inc-${Date.now()}`,
    ip,
    type,
    payload: payload || '',
    time: new Date().toTimeString().slice(0, 8),
    action,
    severity
  };

  db.insert('incidentLogs', incident);
  res.status(201).json(incident);
});

/**
 * @route POST /api/incidents/clear
 * @desc Clear incident log repository
 */
router.post('/clear', (req, res) => {
  db.set('incidentLogs', []);
  res.json({ success: true, message: 'Incident logs cleared' });
});

export default router;
