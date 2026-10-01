import { Router } from 'express';
import { packetStreamManager } from '../services/packetStreamService.js';
import { db } from '../db/database.js';

const router = Router();

/**
 * @route GET /api/traffic/packets
 * @desc Get latest buffered network packets
 */
router.get('/packets', (req, res) => {
  res.json({
    packets: packetStreamManager.getRecentPackets(),
    totalQuarantined: db.get('quarantinedIPs').length,
    totalIncidents: db.get('incidentLogs').length
  });
});

/**
 * @route POST /api/traffic/inject
 * @desc Inject simulated attack vector into live packet stream
 */
router.post('/inject', (req, res) => {
  const { type } = req.body;
  if (!type) {
    return res.status(400).json({ error: 'Attack type is required (e.g., SQLI, XSS, DDOS, POISONING)' });
  }

  const packet = packetStreamManager.injectAttack(type);
  res.json({
    success: true,
    injectedPacket: packet,
    message: `Injected attack vector: ${type}`
  });
});

/**
 * @route GET /api/traffic/quarantined
 * @desc Get list of quarantined IP addresses
 */
router.get('/quarantined', (req, res) => {
  res.json(db.get('quarantinedIPs'));
});

/**
 * @route POST /api/traffic/quarantine
 * @desc Manually quarantine a malicious IP
 */
router.post('/quarantine', (req, res) => {
  const { ip, reason = 'Operator Initiated Defense Isolation' } = req.body;

  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }

  const quarantined = db.get('quarantinedIPs');
  const existing = quarantined.find(q => q.ip === ip);

  if (existing) {
    return res.json({ message: 'IP is already quarantined', entry: existing });
  }

  const entry = {
    ip,
    reason,
    time: new Date().toTimeString().slice(0, 8),
    active: true,
    hits: 1
  };

  db.insert('quarantinedIPs', entry);

  packetStreamManager.broadcast({
    type: 'IP_QUARANTINED',
    entry
  });

  res.status(201).json({ success: true, entry });
});

/**
 * @route DELETE /api/traffic/quarantine/:ip
 * @desc Unban / Release an IP from quarantine
 */
router.delete('/quarantine/:ip', (req, res) => {
  const { ip } = req.params;
  const removed = db.delete('quarantinedIPs', q => q.ip === ip);

  if (removed) {
    packetStreamManager.broadcast({
      type: 'IP_UNBANNED',
      ip
    });
    return res.json({ success: true, message: `IP ${ip} released from quarantine` });
  }

  res.status(404).json({ error: `IP ${ip} was not found in quarantine` });
});

/**
 * @route POST /api/traffic/lockdown
 * @desc Toggle Emergency SOC Level 1 Lockdown
 */
router.post('/lockdown', (req, res) => {
  const status = db.get('socStatus') || {};
  const newLockdown = !status.emergencyLockdown;
  const newThreat = newLockdown ? 'CRITICAL' : 'NORMAL';

  db.set('socStatus', {
    ...status,
    emergencyLockdown: newLockdown,
    threatLevel: newThreat,
    lastSync: new Date().toISOString()
  });

  packetStreamManager.broadcast({
    type: 'EMERGENCY_LOCKDOWN_TOGGLE',
    emergencyLockdown: newLockdown,
    threatLevel: newThreat
  });

  res.json({
    emergencyLockdown: newLockdown,
    threatLevel: newThreat,
    message: newLockdown ? '🚨 SOC EMERGENCY LEVEL 1 LOCKDOWN ENGAGED' : '🛡️ Standard Defense Protocol Restored'
  });
});

export default router;
