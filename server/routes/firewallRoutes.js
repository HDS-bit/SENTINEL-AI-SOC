import { Router } from 'express';
import { inspectSqlQuery, sanitizeQuery } from '../services/securityEngine.js';
import { db } from '../db/database.js';
import { packetStreamManager } from '../services/packetStreamService.js';

const router = Router();

/**
 * @route POST /api/firewall/inspect
 * @desc Inspect and evaluate SQL/NoSQL query in real-time
 */
router.post('/inspect', (req, res) => {
  const { query, ip = req.ip || '127.0.0.1' } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Query string is required' });
  }

  const result = inspectSqlQuery(query);
  const rules = db.get('firewallRules').filter(r => r.enabled);

  // Check dynamic user rules
  let matchedRule = null;
  for (const rule of rules) {
    try {
      const reg = new RegExp(rule.pattern, 'i');
      if (reg.test(query)) {
        matchedRule = rule;
        break;
      }
    } catch (e) {
      // Ignore invalid regex in user-defined rules
    }
  }

  if (matchedRule) {
    result.matchedRule = matchedRule;
    if (matchedRule.action === 'BLOCK') {
      result.isBlocked = true;
      result.riskScore = Math.max(result.riskScore, matchedRule.riskThreshold || 80);
    }
  }

  // If blocked, record to blocked queries database
  if (result.isBlocked) {
    const entry = {
      id: `bq-${Date.now()}`,
      query,
      risk: result.riskScore,
      time: new Date().toTimeString().slice(0, 8),
      ip,
      ruleTriggered: matchedRule ? matchedRule.name : 'AST Heuristic Classifier',
      threats: result.threats
    };

    db.insert('blockedQueries', entry);

    // Auto-quarantine repeat offenders
    if (result.riskScore >= 80) {
      const quarantined = db.get('quarantinedIPs');
      if (!quarantined.some(q => q.ip === ip)) {
        db.insert('quarantinedIPs', {
          ip,
          reason: `SQL Firewall Block: ${matchedRule ? matchedRule.name : 'High Risk Injection'}`,
          time: new Date().toTimeString().slice(0, 8),
          active: true,
          hits: 1
        });
      }
    }

    packetStreamManager.broadcast({
      type: 'FIREWALL_BLOCKED_QUERY',
      entry
    });
  }

  res.json(result);
});

/**
 * @route GET /api/firewall/rules
 * @desc Retrieve all active database firewall rules
 */
router.get('/rules', (req, res) => {
  res.json(db.get('firewallRules'));
});

/**
 * @route POST /api/firewall/rules
 * @desc Add a new firewall rule
 */
router.post('/rules', (req, res) => {
  const { name, pattern, action = 'BLOCK', riskThreshold = 75, category = 'CUSTOM' } = req.body;

  if (!name || !pattern) {
    return res.status(400).json({ error: 'Rule name and regex pattern are required' });
  }

  const newRule = {
    id: `rule-${Date.now()}`,
    name,
    pattern,
    action,
    riskThreshold: Number(riskThreshold),
    enabled: true,
    category
  };

  db.insert('firewallRules', newRule);
  res.status(201).json(newRule);
});

/**
 * @route PUT /api/firewall/rules/:id
 * @desc Update or toggle rule
 */
router.put('/rules/:id', (req, res) => {
  const { id } = req.params;
  const updated = db.update('firewallRules', r => r.id === id, req.body);

  if (!updated) {
    return res.status(404).json({ error: 'Rule not found' });
  }

  res.json(updated);
});

/**
 * @route DELETE /api/firewall/rules/:id
 * @desc Delete a firewall rule
 */
router.delete('/rules/:id', (req, res) => {
  const { id } = req.params;
  const removed = db.delete('firewallRules', r => r.id === id);

  if (!removed) {
    return res.status(404).json({ error: 'Rule not found' });
  }

  res.json({ success: true, message: 'Rule removed' });
});

/**
 * @route GET /api/firewall/logs
 * @desc Get blocked query history
 */
router.get('/logs', (req, res) => {
  res.json(db.get('blockedQueries'));
});

/**
 * @route POST /api/firewall/logs/clear
 * @desc Clear blocked query history
 */
router.post('/logs/clear', (req, res) => {
  db.set('blockedQueries', []);
  res.json({ success: true, message: 'Blocked query logs cleared' });
});

export default router;
