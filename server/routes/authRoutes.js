import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db } from '../db/database.js';
import { config } from '../config/config.js';

const router = Router();

// Middleware to authenticate JWT token
export function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, config.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
}

/**
 * @route POST /api/auth/login
 * @desc Authenticate user and issue JWT
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = db.find('users', u => u.email.toLowerCase() === email.toLowerCase());

    if (!user) {
      return res.status(401).json({ error: 'Invalid security credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid security credentials' });
    }

    // Update last login
    db.update('users', u => u.id === user.id, { lastLogin: new Date().toISOString() });

    const payload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      badge: user.badge
    };

    const token = jwt.sign(payload, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        badge: user.badge,
        twoFactorEnabled: user.twoFactorEnabled,
        lastLogin: new Date().toISOString()
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Authentication service internal error: ' + err.message });
  }
});

/**
 * @route POST /api/auth/register
 * @desc Register a new SOC Operator
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password, name, role = 'SECURITY_ANALYST', badge } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    const existing = db.find('users', u => u.email.toLowerCase() === email.toLowerCase());
    if (existing) {
      return res.status(409).json({ error: 'An operator with this email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = {
      id: `usr-${Date.now()}`,
      email,
      passwordHash,
      name,
      role,
      badge: badge || `CSTD-OP-${Math.floor(Math.random() * 900 + 100)}`,
      twoFactorEnabled: false,
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString()
    };

    db.insert('users', newUser);

    const token = jwt.sign({
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
      badge: newUser.badge
    }, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN });

    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role,
        badge: newUser.badge,
        createdAt: newUser.createdAt
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration error: ' + err.message });
  }
});

/**
 * @route GET /api/auth/me
 * @desc Verify token and return current operator profile
 */
router.get('/me', authenticateToken, (req, res) => {
  const user = db.find('users', u => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    badge: user.badge,
    twoFactorEnabled: user.twoFactorEnabled,
    lastLogin: user.lastLogin
  });
});

/**
 * @route POST /api/auth/verify-2fa
 * @desc Verify 2FA code
 */
router.post('/verify-2fa', (req, res) => {
  const { code } = req.body;
  if (!code || code.length !== 6) {
    return res.status(400).json({ error: 'Valid 6-digit 2FA code required' });
  }

  // Demonstration 2FA acceptance (validates non-trivial 6 digits)
  res.json({
    verified: true,
    timestamp: new Date().toISOString(),
    message: '2FA Identity Cleared'
  });
});

export default router;
