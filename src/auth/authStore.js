/**
 * Secure User Authentication, Password Safety Meter, 2FA & RBAC Store
 */

export const RBAC_ROLES = {
  SOC_COMMANDER: {
    id: 'SOC_COMMANDER',
    name: 'SOC Commander / Lead Analyst',
    level: 4,
    color: 'text-cyan-400 bg-cyan-950/60 border-cyan-500/50',
    permissions: ['ALL_PERMISSIONS', 'FIREWALL_MODIFY', 'IP_BAN', 'EXPORT_FORENSICS', 'TRAIN_MODELS', 'USER_MANAGEMENT']
  },
  THREAT_HUNTER: {
    id: 'THREAT_HUNTER',
    name: 'Senior Threat Hunter',
    level: 3,
    color: 'text-purple-400 bg-purple-950/60 border-purple-500/50',
    permissions: ['VIEW_DASHBOARD', 'RUN_DETECTIONS', 'TRAIN_MODELS', 'SANDBOX_ACCESS', 'QUARANTINE_IP']
  },
  DB_ADMIN: {
    id: 'DB_ADMIN',
    name: 'Database Security Admin',
    level: 3,
    color: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/50',
    permissions: ['VIEW_DASHBOARD', 'FIREWALL_MODIFY', 'QUERY_AUDIT', 'DB_SANDBOX']
  },
  SECURITY_AUDITOR: {
    id: 'SECURITY_AUDITOR',
    name: 'Compliance & Security Auditor',
    level: 1,
    color: 'text-amber-400 bg-amber-950/60 border-amber-500/50',
    permissions: ['VIEW_DASHBOARD', 'VIEW_AUDIT_LOGS', 'EXPORT_REPORTS']
  }
};

// Password Entropy & Crack Time Calculator
export function evaluatePasswordStrength(password = '') {
  if (!password) {
    return {
      score: 0,
      entropy: 0,
      crackTime: 'Instant',
      level: 'Empty',
      color: 'text-gray-500',
      barColor: 'bg-gray-700',
      suggestions: ['Enter a strong password with at least 12 characters, uppercase, lowercase, numbers, and symbols.']
    };
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/\d/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

  const length = password.length;
  // Entropy = length * log2(poolSize)
  const entropy = Math.round(length * (poolSize > 0 ? Math.log2(poolSize) : 0));

  let score = 0;
  const suggestions = [];

  if (length < 8) suggestions.push('Use at least 8 characters (12+ recommended).');
  else if (length < 12) suggestions.push('Increasing length to 12+ characters significantly raises brute-force resistance.');

  if (!/[A-Z]/.test(password)) suggestions.push('Add uppercase letters (A-Z).');
  if (!/[a-z]/.test(password)) suggestions.push('Add lowercase letters (a-z).');
  if (!/\d/.test(password)) suggestions.push('Add numbers (0-9).');
  if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push('Add special symbols (!@#$%^&*).');

  if (entropy < 28) {
    return {
      score: 1,
      entropy,
      crackTime: '< 1 second (High Risk)',
      level: 'Very Weak',
      color: 'text-rose-400',
      barColor: 'bg-rose-500',
      suggestions
    };
  } else if (entropy < 45) {
    return {
      score: 2,
      entropy,
      crackTime: '3.2 minutes',
      level: 'Weak',
      color: 'text-amber-400',
      barColor: 'bg-amber-500',
      suggestions
    };
  } else if (entropy < 65) {
    return {
      score: 3,
      entropy,
      crackTime: '4.8 months',
      level: 'Moderate',
      color: 'text-yellow-400',
      barColor: 'bg-yellow-500',
      suggestions
    };
  } else if (entropy < 85) {
    return {
      score: 4,
      entropy,
      crackTime: '1,400 years',
      level: 'Strong',
      color: 'text-emerald-400',
      barColor: 'bg-emerald-500',
      suggestions
    };
  } else {
    return {
      score: 5,
      entropy,
      crackTime: '2.4 trillion years (Military-Grade)',
      level: 'Ultra Secure',
      color: 'text-cyan-400',
      barColor: 'bg-cyan-400',
      suggestions: ['Excellent password! High resistance to GPU cluster dictionary attacks.']
    };
  }
}

// Pseudo Cryptographic Hasher for Visual Demonstration
export function simulateCryptoHash(text, salt = 'cstd_salt_99') {
  let hash = 0;
  const combined = text + salt;
  for (let i = 0; i < combined.length; i++) {
    const char = combined.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  // Hex representation padded
  const hex1 = Math.abs(hash).toString(16).padStart(8, '0');
  const hex2 = Math.abs(hash ^ 0x5f3759df).toString(16).padStart(8, '0');
  const hex3 = Math.abs((hash * 31) | 0).toString(16).padStart(8, '0');
  const hex4 = Math.abs((hash ^ 0xa5a5a5a5)).toString(16).padStart(8, '0');
  return `sha256$${hex1}${hex2}${hex3}${hex4}`;
}

export function generateTOTPCode() {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  return code;
}

export const INITIAL_USER = {
  id: 'usr_soc_001',
  username: 'Sentinel_Admin',
  email: 'admin@sentinel.cyberops',
  role: 'SOC_COMMANDER',
  twoFactorEnabled: true,
  totpSecret: 'JBSWY3DPEHPK3PXP',
  activeSessionToken: 'sess_sec_994a821e0b',
  lastLogin: '2026-08-29 19:40:02 UTC',
  loginIp: '192.168.1.1',
  passHash: simulateCryptoHash('CyberSecureAdmin2026!#'),
  isLocked: false,
  failedAttempts: 0
};
