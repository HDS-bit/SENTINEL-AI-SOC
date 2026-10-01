/**
 * Database Sentinel Firewall Engine - SQL Lexical Parser, Risk Scorer & Defense Gateway
 */

export const RISK_LEVELS = {
  SAFE: { label: 'SAFE', color: 'emerald', maxScore: 35 },
  SUSPICIOUS: { label: 'SUSPICIOUS', color: 'amber', maxScore: 65 },
  CRITICAL: { label: 'CRITICAL / BLOCKED', color: 'rose', maxScore: 100 }
};

export const DEFAULT_FIREWALL_RULES = [
  { id: 'DBFW-01', name: 'Tautology / Always-True Injection', enabled: true, weight: 35, pattern: /(\d+)\s*=\s*\1|'([^']*)'\s*=\s*'\2'|\bOR\s+1\s*=\s*1\b|\bOR\s+'a'='a'/i },
  { id: 'DBFW-02', name: 'Stacked Query Execution (;)', enabled: true, weight: 40, pattern: /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|EXEC|CREATE)/i },
  { id: 'DBFW-03', name: 'Union-Based Data Extraction', enabled: true, weight: 45, pattern: /\bUNION\s+(ALL\s+)?SELECT\b/i },
  { id: 'DBFW-04', name: 'Time-Based / Blind Delay Probe', enabled: true, weight: 40, pattern: /\b(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|PG_SLEEP\s*\()/i },
  { id: 'DBFW-05', name: 'Schema & System Metadata Harvesting', enabled: true, weight: 30, pattern: /\b(information_schema|sysobjects|syscolumns|sqlite_master|all_tables)\b/i },
  { id: 'DBFW-06', name: 'Command Shell Execution (RCE)', enabled: true, weight: 50, pattern: /\b(xp_cmdshell|exec\s+master|sp_executesql|load_file|into\s+outfile)\b/i },
  { id: 'DBFW-07', name: 'SQL Comment Stripping (-- or /* */)', enabled: true, weight: 20, pattern: /(--|\/\*|\*\/|#)/i },
  { id: 'DBFW-08', name: 'Destructive DDL Command', enabled: true, weight: 45, pattern: /\b(DROP\s+TABLE|TRUNCATE\s+TABLE|DROP\s+DATABASE|ALTER\s+USER)\b/i }
];

export function analyzeSQLQuery(rawQuery = '', rules = DEFAULT_FIREWALL_RULES) {
  const query = String(rawQuery || '').trim();
  if (!query) {
    return {
      query: '',
      riskScore: 0,
      riskLevel: RISK_LEVELS.SAFE,
      verdict: 'ALLOW',
      matchedRules: [],
      tokens: [],
      remediation: '',
      parameterizedQuery: ''
    };
  }

  let totalRisk = 0;
  const matchedRules = [];

  rules.forEach(rule => {
    if (rule.enabled && rule.pattern.test(query)) {
      totalRisk += rule.weight;
      matchedRules.push({
        id: rule.id,
        name: rule.name,
        weight: rule.weight
      });
    }
  });

  // Calculate Shannon entropy on query
  const len = query.length;
  let charMap = {};
  for (let i = 0; i < len; i++) {
    charMap[query[i]] = (charMap[query[i]] || 0) + 1;
  }
  let entropy = 0;
  for (const c in charMap) {
    const p = charMap[c] / len;
    entropy -= p * Math.log2(p);
  }

  if (entropy > 4.2 && len > 50) {
    totalRisk += 15;
    matchedRules.push({
      id: 'DBFW-ENTROPY',
      name: `High Query Entropy (${entropy.toFixed(2)} bits/char - Obfuscation Signal)`,
      weight: 15
    });
  }

  const normalizedRisk = Math.min(Math.round(totalRisk), 100);

  let riskLevel = RISK_LEVELS.SAFE;
  let verdict = 'ALLOW';

  if (normalizedRisk >= 65) {
    riskLevel = RISK_LEVELS.CRITICAL;
    verdict = 'BLOCK & MITIGATE';
  } else if (normalizedRisk >= 35) {
    riskLevel = RISK_LEVELS.SUSPICIOUS;
    verdict = 'WARN / AUDIT';
  }

  // Tokenizer for high-tech visualization
  const tokens = tokenizeSQL(query);

  // Generate defensive prepared statement recommendation
  const parameterized = generateParameterizedSQL(query);

  return {
    query,
    riskScore: normalizedRisk,
    riskLevel,
    verdict,
    matchedRules,
    tokens,
    entropy: Number(entropy.toFixed(3)),
    parameterizedQuery: parameterized.safeQuery,
    remediation: parameterized.explanation
  };
}

function tokenizeSQL(query) {
  const tokenRegex = /(\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|UNION|JOIN|AND|OR|EXEC|INTO|VALUES|SET|TABLE|DATABASE|SLEEP|BENCHMARK)\b)|('[^']*')|(--.*|\/\*[\s\S]*?\*\/)|(\d+)|([=><!;,()+\-*/%])|([a-zA-Z_][a-zA-Z0-9_.]*)/gi;
  
  const tokens = [];
  let match;
  while ((match = tokenRegex.exec(query)) !== null) {
    let type = 'identifier';
    const text = match[0];
    if (match[1]) type = 'keyword';
    else if (match[2]) type = 'string';
    else if (match[3]) type = 'comment';
    else if (match[4]) type = 'number';
    else if (match[5]) type = 'operator';

    tokens.push({ text, type });
  }

  return tokens;
}

function generateParameterizedSQL(query) {
  // Replace raw literal strings and numbers inside WHERE clauses with placeholders ?
  let safeQuery = query.replace(/'[^']*'/g, '?').replace(/\b\d+\b/g, '?');
  // Remove comment sequences
  safeQuery = safeQuery.replace(/--.*|\/\*[\s\S]*?\*\//g, '').trim();

  let explanation = 'Use Prepared Statements / Parameterized Queries with ORM or native database drivers (e.g. mysql2, pg, Prisma, Hibernate) to isolate SQL logic from user data input.';
  if (query.toLowerCase().includes('union')) {
    explanation = 'CRITICAL: Block dynamic UNION queries. Validate column count and enforce strict schema whitelisting.';
  } else if (query.toLowerCase().includes('drop') || query.toLowerCase().includes('truncate')) {
    explanation = 'CRITICAL: DDL operations (DROP/TRUNCATE) must NEVER be executed from public-facing application service roles.';
  }

  return { safeQuery, explanation };
}

// Simulated Mock Database Database State for Live Sandbox
export const MOCK_DATABASE = {
  users: [
    { id: 1, username: 'admin', email: 'admin@secops.corp', role: 'SuperAdmin', pass_hash: '$2b$12$98zJk...' },
    { id: 2, username: 'sarah_soc', email: 'sarah@secops.corp', role: 'SecurityAnalyst', pass_hash: '$2b$12$4Lp10...' },
    { id: 3, username: 'john_dev', email: 'john@secops.corp', role: 'Developer', pass_hash: '$2b$12$7kPq0...' },
    { id: 4, username: 'guest_user', email: 'guest@public.io', role: 'PublicGuest', pass_hash: '$2b$12$2mN91...' }
  ],
  audit_logs: [
    { id: 101, timestamp: '2026-08-29 19:30:11', event: 'LOGIN_SUCCESS', ip: '10.0.0.4' },
    { id: 102, timestamp: '2026-08-29 19:32:45', event: 'CONFIG_CHANGE', ip: '10.0.0.12' }
  ]
};

export function executeMockQuery(query, isFirewallProtected = true) {
  const analysis = analyzeSQLQuery(query);

  if (isFirewallProtected && analysis.verdict === 'BLOCK & MITIGATE') {
    return {
      status: 'BLOCKED_BY_FIREWALL',
      firewallAction: 'INTERCEPTED & DROPPED',
      executionTimeMs: 1.2,
      rowCount: 0,
      results: [],
      error: `[DB-FIREWALL-SHIELD] Access Denied. Malicious pattern violation detected: ${analysis.matchedRules.map(r => r.name).join(', ')}. Incident logged to SOC Sentinel.`,
      analysis
    };
  }

  // Simulate vulnerable execution
  const lower = query.toLowerCase();
  if (lower.includes('or 1=1') || lower.includes("or '1'='1") || lower.includes("or 'a'='a'")) {
    return {
      status: 'EXECUTED_VULNERABLE',
      executionTimeMs: 4.8,
      rowCount: MOCK_DATABASE.users.length,
      results: MOCK_DATABASE.users, // Full database leaked!
      warning: 'DATA BREACH: All user records and password hashes leaked via SQL injection bypass!',
      analysis
    };
  }

  if (lower.includes('union select')) {
    return {
      status: 'EXECUTED_VULNERABLE',
      executionTimeMs: 6.1,
      rowCount: 3,
      results: [
        { column_1: 'SYSTEM_VERSION', column_2: 'PostgreSQL 16.4 / Linux x86_64' },
        { column_1: 'SECRET_API_KEY', column_2: 'sec_live_948f938c82b041a99' },
        { column_1: 'MASTER_KEY', column_2: 'aes-256-gcm:d4f8e9102c91834b' }
      ],
      warning: 'EXPLOITATION SUCCESSFUL: Unauthorized union schema extraction executed.',
      analysis
    };
  }

  if (lower.includes('drop table') || lower.includes('truncate')) {
    return {
      status: 'EXECUTED_VULNERABLE',
      executionTimeMs: 12.4,
      rowCount: 0,
      results: [],
      warning: 'CATASTROPHIC FAILURE: Table dropped! Database integrity destroyed.',
      analysis
    };
  }

  // Normal query
  return {
    status: 'EXECUTED_CLEAN',
    executionTimeMs: 2.5,
    rowCount: 1,
    results: [MOCK_DATABASE.users[0]],
    analysis
  };
}
