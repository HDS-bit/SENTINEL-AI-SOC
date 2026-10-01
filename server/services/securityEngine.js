/**
 * SENTINEL AI - Server-Side Security & Threat Detection Engine
 * Evaluates queries, network payloads, datasets, and files.
 */

// Entropy calculation
export function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const len = str.length;
  const freqs = {};
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    freqs[ch] = (freqs[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const ch in freqs) {
    const p = freqs[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

// SQL Injection Patterns & Weights
const SQL_PATTERNS = [
  { regex: /(\b(union(\s+all)?\s+select)\b)/i, weight: 45, label: 'UNION_BASED_INJECTION' },
  { regex: /('|\b)(or|and)\s+('?\d+'?|\w+)\s*=\s*('?\d+'?|\w+)/i, weight: 35, label: 'BOOLEAN_TAUTOLOGY' },
  { regex: /(--|\/\*|\*\/|#|;)/i, weight: 20, label: 'COMMENT_DELIMITER' },
  { regex: /(\b(drop|alter|truncate|exec|execute|insert|update|delete)\b)/i, weight: 30, label: 'STACKED_DDL_DML' },
  { regex: /(\b(information_schema|sys\.tables|sqlite_master|pg_catalog)\b)/i, weight: 40, label: 'SCHEMA_ENUMERATION' },
  { regex: /(\b(waitfor\s+delay|pg_sleep|sleep\s*\()\b)/i, weight: 50, label: 'TIME_BASED_INJECTION' }
];

// XSS Patterns
const XSS_PATTERNS = [
  { regex: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, weight: 45, label: 'SCRIPT_TAG' },
  { regex: /javascript\s*:/i, weight: 40, label: 'JAVASCRIPT_URI' },
  { regex: /on\w+\s*=\s*["'][^"']*["']/i, weight: 35, label: 'EVENT_HANDLER_INJECTION' },
  { regex: /(document\.cookie|window\.location|eval\s*\(|fetch\s*\()/i, weight: 35, label: 'DOM_EXFILTRATION' },
  { regex: /<iframe|<object|<embed/i, weight: 30, label: 'IFRAME_INCLUSION' }
];

// PII & Secret Patterns
const PII_PATTERNS = [
  { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, label: 'EMAIL_ADDRESS', mask: '***@***.***' },
  { regex: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, label: 'PHONE_NUMBER', mask: '(***) ***-****' },
  { regex: /\b\d{3}-\d{2}-\d{4}\b/, label: 'SSN', mask: '***-**-****' },
  { regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/, label: 'CREDIT_CARD', mask: '****-****-****-****' },
  { regex: /(?:ghp_[0-9a-zA-Z]{36}|sk_live_[0-9a-zA-Z]{24}|AIza[0-9A-Za-z-_]{35})/, label: 'API_SECRET_TOKEN', mask: '***REDACTED_API_KEY***' }
];

/**
 * Inspect SQL Query against known threat vectors
 */
export function inspectSqlQuery(query) {
  if (!query || typeof query !== 'string') {
    return { riskScore: 0, isBlocked: false, threats: [], sanitizedQuery: query };
  }

  let totalRisk = 0;
  const threats = [];

  for (const item of SQL_PATTERNS) {
    if (item.regex.test(query)) {
      totalRisk += item.weight;
      threats.push({ label: item.label, weight: item.weight });
    }
  }

  const entropy = calculateShannonEntropy(query);
  if (entropy > 4.5 && query.length > 25) {
    totalRisk += 15;
    threats.push({ label: 'HIGH_ENTROPY_OBFUSCATION', weight: 15 });
  }

  const finalRisk = Math.min(100, totalRisk);
  const isBlocked = finalRisk >= 60;

  return {
    query,
    riskScore: finalRisk,
    isBlocked,
    threats,
    entropy,
    verdict: isBlocked ? 'BLOCKED_BY_SENTINEL_FIREWALL' : 'PASSED_CLEAN',
    sanitizedQuery: sanitizeQuery(query)
  };
}

/**
 * Inspect text/payload for comprehensive threats
 */
export function inspectPayload(payload) {
  if (!payload || typeof payload !== 'string') {
    return { threatType: 'NORMAL', riskScore: 0, detections: [] };
  }

  let sqlRisk = 0;
  let xssRisk = 0;
  const detections = [];

  for (const p of SQL_PATTERNS) {
    if (p.regex.test(payload)) {
      sqlRisk += p.weight;
      detections.push(`SQL:${p.label}`);
    }
  }

  for (const p of XSS_PATTERNS) {
    if (p.regex.test(payload)) {
      xssRisk += p.weight;
      detections.push(`XSS:${p.label}`);
    }
  }

  let piiCount = 0;
  for (const p of PII_PATTERNS) {
    if (p.regex.test(payload)) {
      piiCount++;
      detections.push(`PII:${p.label}`);
    }
  }

  let threatType = 'NORMAL';
  if (sqlRisk >= 40) threatType = 'SQLI';
  else if (xssRisk >= 40) threatType = 'XSS';
  else if (piiCount > 0) threatType = 'PII_LEAK';
  else if (/SYN_FLOOD|DDOS|BURST|FLOOD/i.test(payload)) threatType = 'DDOS';
  else if (/poison|adversarial|perturbation/i.test(payload)) threatType = 'POISONING';

  const riskScore = Math.min(100, Math.max(sqlRisk, xssRisk, piiCount * 30));

  return {
    payload,
    threatType,
    riskScore,
    entropy: calculateShannonEntropy(payload),
    detections
  };
}

/**
 * Sanitize SQL Query string
 */
export function sanitizeQuery(query) {
  if (!query) return '';
  return query
    .replace(/--.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/'\s*or\s*'1'='1'/gi, "'1'='1' (sanitized)")
    .replace(/union\s+select/gi, '/* blocked_union */ select');
}

/**
 * Sanitize dataset records / JSON rows
 */
export function sanitizeDatasetRows(rows) {
  if (!Array.isArray(rows)) return [];
  
  let modifiedCount = 0;
  let piiMaskedCount = 0;
  let maliciousQuarantined = 0;

  const sanitizedRows = rows.map((row, idx) => {
    const cleanRow = { ...row };
    let rowHadMalice = false;

    for (const key of Object.keys(cleanRow)) {
      let val = cleanRow[key];
      if (typeof val === 'string') {
        // Mask PII
        for (const pii of PII_PATTERNS) {
          if (pii.regex.test(val)) {
            val = val.replace(pii.regex, pii.mask);
            piiMaskedCount++;
            modifiedCount++;
          }
        }

        // Neutralize XSS
        if (/<script|javascript:|onerror=/i.test(val)) {
          val = val.replace(/</g, '&lt;').replace(/>/g, '&gt;');
          rowHadMalice = true;
          modifiedCount++;
        }

        // Neutralize SQLi
        if (/union\s+select|'(\s*)or(\s*)'1'='1'/i.test(val)) {
          val = '[SENTINEL_SANITIZED_SQL_PAYLOAD]';
          rowHadMalice = true;
          modifiedCount++;
        }

        cleanRow[key] = val;
      }
    }

    if (rowHadMalice) maliciousQuarantined++;
    return cleanRow;
  });

  return {
    cleanedRows: sanitizedRows,
    stats: {
      totalRows: rows.length,
      modifiedRowsCount: modifiedCount,
      piiMaskedCount,
      maliciousQuarantined
    }
  };
}
