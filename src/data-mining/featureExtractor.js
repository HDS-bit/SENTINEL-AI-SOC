/**
 * Advanced Data Mining Feature Extraction Engine with Explainability (SHAP & Character Heatmaps)
 */

export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

const SQL_KEYWORDS = [
  'select', 'union', 'insert', 'update', 'delete', 'drop', 'exec', 'execute',
  'where', 'or', 'and', 'sleep', 'benchmark', 'schema', 'information_schema',
  'sysobjects', 'table_name', 'char', 'concat', 'load_file', 'into', 'outfile',
  'truncate', 'alter', 'cast', 'version', 'database', 'user', 'declare', 'waitfor'
];

const XSS_PATTERNS = [
  '<script', 'javascript:', 'onerror', 'onload', 'eval', 'alert', 'prompt',
  'document.cookie', 'window.location', 'src=', 'href=', 'svg', 'iframe',
  'onload', 'onmouseover', 'expression', 'vbscript:', 'fetch', 'xhr'
];

const SPECIAL_CHARS = [
  "'", '"', ';', '--', '/*', '*/', '<', '>', '=', '(', ')', '%', '\\', '/',
  '#', '+', '$', '&', '|', '!', '^', '`', '~', '{', '}', '[', ']'
];

export function extractPayloadFeatures(payload = '') {
  const str = String(payload || '');
  const len = str.length;
  const lower = str.toLowerCase();

  // 1. Shannon Entropy
  const entropy = calculateEntropy(str);

  // 2. Special Characters Count & Ratio
  let specialCount = 0;
  for (let i = 0; i < len; i++) {
    if (SPECIAL_CHARS.includes(str[i])) {
      specialCount++;
    }
  }
  const specialRatio = len > 0 ? Number((specialCount / len).toFixed(4)) : 0;

  // 3. SQL Keywords Count & Density
  let sqlKeywordCount = 0;
  SQL_KEYWORDS.forEach(kw => {
    const regex = new RegExp(`\\b${kw}\\b`, 'gi');
    const matches = lower.match(regex);
    if (matches) sqlKeywordCount += matches.length;
  });

  // 4. XSS Patterns Count
  let xssPatternCount = 0;
  XSS_PATTERNS.forEach(pat => {
    if (lower.includes(pat)) xssPatternCount++;
  });

  // 5. Hex & URL Encoded Character Count (e.g. %20, %27, 0x41)
  const hexMatches = str.match(/%[0-9a-fA-F]{2}|0x[0-9a-fA-F]+/g);
  const encodedCount = hexMatches ? hexMatches.length : 0;

  // 6. Digit / Numeric Ratio
  const digitMatches = str.match(/\d/g);
  const digitCount = digitMatches ? digitMatches.length : 0;
  const digitRatio = len > 0 ? Number((digitCount / len).toFixed(4)) : 0;

  // 7. Uppercase / Lowercase Disparity (Case-Juggling Obfuscation)
  const upperMatches = str.match(/[A-Z]/g);
  const upperCount = upperMatches ? upperMatches.length : 0;
  const upperRatio = len > 0 ? Number((upperCount / len).toFixed(4)) : 0;

  // 8. Tautology / Boolean Operator Density (e.g. 1=1, 'a'='a', OR 1=1)
  const tautologyMatch = lower.match(/(\d+)\s*=\s*\1|'(\w+)'\s*=\s*'\2'|or\s+1\s*=\s*1/gi);
  const tautologyScore = tautologyMatch ? tautologyMatch.length * 2.5 : 0;

  // 9. Bi-Gram Repetition / Shellcode N-Gram Density
  let bigramRepeatScore = 0;
  if (len > 3) {
    const bigrams = {};
    for (let i = 0; i < len - 1; i++) {
      const bg = str.substr(i, 2);
      bigrams[bg] = (bigrams[bg] || 0) + 1;
    }
    const maxRep = Math.max(...Object.values(bigrams));
    bigramRepeatScore = maxRep > 3 ? Number((maxRep / len).toFixed(4)) : 0;
  }

  // 10. Payload Depth / Nesting Bracket Level
  let depth = 0;
  let maxDepth = 0;
  for (let i = 0; i < len; i++) {
    if (str[i] === '(' || str[i] === '{' || str[i] === '[') {
      depth++;
      if (depth > maxDepth) maxDepth = depth;
    } else if (str[i] === ')' || str[i] === '}' || str[i] === ']') {
      if (depth > 0) depth--;
    }
  }
  const nestingScore = Math.min(maxDepth / 5, 1);

  // 10-Dimensional Vector for Advanced ML Models
  const rawVector = [
    Math.min(len / 300, 1),
    Math.min(entropy / 8, 1),
    Math.min(specialRatio, 1),
    Math.min(sqlKeywordCount / 5, 1),
    Math.min(xssPatternCount / 4, 1),
    Math.min(encodedCount / 5, 1),
    Math.min(tautologyScore / 5, 1),
    Math.min(digitRatio, 1),
    Math.min(bigramRepeatScore, 1),
    nestingScore
  ];

  const featureNames = [
    'Length (norm)',
    'Shannon Entropy',
    'Special Char Density',
    'SQL Keyword Weight',
    'XSS Token Density',
    'Hex/URL Obfuscation',
    'Tautology Signature',
    'Numeric Density',
    'N-Gram Repetition',
    'Nesting Bracket Depth'
  ];

  // Character-by-character Anomaly Score Map for Visual Heatmap Dissector
  const charScores = [];
  for (let i = 0; i < len; i++) {
    const char = str[i];
    let score = 0.05; // base nominal
    if (SPECIAL_CHARS.includes(char)) score += 0.45;
    if (char === "'" || char === '"' || char === ';' || char === '<' || char === '>') score += 0.4;
    if (char >= '0' && char <= '9') score += 0.15;
    // Check if within sql keyword substring
    const surrounding = lower.substr(Math.max(0, i - 4), 10);
    if (SQL_KEYWORDS.some(kw => surrounding.includes(kw))) score += 0.35;
    if (XSS_PATTERNS.some(pat => surrounding.includes(pat))) score += 0.45;
    charScores.push(Math.min(Number(score.toFixed(2)), 1.0));
  }

  // Compute SHAP-style Feature Attribution Breakdown vs Nominal Baseline
  const nominalBaseline = [0.15, 0.40, 0.08, 0.00, 0.00, 0.02, 0.00, 0.10, 0.05, 0.10];
  const shapAttributions = rawVector.map((val, idx) => {
    const diff = val - nominalBaseline[idx];
    // Weights corresponding to threat relevance
    const importanceWeight = [0.08, 0.22, 0.18, 0.20, 0.16, 0.06, 0.12, 0.04, 0.05, 0.07][idx];
    const impact = Number((diff * importanceWeight).toFixed(4));
    return {
      feature: featureNames[idx],
      value: val,
      nominal: nominalBaseline[idx],
      impact,
      isRiskFactor: impact > 0
    };
  });

  return {
    rawPayload: str,
    length: len,
    entropy,
    specialCount,
    specialRatio,
    sqlKeywordCount,
    xssPatternCount,
    encodedCount,
    digitRatio,
    upperRatio,
    tautologyScore,
    maxDepth,
    featureVector: rawVector,
    featureNames,
    charScores,
    shapAttributions
  };
}

export function extractNetworkFeatures(packet) {
  const {
    packetSize = 512,
    port = 80,
    synFlag = 1,
    ackFlag = 0,
    requestRate = 12,
    payload = ''
  } = packet;

  const payloadFeatures = extractPayloadFeatures(payload);

  return {
    packetSizeNorm: Math.min(packetSize / 2048, 1),
    portNormalized: Math.min(port / 65535, 1),
    isPrivilegedPort: port < 1024 ? 1 : 0,
    flagRatio: synFlag / (ackFlag + 1),
    requestRateNorm: Math.min(requestRate / 500, 1),
    payloadFeatures,
    vector: [
      Math.min(packetSize / 2048, 1),
      Math.min(requestRate / 500, 1),
      port < 1024 ? 1 : 0,
      payloadFeatures.entropy / 8,
      payloadFeatures.specialRatio,
      payloadFeatures.sqlKeywordCount > 0 ? 1 : 0,
      payloadFeatures.xssPatternCount > 0 ? 1 : 0,
      payloadFeatures.encodedCount > 0 ? 1 : 0,
      payloadFeatures.digitRatio,
      payloadFeatures.maxDepth > 1 ? 1 : 0
    ]
  };
}
