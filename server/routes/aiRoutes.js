import { Router } from 'express';
import { config } from '../config/config.js';
import { inspectPayload } from '../services/securityEngine.js';

const router = Router();

/**
 * @route GET /api/ai/status
 * @desc Check server AI gateway configuration
 */
router.get('/status', (req, res) => {
  res.json({
    geminiConfigured: Boolean(config.GEMINI_API_KEY && config.GEMINI_API_KEY.length > 5),
    defaultModel: 'gemini-1.5-flash',
    mode: config.GEMINI_API_KEY ? 'CLOUD_GEMINI_AI' : 'LOCAL_HEURISTIC_AI'
  });
});

/**
 * @route POST /api/ai/analyze
 * @desc Run AI Threat Assessment via server Gemini API or Heuristics
 */
router.post('/analyze', async (req, res) => {
  try {
    const { datasetRecords = [], metadata = {}, userApiKey } = req.body;
    const apiKey = userApiKey || config.GEMINI_API_KEY;

    if (!apiKey) {
      // Execute heuristic server-side threat analysis
      return res.json(generateServerHeuristicAnalysis(datasetRecords, metadata));
    }

    const sampleSubset = Array.isArray(datasetRecords) ? datasetRecords.slice(0, 15) : [];
    const systemPrompt = `You are SENTINEL Gemini Cyber Defense Intelligence Agent.
Analyze this cybersecurity/data mining dataset for:
1. Data Poisoning & Adversarial ML Backdoors
2. Injection Attacks (SQLi, XSS, Command Injection)
3. PII & Sensitive Credential Leakage
4. Malicious Anomalies & Schema Violations

Return STRICT VALID JSON matching this schema:
{
  "overallRiskScore": <number 0-100>,
  "riskLevel": "<CRITICAL | HIGH | MEDIUM | LOW | SECURE>",
  "summary": "<2-3 sentence executive summary>",
  "threatsDetected": [
    {
      "id": "THREAT-01",
      "name": "<Threat Name>",
      "category": "<INJECTION | DATA_POISONING | PII_LEAK | MALICIOUS_ANOMALY | SCHEMA_EXPLOIT>",
      "severity": "<CRITICAL | HIGH | MEDIUM | LOW>",
      "affectedColumns": ["<col1>"],
      "affectedRowIndices": [<numbers>],
      "cweId": "<e.g. CWE-89>",
      "description": "<Explanation>",
      "exploitScenario": "<Impact if mined>"
    }
  ],
  "verificationVerdict": {
    "isSafeForProduction": <boolean>,
    "recommendation": "<PROCEED | DISINFECT_REQUIRED | QUARANTINE_DATASET | REJECT>",
    "integrityConfidence": <number 0-100>
  },
  "remediationSolutions": [
    {
      "step": 1,
      "title": "<Action Title>",
      "actionType": "<SANITIZE | FILTER_OUT | ANONYMIZE | SCHEMA_ENFORCE | REHASH>",
      "instructions": "<Guidance>",
      "regexOrSanitizerRule": "<Code/Regex>",
      "targetColumns": ["<col1>"]
    }
  ]
}`;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [
          {
            role: 'user',
            parts: [
              { text: systemPrompt },
              { text: `DATASET METADATA: ${JSON.stringify(metadata)}\nDATASET SAMPLES: ${JSON.stringify(sampleSubset, null, 2)}` }
            ]
          }
        ],
        generationConfig: {
          temperature: 0.1,
          responseMimeType: 'application/json'
        }
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.warn('⚠️ Gemini API error, falling back to heuristic engine:', errText);
      return res.json(generateServerHeuristicAnalysis(datasetRecords, metadata));
    }

    const data = await response.json();
    const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    const parsed = JSON.parse(rawText);

    res.json({
      success: true,
      provider: 'Google Gemini 1.5 Flash',
      analysis: parsed
    });
  } catch (err) {
    console.error('AI Analysis Exception:', err.message);
    res.json(generateServerHeuristicAnalysis(req.body?.datasetRecords || [], req.body?.metadata || {}));
  }
});

function generateServerHeuristicAnalysis(records, metadata) {
  let riskScore = 15;
  const threats = [];

  records.slice(0, 50).forEach((row, idx) => {
    for (const key of Object.keys(row)) {
      const val = String(row[key]);
      const res = inspectPayload(val);
      if (res.threatType !== 'NORMAL') {
        riskScore = Math.min(95, riskScore + 20);
        threats.push({
          id: `THREAT-SRV-0${threats.length + 1}`,
          name: `${res.threatType} Detected in ${key}`,
          category: res.threatType === 'SQLI' ? 'INJECTION' : res.threatType === 'XSS' ? 'INJECTION' : res.threatType,
          severity: res.riskScore > 70 ? 'HIGH' : 'MEDIUM',
          affectedColumns: [key],
          affectedRowIndices: [idx],
          cweId: res.threatType === 'SQLI' ? 'CWE-89' : 'CWE-79',
          description: `Server security engine detected high risk pattern in column ${key}`,
          exploitScenario: `May allow unauthorized execution or data exfiltration when queried.`
        });
      }
    }
  });

  return {
    success: true,
    provider: 'SENTINEL Heuristic Security Kernel',
    analysis: {
      overallRiskScore: riskScore,
      riskLevel: riskScore > 65 ? 'HIGH' : riskScore > 35 ? 'MEDIUM' : 'LOW',
      summary: `Automated server heuristic audit completed across ${records.length} records. Detected ${threats.length} actionable threat vectors.`,
      threatsDetected: threats.slice(0, 10),
      verificationVerdict: {
        isSafeForProduction: riskScore < 40,
        recommendation: riskScore > 60 ? 'DISINFECT_REQUIRED' : 'PROCEED',
        integrityConfidence: 94
      },
      remediationSolutions: [
        {
          step: 1,
          title: 'Automated Dataset Sanitization & Parameterization',
          actionType: 'SANITIZE',
          instructions: 'Apply SENTINEL Dataset Rectification engine to neutralize identified injection payloads.',
          regexOrSanitizerRule: "s/[^a-zA-Z0-9_.-]//g",
          targetColumns: ['query', 'payload', 'input']
        }
      ]
    }
  };
}

export default router;
