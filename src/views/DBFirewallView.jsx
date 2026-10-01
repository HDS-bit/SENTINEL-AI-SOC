import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Database, 
  Code2, 
  AlertOctagon, 
  CheckCircle2, 
  Terminal, 
  Sliders, 
  Flame, 
  Lock, 
  Unlock,
  Play,
  RotateCcw,
  FileCode
} from 'lucide-react';
import { 
  analyzeSQLQuery, 
  executeMockQuery, 
  DEFAULT_FIREWALL_RULES,
  MOCK_DATABASE 
} from '../firewall/dbFirewallEngine';
import { threatAudio } from '../components/ThreatAudio';

export default function DBFirewallView({ onQueryBlocked }) {
  const [queryInput, setQueryInput] = useState("SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- AND pass = '123'");
  const [firewallEnabled, setFirewallEnabled] = useState(true);
  const [activeRules, setActiveRules] = useState(DEFAULT_FIREWALL_RULES);
  const [executionResult, setExecutionResult] = useState(null);
  const [auditLog, setAuditLog] = useState([
    { id: 1, query: "SELECT id, title FROM products WHERE cat_id = 4", risk: 0, status: 'ALLOWED', time: '19:35:12', ip: '10.0.0.15' },
    { id: 2, query: "SELECT * FROM users WHERE username = 'admin' OR 1=1", risk: 85, status: 'BLOCKED', time: '19:38:40', ip: '45.33.32.156' },
    { id: 3, query: "SELECT credit_card FROM payments WHERE id = 99", risk: 10, status: 'ALLOWED', time: '19:40:05', ip: '10.0.4.11' }
  ]);

  const queryAnalysis = analyzeSQLQuery(queryInput, activeRules);

  const PRESET_QUERIES = [
    {
      name: "Tautology Bypass (' OR '1'='1')",
      type: "ATTACK",
      sql: "SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- AND pass = '123'"
    },
    {
      name: "Union-Based Schema Leak",
      type: "ATTACK",
      sql: "SELECT id, name FROM products WHERE id = -1 UNION SELECT 1, password_hash FROM users --"
    },
    {
      name: "Time-Based Blind Probe (SLEEP)",
      type: "ATTACK",
      sql: "SELECT * FROM users WHERE id = 1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
    },
    {
      name: "Stacked Command Injection (; DROP)",
      type: "ATTACK",
      sql: "SELECT * FROM accounts WHERE id = 104; DROP TABLE users; --"
    },
    {
      name: "Safe Clean Parameterized Query",
      type: "SAFE",
      sql: "SELECT id, username, email FROM users WHERE id = 2 AND status = 'ACTIVE'"
    }
  ];

  const handleExecute = () => {
    const result = executeMockQuery(queryInput, firewallEnabled);
    setExecutionResult(result);

    if (result.status === 'BLOCKED_BY_FIREWALL') {
      threatAudio.playShieldBlock();
      if (onQueryBlocked) onQueryBlocked(queryInput, queryAnalysis.riskScore);
    } else if (result.status === 'EXECUTED_VULNERABLE') {
      threatAudio.playAlert();
    } else {
      threatAudio.playSuccess();
    }

    // Append to audit log
    const newLog = {
      id: auditLog.length + 1,
      query: queryInput,
      risk: queryAnalysis.riskScore,
      status: result.status === 'BLOCKED_BY_FIREWALL' ? 'BLOCKED' : 'ALLOWED',
      time: new Date().toTimeString().slice(0, 8),
      ip: result.status === 'BLOCKED_BY_FIREWALL' ? '45.33.32.156' : '10.0.0.12'
    };
    setAuditLog([newLog, ...auditLog.slice(0, 7)]);
  };

  const toggleRule = (ruleId) => {
    setActiveRules(activeRules.map(r => r.id === ruleId ? { ...r, enabled: !r.enabled } : r));
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-2xl glass-panel-glow border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400 shrink-0">
            <Database className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              DATABASE SENTINEL FIREWALL & AST INSPECTOR
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 font-semibold">
                SQL INJECTION SHIELD
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Deep lexical AST query tokenization, risk scoring, automated parameterization, and protected execution gateway.
            </p>
          </div>
        </div>

        {/* Global Firewall Mode Toggle */}
        <div className="flex items-center gap-3 w-full md:w-auto">
          <button
            onClick={() => {
              const next = !firewallEnabled;
              setFirewallEnabled(next);
              if (next) threatAudio.playShieldBlock();
              else threatAudio.playAlert();
            }}
            className={`px-4 py-2 rounded-xl font-mono text-xs font-bold flex items-center gap-2 transition-all shadow-md ${
              firewallEnabled
                ? 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/50 shadow-[0_0_15px_rgba(0,245,160,0.2)]'
                : 'bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/50 animate-pulse'
            }`}
          >
            {firewallEnabled ? <Lock className="w-4 h-4 text-emerald-400" /> : <Unlock className="w-4 h-4 text-rose-400" />}
            <span>{firewallEnabled ? 'FIREWALL: ACTIVE (PROTECTED)' : 'FIREWALL: BYPASSED (VULNERABLE)'}</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Interactive SQL Playground & Dual Sandbox */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: SQL Playground, AST Breakdown & Execution */}
        <div className="lg:col-span-2 space-y-6">
          {/* Query Editor & Presets */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold font-mono uppercase text-white">
                  Interactive SQL Inspection Playground
                </h2>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                Select preset or type custom SQL query
              </span>
            </div>

            {/* Presets Badges */}
            <div className="flex flex-wrap gap-2">
              {PRESET_QUERIES.map((preset, i) => (
                <button
                  key={i}
                  onClick={() => {
                    setQueryInput(preset.sql);
                    threatAudio.playScan();
                  }}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-semibold transition-colors border ${
                    preset.type === 'ATTACK'
                      ? 'bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border-rose-700/40'
                      : 'bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border-emerald-700/40'
                  }`}
                >
                  {preset.name}
                </button>
              ))}
            </div>

            {/* Query Input Box */}
            <div className="space-y-1.5 font-mono">
              <div className="flex justify-between text-xs text-slate-400">
                <span>RAW SQL QUERY TEXT:</span>
                <span className="text-cyan-400">{queryInput.length} chars</span>
              </div>
              <textarea
                value={queryInput}
                onChange={(e) => setQueryInput(e.target.value)}
                rows={3}
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500/60 shadow-inner"
              />
            </div>

            {/* Action Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1">
              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="text-slate-400">Query Risk:</span>
                <span className={`px-2 py-0.5 rounded font-bold border ${
                  queryAnalysis.riskScore >= 65 ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                  queryAnalysis.riskScore >= 35 ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                  'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}>
                  {queryAnalysis.riskScore} / 100 ({queryAnalysis.verdict})
                </span>
              </div>

              <button
                onClick={handleExecute}
                className="px-6 py-2.5 rounded-xl font-mono text-xs font-bold bg-gradient-to-r from-purple-500 to-cyan-500 hover:from-purple-400 hover:to-cyan-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(157,78,221,0.3)] transition-all"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>EXECUTE QUERY IN SANDBOX</span>
              </button>
            </div>
          </div>

          {/* Lexical Token Breakdown & Matched Rules */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <Code2 className="w-4 h-4 text-purple-400" />
              AST Lexical Token Stream & Heuristics
            </h2>

            {/* Tokens Ribbon */}
            <div className="space-y-1.5 font-mono text-xs">
              <span className="text-slate-400 text-[11px]">PARSED TOKENS:</span>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/90 flex flex-wrap gap-1.5 max-h-28 overflow-y-auto">
                {queryAnalysis.tokens.map((token, idx) => {
                  let colorClass = 'bg-slate-800 text-slate-200 border-slate-700';
                  if (token.type === 'keyword') colorClass = 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60 font-bold';
                  else if (token.type === 'string') colorClass = 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60';
                  else if (token.type === 'comment') colorClass = 'bg-rose-950/80 text-rose-400 border-rose-700/60 font-bold animate-pulse';
                  else if (token.type === 'operator') colorClass = 'bg-purple-950/80 text-purple-300 border-purple-700/60';

                  return (
                    <span
                      key={idx}
                      className={`px-2 py-0.5 rounded border text-[11px] font-mono ${colorClass}`}
                    >
                      {token.text} <span className="text-[9px] opacity-60">[{token.type}]</span>
                    </span>
                  );
                })}
              </div>
            </div>

            {/* Matched Threat Rules */}
            <div className="space-y-2">
              <span className="text-slate-400 font-mono text-[11px]">FIREWALL RULE VIOLATIONS:</span>
              {queryAnalysis.matchedRules.length > 0 ? (
                <div className="space-y-1.5">
                  {queryAnalysis.matchedRules.map((rule, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-xl bg-rose-950/30 border border-rose-700/50 flex items-center justify-between font-mono text-xs text-rose-300"
                    >
                      <div className="flex items-center gap-2">
                        <AlertOctagon className="w-4 h-4 text-rose-400" />
                        <span className="font-bold">[{rule.id}]</span>
                        <span>{rule.name}</span>
                      </div>
                      <span className="text-rose-400 font-bold">+{rule.weight} Risk</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-2.5 rounded-xl bg-emerald-950/30 border border-emerald-700/40 text-emerald-300 font-mono text-xs flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>No SQL injection patterns detected. Query structure conforms to safe standards.</span>
                </div>
              )}
            </div>
          </div>

          {/* Dual Execution Sandbox Output Result */}
          {executionResult && (
            <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  Sandbox Database Execution Result
                </h2>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                  executionResult.status === 'BLOCKED_BY_FIREWALL' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' :
                  executionResult.status === 'EXECUTED_VULNERABLE' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse' :
                  'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                }`}>
                  {executionResult.status} ({executionResult.executionTimeMs}ms)
                </span>
              </div>

              {/* Error or Warning Banner */}
              {executionResult.error && (
                <div className="p-3.5 rounded-xl bg-emerald-950/50 border border-emerald-500/50 text-xs font-mono text-emerald-300 space-y-1">
                  <div className="font-bold flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span>ZERO-DATA LOSS SHIELD: THREAT INTERCEPTED BEFORE DB KERNEL</span>
                  </div>
                  <p className="text-[11px] text-slate-300">{executionResult.error}</p>
                </div>
              )}

              {executionResult.warning && (
                <div className="p-3.5 rounded-xl bg-rose-950/70 border border-rose-500/70 text-xs font-mono text-rose-300 space-y-1">
                  <div className="font-bold flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse" />
                    <span>SECURITY COMPROMISE DETECTED (FIREWALL DISABLED)</span>
                  </div>
                  <p className="text-[11px] text-rose-200">{executionResult.warning}</p>
                </div>
              )}

              {/* Data Table Result */}
              {executionResult.results && executionResult.results.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-950 text-slate-400">
                        {Object.keys(executionResult.results[0]).map((col, idx) => (
                          <th key={idx} className="p-2.5 uppercase">{col}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {executionResult.results.map((row, rIdx) => (
                        <tr key={rIdx} className="hover:bg-slate-900/40">
                          {Object.values(row).map((val, cIdx) => (
                            <td key={cIdx} className="p-2.5 text-cyan-300 truncate max-w-xs">{String(val)}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Automated Remediation & Parameterized Statement */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              Automated Parameterization & Defensive Code
            </h2>

            <div className="space-y-1.5 font-mono text-xs">
              <span className="text-slate-400 text-[11px]">RECOMMENDED PARAMETERIZED QUERY:</span>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-emerald-400 font-mono">
                {queryAnalysis.parameterizedQuery || 'SELECT * FROM users WHERE id = ?'}
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                {queryAnalysis.remediation}
              </p>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Rule Configuration & Live Audit Log */}
        <div className="space-y-6">
          {/* Active Rule Policies Toggle List */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                Firewall Rule Policies
              </h2>
              <span className="text-[10px] font-mono text-cyan-400">8 POLICIES</span>
            </div>

            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {activeRules.map((rule) => (
                <div
                  key={rule.id}
                  onClick={() => toggleRule(rule.id)}
                  className={`p-2.5 rounded-xl border font-mono text-xs cursor-pointer transition-all flex items-center justify-between ${
                    rule.enabled
                      ? 'bg-slate-900/90 border-slate-700 text-slate-200 hover:border-cyan-500/50'
                      : 'bg-slate-950/50 border-slate-900 text-slate-600'
                  }`}
                >
                  <div className="min-w-0 pr-2">
                    <div className="font-bold text-[11px] truncate">{rule.name}</div>
                    <span className="text-[10px] opacity-60">Weight: +{rule.weight}</span>
                  </div>
                  <div className={`w-8 h-4 rounded-full transition-colors relative ${rule.enabled ? 'bg-cyan-500' : 'bg-slate-800'}`}>
                    <div className={`w-3 h-3 rounded-full bg-white absolute top-0.5 transition-transform ${rule.enabled ? 'right-0.5' : 'left-0.5'}`}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Database Firewall Audit Feed */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-purple-400" />
              Live DB Gateway Audit Log
            </h2>

            <div className="space-y-2">
              {auditLog.map((log) => (
                <div
                  key={log.id}
                  className={`p-2.5 rounded-xl border font-mono text-xs space-y-1 ${
                    log.status === 'BLOCKED'
                      ? 'bg-rose-950/30 border-rose-800/50 text-rose-300'
                      : 'bg-slate-950 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-slate-400">{log.time} [{log.ip}]</span>
                    <span className={`px-1.5 py-0.2 rounded font-bold ${
                      log.status === 'BLOCKED' ? 'bg-rose-500/30 text-rose-300' : 'bg-emerald-500/30 text-emerald-300'
                    }`}>
                      {log.status}
                    </span>
                  </div>
                  <div className="text-[11px] truncate text-slate-200">{log.query}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
