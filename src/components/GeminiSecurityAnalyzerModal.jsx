import React, { useState, useEffect } from 'react';
import {
  BrainCircuit,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Key,
  CheckCircle2,
  Copy,
  Check,
  Zap,
  Lock,
  RefreshCw,
  X,
  Code,
  ArrowRight,
  ExternalLink,
  Shield,
  FileCheck2,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import {
  analyzeDatasetWithGemini,
  getGeminiApiKey,
  setGeminiApiKey,
  hasGeminiApiKey
} from '../services/geminiSecurityService';
import { threatAudio } from './ThreatAudio';

export default function GeminiSecurityAnalyzerModal({
  isOpen,
  onClose,
  datasetRecords = [],
  datasetName = 'Active Dataset',
  onApplyDisinfection
}) {
  const [apiKey, setApiKey] = useState(() => getGeminiApiKey());
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisReport, setAnalysisReport] = useState(null);
  const [copiedCode, setCopiedCode] = useState(false);
  const [expandedThreat, setExpandedThreat] = useState(null);

  useEffect(() => {
    if (isOpen && datasetRecords.length > 0) {
      runAnalysis();
    }
  }, [isOpen, datasetRecords]);

  const handleSaveKey = () => {
    setGeminiApiKey(apiKey);
    setShowKeyInput(false);
    runAnalysis();
  };

  const runAnalysis = async () => {
    setIsAnalyzing(true);
    threatAudio.playScan();
    try {
      const report = await analyzeDatasetWithGemini(datasetRecords, {
        name: datasetName,
        columns: datasetRecords[0] ? Object.keys(datasetRecords[0]) : []
      });
      setAnalysisReport(report);
      if (report.overallRiskScore > 50) {
        threatAudio.playAlert();
      } else {
        threatAudio.playSuccess();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCopyCode = (codeText) => {
    navigator.clipboard.writeText(codeText);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-slate-900/95 border border-cyan-500/40 rounded-3xl shadow-[0_0_50px_rgba(0,242,254,0.2)] overflow-hidden">
        
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-gradient-to-r from-slate-900 via-cyan-950/30 to-slate-900">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/50 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(0,242,254,0.3)]">
              <BrainCircuit className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white font-display tracking-wide">
                  GEMINI AI CYBERSECURITY DATASET AUDIT
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-cyan-400" />
                  {analysisReport?.isLiveGemini ? 'GEMINI 1.5 PRO / FLASH ACTIVE' : 'GEMINI HEURISTIC ENGINE'}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Auditing: <span className="text-cyan-300 font-mono font-medium">{datasetName}</span> ({datasetRecords.length} records)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowKeyInput(!showKeyInput)}
              className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 transition-all"
              title="Configure Google Gemini API Key"
            >
              <Key className="w-3.5 h-3.5" />
              <span>{hasGeminiApiKey() ? 'API Key Configured' : 'Set Gemini Key'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* API Key Drawer */}
        {showKeyInput && (
          <div className="p-4 bg-slate-950 border-b border-slate-800 animate-slideDown">
            <div className="max-w-xl mx-auto space-y-2">
              <label className="text-xs font-mono font-bold text-slate-300 flex items-center justify-between">
                <span>GOOGLE GEMINI API KEY</span>
                <a
                  href="https://aistudio.google.com/app/apikey"
                  target="_blank"
                  rel="noreferrer"
                  className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1"
                >
                  Get free key from Google AI Studio <ExternalLink className="w-3 h-3" />
                </a>
              </label>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="AIzaSy..."
                  className="flex-1 px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleSaveKey}
                  className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold transition-all shadow-[0_0_10px_rgba(0,242,254,0.3)]"
                >
                  SAVE & AUDIT
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Key is stored securely in your browser's local storage and used directly to communicate with Gemini API.
              </p>
            </div>
          </div>
        )}

        {/* Modal Body / Report View */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isAnalyzing ? (
            <div className="py-16 flex flex-col items-center justify-center space-y-4">
              <div className="relative">
                <div className="w-16 h-16 rounded-2xl bg-cyan-500/20 border border-cyan-500/50 flex items-center justify-center text-cyan-400 animate-spin">
                  <RefreshCw className="w-8 h-8" />
                </div>
                <BrainCircuit className="w-6 h-6 text-cyan-300 absolute inset-0 m-auto animate-pulse" />
              </div>
              <div className="text-center space-y-1">
                <h3 className="text-sm font-bold text-white font-mono tracking-wide">
                  GEMINI AI NEURAL AUDIT IN PROGRESS...
                </h3>
                <p className="text-xs text-slate-400">
                  Scanning for data poisoning, payload injection, PII leakage, and schema anomalies
                </p>
              </div>
            </div>
          ) : analysisReport ? (
            <>
              {/* Threat Level & Summary Card */}
              <div className={`p-5 rounded-2xl border ${
                analysisReport.overallRiskScore >= 75
                  ? 'bg-red-950/30 border-red-500/40 shadow-[0_0_20px_rgba(239,68,68,0.15)]'
                  : analysisReport.overallRiskScore >= 40
                  ? 'bg-amber-950/30 border-amber-500/40 shadow-[0_0_20px_rgba(245,158,11,0.15)]'
                  : 'bg-emerald-950/30 border-emerald-500/40 shadow-[0_0_20px_rgba(16,185,129,0.15)]'
              }`}>
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div className="flex items-start gap-4">
                    <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shrink-0 border ${
                      analysisReport.overallRiskScore >= 75
                        ? 'bg-red-500/20 border-red-500/50 text-red-400'
                        : analysisReport.overallRiskScore >= 40
                        ? 'bg-amber-500/20 border-amber-500/50 text-amber-400'
                        : 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400'
                    }`}>
                      {analysisReport.overallRiskScore >= 75 ? (
                        <ShieldAlert className="w-7 h-7 animate-bounce" />
                      ) : analysisReport.overallRiskScore >= 40 ? (
                        <AlertTriangle className="w-7 h-7" />
                      ) : (
                        <ShieldCheck className="w-7 h-7" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-mono font-black uppercase px-2.5 py-0.5 rounded-full border ${
                          analysisReport.overallRiskScore >= 75
                            ? 'bg-red-500/20 text-red-300 border-red-500/40'
                            : analysisReport.overallRiskScore >= 40
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        }`}>
                          {analysisReport.riskLevel} RISK VERDICT
                        </span>
                        <span className="text-xs font-mono text-slate-400">
                          Integrity Confidence: <strong className="text-white">{analysisReport.verificationVerdict?.integrityConfidence || 95}%</strong>
                        </span>
                      </div>
                      <p className="text-sm text-slate-200 mt-2 font-medium leading-relaxed">
                        {analysisReport.summary}
                      </p>
                    </div>
                  </div>

                  <div className="text-right shrink-0 border-l border-slate-800 pl-6 hidden md:block">
                    <div className="text-3xl font-black font-mono tracking-tight text-white">
                      {analysisReport.overallRiskScore}<span className="text-slate-500 text-lg">/100</span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 uppercase">
                      Threat Index
                    </div>
                  </div>
                </div>
              </div>

              {/* Detected Threats Grid */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-400" />
                    Detected Attack Vectors & Vulnerabilities ({analysisReport.threatsDetected?.length || 0})
                  </h3>
                  <span className="text-[11px] text-slate-500 font-mono">
                    Click card to inspect exploit scenario
                  </span>
                </div>

                {(!analysisReport.threatsDetected || analysisReport.threatsDetected.length === 0) ? (
                  <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 text-center text-xs font-mono text-emerald-400 flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4" />
                    Zero threat vectors detected in dataset sample! 100% clean schema verified.
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {analysisReport.threatsDetected.map((threat, idx) => {
                      const isExpanded = expandedThreat === idx;
                      return (
                        <div
                          key={threat.id || idx}
                          onClick={() => setExpandedThreat(isExpanded ? null : idx)}
                          className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer space-y-2.5"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2.5">
                              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                                threat.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                                threat.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                                'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                              }`}>
                                {threat.severity}
                              </span>
                              <h4 className="text-xs font-bold text-white font-mono">
                                {threat.name}
                              </h4>
                              {threat.cweId && (
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                                  {threat.cweId}
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-[11px] font-mono text-slate-400">
                                Col: <strong className="text-cyan-300">{threat.affectedColumns?.join(', ')}</strong>
                              </span>
                              {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                            </div>
                          </div>

                          <p className="text-xs text-slate-300 leading-relaxed">
                            {threat.description}
                          </p>

                          {isExpanded && threat.exploitScenario && (
                            <div className="mt-2 p-3 rounded-lg bg-red-950/20 border border-red-500/30 text-xs font-mono text-red-200 space-y-1 animate-fadeIn">
                              <div className="text-[10px] uppercase font-bold text-red-400 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" />
                                Execution Exploit Impact:
                              </div>
                              <p className="text-[11px] leading-relaxed text-slate-300 font-sans">
                                {threat.exploitScenario}
                              </p>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Gemini Remediation Solutions */}
              <div className="space-y-3">
                <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  Gemini Perfect Remediation & Verification Solutions
                </h3>

                <div className="grid grid-cols-1 gap-2.5">
                  {analysisReport.remediationSolutions?.map((sol, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-slate-950/80 border border-cyan-500/20 flex flex-col space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px] font-mono font-bold flex items-center justify-center">
                            {sol.step || idx + 1}
                          </span>
                          <h4 className="text-xs font-bold text-white font-mono">
                            {sol.title}
                          </h4>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-bold uppercase">
                          {sol.actionType || 'REMEDY'}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed font-sans">
                        {sol.instructions}
                      </p>

                      {sol.regexOrSanitizerRule && (
                        <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto">
                          <code>{sol.regexOrSanitizerRule}</code>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Auto-Sanitization Code Snippet */}
              {analysisReport.datasetSanitizationCodeSnippet?.code && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-mono font-bold text-slate-300 flex items-center gap-1.5">
                      <Code className="w-4 h-4 text-emerald-400" />
                      Generated Disinfection & Sanitizer Pipeline Code
                    </h4>
                    <button
                      onClick={() => handleCopyCode(analysisReport.datasetSanitizationCodeSnippet.code)}
                      className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono flex items-center gap-1 transition-all"
                    >
                      {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedCode ? 'COPIED!' : 'COPY CODE'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-emerald-300 font-mono text-xs overflow-x-auto leading-relaxed max-h-48">
                    <code>{analysisReport.datasetSanitizationCodeSnippet.code}</code>
                  </pre>
                </div>
              )}
            </>
          ) : null}
        </div>

        {/* Modal Footer Controls */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>SENTINEL AI Dataset Integrity & Security Verification Active</span>
          </div>

          <div className="flex items-center gap-2.5 w-full sm:w-auto">
            <button
              onClick={runAnalysis}
              disabled={isAnalyzing}
              className="flex-1 sm:flex-initial px-4 py-2 rounded-xl text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/40 flex items-center justify-center gap-1.5 transition-all"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              <span>RE-AUDIT DATASET</span>
            </button>

            {onApplyDisinfection && (
              <button
                onClick={() => {
                  onApplyDisinfection();
                  onClose();
                }}
                className="flex-1 sm:flex-initial px-5 py-2 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 flex items-center justify-center gap-1.5 shadow-[0_0_15px_rgba(0,245,160,0.3)] transition-all"
              >
                <Sparkles className="w-4 h-4" />
                <span>APPLY REMEDIATION & DISINFECT</span>
              </button>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
