import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Cpu,
  Terminal,
  Ban,
  CheckCircle2,
  ArrowRight,
  Play,
  Pause,
  RotateCcw,
  Sparkles,
  Zap,
  Lock,
  Layers,
  Activity,
  FileText,
  Download,
  Copy,
  Check,
  ChevronRight,
  ExternalLink,
  Sliders,
  UserCheck,
  X
} from 'lucide-react';
import { threatAudio } from './ThreatAudio';

export const PLAYBOOK_STEPS = [
  {
    id: 1,
    title: 'Suspicious Login',
    subtitle: 'Event Ingestion',
    badge: 'INGESTION',
    color: 'rose',
    icon: ShieldAlert,
    summary: 'Burst of 14 failed authentication attempts within 3.2 seconds from single external IP.'
  },
  {
    id: 2,
    title: 'AI Analyzes Event',
    subtitle: 'Multi-Model Inference',
    badge: 'AI INFERENCE',
    color: 'cyan',
    icon: Cpu,
    summary: 'Time-series behavioral anomaly baselining and multi-vector ML inference across model zoo.'
  },
  {
    id: 3,
    title: 'Risk Score: 91/100',
    subtitle: 'Threat Assessment',
    badge: 'CRITICAL',
    color: 'amber',
    icon: Activity,
    summary: 'Calculated composite risk score: 91/100 (Exceeds 75 Critical SOC Action Threshold).'
  },
  {
    id: 4,
    title: 'Threat: Brute Force',
    subtitle: 'Attack Taxonomy',
    badge: 'CLASSIFICATION',
    color: 'purple',
    icon: Zap,
    summary: 'High-confidence classification: Credential Brute Force & Automated Dictionary Probe.'
  },
  {
    id: 5,
    title: 'MITRE ATT&CK: T1110',
    subtitle: 'Technique Mapping',
    badge: 'MITRE T1110',
    color: 'indigo',
    icon: Layers,
    summary: 'Mapped to MITRE ATT&CK T1110 (Brute Force) and Sub-technique T1110.001 (Password Guessing).'
  },
  {
    id: 6,
    title: 'Why Detected? (XAI)',
    subtitle: 'Explainable AI',
    badge: 'XAI REASONING',
    color: 'teal',
    icon: Sparkles,
    summary: '"Multiple failed authentication attempts from the same source within a short period."'
  },
  {
    id: 7,
    title: 'Recommended Response',
    subtitle: 'SOAR Action Playbook',
    badge: 'SOAR PLAYBOOK',
    color: 'emerald',
    icon: Ban,
    summary: '"Temporarily block source IP (194.26.29.112)" and enforce step-up authentication challenge.'
  },
  {
    id: 8,
    title: 'Create Incident',
    subtitle: 'NIST SP 800-61 Record',
    badge: 'FORENSIC TICKET',
    color: 'blue',
    icon: FileText,
    summary: 'Incident ticket INC-2026-T1110-8912 generated with SHA-256 evidence chain and PCAP snippet.'
  },
  {
    id: 9,
    title: 'SOC Analyst',
    subtitle: 'Human-in-the-Loop',
    badge: 'VERIFIED',
    color: 'emerald',
    icon: UserCheck,
    summary: 'SOC Analyst validates AI recommendation, executes zero-trust quarantine, and logs triage sign-off.'
  }
];

export default function MitreT1110PlaybookModal({
  isOpen,
  onClose,
  onQuarantineIP,
  onAddIncident,
  quarantinedIPs = []
}) {
  const [currentStep, setCurrentStep] = useState(1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [simulationSpeed, setSimulationSpeed] = useState(2400);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [analystNote, setAnalystNote] = useState('AI classification confirmed. Source IP executed dictionary attack against root/admin endpoints. IP quarantined under Zero-Trust perimeter policy.');
  const [activeMitreSub, setActiveMitreSub] = useState('T1110.001');

  const attackIP = '194.26.29.112';
  const targetUser = 'admin';
  const incidentId = 'INC-2026-T1110-8912';

  // Check if IP is already in quarantine list
  useEffect(() => {
    if (quarantinedIPs.some(q => q.ip === attackIP)) {
      setIsQuarantined(true);
    }
  }, [quarantinedIPs]);

  // Automated Simulation Player
  useEffect(() => {
    let timer;
    if (isPlaying && isOpen) {
      timer = setInterval(() => {
        setCurrentStep(prev => {
          if (prev >= 9) {
            setIsPlaying(false);
            threatAudio.playSuccess();
            return 9;
          }
          const next = prev + 1;
          if (next === 3 || next === 4) threatAudio.playAlert();
          else if (next === 7) threatAudio.playShieldBlock();
          else threatAudio.playScan();
          return next;
        });
      }, simulationSpeed);
    }
    return () => clearInterval(timer);
  }, [isPlaying, isOpen, simulationSpeed]);

  const handleStartSimulation = () => {
    setCurrentStep(1);
    setIsPlaying(true);
    threatAudio.playAlert();
  };

  const handleStopSimulation = () => {
    setIsPlaying(false);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentStep(1);
  };

  const handleExecuteQuarantine = () => {
    if (onQuarantineIP) {
      onQuarantineIP(attackIP, 'MITRE T1110: Brute Force Authentication Burst');
    }
    if (onAddIncident) {
      onAddIncident({
        ip: attackIP,
        type: 'BRUTE_FORCE',
        payload: `POST /api/v1/auth/login user=${targetUser} (14 failed tries in 3.2s) [MITRE T1110]`,
        time: new Date().toTimeString().slice(0, 8),
        action: 'AUTO-QUARANTINED BY PLAYBOOK'
      });
    }
    setIsQuarantined(true);
    threatAudio.playShieldBlock();
  };

  const handleCopyCode = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  const handleExportIncidentReport = () => {
    const report = {
      incidentId,
      timestamp: new Date().toISOString(),
      threatName: 'Brute Force Authentication Burst',
      mitreTechnique: 'T1110',
      mitreSubtechnique: activeMitreSub,
      riskScore: 91,
      riskLevel: 'CRITICAL',
      sourceIp: attackIP,
      targetEndpoint: '/api/v1/auth/login',
      targetedAccounts: ['admin', 'root', 'service_account', 'devops_admin'],
      failedAttemptsCount: 14,
      durationSeconds: 3.2,
      xaiReason: 'Multiple failed authentication attempts from the same source within a short period.',
      featureContributions: {
        attemptVelocity: '+42%',
        usernameEntropy: '+28%',
        singleSourceIpDensity: '+21%',
        nonBrowserUserAgent: '+9%'
      },
      recommendedResponse: 'Temporarily block source IP (194.26.29.112)',
      remediationStatus: isQuarantined ? 'EXECUTED_QUARANTINE' : 'PENDING_APPROVAL',
      complianceStandard: 'NIST SP 800-61 Rev. 2 & ISO/IEC 27001',
      analystVerification: {
        verifiedBy: 'SOC Tier-2 Analyst',
        note: analystNote,
        status: 'RESOLVED & ISOLATED'
      },
      forensicsSignature: 'sha256$8f91b72a0c44129b01e4f9012356abde4920'
    };

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${incidentId}-forensic-dossier.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    threatAudio.playSuccess();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 md:p-6 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
      <div className="relative w-full max-w-6xl max-h-[92vh] flex flex-col bg-slate-900/95 border border-cyan-500/40 rounded-3xl shadow-[0_0_50px_rgba(0,242,254,0.25)] overflow-hidden font-sans">
        
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-gradient-to-r from-slate-900 via-cyan-950/40 to-slate-900">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 sm:w-11 sm:h-11 rounded-xl bg-gradient-to-br from-rose-500/20 to-purple-600/20 border border-rose-500/40 flex items-center justify-center text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.3)] shrink-0">
              <ShieldAlert className="w-5 h-5 sm:w-6 sm:h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base sm:text-lg font-bold text-white font-display tracking-wide">
                  AI SOC INCIDENT RESPONSE PLAYBOOK
                </h2>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-300 font-bold">
                  MITRE ATT&CK T1110
                </span>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 font-bold">
                  NIST SP 800-61
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Automated Event Ingestion → Multi-Model XAI Triage → SOAR Quarantine Pipeline
              </p>
            </div>
          </div>

          {/* Controls & Close */}
          <div className="flex items-center gap-2">
            <button
              onClick={isPlaying ? handleStopSimulation : handleStartSimulation}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold flex items-center gap-1.5 transition-all shadow-md ${
                isPlaying 
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30' 
                  : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-[0_0_15px_rgba(0,242,254,0.3)]'
              }`}
            >
              {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              <span>{isPlaying ? 'Pause Simulation' : 'Run Full Simulation'}</span>
            </button>

            <button
              onClick={handleReset}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors border border-slate-700"
              title="Reset to Step 1"
            >
              <RotateCcw className="w-4 h-4" />
            </button>

            <button
              onClick={onClose}
              className="p-2 rounded-xl bg-slate-800 hover:bg-rose-600/80 text-slate-400 hover:text-white transition-colors border border-slate-700 ml-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* 9-Stage Interactive Flowchart Progress Ribbon */}
        <div className="bg-slate-950/90 border-b border-slate-800/90 p-2 sm:p-3 overflow-x-auto">
          <div className="flex items-center gap-1.5 sm:gap-2 min-w-[780px]">
            {PLAYBOOK_STEPS.map((step, idx) => {
              const Icon = step.icon;
              const isCurrent = currentStep === step.id;
              const isCompleted = currentStep > step.id;

              return (
                <React.Fragment key={step.id}>
                  <button
                    onClick={() => {
                      setCurrentStep(step.id);
                      threatAudio.playScan();
                    }}
                    className={`flex-1 flex flex-col items-start p-2 rounded-xl text-left font-mono transition-all border ${
                      isCurrent 
                        ? 'bg-gradient-to-b from-cyan-500/20 to-slate-900 border-cyan-400 text-white shadow-[0_0_15px_rgba(0,242,254,0.25)] scale-[1.02]'
                        : isCompleted
                        ? 'bg-slate-900/80 border-emerald-500/40 text-emerald-300 hover:border-emerald-400'
                        : 'bg-slate-900/40 border-slate-800/80 text-slate-500 hover:border-slate-700 hover:text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between w-full mb-1">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-4 h-4 rounded-full text-[10px] font-bold flex items-center justify-center ${
                          isCurrent 
                            ? 'bg-cyan-400 text-slate-950 font-bold'
                            : isCompleted
                            ? 'bg-emerald-500 text-slate-950'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {isCompleted ? '✓' : step.id}
                        </span>
                        <span className="text-[10px] uppercase font-bold tracking-tight truncate max-w-[80px]">
                          {step.badge}
                        </span>
                      </div>
                      <Icon className={`w-3.5 h-3.5 ${
                        isCurrent ? 'text-cyan-400 animate-pulse' : isCompleted ? 'text-emerald-400' : 'text-slate-600'
                      }`} />
                    </div>
                    <span className="text-[11px] font-semibold truncate w-full text-slate-200">
                      {step.title}
                    </span>
                  </button>

                  {idx < PLAYBOOK_STEPS.length - 1 && (
                    <ChevronRight className={`w-3.5 h-3.5 shrink-0 ${
                      currentStep > step.id ? 'text-emerald-500' : 'text-slate-700'
                    }`} />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* Modal Body: Active Stage Deep-Dive Panel */}
        <div className="p-4 sm:p-6 overflow-y-auto flex-1 space-y-6">
          
          {/* Active Step Summary Header */}
          <div className="p-4 rounded-2xl bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                <span className="text-xl font-bold font-mono">0{currentStep}</span>
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white font-display">
                    {PLAYBOOK_STEPS[currentStep - 1].title}
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-semibold">
                    STAGE {currentStep} OF 9
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  {PLAYBOOK_STEPS[currentStep - 1].summary}
                </p>
              </div>
            </div>

            {/* Navigation Stepper buttons */}
            <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end">
              <button
                disabled={currentStep <= 1}
                onClick={() => setCurrentStep(prev => Math.max(1, prev - 1))}
                className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-xs font-mono text-slate-300 transition-colors"
              >
                ← Previous Stage
              </button>
              <button
                disabled={currentStep >= 9}
                onClick={() => {
                  setCurrentStep(prev => Math.min(9, prev + 1));
                  threatAudio.playScan();
                }}
                className="px-4 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 disabled:hover:bg-cyan-500 text-xs font-mono font-bold text-slate-950 transition-colors shadow-md"
              >
                Next Stage →
              </button>
            </div>
          </div>

          {/* Dynamic Content Per Step */}
          {currentStep === 1 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-fadeIn">
              <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold font-mono uppercase text-rose-400 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" />
                    Authentication Telemetry Stream
                  </h4>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    INGESTION TRIGGER
                  </span>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs space-y-2">
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">Target Endpoint:</span>
                    <span className="text-cyan-300 font-semibold">POST /api/v1/auth/login</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">Attacker Source IP:</span>
                    <span className="text-rose-400 font-bold">{attackIP}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">Burst Frequency:</span>
                    <span className="text-amber-300 font-semibold">14 attempts in 3.2 seconds</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">Origin Geolocation:</span>
                    <span className="text-slate-300">Moscow, Russia (AS48282)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">User-Agent Signature:</span>
                    <span className="text-purple-300 truncate max-w-[200px]">Python-requests/2.28 (BruteBot)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-400">Velocity Deviation from Baseline:</span>
                    <span className="text-rose-400 font-bold">+340% (Anomaly)</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                    <div className="bg-gradient-to-r from-amber-500 to-rose-500 h-full w-[88%]"></div>
                  </div>
                </div>
              </div>

              {/* Raw Ingestion Payload Inspector */}
              <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-bold uppercase text-slate-300 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      Raw Packet Payload Capture
                    </span>
                    <button
                      onClick={() => handleCopyCode(`POST /api/v1/auth/login HTTP/1.1\nHost: sentinel.cstd.io\nUser-Agent: Python-requests/2.28\nContent-Type: application/json\n\n{"username":"admin","password":"password123","attempt":14}`)}
                      className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                    >
                      {copiedPayload ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedPayload ? 'Copied' : 'Copy Payload'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed">
{`POST /api/v1/auth/login HTTP/1.1
Host: sentinel.cstd.io
User-Agent: Python-requests/2.28 (BruteBot/1.4)
X-Forwarded-For: 194.26.29.112
Content-Type: application/json

{
  "username": "admin",
  "password_attempt": "123456",
  "burst_seq": 14,
  "elapsed_ms": 3210
}`}
                  </pre>
                </div>

                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 font-mono flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>Heuristic Alert: Rate threshold (5 req/min) exceeded by 280%. Event queued for ML Classifier.</span>
                </div>
              </div>
            </div>
          )}

          {currentStep === 2 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-fadeIn">
              <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
                <h4 className="text-sm font-bold font-mono uppercase text-cyan-400 flex items-center gap-2">
                  <Cpu className="w-4 h-4" />
                  Multi-Model Feature Vector Inference
                </h4>
                <p className="text-xs text-slate-400">
                  Extracted 10-dimensional cybersecurity feature vector ingested into client and neural classification engines.
                </p>

                <div className="space-y-2.5 font-mono text-xs">
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex justify-between items-center">
                    <span className="text-slate-300">Random Forest Ensemble (9 Trees):</span>
                    <span className="text-emerald-400 font-bold">98.8% BRUTE_FORCE</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex justify-between items-center">
                    <span className="text-slate-300">Multi-Layer Perceptron (Neural Net):</span>
                    <span className="text-cyan-400 font-bold">96.5% BRUTE_FORCE</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex justify-between items-center">
                    <span className="text-slate-300">k-Nearest Neighbors (k=5):</span>
                    <span className="text-purple-400 font-bold">94.2% BRUTE_FORCE</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex justify-between items-center">
                    <span className="text-slate-300">Support Vector Machine (RBF Kernel):</span>
                    <span className="text-amber-400 font-bold">95.1% BRUTE_FORCE</span>
                  </div>
                </div>
              </div>

              <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
                <h4 className="text-sm font-bold font-mono uppercase text-cyan-400 flex items-center gap-2">
                  <Sliders className="w-4 h-4" />
                  Extracted Feature Weights (Normalized)
                </h4>
                <div className="space-y-2 font-mono text-xs">
                  <div>
                    <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                      <span>Auth Request Velocity (req/s)</span>
                      <span className="text-cyan-400 font-bold">0.94</span>
                    </div>
                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-cyan-400 h-full w-[94%]"></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                      <span>Password Entropy & Length Ratio</span>
                      <span className="text-purple-400 font-bold">0.82</span>
                    </div>
                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-purple-400 h-full w-[82%]"></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                      <span>Source IP Reputation Anomaly</span>
                      <span className="text-rose-400 font-bold">0.89</span>
                    </div>
                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-rose-400 h-full w-[89%]"></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                      <span>Session Nonce Variance</span>
                      <span className="text-emerald-400 font-bold">0.12 (Low = Bot)</span>
                    </div>
                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-emerald-400 h-full w-[12%]"></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {currentStep === 3 && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-fadeIn">
              {/* Circular Risk Score Dial */}
              <div className="p-6 rounded-2xl glass-panel border-amber-500/30 flex flex-col items-center justify-center text-center space-y-3">
                <span className="text-xs font-mono font-bold uppercase text-slate-400">
                  COMPOSITE RISK INDEX
                </span>
                
                <div className="relative w-36 h-36 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="40" stroke="#1e293b" strokeWidth="8" fill="transparent" />
                    <circle 
                      cx="50" 
                      cy="50" 
                      r="40" 
                      stroke="#f59e0b" 
                      strokeWidth="8" 
                      strokeDasharray="251.2" 
                      strokeDashoffset={251.2 * (1 - 0.91)} 
                      strokeLinecap="round" 
                      fill="transparent" 
                      className="transition-all duration-1000"
                    />
                  </svg>
                  <div className="absolute flex flex-col items-center justify-center">
                    <span className="text-4xl font-extrabold font-mono text-amber-400 tracking-tight">91</span>
                    <span className="text-[10px] font-mono text-slate-400">/ 100</span>
                  </div>
                </div>

                <div className="px-3 py-1 rounded-full bg-rose-500/20 border border-rose-500/40 text-rose-300 text-xs font-mono font-bold">
                  CRITICAL SEVERITY
                </div>
              </div>

              {/* Risk Breakdown */}
              <div className="md:col-span-2 p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
                <h4 className="text-sm font-bold font-mono uppercase text-amber-400 flex items-center gap-2">
                  <Activity className="w-4 h-4" />
                  Multi-Factor Risk Score Calculation Matrix
                </h4>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">AUTHENTICATION VELOCITY</div>
                    <div className="text-base font-bold text-rose-400 mt-1">94 / 100</div>
                    <p className="text-[11px] text-slate-400 mt-0.5">14 requests in 3.2s exceeds human capability</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">GEO & ASN REPUTATION</div>
                    <div className="text-base font-bold text-amber-400 mt-1">88 / 100</div>
                    <p className="text-[11px] text-slate-400 mt-0.5">Known bulletproof hosting ASN range</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">USER TARGETING DENSITY</div>
                    <div className="text-base font-bold text-purple-400 mt-1">92 / 100</div>
                    <p className="text-[11px] text-slate-400 mt-0.5">Focusing on privileged 'admin' & 'root' roles</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">PREVIOUS BASELINE CONFIDENCE</div>
                    <div className="text-base font-bold text-emerald-400 mt-1">99.2%</div>
                    <p className="text-[11px] text-slate-400 mt-0.5">Zero false-positive overlap in baseline</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {currentStep === 4 && (
            <div className="p-5 rounded-2xl glass-panel border-purple-500/30 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap className="w-5 h-5 text-purple-400" />
                  <h4 className="text-sm font-bold font-mono uppercase text-white">
                    Threat Taxonomy: Credential Brute Force
                  </h4>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold">
                  HIGH CONFIDENCE MATCH (98.4%)
                </span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                The incoming traffic sequence exhibits mathematical signatures of an automated credential dictionary attack. The bot agent iterates through top common passwords against administrative accounts with minimal delay and predictable token entropy.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-purple-300 font-bold block mb-1">Attack Pattern</span>
                  <span className="text-slate-400">Sequential Dictionary Spray</span>
                </div>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-purple-300 font-bold block mb-1">Target Account</span>
                  <span className="text-slate-400">admin, root, service_account</span>
                </div>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-purple-300 font-bold block mb-1">Threat Classification</span>
                  <span className="text-rose-400 font-bold">ACTIVE ATTACK VECTOR</span>
                </div>
              </div>
            </div>
          )}

          {currentStep === 5 && (
            <div className="p-5 rounded-2xl glass-panel border-indigo-500/30 space-y-4 animate-fadeIn">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <Layers className="w-5 h-5 text-indigo-400" />
                    <h4 className="text-base font-bold font-mono uppercase text-white">
                      MITRE ATT&CK Framework: Technique T1110 (Brute Force)
                    </h4>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Tactic: Credential Access (TA0006) • Enterprise Matrix
                  </p>
                </div>
                <a
                  href="https://attack.mitre.org/techniques/T1110/"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-mono text-indigo-300 hover:text-indigo-200 flex items-center gap-1 bg-indigo-950/40 px-3 py-1 rounded-xl border border-indigo-500/30"
                >
                  <span>MITRE Matrix Documentation</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Sub-Technique Tabs */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800">
                {[
                  { id: 'T1110.001', name: 'T1110.001: Password Guessing (Active)' },
                  { id: 'T1110.002', name: 'T1110.002: Password Cracking' },
                  { id: 'T1110.003', name: 'T1110.003: Password Spraying' },
                  { id: 'T1110.004', name: 'T1110.004: Credential Stuffing' }
                ].map(sub => (
                  <button
                    key={sub.id}
                    onClick={() => setActiveMitreSub(sub.id)}
                    className={`px-3 py-1.5 rounded-xl text-xs font-mono transition-all ${
                      activeMitreSub === sub.id
                        ? 'bg-indigo-600 text-white font-bold shadow-md'
                        : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                    }`}
                  >
                    {sub.name}
                  </button>
                ))}
              </div>

              {/* Subtechnique Details Card */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center text-indigo-300 font-bold">
                  <span>SUB-TECHNIQUE PROFILE: {activeMitreSub}</span>
                  <span className="text-emerald-400">DEFENSE STATUS: ACTIVE INTERCEPT</span>
                </div>
                <p className="text-slate-300 font-sans text-xs">
                  {activeMitreSub === 'T1110.001' && 'Adversaries iteratively guess passwords against standard user accounts without prior knowledge of system passwords. Often executed systematically with dictionaries of common words.'}
                  {activeMitreSub === 'T1110.002' && 'Adversaries recover passwords from hash dumps obtained through credential harvesting techniques or database breaches using offline hashcat/John-the-Ripper.'}
                  {activeMitreSub === 'T1110.003' && 'Adversaries spray a single common password against many accounts across an organization to avoid account lockout policy triggers.'}
                  {activeMitreSub === 'T1110.004' && 'Adversaries take compromised username/password pairs leaked in external breaches and test them against targeted authentication endpoints.'}
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">MITRE MITIGATION</span>
                    <span className="text-white font-semibold">M1036: Account Use Policies</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">DEFENSIVE CONTROL</span>
                    <span className="text-white font-semibold">M1032: Multi-Factor Authentication</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {currentStep === 6 && (
            <div className="p-5 rounded-2xl glass-panel border-teal-500/30 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-teal-400 animate-pulse" />
                  <h4 className="text-sm font-bold font-mono uppercase text-white">
                    Explainable AI (XAI) Root Cause Breakdown
                  </h4>
                </div>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-teal-500/20 text-teal-300 border border-teal-500/40">
                  SHAP CONTRIBUTIONS
                </span>
              </div>

              {/* Exact Quote Banner */}
              <div className="p-4 rounded-2xl bg-teal-950/40 border border-teal-500/40 text-teal-200 font-mono text-sm leading-relaxed shadow-[0_0_20px_rgba(20,184,166,0.15)]">
                <span className="text-xs text-teal-400 block font-bold mb-1">WHY DETECTED?</span>
                “Multiple failed authentication attempts from the same source within a short period.”
              </div>

              {/* SHAP Feature Contribution Waterfall */}
              <div className="space-y-3 font-mono text-xs pt-2">
                <span className="text-[11px] text-slate-400 uppercase font-semibold block">
                  FEATURE ATTRIBUTION IMPACT ON RISK SCORE (+91):
                </span>
                
                <div>
                  <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                    <span>1. Request Rate Frequency Burst (&gt;4.3 req/s)</span>
                    <span className="text-rose-400 font-bold">+42% (+38.2 pts)</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                    <div className="bg-rose-500 h-full w-[42%]"></div>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                    <span>2. Username Repetition & Entropy Deviation</span>
                    <span className="text-amber-400 font-bold">+28% (+25.5 pts)</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                    <div className="bg-amber-500 h-full w-[28%]"></div>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                    <span>3. Single Source IP Concentration</span>
                    <span className="text-purple-400 font-bold">+21% (+19.1 pts)</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                    <div className="bg-purple-500 h-full w-[21%]"></div>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                    <span>4. Scripted Automated User-Agent Header</span>
                    <span className="text-teal-400 font-bold">+9% (+8.2 pts)</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                    <div className="bg-teal-400 h-full w-[9%]"></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {currentStep === 7 && (
            <div className="p-5 rounded-2xl glass-panel border-emerald-500/30 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Ban className="w-5 h-5 text-emerald-400" />
                  <h4 className="text-sm font-bold font-mono uppercase text-white">
                    Recommended Response (SOAR Playbook)
                  </h4>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold">
                  AUTOMATED REMEDIATION READY
                </span>
              </div>

              {/* Exact Recommended Response Banner */}
              <div className="p-4 rounded-2xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-200 font-mono text-sm shadow-[0_0_20px_rgba(16,185,129,0.15)]">
                <span className="text-xs text-emerald-400 block font-bold mb-1">RECOMMENDED ACTION</span>
                “Temporarily block source IP”
              </div>

              {/* SOAR Action Card */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center text-slate-300">
                  <span>Target IP to Block: <strong className="text-rose-400">{attackIP}</strong></span>
                  <span>Duration: <strong className="text-cyan-300">120 Minutes (Temporary Jail)</strong></span>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
                  <code># Automated Perimeter Firewall Injection:</code><br />
                  <code className="text-emerald-400">iptables -I INPUT -s {attackIP} -p tcp --dport 443 -j DROP</code>
                </div>

                <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
                  <div className="text-[11px] text-slate-400">
                    Status: {isQuarantined ? <span className="text-emerald-400 font-bold">✓ IP CURRENTLY BLOCKED & ISOLATED</span> : <span className="text-amber-400 font-semibold">Ready for execution</span>}
                  </div>
                  <button
                    onClick={handleExecuteQuarantine}
                    disabled={isQuarantined}
                    className={`px-4 py-2 rounded-xl text-xs font-mono font-bold flex items-center gap-2 transition-all ${
                      isQuarantined 
                        ? 'bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 cursor-default'
                        : 'bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 shadow-[0_0_15px_rgba(16,185,129,0.3)]'
                    }`}
                  >
                    <Ban className="w-4 h-4" />
                    <span>{isQuarantined ? 'Source IP Quarantined' : '⚡ Execute Auto-Quarantine'}</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {currentStep === 8 && (
            <div className="p-5 rounded-2xl glass-panel border-blue-500/30 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="w-5 h-5 text-blue-400" />
                  <h4 className="text-sm font-bold font-mono uppercase text-white">
                    Create Incident: Forensic Audit Record
                  </h4>
                </div>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40 font-bold">
                  NIST SP 800-61 Rev. 2
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs space-y-2.5">
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">INCIDENT ID:</span>
                  <span className="text-cyan-400 font-bold">{incidentId}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">CLASSIFICATION:</span>
                  <span className="text-rose-400 font-bold">BRUTE_FORCE_AUTHENTICATION_BURST</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">SECURITY COMPLIANCE:</span>
                  <span className="text-emerald-400">NIST SP 800-61 / ISO/IEC 27001 AUDIT READY</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">CRYPTOGRAPHIC EVIDENCE PROOF:</span>
                  <span className="text-purple-300 text-[10px]">sha256$8f91b72a0c44129b01e4f9012356abde4920</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">GENERATED AT:</span>
                  <span className="text-slate-300">{new Date().toISOString()}</span>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={handleExportIncidentReport}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-blue-500 to-cyan-600 hover:from-blue-400 hover:to-cyan-500 text-slate-950 font-mono font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all"
                >
                  <Download className="w-4 h-4" />
                  <span>Export Forensic Evidence Package (.JSON)</span>
                </button>
              </div>
            </div>
          )}

          {currentStep === 9 && (
            <div className="p-5 rounded-2xl glass-panel border-emerald-500/30 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <UserCheck className="w-5 h-5 text-emerald-400" />
                  <h4 className="text-sm font-bold font-mono uppercase text-white">
                    SOC Analyst: Human-in-the-Loop Verification & Closure
                  </h4>
                </div>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold">
                  TRIAGE COMPLETED
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <label className="block text-slate-300">
                  Analyst Investigation Notes & Sign-off:
                </label>
                <textarea
                  rows={3}
                  value={analystNote}
                  onChange={(e) => setAnalystNote(e.target.value)}
                  className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/60 font-mono text-xs resize-none"
                />

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div>
                    <span className="text-slate-400 block text-[10px]">CURRENT INCIDENT STATUS</span>
                    <span className="text-emerald-400 font-bold text-sm">✓ RESOLVED & SOURCE IP BLOCKED</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleExportIncidentReport}
                      className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs flex items-center gap-1.5 border border-slate-700"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download Audit Dossier</span>
                    </button>
                    <button
                      onClick={onClose}
                      className="px-4 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs shadow-md transition-colors"
                    >
                      <span>Close Playbook</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Modal Footer */}
        <div className="p-3.5 sm:p-4 border-t border-slate-800 bg-slate-950/80 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-slate-400 text-[11px]">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>SENTINEL AI SOC • Playbook Mode: MITRE ATT&CK T1110 Automated Response</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-500 text-[11px]">Simulation Speed:</span>
            <select
              value={simulationSpeed}
              onChange={(e) => setSimulationSpeed(Number(e.target.value))}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2 py-1 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value={1500}>Fast (1.5s)</option>
              <option value={2400}>Normal (2.4s)</option>
              <option value={4000}>Detailed (4.0s)</option>
            </select>
          </div>
        </div>

      </div>
    </div>
  );
}
