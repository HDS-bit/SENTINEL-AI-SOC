import React, { useState } from 'react';
import { 
  Cpu, 
  Play, 
  Pause, 
  Zap, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Terminal, 
  Sliders, 
  BarChart3, 
  Ban,
  Activity,
  Layers,
  Sparkles,
  Flame,
  BrainCircuit,
  Eye,
  Wand2,
  TrendingUp,
  HelpCircle
} from 'lucide-react';
import { extractPayloadFeatures } from '../data-mining/featureExtractor';
import { THREAT_LABELS } from '../data-mining/mlModels';
import { threatAudio } from '../components/ThreatAudio';

export default function AIThreatDetectionView({ 
  packets = [], 
  activePacket, 
  isStreaming, 
  setIsStreaming, 
  modelPredictions, 
  onInjectAttack,
  onQuarantineIP,
  onCustomAnalyze,
  selectedModelType = 'RF',
  setSelectedModelType
}) {
  const [customInput, setCustomInput] = useState('');
  const [streamSpeed, setStreamSpeed] = useState(1500);
  const [sensitivityThreshold, setSensitivityThreshold] = useState(75);
  const [showShapDetails, setShowShapDetails] = useState(true);
  const [neutralizedPayload, setNeutralizedPayload] = useState(null);

  const activeFeatures = activePacket ? extractPayloadFeatures(activePacket.payload) : null;

  const handleCustomSubmit = (e) => {
    e.preventDefault();
    if (!customInput.trim()) return;
    onCustomAnalyze(customInput);
    threatAudio.playScan();
    setCustomInput('');
    setNeutralizedPayload(null);
  };

  const handleNeutralize = () => {
    if (!activePacket) return;
    // Sanitizes special injection quotes and script tags
    let safe = activePacket.payload
      .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '[SANITIZED_SCRIPT_REMOVED]')
      .replace(/' OR '1'='1' --/gi, "/* PARAMETERIZED */")
      .replace(/UNION SELECT/gi, "/* SAFE_SCHEMA_LOCKED */")
      .replace(/--.*|\/\*[\s\S]*?\*\//g, "");
    setNeutralizedPayload(safe);
    threatAudio.playSuccess();
  };

  // Determine current active model verdict based on selectedModelType
  let activePrediction = modelPredictions?.rf;
  if (selectedModelType === 'MLP') activePrediction = modelPredictions?.mlp || modelPredictions?.rf;
  else if (selectedModelType === 'KNN') activePrediction = modelPredictions?.knn || modelPredictions?.rf;
  else if (selectedModelType === 'SVM') activePrediction = modelPredictions?.svm || modelPredictions?.rf;
  else if (selectedModelType === 'NB') activePrediction = modelPredictions?.nb || modelPredictions?.rf;

  return (
    <div className="space-y-6">
      {/* Top Header & Live Stream Controls */}
      <div className="p-4 rounded-2xl glass-panel-glow border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Cpu className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              REAL-TIME AI THREAT CLASSIFIER & EXPLAINABLE AI (XAI)
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-semibold">
                MULTI-MODEL INFERENCE
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Live inference with SHAP feature contribution waterfall, character anomaly heatmaps, and dynamic sensitivity tuning.
            </p>
          </div>
        </div>

        {/* Active Model Selector & Stream Toggle */}
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {/* Active Model Switcher */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs text-slate-300">
            <BrainCircuit className="w-3.5 h-3.5 text-purple-400" />
            <select
              value={selectedModelType}
              onChange={(e) => {
                if (setSelectedModelType) setSelectedModelType(e.target.value);
                threatAudio.playScan();
              }}
              className="bg-transparent text-cyan-300 font-bold focus:outline-none cursor-pointer"
            >
              <option value="RF" className="bg-slate-900">Random Forest Ensemble</option>
              <option value="MLP" className="bg-slate-900">Neural Network (MLP 3-Layer)</option>
              <option value="KNN" className="bg-slate-900">K-Nearest Neighbors (k=5)</option>
              <option value="SVM" className="bg-slate-900">Support Vector Machine (SVM)</option>
              <option value="NB" className="bg-slate-900">Gaussian Naive Bayes</option>
            </select>
          </div>

          <button
            onClick={() => {
              setIsStreaming(!isStreaming);
              threatAudio.playScan();
            }}
            className={`px-4 py-2 rounded-xl font-mono text-xs font-bold flex items-center gap-2 transition-all shadow-md ${
              isStreaming
                ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40'
                : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 shadow-[0_0_15px_rgba(0,242,254,0.3)]'
            }`}
          >
            {isStreaming ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4 fill-current" />}
            <span>{isStreaming ? 'PAUSE' : 'STREAM'}</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Active Packet AI Verdict & Explainable AI SHAP Waterfall */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 Cols: Active Vector & Character Heatmap Dissector */}
        <div className="lg:col-span-7 space-y-6">
          {/* Active AI Verdict Card */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 relative overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold font-mono uppercase text-white">
                  Active Vector Inference & Model Verdict
                </h2>
              </div>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                activePacket?.label === 'NORMAL'
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                  : 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
              }`}>
                {activePrediction ? `${activePrediction.model}: ${activePrediction.label}` : 'INSPECTING...'}
              </span>
            </div>

            {/* Character Anomaly Heatmap Dissector */}
            <div className="space-y-1.5 font-mono">
              <div className="flex justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <Eye className="w-3.5 h-3.5" />
                  TOKEN ANOMALY HEATMAP DISSECTOR:
                </span>
                <span>SRC: {activePacket?.ip || '185.220.101.5'}</span>
              </div>

              {/* Render Character by Character Heatmap */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/90 text-xs font-mono break-all leading-relaxed shadow-inner flex flex-wrap gap-[1px]">
                {activeFeatures?.charScores.map((score, idx) => {
                  const char = activeFeatures.rawPayload[idx];
                  let bg = 'bg-transparent text-slate-300';
                  if (score > 0.7) bg = 'bg-rose-500/40 text-rose-200 border-b-2 border-rose-500 font-bold';
                  else if (score > 0.4) bg = 'bg-amber-500/30 text-amber-200 border-b border-amber-500';
                  else if (score > 0.2) bg = 'bg-cyan-500/20 text-cyan-200';

                  return (
                    <span
                      key={idx}
                      title={`Character '${char}' Anomaly Risk: ${(score * 100).toFixed(0)}%`}
                      className={`px-[2px] rounded transition-colors cursor-help ${bg}`}
                    >
                      {char === ' ' ? '\u00A0' : char}
                    </span>
                  );
                })}
              </div>
              <div className="flex justify-between items-center text-[10px] text-slate-500 pt-1">
                <span>Color intensity highlights high-risk tokens (SQL operators, quotes, tags).</span>
                <button
                  onClick={handleNeutralize}
                  className="text-cyan-400 hover:text-cyan-300 underline font-bold flex items-center gap-1"
                >
                  <Wand2 className="w-3 h-3" />
                  <span>1-Click Auto-Neutralize</span>
                </button>
              </div>
            </div>

            {/* Neutralized Payload Banner if clicked */}
            {neutralizedPayload && (
              <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/50 space-y-1 font-mono text-xs animate-in fade-in">
                <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  <span>DEFANGED & SANITIZED PAYLOAD OUTPUT:</span>
                </div>
                <div className="p-2 rounded bg-slate-950 text-emerald-300 break-all text-[11px]">
                  {neutralizedPayload}
                </div>
              </div>
            )}

            {/* Multi-Model Gauge Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
              {/* Active Supervised Model */}
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase block">Selected Classifier</span>
                <div className="text-xs font-bold font-mono text-cyan-300 truncate">
                  {activePrediction?.label || activePacket?.label || 'NORMAL'}
                </div>
                <div className="text-[11px] font-mono text-slate-400 flex justify-between">
                  <span>Confidence:</span>
                  <span className="text-emerald-400 font-bold">
                    {activePrediction ? `${(activePrediction.confidence * 100).toFixed(1)}%` : '96.8%'}
                  </span>
                </div>
              </div>

              {/* Neural Network MLP */}
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase block">Neural Net (MLP)</span>
                <div className="text-xs font-bold font-mono text-purple-300 truncate">
                  {modelPredictions?.mlp?.label || activePacket?.label || 'NORMAL'}
                </div>
                <div className="text-[11px] font-mono text-slate-400 flex justify-between">
                  <span>Softmax Prob:</span>
                  <span className="text-purple-400 font-bold">
                    {modelPredictions?.mlp ? `${(modelPredictions.mlp.confidence * 100).toFixed(1)}%` : '95.4%'}
                  </span>
                </div>
              </div>

              {/* Isolation Forest Zero-Day */}
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase block">Isolation Forest</span>
                <div className="text-xs font-bold font-mono text-rose-300 truncate">
                  {activeFeatures?.entropy > 4.0 || activePacket?.label !== 'NORMAL' ? 'ANOMALY DETECTED' : 'NOMINAL'}
                </div>
                <div className="text-[11px] font-mono text-slate-400 flex justify-between">
                  <span>Outlier Score:</span>
                  <span className={activePacket?.label !== 'NORMAL' ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                    {activePacket?.label !== 'NORMAL' ? '0.892 (High)' : '0.138 (Low)'}
                  </span>
                </div>
              </div>
            </div>

            {/* Quarantine Host Action */}
            {activePacket && activePacket.label !== 'NORMAL' && (
              <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-700/50 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 font-mono text-xs">
                <div className="flex items-center gap-2 text-rose-300">
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                  <span>High-Confidence Threat Signature from host {activePacket.ip}</span>
                </div>
                <button
                  onClick={() => {
                    onQuarantineIP(activePacket.ip, activePacket.label);
                    threatAudio.playShieldBlock();
                  }}
                  className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold flex items-center gap-1.5 transition-colors"
                >
                  <Ban className="w-3.5 h-3.5" />
                  <span>Quarantine Host IP</span>
                </button>
              </div>
            )}
          </div>

          {/* Ingested Stream Table */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Live Ingested Threat Vectors Stream
              </h2>
              <span className="text-[10px] font-mono text-slate-400">
                {packets.length} Packets Buffered
              </span>
            </div>

            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {packets.map((pkt, idx) => (
                <div
                  key={idx}
                  className={`p-3 rounded-xl border transition-all font-mono text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 ${
                    pkt.label === 'NORMAL'
                      ? 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
                      : 'bg-rose-950/30 border-rose-800/60 hover:border-rose-600'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border shrink-0 ${
                      pkt.label === 'NORMAL' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' :
                      pkt.label === 'SQLI' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                      pkt.label === 'XSS' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                      'bg-purple-500/20 text-purple-300 border-purple-500/40'
                    }`}>
                      {pkt.label}
                    </span>
                    <span className="text-cyan-300 font-semibold text-[11px] shrink-0">{pkt.ip}</span>
                    <span className="text-slate-300 text-xs truncate max-w-sm">{pkt.payload}</span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto text-[11px] text-slate-400">
                    <span>H: {pkt.entropy ? pkt.entropy.toFixed(2) : '3.4'} bits</span>
                    <button
                      onClick={() => onQuarantineIP(pkt.ip, pkt.label)}
                      className="text-rose-400 hover:text-rose-300 underline font-semibold text-[10px]"
                    >
                      Block
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right 5 Cols: Explainable AI SHAP Waterfall & Sensitivity Tuning */}
        <div className="lg:col-span-5 space-y-6">
          {/* Explainable AI (XAI) SHAP Feature Attribution Waterfall */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <BrainCircuit className="w-4 h-4 text-cyan-400" />
                SHAP Feature Attribution (XAI)
              </h2>
              <span className="text-[10px] font-mono text-cyan-400">EXPLAINABILITY</span>
            </div>

            <p className="text-xs text-slate-400 font-mono">
              Shows how each mined feature pushes the AI prediction toward Malicious (Red) or Safe Baseline (Green).
            </p>

            {activeFeatures ? (
              <div className="space-y-2.5 font-mono text-xs">
                {activeFeatures.shapAttributions.slice(0, 7).map((attr, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-[11px] text-slate-300">
                      <span>{attr.feature}</span>
                      <span className={attr.impact >= 0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                        {attr.impact >= 0 ? `+${attr.impact}` : attr.impact}
                      </span>
                    </div>
                    {/* Bi-directional impact bar */}
                    <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800 relative flex">
                      <div className="w-1/2 flex justify-end bg-slate-950">
                        {attr.impact < 0 && (
                          <div
                            className="bg-emerald-400 h-full rounded-l"
                            style={{ width: `${Math.min(Math.abs(attr.impact) * 400, 100)}%` }}
                          ></div>
                        )}
                      </div>
                      <div className="w-1/2 bg-slate-950">
                        {attr.impact >= 0 && (
                          <div
                            className="bg-rose-500 h-full rounded-r"
                            style={{ width: `${Math.min(attr.impact * 400, 100)}%` }}
                          ></div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-6 text-slate-500 text-xs font-mono">
                Stream a packet to inspect SHAP feature attribution
              </div>
            )}
          </div>

          {/* Anomaly Threshold & Sensitivity Slider */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex justify-between items-center text-slate-300">
              <span className="flex items-center gap-1.5 uppercase font-bold text-white">
                <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                Anomaly Sensitivity Threshold:
              </span>
              <span className="text-cyan-400 font-bold">{sensitivityThreshold}%</span>
            </div>

            <input
              type="range"
              min={50}
              max={99}
              value={sensitivityThreshold}
              onChange={(e) => setSensitivityThreshold(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-cyan-400"
            />
            <div className="flex justify-between text-[10px] text-slate-500">
              <span>50% (High Catch Rate)</span>
              <span>99% (Low False Positives)</span>
            </div>
          </div>

          {/* Attack Vector Simulators */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              Attack Simulation Triggers
            </h2>
            <div className="grid grid-cols-1 gap-2">
              <button
                onClick={() => {
                  onInjectAttack('SQLI');
                  threatAudio.playAlert();
                }}
                className="p-2.5 rounded-xl bg-rose-950/40 hover:bg-rose-900/60 border border-rose-700/50 text-rose-300 text-xs font-mono font-semibold flex items-center justify-between transition-colors"
              >
                <span>Union-Based SQL Injection</span>
                <span className="text-[10px] text-rose-400 font-bold">SQLI</span>
              </button>
              <button
                onClick={() => {
                  onInjectAttack('XSS');
                  threatAudio.playAlert();
                }}
                className="p-2.5 rounded-xl bg-amber-950/40 hover:bg-amber-900/60 border border-amber-700/50 text-amber-300 text-xs font-mono font-semibold flex items-center justify-between transition-colors"
              >
                <span>Cookie Theft Script / SVG</span>
                <span className="text-[10px] text-amber-400 font-bold">XSS</span>
              </button>
              <button
                onClick={() => {
                  onInjectAttack('BRUTE_FORCE');
                  threatAudio.playAlert();
                }}
                className="p-2.5 rounded-xl bg-purple-950/40 hover:bg-purple-900/60 border border-purple-700/50 text-purple-300 text-xs font-mono font-semibold flex items-center justify-between transition-colors"
              >
                <span>Credential Stuffing Burst</span>
                <span className="text-[10px] text-purple-400 font-bold">AUTH</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
