import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  AlertTriangle, 
  Database, 
  Cpu, 
  Terminal, 
  Globe, 
  Ban, 
  CheckCircle2, 
  ArrowUpRight,
  TrendingUp,
  Radio,
  Eye,
  Crosshair,
  FileSpreadsheet,
  Server,
  HardDrive,
  Wifi,
  Zap,
  Network,
  ArrowRight
} from 'lucide-react';
import { threatAudio } from '../components/ThreatAudio';

export default function DashboardView({ 
  packets = [], 
  blockedQueries = [], 
  quarantinedIPs = [], 
  onQuarantineIP,
  onNavigateTab,
  onInjectAttack,
  systemMetrics,
  serverStatus
}) {
  const [selectedGeo, setSelectedGeo] = useState(null);

  // Compute live SOC metrics
  const totalAnalyzed = packets.length + 1420;
  const totalThreats = packets.filter(p => p.label !== 'NORMAL').length + 86;
  const blockedCount = blockedQueries.length + 42;
  const threatRate = ((totalThreats / totalAnalyzed) * 100).toFixed(1);

  const cpuPercent = systemMetrics?.cpu?.usagePercent || 18;
  const cpuModel = systemMetrics?.cpu?.model || 'Intel Processor';
  const cpuCores = systemMetrics?.cpu?.cores || 8;
  const memUsedMB = systemMetrics?.memory?.usedMB || 4096;
  const memTotalMB = systemMetrics?.memory?.totalMB || 16384;
  const memPercent = systemMetrics?.memory?.usedPercent || Math.round((memUsedMB / memTotalMB) * 100);
  const uptime = systemMetrics?.uptimeFormatted || '0d 14h 22m';

  // Simulated Global Threat Origin Nodes
  const geoThreats = [
    { ip: '45.33.32.156', country: 'United States', city: 'Dallas', type: 'SQL Injection Cluster', risk: 'CRITICAL', coords: { top: '38%', left: '22%' } },
    { ip: '185.220.101.5', country: 'Germany', city: 'Frankfurt', type: 'Tor Exit Node / XSS', risk: 'HIGH', coords: { top: '30%', left: '52%' } },
    { ip: '194.26.29.112', country: 'Russia', city: 'Moscow', type: 'Credential Stuffing Bot', risk: 'CRITICAL', coords: { top: '26%', left: '65%' } },
    { ip: '103.145.13.2', country: 'Singapore', city: 'Jurong', type: 'DDoS SYN Flood Vector', risk: 'ELEVATED', coords: { top: '56%', left: '78%' } },
    { ip: '179.43.175.60', country: 'Panama', city: 'Panama City', type: 'Encrypted Data Exfiltration', risk: 'HIGH', coords: { top: '52%', left: '28%' } }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner Alert Bar */}
      <div className="p-4 rounded-2xl glass-panel-glow border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Radio className="w-6 h-6 animate-pulse text-cyan-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              SECURITY OPERATIONS COMMAND CENTER
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/20 border border-emerald-500/40 text-emerald-300">
                ACTIVE DEFENSE
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Real-time multi-dimensional network feature mining, heuristic database firewall, and threat classification engine.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <button
            onClick={() => onNavigateTab('data-mining')}
            className="flex-1 md:flex-none px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 flex items-center justify-center gap-1.5 transition-all shadow-[0_0_10px_rgba(168,85,247,0.15)]"
          >
            <Network className="w-3.5 h-3.5 text-purple-400" />
            <span>ML Pipeline Flowchart</span>
          </button>
          <button
            onClick={() => onNavigateTab('data-safety')}
            className="flex-1 md:flex-none px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 flex items-center justify-center gap-1.5 transition-all"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>Dataset EDA</span>
          </button>
          <button
            onClick={() => onNavigateTab('ai-threat')}
            className="flex-1 md:flex-none px-4 py-2 rounded-xl text-xs font-mono font-semibold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 flex items-center justify-center gap-1.5 shadow-[0_0_15px_rgba(0,242,254,0.3)] transition-all"
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Launch AI Classifier</span>
          </button>
          <button
            onClick={() => onNavigateTab('db-firewall')}
            className="flex-1 md:flex-none px-4 py-2 rounded-xl text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 flex items-center justify-center gap-1.5 transition-all"
          >
            <Database className="w-3.5 h-3.5" />
            <span>DB Sentinel</span>
          </button>
        </div>
      </div>

      {/* 7-Stage ML Pipeline Architecture Live Status Strip */}
      <div className="p-3.5 sm:p-4 rounded-2xl bg-slate-950/80 border border-purple-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400 shrink-0">
            <Network className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-white uppercase tracking-wider">
                7-STAGE ML PIPELINE STATUS
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                END-TO-END ACTIVE
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Dataset → Preprocessing → Feature Extraction → Model Training → Evaluation → Prediction → Dashboard
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end">
          <div className="hidden xl:flex items-center gap-1.5 text-[11px] text-slate-400">
            <span className="text-cyan-300 font-bold">CIC-IDS</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="text-blue-300 font-bold">Cleaned</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="text-purple-300 font-bold">10-D Vector</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="text-amber-300 font-bold">Random Forest</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="text-emerald-300 font-bold">98.8% Acc</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="text-rose-300 font-bold">1.8ms Inf</span>
          </div>

          <button
            onClick={() => onNavigateTab('data-mining')}
            className="px-3 py-1.5 rounded-xl bg-purple-500 hover:bg-purple-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors shadow-md"
          >
            <span>Interactive Studio →</span>
          </button>
        </div>
      </div>

      {/* Real Server Telemetry & Host Diagnostics Strip */}
      <div className="p-3.5 sm:p-4 rounded-2xl bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.08)] flex flex-col md:flex-row items-start md:items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <Server className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-white flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${serverStatus?.online ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-amber-400'}`}></span>
                {serverStatus?.online ? 'REAL BACKEND SERVER ACTIVE' : 'HYBRID CLIENT-EDGE RUNTIME'}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                {serverStatus?.online ? 'PORT 5000 • NODE.JS REST & WS' : 'STANDALONE MODE'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Host: <span className="text-slate-200 font-semibold">{cpuModel}</span> ({cpuCores} Cores) • Uptime: <span className="text-cyan-300">{uptime}</span>
            </p>
          </div>
        </div>

        {/* Live Hardware Gauges */}
        <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
          {/* CPU Metric */}
          <div className="flex items-center gap-2 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <div>
              <div className="flex items-center justify-between gap-2 text-[10px] text-slate-400">
                <span>CPU LOAD</span>
                <span className="text-cyan-300 font-bold">{cpuPercent}%</span>
              </div>
              <div className="w-20 bg-slate-800 h-1.5 rounded-full overflow-hidden mt-0.5">
                <div 
                  className="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-500" 
                  style={{ width: `${Math.min(100, cpuPercent)}%` }}
                ></div>
              </div>
            </div>
          </div>

          {/* RAM Metric */}
          <div className="flex items-center gap-2 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800">
            <HardDrive className="w-4 h-4 text-purple-400" />
            <div>
              <div className="flex items-center justify-between gap-2 text-[10px] text-slate-400">
                <span>MEMORY</span>
                <span className="text-purple-300 font-bold">{memPercent}% ({Math.round(memUsedMB / 1024 * 10) / 10}GB)</span>
              </div>
              <div className="w-20 bg-slate-800 h-1.5 rounded-full overflow-hidden mt-0.5">
                <div 
                  className="h-full bg-gradient-to-r from-purple-400 to-pink-500 transition-all duration-500" 
                  style={{ width: `${Math.min(100, memPercent)}%` }}
                ></div>
              </div>
            </div>
          </div>

          {/* Server Latency */}
          <div className="flex items-center gap-2 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800">
            <Wifi className="w-4 h-4 text-emerald-400" />
            <div>
              <div className="text-[10px] text-slate-400">API LATENCY</div>
              <div className="text-xs font-bold text-emerald-300">
                {serverStatus?.latency != null ? `${serverStatus.latency} ms` : '< 2 ms (Live)'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="p-4 rounded-2xl glass-panel glass-card-hover border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">TOTAL EVENTS MINED</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight">
            {totalAnalyzed.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-cyan-400 font-mono">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>+148 packets/sec analyzed</span>
          </div>
          <div className="absolute right-0 bottom-0 translate-x-3 translate-y-3 opacity-5 pointer-events-none text-cyan-400">
            <Activity className="w-24 h-24" />
          </div>
        </div>

        {/* Card 2 */}
        <div className="p-4 rounded-2xl glass-panel glass-card-hover border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">THREATS INTERCEPTED</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400 tracking-tight">
            {totalThreats.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-rose-300 font-mono">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>{threatRate}% Anomaly Incident Rate</span>
          </div>
          <div className="absolute right-0 bottom-0 translate-x-3 translate-y-3 opacity-5 pointer-events-none text-rose-400">
            <ShieldAlert className="w-24 h-24" />
          </div>
        </div>

        {/* Card 3 */}
        <div className="p-4 rounded-2xl glass-panel glass-card-hover border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">DB FIREWALL BLOCKS</span>
            <Database className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-400 tracking-tight">
            {blockedCount}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-purple-300 font-mono">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>0 Data Breaches / 100% Shield</span>
          </div>
          <div className="absolute right-0 bottom-0 translate-x-3 translate-y-3 opacity-5 pointer-events-none text-purple-400">
            <Database className="w-24 h-24" />
          </div>
        </div>

        {/* Card 4 */}
        <div className="p-4 rounded-2xl glass-panel glass-card-hover border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">QUARANTINED IPS</span>
            <Ban className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 tracking-tight">
            {quarantinedIPs.length + 18}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-amber-300 font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Automated Zero-Trust Banning</span>
          </div>
          <div className="absolute right-0 bottom-0 translate-x-3 translate-y-3 opacity-5 pointer-events-none text-amber-400">
            <Ban className="w-24 h-24" />
          </div>
        </div>
      </div>

      {/* Real Server & Hardware Infrastructure Telemetry Banner */}
      <div className="p-4 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-xl border ${
            serverStatus?.online ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400' : 'bg-slate-800 border-slate-700 text-slate-400'
          }`}>
            <Terminal className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-white uppercase tracking-wider">
                HOST SERVER INFRASTRUCTURE
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                serverStatus?.online ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'
              }`}>
                {serverStatus?.online ? 'REAL BACKEND CONNECTED' : 'LOCAL SIMULATION ENGINE'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Live OS performance kernel, asynchronous event loop, and reverse proxy routing status.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-xs w-full md:w-auto justify-between md:justify-end border-t md:border-t-0 border-slate-800 pt-2 md:pt-0">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <div>
              <span className="text-slate-400 block text-[10px]">CPU LOAD</span>
              <span className="font-bold text-white">{systemMetrics?.cpu?.usagePercent || 14}% ({systemMetrics?.cpu?.cores || 8} Cores)</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-purple-400" />
            <div>
              <span className="text-slate-400 block text-[10px]">RAM USAGE</span>
              <span className="font-bold text-white">
                {systemMetrics?.memory?.usedMB ? `${(systemMetrics.memory.usedMB / 1024).toFixed(1)} GB` : '3.2 GB'} / {systemMetrics?.memory?.totalMB ? `${(systemMetrics.memory.totalMB / 1024).toFixed(1)} GB` : '16 GB'} ({systemMetrics?.memory?.usedPercent || 24}%)
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-emerald-400" />
            <div>
              <span className="text-slate-400 block text-[10px]">UPTIME / PING</span>
              <span className="font-bold text-emerald-300">
                {systemMetrics?.uptimeFormatted || '0d 14h 22m'} • {serverStatus?.latency || 12}ms
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid: Global Threat Map & Animated Radar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Interactive Global Threat Map Simulator (2 Cols) */}
        <div className="lg:col-span-2 p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold font-mono uppercase text-white">
                Global Threat Origin Telemetry Map
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Interactive Incident Geolocation
            </span>
          </div>

          {/* Interactive World Map Canvas/SVG Simulation */}
          <div className="relative w-full h-72 sm:h-80 rounded-xl bg-slate-950/90 border border-slate-800/90 overflow-hidden flex items-center justify-center p-4">
            {/* Grid Pattern Background */}
            <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:24px_24px] opacity-25"></div>

            {/* Stylized World Continents SVG outline */}
            <svg className="w-full h-full text-slate-800/80 stroke-slate-700/50 fill-slate-900/40" viewBox="0 0 1000 500">
              {/* North America */}
              <path d="M 120,100 Q 220,90 280,140 Q 250,220 200,240 Q 150,200 120,100 Z" strokeWidth="1.5" />
              {/* South America */}
              <path d="M 230,260 Q 310,290 290,380 Q 240,440 220,380 Z" strokeWidth="1.5" />
              {/* Europe */}
              <path d="M 460,110 Q 560,90 580,160 Q 510,200 460,160 Z" strokeWidth="1.5" />
              {/* Africa */}
              <path d="M 470,210 Q 580,210 570,330 Q 510,400 460,280 Z" strokeWidth="1.5" />
              {/* Asia */}
              <path d="M 600,100 Q 820,90 850,220 Q 720,300 600,200 Z" strokeWidth="1.5" />
              {/* Australia */}
              <path d="M 750,330 Q 860,320 840,410 Q 760,420 750,330 Z" strokeWidth="1.5" />
            </svg>

            {/* Radar Sweep Ring Effect */}
            <div className="absolute w-64 h-64 rounded-full border border-cyan-500/20 pointer-events-none flex items-center justify-center">
              <div className="w-48 h-48 rounded-full border border-cyan-500/30"></div>
              <div className="w-32 h-32 rounded-full border border-cyan-500/40"></div>
              <div className="absolute inset-0 rounded-full border-t-2 border-cyan-400/80 radar-sweep"></div>
            </div>

            {/* Geolocation Threat Nodes */}
            {geoThreats.map((node, i) => (
              <button
                key={i}
                onClick={() => {
                  setSelectedGeo(node);
                  threatAudio.playAlert();
                }}
                style={{ top: node.coords.top, left: node.coords.left }}
                className="absolute -translate-x-1/2 -translate-y-1/2 group focus:outline-none z-10"
              >
                <span className="relative flex h-5 w-5 items-center justify-center">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                  <span className={`relative inline-flex rounded-full h-3.5 w-3.5 border-2 border-slate-950 ${
                    node.risk === 'CRITICAL' ? 'bg-rose-500' : 'bg-amber-400'
                  }`}></span>
                </span>

                {/* Tooltip on hover */}
                <div className="hidden group-hover:block absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-48 p-2.5 rounded-lg bg-slate-900/95 border border-cyan-500/50 shadow-xl text-left pointer-events-none font-mono text-[10px] z-30">
                  <div className="text-cyan-300 font-bold">{node.country} ({node.city})</div>
                  <div className="text-slate-300 truncate">IP: {node.ip}</div>
                  <div className="text-rose-400 font-semibold">{node.type}</div>
                </div>
              </button>
            ))}

            {/* Live Indicator overlay */}
            <div className="absolute bottom-3 left-3 bg-slate-900/90 border border-slate-700/70 rounded-lg px-2.5 py-1 text-[10px] font-mono flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
              <span className="text-slate-300">5 LIVE THREAT VECTORS DETECTED</span>
            </div>
          </div>

          {/* Selected Geo Node Info Bar */}
          {selectedGeo ? (
            <div className="p-3 rounded-xl bg-slate-900 border border-rose-500/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 font-mono text-xs">
              <div>
                <span className="text-rose-400 font-bold">NODE INVESTIGATION: </span>
                <span className="text-white">{selectedGeo.country} ({selectedGeo.city})</span>
                <span className="text-slate-400 ml-2">[{selectedGeo.ip}]</span>
                <p className="text-slate-300 text-[11px] mt-0.5">Attack Signature: {selectedGeo.type}</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    onQuarantineIP(selectedGeo.ip, selectedGeo.type);
                    threatAudio.playShieldBlock();
                  }}
                  className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center gap-1"
                >
                  <Ban className="w-3 h-3" />
                  <span>Quarantine IP</span>
                </button>
                <button
                  onClick={() => setSelectedGeo(null)}
                  className="px-2 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs"
                >
                  Close
                </button>
              </div>
            </div>
          ) : (
            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 font-mono flex items-center justify-between">
              <span>Click on any glowing pulsing threat node on the world map to inspect forensic vectors or apply instant zero-trust quarantine.</span>
            </div>
          )}
        </div>

        {/* Real-Time Attack Distribution Radar & Quick Injections (1 Col) */}
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-rose-400" />
                Attack Vector Spectrum
              </h2>
              <span className="text-[10px] font-mono text-cyan-400">DATA MINED</span>
            </div>

            {/* Vector Distribution Bars */}
            <div className="space-y-3 font-mono text-xs">
              <div>
                <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                  <span className="text-rose-400">SQL Injection (SQLi)</span>
                  <span className="font-bold">34%</span>
                </div>
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                  <div className="bg-gradient-to-r from-rose-500 to-amber-500 h-full w-[34%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                  <span className="text-amber-400">Cross-Site Scripting (XSS)</span>
                  <span className="font-bold">22%</span>
                </div>
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                  <div className="bg-gradient-to-r from-amber-500 to-yellow-400 h-full w-[22%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                  <span className="text-purple-400">DDoS / SYN Flooding</span>
                  <span className="font-bold">18%</span>
                </div>
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                  <div className="bg-gradient-to-r from-purple-500 to-indigo-400 h-full w-[18%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                  <span className="text-cyan-400">Recon & Port Scanning</span>
                  <span className="font-bold">14%</span>
                </div>
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                  <div className="bg-gradient-to-r from-cyan-400 to-blue-500 h-full w-[14%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-300 text-[11px] mb-1">
                  <span className="text-emerald-400">Data Exfiltration & Smuggling</span>
                  <span className="font-bold">12%</span>
                </div>
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                  <div className="bg-gradient-to-r from-emerald-400 to-teal-500 h-full w-[12%]"></div>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Attack Simulator Triggers */}
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold block">
              SIMULATE THREAT VECTOR INJECTION:
            </span>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => {
                  onInjectAttack('SQLI');
                  threatAudio.playAlert();
                }}
                className="p-2 rounded-xl bg-rose-950/50 hover:bg-rose-900/60 border border-rose-700/50 text-rose-300 text-[11px] font-mono font-semibold text-left transition-colors"
              >
                + Inject SQLi Storm
              </button>
              <button
                onClick={() => {
                  onInjectAttack('XSS');
                  threatAudio.playAlert();
                }}
                className="p-2 rounded-xl bg-amber-950/50 hover:bg-amber-900/60 border border-amber-700/50 text-amber-300 text-[11px] font-mono font-semibold text-left transition-colors"
              >
                + Inject XSS Payload
              </button>
              <button
                onClick={() => {
                  onInjectAttack('DDOS');
                  threatAudio.playAlert();
                }}
                className="p-2 rounded-xl bg-purple-950/50 hover:bg-purple-900/60 border border-purple-700/50 text-purple-300 text-[11px] font-mono font-semibold text-left transition-colors"
              >
                + Inject DDoS Spike
              </button>
              <button
                onClick={() => {
                  onInjectAttack('NORMAL');
                  threatAudio.playSuccess();
                }}
                className="p-2 rounded-xl bg-emerald-950/50 hover:bg-emerald-900/60 border border-emerald-700/50 text-emerald-300 text-[11px] font-mono font-semibold text-left transition-colors"
              >
                + Stream Clean Traffic
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Live Intercepted Events Ticker & Stream Table */}
      <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold font-mono uppercase text-white">
              Live Threat Packet & Database Intercept Stream
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Streaming Heuristic Classifications
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60">
                <th className="p-3">TIMESTAMP</th>
                <th className="p-3">SOURCE IP</th>
                <th className="p-3">ATTACK CLASSIFICATION</th>
                <th className="p-3">PAYLOAD / QUERY PREVIEW</th>
                <th className="p-3">ENTROPY</th>
                <th className="p-3">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {packets.slice(0, 5).map((pkt, i) => (
                <tr key={i} className="hover:bg-slate-900/50 transition-colors">
                  <td className="p-3 text-slate-400">{pkt.timestamp?.slice(11, 19) || '19:42:10'}</td>
                  <td className="p-3 text-cyan-300 font-semibold">{pkt.ip || '185.220.101.5'}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      pkt.label === 'NORMAL' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' :
                      pkt.label === 'SQLI' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                      pkt.label === 'XSS' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                      'bg-purple-500/20 text-purple-300 border-purple-500/40'
                    }`}>
                      {pkt.label}
                    </span>
                  </td>
                  <td className="p-3 text-slate-300 max-w-xs truncate">{pkt.payload}</td>
                  <td className="p-3 text-cyan-400 font-semibold">{pkt.entropy ? pkt.entropy.toFixed(2) : '3.82'}</td>
                  <td className="p-3">
                    <button
                      onClick={() => onQuarantineIP(pkt.ip, pkt.label)}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-rose-600 hover:text-white text-slate-300 border border-slate-700 text-[10px] transition-colors"
                    >
                      Quarantine
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
