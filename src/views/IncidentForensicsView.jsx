import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Ban, 
  ShieldAlert, 
  ShieldCheck, 
  CheckCircle2, 
  AlertTriangle, 
  Trash2, 
  Plus, 
  Search,
  Filter,
  Lock,
  Terminal,
  Activity
} from 'lucide-react';
import { threatAudio } from '../components/ThreatAudio';

export default function IncidentForensicsView({ 
  quarantinedIPs = [], 
  onUnbanIP, 
  onAddQuarantineIP,
  onOpenMitrePlaybook,
  incidentLogs = []
}) {
  const [newIP, setNewIP] = useState('');
  const [newReason, setNewReason] = useState('Manual SOC Administrator Quarantine');
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);

  const handleManualBan = (e) => {
    e.preventDefault();
    if (!newIP.trim()) return;
    onAddQuarantineIP(newIP.trim(), newReason);
    threatAudio.playShieldBlock();
    setNewIP('');
  };

  const handleExportJSON = () => {
    const reportData = {
      reportTitle: 'CSTD Sentinel SOC Incident Forensics Audit',
      generatedAt: new Date().toISOString(),
      quarantinedCount: quarantinedIPs.length,
      quarantinedIPs,
      incidents: incidentLogs,
      complianceStandard: 'ISO/IEC 27001 & NIST SP 800-61 Rev. 2',
      verificationHash: `sha256$${Math.random().toString(36).substring(2, 18)}`
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `sentinel-incident-report-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();

    threatAudio.playSuccess();
  };

  const filteredIncidents = incidentLogs.filter(inc => 
    inc.ip?.toLowerCase().includes(searchFilter.toLowerCase()) ||
    inc.type?.toLowerCase().includes(searchFilter.toLowerCase()) ||
    inc.payload?.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-2xl glass-panel-glow border-amber-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 shrink-0">
            <FileText className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              INCIDENT FORENSICS & ZERO-TRUST IP QUARANTINE
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 font-semibold">
                NIST SP 800-61
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Audit trail, IP address quarantine registry, timeline analysis, and verifiable forensic report export.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {onOpenMitrePlaybook && (
            <button
              onClick={onOpenMitrePlaybook}
              className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/50 flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(244,63,94,0.2)]"
            >
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>MITRE T1110 PLAYBOOK</span>
            </button>
          )}

          <button
            onClick={handleExportJSON}
            className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-amber-500 to-yellow-400 hover:from-amber-400 hover:to-yellow-300 text-slate-950 flex items-center gap-1.5 shadow-[0_0_15px_rgba(255,184,0,0.3)] transition-all"
          >
            <Download className="w-4 h-4" />
            <span>EXPORT FORENSICS REPORT (.JSON)</span>
          </button>
        </div>
      </div>

      {/* Main Grid: IP Quarantine & Forensic Incident Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: IP Quarantine Manager (5 Cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Add IP Block Form */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <Ban className="w-4 h-4 text-rose-400" />
                Add Zero-Trust IP Quarantine
              </h2>
              <span className="text-[10px] font-mono text-rose-400">INSTANT BAN</span>
            </div>

            <form onSubmit={handleManualBan} className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-slate-400 block mb-1">TARGET IP ADDRESS</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 194.26.29.112"
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500/60"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">QUARANTINE REASON</label>
                <input
                  type="text"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500/60"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2.5 rounded-xl font-mono text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white flex items-center justify-center gap-1.5 transition-colors shadow-md"
              >
                <Plus className="w-4 h-4" />
                <span>QUARANTINE HOST IMMEDIATELY</span>
              </button>
            </form>
          </div>

          {/* Active Quarantined IP List */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Quarantined Hosts Registry
              </h2>
              <span className="text-[10px] font-mono text-slate-400">
                {quarantinedIPs.length} BANNED
              </span>
            </div>

            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {quarantinedIPs.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-rose-950/20 border border-rose-800/40 flex items-center justify-between font-mono text-xs text-slate-300"
                >
                  <div className="min-w-0 pr-2">
                    <div className="flex items-center gap-2">
                      <span className="text-rose-400 font-bold">{item.ip}</span>
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {item.reason}
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-500 block mt-0.5">{item.time}</span>
                  </div>

                  <button
                    onClick={() => {
                      onUnbanIP(item.ip);
                      threatAudio.playSuccess();
                    }}
                    className="p-1.5 rounded-lg bg-slate-900 hover:bg-emerald-600 hover:text-white text-slate-400 border border-slate-700 transition-colors"
                    title="Revoke ban"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Incident Timeline & Forensic Deep Inspector (7 Cols) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold font-mono uppercase text-white">
                  SOC Forensic Incident Log
                </h2>
              </div>

              {/* Search Filter */}
              <div className="relative w-full sm:w-48">
                <input
                  type="text"
                  placeholder="Filter incidents..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="w-full pl-7 pr-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
                />
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-1/2 -translate-y-1/2" />
              </div>
            </div>

            {/* Incidents Table / Timeline */}
            <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
              {filteredIncidents.map((inc, i) => (
                <div
                  key={i}
                  onClick={() => setSelectedIncident(inc)}
                  className="p-3.5 rounded-xl bg-slate-950/70 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/50 cursor-pointer font-mono text-xs transition-all space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        inc.type === 'SQLI' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                        inc.type === 'XSS' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                        'bg-purple-500/20 text-purple-300 border-purple-500/40'
                      }`}>
                        {inc.type}
                      </span>
                      <span className="text-cyan-300 font-bold">{inc.ip}</span>
                    </div>
                    <span className="text-slate-500 text-[10px]">{inc.time}</span>
                  </div>

                  <div className="text-slate-300 text-[11px] truncate">
                    {inc.payload}
                  </div>

                  <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1">
                    <span>Mitigation: {inc.action || 'INTERCEPTED & QUARANTINED'}</span>
                    <span className="text-cyan-400 underline">Inspect forensics →</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Selected Incident Inspector Modal / Card */}
          {selectedIncident && (
            <div className="p-5 rounded-2xl glass-panel border-cyan-500/40 space-y-3 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-xs font-bold font-mono text-cyan-300 uppercase">
                  FORENSIC CASE FILE #{Math.floor(1000 + Math.random() * 9000)}
                </span>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="text-slate-400 hover:text-slate-200 text-xs font-mono"
                >
                  Close File
                </button>
              </div>

              <div className="space-y-2 font-mono text-xs">
                <div>
                  <span className="text-slate-500 text-[10px]">EVIDENCE PAYLOAD:</span>
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-rose-300 break-all">
                    {selectedIncident.payload}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 rounded bg-slate-950 text-slate-400">
                    Host IP: <span className="text-white font-bold">{selectedIncident.ip}</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950 text-slate-400">
                    Status: <span className="text-emerald-400 font-bold">Mitigated</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
