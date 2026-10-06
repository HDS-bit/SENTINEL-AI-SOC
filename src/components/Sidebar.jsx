import React from 'react';
import { 
  LayoutDashboard, 
  Cpu, 
  ShieldCheck, 
  Binary, 
  Terminal, 
  UserCheck, 
  FileText, 
  Zap,
  Flame,
  Fingerprint,
  FolderOpen,
  FileSpreadsheet
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, blockedCount = 0, incidentCount = 0 }) {
  const navItems = [
    {
      id: 'dashboard',
      name: 'SOC Command Center',
      icon: LayoutDashboard,
      badge: null,
      description: 'Threat radar, telemetry & active alerts'
    },
    {
      id: 'ai-threat',
      name: 'AI Threat Detection',
      icon: Cpu,
      badge: 'LIVE ML',
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
      description: 'Real-time packet stream & multi-attack classifier'
    },
    {
      id: 'db-firewall',
      name: 'Database Firewall',
      icon: ShieldCheck,
      badge: blockedCount > 0 ? `${blockedCount} BLOCKED` : 'ACTIVE',
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
      description: 'SQL AST inspection & injection prevention'
    },
    {
      id: 'data-safety',
      name: 'Dataset Upload & Analysis',
      icon: FileSpreadsheet,
      badge: 'DATASET EDA',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      description: 'Upload CSV/JSON, statistical EDA & threat disinfection'
    },
    {
      id: 'data-mining',
      name: 'ML Pipeline & Data Mining',
      icon: Binary,
      badge: '7-STAGE FLOWCHART',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      description: 'Dataset → Prep → Features → Train → Eval → Pred → Dashboard'
    },
    {
      id: 'file-manager',
      name: 'Secure File Vault & Rectifier',
      icon: FolderOpen,
      badge: 'RECTIFIER',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      description: 'Upload scan, error rectification & threat avoidance'
    },
    {
      id: 'sandbox',
      name: 'Threat Payload Sandbox',
      icon: Terminal,
      badge: null,
      description: 'Deep payload tokenizer & multi-layer audit'
    },
    {
      id: 'user-safety',
      name: 'User Safety & Auth Center',
      icon: Fingerprint,
      badge: '2FA / RBAC',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      description: 'Secure registration, password entropy & hashes'
    },
    {
      id: 'forensics',
      name: 'Incident Forensics & IP Ban',
      icon: FileText,
      badge: incidentCount > 0 ? `${incidentCount} ALERTS` : null,
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      description: 'Forensics report export & IP quarantine'
    }
  ];

  return (
    <aside className="w-full lg:w-72 bg-slate-950/70 border-r border-slate-800/80 p-3 lg:p-4 flex flex-col justify-between shrink-0">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center justify-between">
          <span>OPERATIONS NAVIGATION</span>
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
        </div>

        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-start gap-3 p-2.5 lg:p-3 rounded-xl text-left transition-all duration-200 group relative ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-950/70 to-slate-900/90 text-cyan-300 border border-cyan-500/40 shadow-[0_0_15px_rgba(0,242,254,0.12)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                {isActive && (
                  <span className="absolute left-0 top-2 bottom-2 w-1 bg-cyan-400 rounded-r-full shadow-[0_0_8px_#00f2fe]"></span>
                )}

                <div className={`p-2 rounded-lg mt-0.5 transition-colors ${
                  isActive 
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' 
                    : 'bg-slate-900 text-slate-400 group-hover:text-cyan-400 group-hover:bg-slate-800'
                }`}>
                  <Icon className="w-4 h-4" />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-1">
                    <span className={`text-xs font-semibold truncate ${isActive ? 'text-white' : ''}`}>
                      {item.name}
                    </span>
                    {item.badge && (
                      <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-bold ${item.badgeColor}`}>
                        {item.badge}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 truncate mt-0.5">
                    {item.description}
                  </p>
                </div>
              </button>
            );
          })}
        </nav>
      </div>

      {/* SOC System Health Monitor Card */}
      <div className="mt-4 p-3 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-mono space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="flex items-center gap-1.5 text-[10px] uppercase text-cyan-400">
            <Zap className="w-3 h-3" />
            AI SENTINEL ENGINE
          </span>
          <span className="text-[10px] text-emerald-400 font-bold">ONLINE</span>
        </div>

        <div className="space-y-1.5 text-[11px]">
          <div className="flex justify-between text-slate-400">
            <span>Inference Latency:</span>
            <span className="text-cyan-300 font-bold">1.8ms</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-400 to-emerald-400 h-full w-[96%]"></div>
          </div>
          <div className="flex justify-between text-slate-400 text-[10px]">
            <span>Model Health: 99.9%</span>
            <span>DB Firewall: Active</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
