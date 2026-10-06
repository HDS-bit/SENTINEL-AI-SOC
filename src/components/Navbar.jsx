import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Radio, 
  User, 
  Volume2, 
  VolumeX, 
  Activity,
  Lock,
  RefreshCw,
  LogOut,
  Server,
  Cpu,
  Menu,
  X
} from 'lucide-react';
import { RBAC_ROLES } from '../auth/authStore';
import { threatAudio } from './ThreatAudio';
import ServerStatusModal from './ServerStatusModal';

export default function Navbar({ 
  currentUser, 
  threatLevel = 'NORMAL', 
  soundEnabled, 
  setSoundEnabled,
  onEmergencyLockdown,
  emergencyActive,
  onResetSystem,
  onLogout,
  serverStatus,
  systemMetrics,
  mobileMenuOpen,
  onToggleMobileMenu
}) {
  const [time, setTime] = useState(new Date().toUTCString().slice(17, 25));
  const [showServerModal, setShowServerModal] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toUTCString().slice(17, 25));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const roleMeta = RBAC_ROLES[currentUser?.role] || RBAC_ROLES.SOC_COMMANDER;
  const cpuPercent = systemMetrics?.cpu?.usagePercent || 14;

  return (
    <>
      <ServerStatusModal 
        isOpen={showServerModal}
        onClose={() => setShowServerModal(false)}
        serverStatus={serverStatus}
        systemMetrics={systemMetrics}
      />

      <header className="sticky top-0 z-40 w-full glass-panel border-b border-slate-800/80 bg-cyber-bg/95 backdrop-blur-md px-3 sm:px-4 lg:px-6 py-2.5 sm:py-3 flex items-center justify-between">
        {/* Left Side: Brand, Mobile Menu Toggle, and Indicators */}
        <div className="flex items-center gap-2 sm:gap-4 min-w-0">
          {/* Mobile Hamburger Menu Toggle */}
          <button
            onClick={onToggleMobileMenu}
            className="lg:hidden p-2 rounded-xl bg-slate-900 border border-slate-700/80 text-cyan-400 hover:text-white transition-colors shrink-0"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          {/* Logo Brand */}
          <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
            <div className="relative flex items-center justify-center w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 text-cyan-400 shadow-[0_0_15px_rgba(0,242,254,0.3)]">
              <ShieldAlert className="w-4 h-4 sm:w-5 sm:h-5 animate-pulse" />
              <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
            </div>
            <div>
              <div className="flex items-center gap-1.5 sm:gap-2">
                <span className="font-display font-bold text-sm sm:text-lg tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-400">
                  SENTINEL
                </span>
                <span className="text-[9px] sm:text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-semibold hidden xs:inline-block">
                  v3.4
                </span>
              </div>
              <p className="text-[10px] sm:text-xs text-slate-400 font-mono hidden md:flex items-center gap-1.5">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                CYBER SOC & ML DEFENSE
              </p>
            </div>
          </div>

          {/* Real Server Telemetry Badge */}
          <button
            onClick={() => setShowServerModal(true)}
            className={`hidden sm:flex items-center gap-2 px-2.5 sm:px-3 py-1.5 rounded-xl border text-xs font-mono transition-all shrink-0 ${
              serverStatus?.online
                ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300 hover:border-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
                : 'bg-slate-900/90 border-slate-700/70 text-slate-400 hover:border-slate-500'
            }`}
            title="Click to view Real Server Diagnostics & Host Telemetry"
          >
            <div className="relative flex items-center justify-center">
              <Server className={`w-3.5 h-3.5 ${serverStatus?.online ? 'text-emerald-400' : 'text-slate-500'}`} />
              {serverStatus?.online && (
                <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
              )}
            </div>
            <div className="flex flex-col text-left leading-tight">
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${serverStatus?.online ? 'bg-emerald-400 shadow-[0_0_6px_#34d399]' : 'bg-slate-500'}`}></span>
                <span className="font-bold text-[11px] sm:text-xs">
                  {serverStatus?.online ? 'SERVER ONLINE' : 'EDGE CLIENT'}
                </span>
                {serverStatus?.latency != null && (
                  <span className="text-[10px] text-emerald-400 font-semibold">({serverStatus.latency}ms)</span>
                )}
              </div>
            </div>
          </button>

          {/* Global Threat Matrix Status */}
          <div className="hidden lg:flex items-center gap-3 pl-2 border-l border-slate-800">
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-700/60">
              <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span className="text-xs text-slate-400 font-mono">THREAT:</span>
              <span className={`text-xs font-mono font-bold uppercase ${
                threatLevel === 'CRITICAL' || emergencyActive ? 'text-rose-400 animate-pulse' :
                threatLevel === 'ELEVATED' ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {emergencyActive ? '🔴 LOCKDOWN' : threatLevel}
              </span>
            </div>
          </div>
        </div>

        {/* Right Controls & User Info */}
        <div className="flex items-center gap-1.5 sm:gap-3 shrink-0">
          {/* Reset / Reload Demo */}
          <button
            onClick={onResetSystem}
            title="Reset Simulation Metrics"
            className="hidden md:flex items-center gap-1 px-2.5 py-1.5 text-xs font-mono rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors"
          >
            <RefreshCw className="w-3 h-3 text-cyan-400" />
            <span>Reset</span>
          </button>

          {/* Emergency Defense Button */}
          <button
            onClick={() => {
              onEmergencyLockdown();
              threatAudio.playShieldBlock();
            }}
            className={`flex items-center gap-1 sm:gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg text-[11px] sm:text-xs font-mono font-semibold transition-all shadow-md ${
              emergencyActive 
                ? 'bg-rose-600 hover:bg-rose-500 text-white border border-rose-400 animate-pulse shadow-[0_0_15px_rgba(255,51,102,0.6)]' 
                : 'bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-700/50 hover:border-rose-500'
            }`}
          >
            <Lock className="w-3.5 h-3.5 shrink-0" />
            <span className="hidden xs:inline">{emergencyActive ? 'LOCKDOWN' : 'SHIELD'}</span>
          </button>

          {/* Audio Toggle */}
          <button
            onClick={() => {
              const nextState = !soundEnabled;
              setSoundEnabled(nextState);
              threatAudio.toggleSound(nextState);
              if (nextState) threatAudio.playScan();
            }}
            className="p-1.5 sm:p-2 rounded-lg bg-slate-900/80 border border-slate-700/60 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 transition-colors"
            title={soundEnabled ? 'Mute Cyber Audio' : 'Enable Cyber Audio'}
          >
            {soundEnabled ? <Volume2 className="w-4 h-4 text-cyan-400" /> : <VolumeX className="w-4 h-4 text-slate-500" />}
          </button>

          {/* User Profile & Logout Pill */}
          <div className="flex items-center gap-1.5 sm:gap-2 pl-1 sm:pl-2 border-l border-slate-800">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-semibold text-slate-200 flex items-center justify-end gap-1.5">
                <span className="truncate max-w-[120px]">{currentUser?.username || 'Admin'}</span>
                {currentUser?.twoFactorEnabled && (
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" title="2FA Protected" />
                )}
              </div>
              <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-medium inline-block ${roleMeta.color}`}>
                {roleMeta.name.split(' ')[0]}
              </span>
            </div>

            <button
              onClick={() => {
                if (onLogout) onLogout();
                threatAudio.playAlert();
              }}
              title="Lock & Exit to Login Portal"
              className="p-1.5 sm:p-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-slate-400 hover:text-rose-400 hover:border-rose-500/40 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>
    </>
  );
}
