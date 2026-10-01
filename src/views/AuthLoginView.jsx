import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Fingerprint, 
  KeyRound, 
  UserPlus, 
  LogIn, 
  QrCode, 
  Clock, 
  CheckCircle2, 
  AlertTriangle, 
  Eye, 
  EyeOff, 
  Copy, 
  Check, 
  Sparkles, 
  User,
  Zap,
  RefreshCw,
  Hash,
  Server,
  Wifi
} from 'lucide-react';
import { 
  evaluatePasswordStrength, 
  simulateCryptoHash, 
  generateTOTPCode, 
  RBAC_ROLES, 
  INITIAL_USER 
} from '../auth/authStore';
import { threatAudio } from '../components/ThreatAudio';
import { apiService } from '../services/apiService';

export default function AuthLoginView({ onLoginSuccess }) {
  const [mode, setMode] = useState('LOGIN'); // 'LOGIN' | 'REGISTER' | '2FA'
  const [showPassword, setShowPassword] = useState(false);
  const [serverStatus, setServerStatus] = useState({ online: false, latency: null });

  useEffect(() => {
    let isMounted = true;
    const probe = async () => {
      const status = await apiService.checkHealth();
      if (isMounted) setServerStatus(status);
    };
    probe();
    const interval = setInterval(probe, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Login form state
  const [loginUser, setLoginUser] = useState('Sentinel_Admin');
  const [loginPass, setLoginPass] = useState('CyberSecureAdmin2026!#');
  const [loginError, setLoginError] = useState('');
  const [failedAttempts, setFailedAttempts] = useState(0);

  // Registration form state
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState('SOC_COMMANDER');

  // 2FA state
  const [pendingUser, setPendingUser] = useState(INITIAL_USER);
  const [totpInput, setTotpInput] = useState('');
  const [generatedCode, setGeneratedCode] = useState(generateTOTPCode());
  const [copied, setCopied] = useState(false);
  const [totpError, setTotpError] = useState('');

  const passStrength = evaluatePasswordStrength(regPassword || loginPass);

  const handleLoginSubmit = (e) => {
    e.preventDefault();
    if (failedAttempts >= 3) {
      setLoginError('ACCOUNT LOCKED: Database Sentinel firewall locked access due to 3 failed attempts.');
      threatAudio.playShieldBlock();
      return;
    }

    if (loginPass.length >= 6) {
      setLoginError('');
      const user = {
        ...INITIAL_USER,
        username: loginUser,
        role: loginUser.toLowerCase().includes('hunter') ? 'THREAT_HUNTER' :
              loginUser.toLowerCase().includes('db') ? 'DB_ADMIN' : 'SOC_COMMANDER'
      };
      setPendingUser(user);
      setGeneratedCode(generateTOTPCode());
      threatAudio.playSuccess();
      setMode('2FA');
    } else {
      setFailedAttempts(failedAttempts + 1);
      setLoginError(`Invalid credentials. Attempt ${failedAttempts + 1}/3 before zero-trust firewall lockout.`);
      threatAudio.playAlert();
    }
  };

  const handleRegisterSubmit = (e) => {
    e.preventDefault();
    if (!regUsername || !regPassword) return;

    const newUser = {
      id: `usr_${Math.floor(100 + Math.random() * 900)}`,
      username: regUsername,
      email: regEmail || `${regUsername}@sentinel.sec`,
      role: regRole,
      twoFactorEnabled: true,
      totpSecret: 'JBSWY3DPEHPK3PXP',
      activeSessionToken: `sess_${Math.random().toString(36).substring(2, 12)}`,
      lastLogin: new Date().toUTCString(),
      loginIp: '192.168.1.105',
      passHash: simulateCryptoHash(regPassword),
      isLocked: false
    };

    setPendingUser(newUser);
    setGeneratedCode(generateTOTPCode());
    threatAudio.playSuccess();
    setMode('2FA');
  };

  const handleVerify2FA = (e) => {
    e.preventDefault();
    if (totpInput === generatedCode || totpInput.length === 6) {
      setTotpError('');
      threatAudio.playSuccess();
      onLoginSuccess(pendingUser);
    } else {
      setTotpError('Invalid 2FA authentication code. Please check your authenticator.');
      threatAudio.playAlert();
    }
  };

  const handleQuickDemoLogin = (roleKey = 'SOC_COMMANDER') => {
    const demoUser = {
      ...INITIAL_USER,
      role: roleKey,
      username: roleKey === 'SOC_COMMANDER' ? 'SOC_Commander_Lead' : 
                roleKey === 'THREAT_HUNTER' ? 'Senior_Threat_Hunter' : 'DB_Security_Admin'
    };
    threatAudio.playSuccess();
    onLoginSuccess(demoUser);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(generatedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background Cyber Glow & Grid Effects */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(0,242,254,0.08),transparent_50%),radial-gradient(circle_at_80%_80%,rgba(157,78,221,0.08),transparent_50%)] pointer-events-none"></div>
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:32px_32px] opacity-20 pointer-events-none"></div>

      {/* Main Login Card Container */}
      <div className="w-full max-w-md glass-panel-glow border-cyan-500/40 rounded-3xl p-6 sm:p-8 space-y-6 relative z-10 shadow-2xl">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/50 flex items-center justify-center text-cyan-400 mx-auto shadow-[0_0_20px_rgba(0,242,254,0.3)]">
            <ShieldAlert className="w-7 h-7 animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white font-display tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-400">
              CSTD SENTINEL AI
            </h1>
            <p className="text-xs font-mono text-slate-400">
              ZERO-TRUST CYBER SECURITY OPERATIONS PORTAL
            </p>
          </div>

          {/* Real Server Status Indicator */}
          <div className={`mx-auto inline-flex items-center gap-2 px-3 py-1 rounded-full text-[11px] font-mono border transition-all ${
            serverStatus.online
              ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.25)]'
              : 'bg-slate-950/80 border-slate-800 text-slate-400'
          }`}>
            <Server className={`w-3 h-3 ${serverStatus.online ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            <span className="font-bold">
              {serverStatus.online ? 'REAL SERVER ACTIVE (PORT 5000)' : 'STANDALONE LOCAL MODE'}
            </span>
            {serverStatus.latency != null && (
              <span className="text-[10px] text-emerald-400">({serverStatus.latency}ms)</span>
            )}
          </div>
        </div>

        {/* Mode Switcher Tabs (Login vs Register) */}
        {mode !== '2FA' && (
          <div className="grid grid-cols-2 p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono">
            <button
              onClick={() => {
                setMode('LOGIN');
                setLoginError('');
              }}
              className={`py-2 rounded-lg font-bold transition-all flex items-center justify-center gap-1.5 ${
                mode === 'LOGIN'
                  ? 'bg-cyan-500 text-slate-950 shadow-[0_0_12px_rgba(0,242,254,0.3)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>SECURE SIGN IN</span>
            </button>
            <button
              onClick={() => {
                setMode('REGISTER');
                setLoginError('');
              }}
              className={`py-2 rounded-lg font-bold transition-all flex items-center justify-center gap-1.5 ${
                mode === 'REGISTER'
                  ? 'bg-emerald-500 text-slate-950 shadow-[0_0_12px_rgba(0,245,160,0.3)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>CREATE ACCOUNT</span>
            </button>
          </div>
        )}

        {/* 1. SIGN IN FORM */}
        {mode === 'LOGIN' && (
          <form onSubmit={handleLoginSubmit} className="space-y-4 font-mono text-xs animate-in fade-in">
            <div>
              <label className="text-slate-400 block mb-1">USERNAME OR ANALYST ID</label>
              <input
                type="text"
                required
                value={loginUser}
                onChange={(e) => setLoginUser(e.target.value)}
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/60"
              />
            </div>

            <div>
              <div className="flex justify-between items-center text-slate-400 mb-1">
                <label>SECURITY PASSWORD</label>
                <span className="text-[10px] text-cyan-400">Encrypted</span>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={loginPass}
                  onChange={(e) => setLoginPass(e.target.value)}
                  className="w-full p-3 pr-10 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/60"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {loginError && (
              <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-500/60 text-rose-300 flex items-center gap-2 text-[11px]">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{loginError}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={failedAttempts >= 3}
              className="w-full py-3 rounded-xl font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,242,254,0.3)] transition-all disabled:opacity-50"
            >
              <Lock className="w-4 h-4" />
              <span>AUTHENTICATE & PROCEED TO 2FA</span>
            </button>

            {/* 1-Click Quick Demo Access */}
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <span className="text-[10px] text-slate-500 uppercase block text-center">
                OR 1-CLICK INSTANT DEMO ACCESS:
              </span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => handleQuickDemoLogin('SOC_COMMANDER')}
                  className="p-2 rounded-xl bg-cyan-950/50 hover:bg-cyan-900/60 border border-cyan-700/50 text-cyan-300 text-[11px] font-bold transition-colors"
                >
                  ⚡ SOC Commander
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickDemoLogin('THREAT_HUNTER')}
                  className="p-2 rounded-xl bg-purple-950/50 hover:bg-purple-900/60 border border-purple-700/50 text-purple-300 text-[11px] font-bold transition-colors"
                >
                  ⚡ Threat Hunter
                </button>
              </div>
            </div>
          </form>
        )}

        {/* 2. CREATE ACCOUNT / REGISTRATION FORM */}
        {mode === 'REGISTER' && (
          <form onSubmit={handleRegisterSubmit} className="space-y-4 font-mono text-xs animate-in fade-in">
            <div>
              <label className="text-slate-400 block mb-1">USERNAME</label>
              <input
                type="text"
                required
                placeholder="e.g. sec_officer_99"
                value={regUsername}
                onChange={(e) => setRegUsername(e.target.value)}
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-emerald-500/60"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">SOC EMAIL</label>
              <input
                type="email"
                placeholder="officer@sentinel.sec"
                value={regEmail}
                onChange={(e) => setRegEmail(e.target.value)}
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-emerald-500/60"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">ASSIGNED RBAC ROLE</label>
              <select
                value={regRole}
                onChange={(e) => setRegRole(e.target.value)}
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-bold focus:outline-none focus:border-emerald-500/60"
              >
                {Object.values(RBAC_ROLES).map((r) => (
                  <option key={r.id} value={r.id} className="bg-slate-900 text-slate-200">
                    {r.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Password with Real-Time Strength Meter */}
            <div className="space-y-2">
              <div className="flex justify-between items-center text-slate-400">
                <label>PASSWORD</label>
                <span className={`font-bold ${passStrength.color}`}>{passStrength.level} ({passStrength.entropy} bits)</span>
              </div>
              <input
                type="password"
                required
                placeholder="Minimum 10 characters..."
                value={regPassword}
                onChange={(e) => setRegPassword(e.target.value)}
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-emerald-500/60"
              />
              <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden border border-slate-800">
                <div
                  className={`h-full transition-all duration-300 ${passStrength.barColor}`}
                  style={{ width: `${Math.min((passStrength.entropy / 85) * 100, 100)}%` }}
                ></div>
              </div>
              <div className="text-[10px] text-slate-400 flex justify-between">
                <span>Brute-force crack resistance:</span>
                <span className="text-emerald-400 font-bold">{passStrength.crackTime}</span>
              </div>
            </div>

            <button
              type="submit"
              className="w-full py-3 rounded-xl font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,245,160,0.3)] transition-all"
            >
              <ShieldCheck className="w-4 h-4" />
              <span>REGISTER SAFE ACCOUNT & SETUP 2FA</span>
            </button>
          </form>
        )}

        {/* 3. 2FA / TOTP CODE CHALLENGE */}
        {mode === '2FA' && (
          <form onSubmit={handleVerify2FA} className="space-y-4 font-mono text-xs animate-in fade-in">
            <div className="text-center space-y-1">
              <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-400 flex items-center justify-center mx-auto">
                <KeyRound className="w-5 h-5 animate-pulse" />
              </div>
              <h2 className="text-sm font-bold text-white uppercase">2FA Authenticator Challenge</h2>
              <p className="text-[11px] text-slate-400">
                Account: <span className="text-cyan-300 font-bold">{pendingUser?.username}</span>
              </p>
            </div>

            {/* Simulated Authenticator OTP Code Badge */}
            <div className="p-3 rounded-xl bg-purple-950/40 border border-purple-700/50 flex items-center justify-between">
              <div className="flex items-center gap-2 text-purple-300">
                <Clock className="w-4 h-4 text-purple-400 animate-spin" />
                <span>CURRENT TIME-BASED OTP:</span>
                <span className="text-white font-bold tracking-widest bg-slate-900 px-2 py-0.5 rounded border border-purple-500/40 text-sm">
                  {generatedCode}
                </span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setTotpInput(generatedCode);
                  threatAudio.playScan();
                }}
                className="text-cyan-400 hover:text-cyan-300 text-[11px] underline font-bold"
              >
                Autofill
              </button>
            </div>

            <div>
              <label className="text-slate-400 block mb-1 text-center">ENTER 6-DIGIT VERIFICATION CODE</label>
              <input
                type="text"
                maxLength={6}
                required
                value={totpInput}
                onChange={(e) => setTotpInput(e.target.value)}
                placeholder="e.g. 849201"
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-center text-lg font-bold tracking-widest text-cyan-300 focus:outline-none focus:border-purple-500/60"
              />
            </div>

            {totpError && (
              <div className="p-2.5 rounded-xl bg-rose-950/60 border border-rose-500/60 text-rose-300 text-[11px] text-center">
                {totpError}
              </div>
            )}

            <button
              type="submit"
              className="w-full py-3 rounded-xl font-bold bg-purple-500 hover:bg-purple-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(157,78,221,0.3)] transition-all"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>VERIFY 2FA & ACCESS SOC PLATFORM</span>
            </button>

            <button
              type="button"
              onClick={() => setMode('LOGIN')}
              className="w-full text-center text-slate-500 hover:text-slate-300 text-[11px]"
            >
              ← Back to Sign In
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
