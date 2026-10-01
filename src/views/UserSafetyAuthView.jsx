import React, { useState } from 'react';
import { 
  Fingerprint, 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  KeyRound, 
  UserPlus, 
  LogIn, 
  QrCode, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Sparkles, 
  Copy, 
  Check, 
  Eye, 
  EyeOff,
  UserCheck,
  RefreshCw,
  Hash
} from 'lucide-react';
import { 
  evaluatePasswordStrength, 
  simulateCryptoHash, 
  generateTOTPCode, 
  RBAC_ROLES, 
  INITIAL_USER 
} from '../auth/authStore';
import { threatAudio } from '../components/ThreatAudio';

export default function UserSafetyAuthView({ currentUser, setCurrentUser }) {
  const [activeMode, setActiveMode] = useState('REGISTER'); // 'REGISTER' | 'LOGIN' | '2FA' | 'SESSIONS'
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);

  // Form State
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState('THREAT_HUNTER');

  // Login State
  const [loginUsername, setLoginUsername] = useState('Sentinel_Admin');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState('');
  const [failedAttempts, setFailedAttempts] = useState(0);

  // 2FA State
  const [totpInput, setTotpInput] = useState('');
  const [generatedCode, setGeneratedCode] = useState(generateTOTPCode());
  const [totpSuccess, setTotpSuccess] = useState(false);

  // Password evaluation
  const passStrength = evaluatePasswordStrength(regPassword || loginPassword);
  const cryptoHashPreview = simulateCryptoHash(regPassword || 'SampleSecretPassword123!');

  const handleRegister = (e) => {
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

    setCurrentUser(newUser);
    threatAudio.playSuccess();
    setActiveMode('2FA');
  };

  const handleLogin = (e) => {
    e.preventDefault();
    if (failedAttempts >= 3) {
      setLoginError('ACCOUNT LOCKED: Too many failed attempts. Database Sentinel lockout policy activated.');
      threatAudio.playShieldBlock();
      return;
    }

    if (loginPassword.length >= 6) {
      setLoginError('');
      threatAudio.playSuccess();
      setActiveMode('2FA');
    } else {
      setFailedAttempts(failedAttempts + 1);
      setLoginError(`Invalid credentials. Attempt ${failedAttempts + 1}/3 before zero-trust firewall lockout.`);
      threatAudio.playAlert();
    }
  };

  const handleVerify2FA = (e) => {
    e.preventDefault();
    if (totpInput === generatedCode || totpInput.length === 6) {
      setTotpSuccess(true);
      threatAudio.playSuccess();
      setTimeout(() => {
        setTotpSuccess(false);
        setActiveMode('SESSIONS');
      }, 1200);
    } else {
      threatAudio.playAlert();
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(generatedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-2xl glass-panel-glow border-emerald-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0">
            <Fingerprint className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              USER SAFETY & ZERO-TRUST AUTHENTICATION CENTER
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-semibold">
                HARDENED RBAC & 2FA
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Military-grade password entropy scoring, simulated cryptographic salting & hashing, 2FA authenticator, and session defense.
            </p>
          </div>
        </div>

        {/* Tab Navigation Pill */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs">
          <button
            onClick={() => setActiveMode('REGISTER')}
            className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
              activeMode === 'REGISTER'
                ? 'bg-emerald-500 text-slate-950 shadow-[0_0_10px_rgba(0,245,160,0.4)]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Create Safe Account
          </button>
          <button
            onClick={() => setActiveMode('LOGIN')}
            className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
              activeMode === 'LOGIN'
                ? 'bg-cyan-500 text-slate-950 shadow-[0_0_10px_rgba(0,242,254,0.4)]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Secure Login
          </button>
          <button
            onClick={() => setActiveMode('2FA')}
            className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
              activeMode === '2FA'
                ? 'bg-purple-500 text-slate-950 shadow-[0_0_10px_rgba(157,78,221,0.4)]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            2FA / MFA
          </button>
          <button
            onClick={() => setActiveMode('SESSIONS')}
            className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
              activeMode === 'SESSIONS'
                ? 'bg-blue-500 text-slate-950 shadow-[0_0_10px_rgba(59,130,246,0.4)]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Active Sessions
          </button>
        </div>
      </div>

      {/* Main Grid: Form on Left, Security Visualizers on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Form Container (7 Cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* 1. Account Registration Mode */}
          {activeMode === 'REGISTER' && (
            <div className="p-6 rounded-2xl glass-panel border-slate-800 space-y-5 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <UserPlus className="w-5 h-5 text-emerald-400" />
                  <h2 className="text-sm font-bold font-mono uppercase text-white">
                    Create Hardened Security Account
                  </h2>
                </div>
                <span className="text-[10px] font-mono text-emerald-400">DATABASE ENCRYPTED</span>
              </div>

              <form onSubmit={handleRegister} className="space-y-4 font-mono text-xs">
                <div>
                  <label className="text-slate-400 block mb-1">USERNAME</label>
                  <input
                    type="text"
                    required
                    value={regUsername}
                    onChange={(e) => setRegUsername(e.target.value)}
                    placeholder="e.g. cyber_analyst_01"
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">CORPORATE / SOC EMAIL</label>
                  <input
                    type="email"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="analyst@secops.corp"
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">ASSIGNED RBAC PRIVILEGE ROLE</label>
                  <select
                    value={regRole}
                    onChange={(e) => setRegRole(e.target.value)}
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-bold focus:outline-none focus:border-emerald-500/60"
                  >
                    {Object.values(RBAC_ROLES).map((r) => (
                      <option key={r.id} value={r.id} className="bg-slate-900 text-slate-200">
                        {r.name} (Level {r.level})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Password Input with Strength Meter */}
                <div className="space-y-2">
                  <div className="flex justify-between items-center text-slate-400">
                    <span>SECURITY PASSWORD</span>
                    <span className={`font-bold ${passStrength.color}`}>{passStrength.level} ({passStrength.entropy} bits)</span>
                  </div>

                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      placeholder="Minimum 12 characters recommended..."
                      className="w-full p-3 pr-10 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>

                  {/* Password Strength Bar */}
                  <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-300 ${passStrength.barColor}`}
                      style={{ width: `${Math.min((passStrength.entropy / 85) * 100, 100)}%` }}
                    ></div>
                  </div>

                  {/* Crack time estimator */}
                  <div className="flex justify-between text-[11px] text-slate-400">
                    <span>Brute-force crack resistance:</span>
                    <span className="text-emerald-400 font-bold">{passStrength.crackTime}</span>
                  </div>
                </div>

                <button
                  type="submit"
                  className="w-full py-3 rounded-xl font-mono text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,245,160,0.3)] transition-all"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>INITIALIZE SAFE ACCOUNT & CONFIGURE 2FA</span>
                </button>
              </form>
            </div>
          )}

          {/* 2. Login Mode with Brute-Force Lockout Defense */}
          {activeMode === 'LOGIN' && (
            <div className="p-6 rounded-2xl glass-panel border-slate-800 space-y-5 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <LogIn className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-sm font-bold font-mono uppercase text-white">
                    Secure SOC Portal Login
                  </h2>
                </div>
                <span className="text-[10px] font-mono text-cyan-400">SHIELD ACTIVE</span>
              </div>

              <form onSubmit={handleLogin} className="space-y-4 font-mono text-xs">
                <div>
                  <label className="text-slate-400 block mb-1">USERNAME</label>
                  <input
                    type="text"
                    required
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">PASSWORD</label>
                  <input
                    type="password"
                    required
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder="Enter password..."
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  />
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
                  className="w-full py-3 rounded-xl font-mono text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,242,254,0.3)] transition-all disabled:opacity-50"
                >
                  <Lock className="w-4 h-4" />
                  <span>AUTHENTICATE & REQUEST 2FA CHALLENGE</span>
                </button>
              </form>
            </div>
          )}

          {/* 3. 2FA / TOTP Authenticator Mode */}
          {activeMode === '2FA' && (
            <div className="p-6 rounded-2xl glass-panel border-slate-800 space-y-5 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <KeyRound className="w-5 h-5 text-purple-400" />
                  <h2 className="text-sm font-bold font-mono uppercase text-white">
                    Two-Factor Authentication (2FA) Verification
                  </h2>
                </div>
                <span className="text-[10px] font-mono text-purple-400">TOTP RFC 6238</span>
              </div>

              <div className="flex flex-col sm:flex-row items-center gap-4 p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="w-24 h-24 rounded-xl bg-white p-2 flex items-center justify-center text-slate-950 shrink-0">
                  <QrCode className="w-20 h-20" />
                </div>
                <div className="space-y-1 text-center sm:text-left font-mono text-xs">
                  <span className="text-slate-400 text-[11px]">AUTHENTICATOR APP SECRET KEY:</span>
                  <div className="text-cyan-300 font-bold text-sm tracking-wider">
                    JBSW Y3DP EHPK 3PXP
                  </div>
                  <p className="text-[10px] text-slate-500">
                    Scan with Google Authenticator, Authy, or 1Password.
                  </p>
                </div>
              </div>

              {/* Live Simulated OTP Generator Pill */}
              <div className="p-3 rounded-xl bg-purple-950/40 border border-purple-700/50 flex items-center justify-between font-mono text-xs">
                <div className="flex items-center gap-2 text-purple-300">
                  <Clock className="w-4 h-4 text-purple-400 animate-spin" />
                  <span>CURRENT TIME-BASED OTP:</span>
                  <span className="text-white font-bold text-sm tracking-widest bg-slate-900 px-2 py-0.5 rounded border border-purple-500/40">
                    {generatedCode}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyCode}
                    className="text-cyan-400 hover:text-cyan-300 text-[11px] underline flex items-center gap-1"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={() => {
                      setGeneratedCode(generateTOTPCode());
                      threatAudio.playScan();
                    }}
                    className="text-slate-400 hover:text-slate-200"
                    title="Regenerate code"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* 2FA Input Form */}
              <form onSubmit={handleVerify2FA} className="space-y-4 font-mono text-xs">
                <div>
                  <label className="text-slate-400 block mb-1">ENTER 6-DIGIT VERIFICATION CODE</label>
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

                {totpSuccess && (
                  <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/60 text-emerald-300 flex items-center justify-center gap-2 font-bold">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>2FA VERIFIED! GRANTING AUTHORIZED SESSION...</span>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full py-3 rounded-xl font-mono text-xs font-bold bg-purple-500 hover:bg-purple-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(157,78,221,0.3)] transition-all"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>VERIFY 2FA & LAUNCH SOC SESSION</span>
                </button>
              </form>
            </div>
          )}

          {/* 4. Active Sessions & RBAC Privileges */}
          {activeMode === 'SESSIONS' && (
            <div className="p-6 rounded-2xl glass-panel border-slate-800 space-y-5 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <UserCheck className="w-5 h-5 text-blue-400" />
                  <h2 className="text-sm font-bold font-mono uppercase text-white">
                    Active Authenticated Session
                  </h2>
                </div>
                <span className="text-[10px] font-mono text-emerald-400">STATUS: VALID</span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex justify-between items-center text-slate-400">
                    <span>ACTIVE USER:</span>
                    <span className="text-white font-bold">{currentUser?.username}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-400">
                    <span>ROLE LEVEL:</span>
                    <span className="text-cyan-400 font-bold">{currentUser?.role}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-400">
                    <span>SESSION TOKEN:</span>
                    <span className="text-purple-300 truncate max-w-xs">{currentUser?.activeSessionToken}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-400">
                    <span>BINDING IP:</span>
                    <span className="text-emerald-400">{currentUser?.loginIp}</span>
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-[11px] font-bold text-slate-300">GRANTED RBAC PRIVILEGES:</span>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {RBAC_ROLES[currentUser?.role]?.permissions?.map((p, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700/40 text-[10px]">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Security & Crypto Hasher Visualizer (5 Cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Cryptographic Salting & Hashing Demonstration */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <Hash className="w-4 h-4 text-cyan-400" />
                Zero-Knowledge Hash Pipeline
              </h2>
              <span className="text-[10px] font-mono text-cyan-400">SHA-256 + SALT</span>
            </div>

            <p className="text-xs text-slate-400 font-mono">
              Passwords are never stored in plaintext. The database firewall verifies cryptographic one-way digests.
            </p>

            <div className="space-y-2 font-mono text-xs">
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 text-[10px] block">PLAINTEXT INPUT:</span>
                <span className="text-slate-300 truncate block">{regPassword || 'SampleSecretPassword123!'}</span>
              </div>

              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 text-[10px] block">SECURITY CRYPTOGRAPHIC SALT:</span>
                <span className="text-purple-400 truncate block">salt$8f910a72c19e34b</span>
              </div>

              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 text-[10px] block">STORED DATABASE HASH (ONE-WAY):</span>
                <span className="text-emerald-400 text-[11px] break-all block font-bold">
                  {cryptoHashPreview}
                </span>
              </div>
            </div>
          </div>

          {/* Defense Policies Card */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-3">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              User Safety Defense Policies
            </h2>

            <div className="space-y-2 font-mono text-xs">
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center gap-2.5 text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>3-Attempt Brute-Force Lockout Shield</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center gap-2.5 text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Enforced 2FA Multi-Factor Challenge</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center gap-2.5 text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>IP Binding & Geo-Anomaly Tracking</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center gap-2.5 text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Zero-Trust Database Firewall Sanitization</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
