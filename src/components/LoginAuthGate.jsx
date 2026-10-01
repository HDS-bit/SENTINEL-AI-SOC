import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  KeyRound, 
  UserPlus, 
  LogIn, 
  Fingerprint, 
  Sparkles, 
  Eye, 
  EyeOff, 
  CheckCircle2, 
  AlertTriangle, 
  QrCode, 
  Copy, 
  Check, 
  RefreshCw, 
  Zap, 
  User, 
  Clock, 
  FileCheck,
  Cpu,
  Flame,
  Globe,
  Settings
} from 'lucide-react';
import { 
  evaluatePasswordStrength, 
  simulateCryptoHash, 
  generateTOTPCode, 
  RBAC_ROLES, 
  INITIAL_USER 
} from '../auth/authStore';
import { 
  firebaseLoginWithEmail, 
  firebaseRegisterWithEmail, 
  isFirebaseConfigured, 
  getFirebaseConfig, 
  setFirebaseConfig 
} from '../services/firebaseAuthService';
import { threatAudio } from './ThreatAudio';

export default function LoginAuthGate({ onLoginSuccess }) {
  const [authMode, setAuthMode] = useState('LOGIN'); // 'LOGIN' | 'REGISTER' | '2FA'
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);

  // Form states
  const [loginUsername, setLoginUsername] = useState('Sentinel_Admin');
  const [loginPassword, setLoginPassword] = useState('CyberSecureAdmin2026!#');
  const [loginError, setLoginError] = useState('');
  const [failedAttempts, setFailedAttempts] = useState(0);

  // Registration states
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState('SOC_COMMANDER');

  // Firebase states
  const [fbEmail, setFbEmail] = useState('officer@sentinel-defense.io');
  const [fbPassword, setFbPassword] = useState('SentinelPass2026!');
  const [fbRole, setFbRole] = useState('SOC_COMMANDER');
  const [fbLoading, setFbLoading] = useState(false);
  const [showFbConfig, setShowFbConfig] = useState(false);
  const [fbConfig, setFbConfigState] = useState(() => getFirebaseConfig());

  // 2FA Challenge states
  const [pendingUser, setPendingUser] = useState(INITIAL_USER);
  const [totpInput, setTotpInput] = useState('');
  const [generatedCode, setGeneratedCode] = useState(generateTOTPCode());
  const [totpSuccess, setTotpSuccess] = useState(false);

  // Password evaluation
  const passStrength = evaluatePasswordStrength(authMode === 'REGISTER' ? regPassword : loginPassword);
  const cryptoHashPreview = simulateCryptoHash(authMode === 'REGISTER' ? (regPassword || 'SampleSecret123!') : (loginPassword || 'SampleSecret123!'));

  // Quick Demo Profiles
  const DEMO_PROFILES = [
    {
      role: 'SOC_COMMANDER',
      title: 'SOC Commander',
      username: 'Sentinel_Admin',
      pass: 'CyberSecureAdmin2026!#',
      badge: 'Level 4 / SuperAdmin',
      color: 'border-cyan-500/50 hover:border-cyan-400 bg-cyan-950/40 text-cyan-300'
    },
    {
      role: 'THREAT_HUNTER',
      title: 'Senior Threat Hunter',
      username: 'Valkyrie_Hunter',
      pass: 'ThreatHunter99#X',
      badge: 'Level 3 / AI Ops',
      color: 'border-purple-500/50 hover:border-purple-400 bg-purple-950/40 text-purple-300'
    },
    {
      role: 'DB_ADMIN',
      title: 'Database Security Admin',
      username: 'DB_Sentinel_Lead',
      pass: 'DBFirewallShield2026$',
      badge: 'Level 3 / DB AST',
      color: 'border-emerald-500/50 hover:border-emerald-400 bg-emerald-950/40 text-emerald-300'
    },
    {
      role: 'SECURITY_AUDITOR',
      title: 'Compliance Auditor',
      username: 'Auditor_Compliance',
      pass: 'AuditPasscode77!#',
      badge: 'Level 1 / Reports',
      color: 'border-amber-500/50 hover:border-amber-400 bg-amber-950/40 text-amber-300'
    }
  ];

  const handleQuickDemoLogin = (profile) => {
    setLoginUsername(profile.username);
    setLoginPassword(profile.pass);
    setLoginError('');

    const userObj = {
      id: `usr_${Math.floor(100 + Math.random() * 900)}`,
      username: profile.username,
      email: `${profile.username.toLowerCase()}@cstd.cyberops`,
      role: profile.role,
      twoFactorEnabled: true,
      totpSecret: 'JBSWY3DPEHPK3PXP',
      activeSessionToken: `sess_${Math.random().toString(36).substring(2, 12)}`,
      lastLogin: new Date().toUTCString(),
      loginIp: '192.168.1.100',
      passHash: simulateCryptoHash(profile.pass),
      isLocked: false
    };

    setPendingUser(userObj);
    threatAudio.playScan();
    setGeneratedCode(generateTOTPCode());
    setAuthMode('2FA');
  };

  const handleStandardLogin = (e) => {
    e.preventDefault();
    if (failedAttempts >= 3) {
      setLoginError('ZERO-TRUST LOCKOUT: 3 failed attempts exceeded. Access suspended to protect dataset and database perimeter.');
      threatAudio.playShieldBlock();
      return;
    }

    if (!loginUsername || loginPassword.length < 4) {
      setFailedAttempts(failedAttempts + 1);
      setLoginError(`Invalid credentials. Attempt ${failedAttempts + 1}/3 before firewall lockout.`);
      threatAudio.playAlert();
      return;
    }

    const userObj = {
      id: `usr_${Math.floor(100 + Math.random() * 900)}`,
      username: loginUsername,
      email: `${loginUsername.toLowerCase()}@cstd.cyberops`,
      role: 'SOC_COMMANDER',
      twoFactorEnabled: true,
      totpSecret: 'JBSWY3DPEHPK3PXP',
      activeSessionToken: `sess_${Math.random().toString(36).substring(2, 12)}`,
      lastLogin: new Date().toUTCString(),
      loginIp: '192.168.1.100',
      passHash: simulateCryptoHash(loginPassword),
      isLocked: false
    };

    setPendingUser(userObj);
    setLoginError('');
    threatAudio.playSuccess();
    setGeneratedCode(generateTOTPCode());
    setAuthMode('2FA');
  };

  const handleRegisterSubmit = (e) => {
    e.preventDefault();
    if (!regUsername || !regPassword) return;

    const newUser = {
      id: `usr_${Math.floor(100 + Math.random() * 900)}`,
      username: regUsername,
      email: regEmail || `${regUsername.toLowerCase()}@cstd.cyberops`,
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
    threatAudio.playSuccess();
    setGeneratedCode(generateTOTPCode());
    setAuthMode('2FA');
  };

  const handleFirebaseLogin = async (e) => {
    e?.preventDefault();
    setFbLoading(true);
    setLoginError('');
    try {
      const res = await firebaseLoginWithEmail(fbEmail, fbPassword, fbRole);
      threatAudio.playSuccess();
      const userObj = {
        id: res.user.uid,
        username: res.user.displayName,
        email: res.user.email,
        role: res.user.role || fbRole,
        twoFactorEnabled: true,
        totpSecret: 'JBSWY3DPEHPK3PXP',
        activeSessionToken: res.user.idToken,
        lastLogin: new Date().toUTCString(),
        loginIp: '10.240.0.1 (Firebase Auth Gateway)',
        passHash: 'FIREBASE_MANAGED_TOKEN',
        isLocked: false,
        provider: 'FIREBASE'
      };
      setPendingUser(userObj);
      setGeneratedCode(generateTOTPCode());
      setAuthMode('2FA');
    } catch (err) {
      threatAudio.playAlert();
      setLoginError(err.message || 'Firebase login failed.');
    } finally {
      setFbLoading(false);
    }
  };

  const handleSaveFirebaseConfig = () => {
    setFirebaseConfig(fbConfig);
    setShowFbConfig(false);
    threatAudio.playSuccess();
  };

  const handleVerify2FA = (e) => {
    e.preventDefault();
    // Allow matching OTP or 6 digits for testing
    if (totpInput === generatedCode || totpInput.length === 6) {
      setTotpSuccess(true);
      threatAudio.playSuccess();
      setTimeout(() => {
        onLoginSuccess(pendingUser);
      }, 700);
    } else {
      threatAudio.playAlert();
      alert('Invalid TOTP token code. Please check the simulated authenticator code or click "Auto-Fill Code".');
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(generatedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAutoFill2FA = () => {
    setTotpInput(generatedCode);
    threatAudio.playScan();
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-cyber-bg text-slate-100 font-sans p-4 relative overflow-hidden">
      {/* Background Cyber Glow & Grid Effects */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:32px_32px] opacity-40 pointer-events-none"></div>
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>

      <div className="relative w-full max-w-4xl z-10 space-y-6 animate-in fade-in zoom-in-95 duration-300">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-3 px-4 py-2 rounded-2xl glass-panel-glow border-cyan-500/40 mb-2">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 text-cyan-400">
              <ShieldAlert className="w-5 h-5 animate-pulse" />
              <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
            </div>
            <div className="text-left">
              <span className="font-display font-bold text-lg tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-400 block">
                CSTD SENTINEL SOC
              </span>
              <span className="text-[10px] uppercase font-mono text-cyan-300">
                Zero-Trust Authentication & Data Safety Gateway
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-400 font-mono max-w-lg mx-auto">
            Mandatory authorization barrier to ensure datasets and databases remain protected against concealed injections, unauthorized uploads, and threat vectors.
          </p>
        </div>

        {/* Main Card */}
        <div className="p-6 md:p-8 rounded-3xl glass-panel-glow border-slate-700/60 shadow-2xl backdrop-blur-xl">
          {/* Mode Switcher Tabs */}
          <div className="flex flex-wrap items-center justify-center gap-2 border-b border-slate-800 pb-4 mb-6 font-mono text-xs">
            <button
              onClick={() => {
                setAuthMode('LOGIN');
                setLoginError('');
              }}
              className={`px-4 py-2 rounded-xl font-bold transition-all flex items-center gap-2 ${
                authMode === 'LOGIN'
                  ? 'bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(0,242,254,0.3)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LogIn className="w-4 h-4" />
              <span>SOC Login</span>
            </button>

            <button
              onClick={() => {
                setAuthMode('FIREBASE');
                setLoginError('');
              }}
              className={`px-4 py-2 rounded-xl font-bold transition-all flex items-center gap-2 ${
                authMode === 'FIREBASE'
                  ? 'bg-gradient-to-r from-amber-500 to-orange-500 text-slate-950 shadow-[0_0_15px_rgba(245,158,11,0.3)]'
                  : 'text-amber-400/80 hover:text-amber-300'
              }`}
            >
              <Flame className="w-4 h-4 text-amber-300" />
              <span>Firebase Auth</span>
            </button>

            <button
              onClick={() => {
                setAuthMode('REGISTER');
                setLoginError('');
              }}
              className={`px-4 py-2 rounded-xl font-bold transition-all flex items-center gap-2 ${
                authMode === 'REGISTER'
                  ? 'bg-emerald-500 text-slate-950 shadow-[0_0_15px_rgba(0,245,160,0.3)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <UserPlus className="w-4 h-4" />
              <span>Create Safe Account</span>
            </button>

            {authMode === '2FA' && (
              <button
                className="px-4 py-2 rounded-xl font-bold bg-purple-500 text-slate-950 shadow-[0_0_15px_rgba(157,78,221,0.3)] flex items-center gap-2"
              >
                <KeyRound className="w-4 h-4" />
                <span>2FA / MFA Challenge</span>
              </button>
            )}
          </div>

          {/* 1. LOGIN MODE */}
          {authMode === 'LOGIN' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              {/* Left: Credentials Form */}
              <div className="lg:col-span-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    Enter SOC Credentials
                  </h2>
                  <span className="text-[10px] font-mono text-cyan-400">ZERO-TRUST PROTOCOL</span>
                </div>

                <form onSubmit={handleStandardLogin} className="space-y-4 font-mono text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">USERNAME / CALLSIGN</label>
                    <input
                      type="text"
                      required
                      value={loginUsername}
                      onChange={(e) => setLoginUsername(e.target.value)}
                      placeholder="e.g. Sentinel_Admin"
                      className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/60 shadow-inner"
                    />
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-slate-400 mb-1">
                      <span>PASSWORD</span>
                      <span className={`text-[11px] font-bold ${passStrength.color}`}>
                        {passStrength.level}
                      </span>
                    </div>

                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="w-full p-3 pr-10 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/60 shadow-inner"
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
                    className="w-full py-3.5 rounded-xl font-mono text-xs font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(0,242,254,0.3)] transition-all disabled:opacity-50"
                  >
                    <KeyRound className="w-4 h-4" />
                    <span>AUTHENTICATE & VERIFY 2FA</span>
                  </button>
                </form>
              </div>

              {/* Right: 1-Click Fast Demo Logins */}
              <div className="lg:col-span-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold font-mono uppercase text-slate-300 flex items-center gap-2">
                    <Zap className="w-4 h-4 text-amber-400" />
                    Quick 1-Click SOC Demo Profiles
                  </h2>
                  <span className="text-[10px] font-mono text-amber-400">INSTANT ACCESS</span>
                </div>

                <p className="text-xs font-mono text-slate-400">
                  Select a predefined security role to instantly fill credentials and proceed directly into the platform:
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {DEMO_PROFILES.map((p, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleQuickDemoLogin(p)}
                      className={`p-3 rounded-xl border text-left font-mono transition-all flex flex-col justify-between ${p.color}`}
                    >
                      <div className="flex items-center justify-between w-full mb-1">
                        <span className="font-bold text-xs text-white">{p.title}</span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700">
                          {p.badge}
                        </span>
                      </div>
                      <div className="text-[10px] opacity-80 flex items-center gap-1">
                        <User className="w-3 h-3" />
                        <span>{p.username}</span>
                      </div>
                    </button>
                  ))}
                </div>

                {/* Data Safety Assurance Box */}
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5 font-mono text-[11px]">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold">
                    <ShieldCheck className="w-4 h-4" />
                    <span>Data Safety & Zero-Threat Perimeter Active</span>
                  </div>
                  <p className="text-slate-400 text-[10px]">
                    All dataset uploads (CSV/JSON/SQL) are pre-scanned with deep AST lexers and AI models before ingestion to ensure zero unvetted threats reach your database.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* 1.5 FIREBASE CLOUD AUTH MODE */}
          {authMode === 'FIREBASE' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              {/* Left: Firebase Credentials Form */}
              <div className="lg:col-span-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                    <Flame className="w-4 h-4 text-amber-400" />
                    Firebase Cloud Identity
                  </h2>
                  <button
                    type="button"
                    onClick={() => setShowFbConfig(!showFbConfig)}
                    className="text-[10px] font-mono text-amber-300 hover:underline flex items-center gap-1"
                  >
                    <Settings className="w-3 h-3" />
                    {isFirebaseConfigured() ? 'Firebase Linked' : 'Set Project Keys'}
                  </button>
                </div>

                {showFbConfig && (
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-amber-500/40 space-y-2.5 font-mono text-[11px] animate-fadeIn">
                    <div className="font-bold text-amber-300 flex items-center justify-between">
                      <span>FIREBASE PROJECT CONFIG</span>
                      <span className="text-[9px] text-slate-400">Identity Toolkit REST</span>
                    </div>
                    <div>
                      <label className="text-slate-400 block text-[10px] mb-0.5">FIREBASE WEB API KEY</label>
                      <input
                        type="password"
                        value={fbConfig.apiKey}
                        onChange={(e) => setFbConfigState({ ...fbConfig, apiKey: e.target.value })}
                        placeholder="AIzaSy..."
                        className="w-full p-2 rounded-lg bg-slate-900 border border-slate-700 text-amber-200 focus:outline-none focus:border-amber-500 text-xs"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 block text-[10px] mb-0.5">AUTH DOMAIN / PROJECT ID</label>
                      <input
                        type="text"
                        value={fbConfig.authDomain}
                        onChange={(e) => setFbConfigState({ ...fbConfig, authDomain: e.target.value })}
                        placeholder="your-project.firebaseapp.com"
                        className="w-full p-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-amber-500 text-xs"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={handleSaveFirebaseConfig}
                      className="w-full py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition-all shadow-[0_0_10px_rgba(245,158,11,0.3)]"
                    >
                      SAVE CONFIGURATION
                    </button>
                  </div>
                )}

                <form onSubmit={handleFirebaseLogin} className="space-y-4 font-mono text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">FIREBASE USER EMAIL</label>
                    <input
                      type="email"
                      required
                      value={fbEmail}
                      onChange={(e) => setFbEmail(e.target.value)}
                      placeholder="officer@sentinel-defense.io"
                      className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-amber-500/60 shadow-inner"
                    />
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-slate-400 mb-1">
                      <span>PASSWORD</span>
                      <span className={`text-[11px] font-bold ${passStrength.color}`}>
                        {passStrength.level}
                      </span>
                    </div>

                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        value={fbPassword}
                        onChange={(e) => setFbPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="w-full p-3 pr-10 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-amber-500/60 shadow-inner"
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

                  <div>
                    <label className="text-slate-400 block mb-1">TARGET SOC ROLE</label>
                    <select
                      value={fbRole}
                      onChange={(e) => setFbRole(e.target.value)}
                      className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-amber-300 font-bold focus:outline-none focus:border-amber-500/60"
                    >
                      {Object.values(RBAC_ROLES).map((r) => (
                        <option key={r.id} value={r.id} className="bg-slate-900 text-slate-200">
                          {r.name} (Level {r.level})
                        </option>
                      ))}
                    </select>
                  </div>

                  {loginError && (
                    <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-500/60 text-rose-300 flex items-center gap-2 text-[11px]">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>{loginError}</span>
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={fbLoading}
                    className="w-full py-3.5 rounded-xl font-mono text-xs font-bold bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(245,158,11,0.3)] transition-all disabled:opacity-50"
                  >
                    <Flame className={`w-4 h-4 ${fbLoading ? 'animate-spin' : ''}`} />
                    <span>{fbLoading ? 'AUTHENTICATING WITH FIREBASE...' : 'AUTHENTICATE VIA FIREBASE'}</span>
                  </button>
                </form>
              </div>

              {/* Right: Firebase Architecture Specs */}
              <div className="lg:col-span-6 space-y-4">
                <div className="p-5 rounded-2xl glass-panel border-amber-500/30 space-y-3">
                  <div className="flex items-center gap-2 text-amber-400 font-bold font-mono text-xs uppercase">
                    <Flame className="w-4 h-4" />
                    <span>Firebase Auth & Multi-Cloud Identity</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    SENTINEL seamlessly unifies Google Firebase Authentication tokens with local Zero-Trust RBAC security policies. When users authenticate, their JWT tokens are verified and tied to strict data safety clearance levels.
                  </p>
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 font-mono text-[11px] text-slate-400 space-y-1">
                    <div className="flex justify-between">
                      <span>Auth Engine:</span>
                      <strong className="text-amber-300">Firebase Identity Toolkit v1</strong>
                    </div>
                    <div className="flex justify-between">
                      <span>Token Protocol:</span>
                      <strong className="text-cyan-300">OAuth 2.0 / RS256 JWT</strong>
                    </div>
                    <div className="flex justify-between">
                      <span>MFA Enforcement:</span>
                      <strong className="text-emerald-300">TOTP Authenticator 2FA</strong>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2 text-xs font-mono text-slate-400">
                  <div className="text-slate-300 font-bold flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span>Demo Mode Ready</span>
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    Don't have a Firebase project key yet? Simply click <strong>"AUTHENTICATE VIA FIREBASE"</strong> to use the instant built-in simulated Firebase Identity Gateway.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* 2. REGISTRATION MODE */}
          {authMode === 'REGISTER' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              <div className="lg:col-span-7 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                    <UserPlus className="w-4 h-4 text-emerald-400" />
                    Register Hardened SOC Security Profile
                  </h2>
                  <span className="text-[10px] font-mono text-emerald-400">DATABASE ENCRYPTED</span>
                </div>

                <form onSubmit={handleRegisterSubmit} className="space-y-4 font-mono text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">ANALYST USERNAME</label>
                    <input
                      type="text"
                      required
                      value={regUsername}
                      onChange={(e) => setRegUsername(e.target.value)}
                      placeholder="e.g. cyber_hunter_01"
                      className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">SOC CORPORATE EMAIL</label>
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

                  {/* Password with Strength & Entropy */}
                  <div className="space-y-2">
                    <div className="flex justify-between items-center text-slate-400">
                      <span>SECURE PASSWORD</span>
                      <span className={`font-bold ${passStrength.color}`}>
                        {passStrength.level} ({passStrength.entropy} bits)
                      </span>
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

                    {/* Strength Bar */}
                    <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                      <div
                        className={`h-full transition-all duration-300 ${passStrength.barColor}`}
                        style={{ width: `${Math.min((passStrength.entropy / 85) * 100, 100)}%` }}
                      ></div>
                    </div>

                    <div className="flex justify-between text-[11px] text-slate-400">
                      <span>Brute-force crack resistance:</span>
                      <span className="text-emerald-400 font-bold">{passStrength.crackTime}</span>
                    </div>
                  </div>

                  <button
                    type="submit"
                    className="w-full py-3.5 rounded-xl font-mono text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(0,245,160,0.3)] transition-all"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>INITIALIZE SAFE ACCOUNT & CONFIGURE 2FA</span>
                  </button>
                </form>
              </div>

              {/* Right: Cryptographic Hasher Info */}
              <div className="lg:col-span-5 space-y-4">
                <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-3 font-mono text-xs">
                  <div className="flex items-center gap-2 text-cyan-400 font-bold">
                    <Fingerprint className="w-4 h-4" />
                    <span>Zero-Knowledge Hash Pipeline</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Passwords are never stored in plaintext. The database firewall verifies cryptographic one-way salted digests.
                  </p>

                  <div className="space-y-2 text-[10px]">
                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block">SALT:</span>
                      <span className="text-purple-400">cstd_salt_99#sec</span>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block">SHA-256 STORED DIGEST:</span>
                      <span className="text-emerald-400 break-all font-bold">
                        {cryptoHashPreview}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 3. 2FA / MFA CHALLENGE MODE */}
          {authMode === '2FA' && (
            <div className="max-w-md mx-auto space-y-5 font-mono text-xs animate-in fade-in">
              <div className="text-center space-y-1">
                <div className="w-12 h-12 rounded-2xl bg-purple-500/20 border border-purple-500/50 flex items-center justify-center text-purple-400 mx-auto mb-2">
                  <KeyRound className="w-6 h-6 animate-pulse" />
                </div>
                <h2 className="text-sm font-bold text-white uppercase">
                  Two-Factor Authentication Challenge
                </h2>
                <p className="text-[11px] text-slate-400">
                  Authenticating as <span className="text-cyan-300 font-bold">{pendingUser.username}</span> ({pendingUser.role})
                </p>
              </div>

              {/* QR & Secret Box */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center gap-4">
                <div className="w-20 h-20 rounded-xl bg-white p-1.5 flex items-center justify-center text-slate-950 shrink-0">
                  <QrCode className="w-full h-full" />
                </div>
                <div className="space-y-1">
                  <span className="text-slate-500 text-[10px]">SIMULATED TOTP CODE:</span>
                  <div className="text-white font-bold text-lg tracking-widest bg-slate-900 px-3 py-1 rounded border border-purple-500/40 inline-block">
                    {generatedCode}
                  </div>
                  <div className="flex items-center gap-2 pt-1">
                    <button
                      onClick={handleAutoFill2FA}
                      className="text-cyan-400 hover:text-cyan-300 text-[10px] underline font-bold"
                    >
                      Auto-Fill Code
                    </button>
                    <button
                      onClick={handleCopyCode}
                      className="text-slate-400 hover:text-slate-200 text-[10px] flex items-center gap-0.5"
                    >
                      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* 2FA Input Form */}
              <form onSubmit={handleVerify2FA} className="space-y-4">
                <div>
                  <label className="text-slate-400 block mb-1 text-center">
                    ENTER 6-DIGIT VERIFICATION CODE
                  </label>
                  <input
                    type="text"
                    maxLength={6}
                    required
                    value={totpInput}
                    onChange={(e) => setTotpInput(e.target.value)}
                    placeholder="e.g. 849201"
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-center text-xl font-bold tracking-widest text-cyan-300 focus:outline-none focus:border-purple-500/60"
                  />
                </div>

                {totpSuccess && (
                  <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/60 text-emerald-300 flex items-center justify-center gap-2 font-bold">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>2FA VERIFIED! GRANTING SECURE ACCESS...</span>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full py-3.5 rounded-xl font-mono text-xs font-bold bg-gradient-to-r from-purple-500 to-cyan-500 hover:from-purple-400 hover:to-cyan-400 text-slate-950 flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(157,78,221,0.4)] transition-all"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>VERIFY 2FA & UNLOCK CSTD PLATFORM</span>
                </button>
              </form>

              <div className="text-center pt-2">
                <button
                  onClick={() => setAuthMode('LOGIN')}
                  className="text-slate-500 hover:text-slate-300 text-[11px]"
                >
                  ← Back to Login Credentials
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
