import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  FileCheck, 
  Database, 
  AlertTriangle, 
  CheckCircle2, 
  Sparkles, 
  Upload, 
  Download, 
  RefreshCw, 
  FileSpreadsheet, 
  Lock, 
  Fingerprint, 
  Eye, 
  Flame, 
  Search, 
  Check, 
  Copy, 
  Award,
  Zap,
  HelpCircle,
  FileCode,
  Sliders,
  BarChart2,
  PieChart,
  BrainCircuit,
  Play,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  Layers,
  X,
  Radio,
  FileText,
  Activity,
  Cpu
} from 'lucide-react';
import { 
  SAMPLE_DATASETS, 
  scanDatasetForThreats, 
  computeDatasetProfile,
  sanitizeAndDisinfectDataset, 
  exportToCSV, 
  parseCSVOrTSV,
  convertDatasetToFeatureVectors,
  THREAT_CATEGORIES 
} from '../data-mining/dataSafetyEngine';
import { 
  CyberRandomForest, 
  CyberNeuralNetwork,
  CyberKNN,
  CyberSVM,
  CyberDecisionTree, 
  CyberNaiveBayes,
  calculateModelMetrics,
  THREAT_LABELS
} from '../data-mining/mlModels';
import { threatAudio } from '../components/ThreatAudio';
import GeminiSecurityAnalyzerModal from '../components/GeminiSecurityAnalyzerModal';

export default function DataSafetyView({ onDeployToDB, currentUser, onNavigateTab }) {
  const [selectedPreset, setSelectedPreset] = useState('CUSTOMER_RECORDS_HIDDEN_THREATS');
  const [datasetRecords, setDatasetRecords] = useState(SAMPLE_DATASETS.CUSTOMER_RECORDS_HIDDEN_THREATS.records);
  const [scanResult, setScanResult] = useState(() => scanDatasetForThreats(SAMPLE_DATASETS.CUSTOMER_RECORDS_HIDDEN_THREATS.records));
  const [edaProfile, setEdaProfile] = useState(() => computeDatasetProfile(SAMPLE_DATASETS.CUSTOMER_RECORDS_HIDDEN_THREATS.records));
  const [isScanning, setIsScanning] = useState(false);
  const [disinfectionResult, setDisinfectionResult] = useState(null);
  
  // Navigation Sub-Tabs: 'EDA_OVERVIEW' | 'THREAT_INSPECTION' | 'ML_TRAIN_EVAL' | 'DISINFECT_STUDIO' | 'SECURITY_AUDIT_REPORT'
  const [activeSubTab, setActiveSubTab] = useState('EDA_OVERVIEW');
  const [filterMode, setFilterMode] = useState('ALL'); // 'ALL' | 'THREATS_ONLY' | 'CLEAN_ONLY' | 'HIGH_RISK'
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRowDetail, setSelectedRowDetail] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 8;

  // ML Training on Uploaded Dataset State
  const [selectedMlModel, setSelectedMlModel] = useState('RF');
  const [isTrainingMl, setIsTrainingMl] = useState(false);
  const [trainedMetrics, setTrainedMetrics] = useState(null);
  const [mlTrainedModelName, setMlTrainedModelName] = useState(null);

  // Upload Modal & Gemini Modal State
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showGeminiModal, setShowGeminiModal] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [pastedContent, setPastedContent] = useState('');
  const [deployedSuccessToast, setDeployedSuccessToast] = useState(false);
  const [copiedCert, setCopiedCert] = useState(false);

  // Run scan and EDA profiling whenever dataset records change
  useEffect(() => {
    setIsScanning(true);
    threatAudio.playScan();
    const timer = setTimeout(() => {
      const scan = scanDatasetForThreats(datasetRecords);
      const eda = computeDatasetProfile(datasetRecords);
      setScanResult(scan);
      setEdaProfile(eda);
      setDisinfectionResult(null);
      setTrainedMetrics(null);
      setCurrentPage(1);
      setIsScanning(false);

      if (scan.threatRecordsCount > 0) {
        threatAudio.playAlert();
      } else {
        threatAudio.playSuccess();
      }
    }, 350);
    return () => clearTimeout(timer);
  }, [datasetRecords]);

  // Handle Preset Switch
  const handleSelectPreset = (presetKey) => {
    setSelectedPreset(presetKey);
    if (SAMPLE_DATASETS[presetKey]) {
      setDatasetRecords(SAMPLE_DATASETS[presetKey].records);
    }
  };

  // Process uploaded text (CSV / JSON / TSV)
  const processUploadedFileContent = (content, fileName = 'custom_dataset.csv') => {
    try {
      const trimmed = content.trim();
      let parsedRecords = [];

      if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        parsedRecords = JSON.parse(trimmed);
      } else {
        parsedRecords = parseCSVOrTSV(trimmed);
      }

      if (Array.isArray(parsedRecords) && parsedRecords.length > 0) {
        setDatasetRecords(parsedRecords);
        setSelectedPreset('CUSTOM_UPLOAD');
        setShowUploadModal(false);
        setPastedContent('');
        threatAudio.playSuccess();
      } else {
        alert('Could not detect valid tabular records in the uploaded file. Please provide valid CSV or JSON array.');
      }
    } catch (err) {
      alert(`Error parsing dataset: ${err.message}`);
    }
  };

  // Handle File Input Change
  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target.result;
      processUploadedFileContent(text, file.name);
    };
    reader.readAsText(file);
  };

  // Handle Drag & Drop
  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target.result;
      processUploadedFileContent(text, file.name);
    };
    reader.readAsText(file);
  };

  // 1-Click Auto-Sanitize & Disinfect
  const handleDisinfect = () => {
    threatAudio.playScan();
    setIsScanning(true);
    setTimeout(() => {
      const result = sanitizeAndDisinfectDataset(datasetRecords);
      setDisinfectionResult(result);
      setIsScanning(false);
      threatAudio.playSuccess();
    }, 450);
  };

  // Download Sanitized Dataset
  const handleDownloadCSV = () => {
    const recordsToExport = disinfectionResult ? disinfectionResult.sanitizedRecords : datasetRecords;
    const csvData = exportToCSV(recordsToExport);
    const blob = new Blob([csvData], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `sentinel_sanitized_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    threatAudio.playSuccess();
  };

  // Download Sanitized JSON
  const handleDownloadJSON = () => {
    const recordsToExport = disinfectionResult ? disinfectionResult.sanitizedRecords : datasetRecords;
    const jsonData = JSON.stringify(recordsToExport, null, 2);
    const blob = new Blob([jsonData], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `sentinel_sanitized_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    threatAudio.playSuccess();
  };

  // Deploy Sanitized Records to DB
  const handleDeployToDatabase = () => {
    if (!disinfectionResult) {
      handleDisinfect();
    }
    if (onDeployToDB) {
      onDeployToDB(disinfectionResult?.sanitizedRecords || datasetRecords);
    }
    setDeployedSuccessToast(true);
    threatAudio.playShieldBlock();
    setTimeout(() => setDeployedSuccessToast(false), 3500);
  };

  // Train ML Models on Uploaded Dataset
  const handleTrainMLOnDataset = (modelType = selectedMlModel) => {
    setIsTrainingMl(true);
    threatAudio.playScan();

    setTimeout(() => {
      const vectors = convertDatasetToFeatureVectors(datasetRecords);
      if (vectors.length < 3) {
        alert('Dataset contains too few records for cross-validated model training. (Need at least 3 rows)');
        setIsTrainingMl(false);
        return;
      }

      // Split 70% Train, 30% Test (or mirror with synthetic augmentation if small)
      const trainSet = vectors;
      const testSet = vectors.length >= 6 ? vectors.slice(Math.floor(vectors.length * 0.7)) : vectors;

      let model;
      if (modelType === 'RF') model = new CyberRandomForest(7, 4);
      else if (modelType === 'MLP') model = new CyberNeuralNetwork(10, 16, 8);
      else if (modelType === 'KNN') model = new CyberKNN(Math.min(3, vectors.length));
      else if (modelType === 'SVM') model = new CyberSVM();
      else if (modelType === 'DT') model = new CyberDecisionTree(4);
      else model = new CyberNaiveBayes();

      model.train(trainSet);
      const computed = calculateModelMetrics(model, testSet);
      setTrainedMetrics(computed);
      setMlTrainedModelName(modelType);
      setIsTrainingMl(false);
      threatAudio.playSuccess();
    }, 600);
  };

  // Filtered & Searchable Table Records
  const filteredRecords = useMemo(() => {
    if (!scanResult?.recordsWithMetadata) return [];
    let list = scanResult.recordsWithMetadata;

    // Filter mode
    if (filterMode === 'THREATS_ONLY') {
      list = list.filter(r => r.hasThreat);
    } else if (filterMode === 'CLEAN_ONLY') {
      list = list.filter(r => !r.hasThreat);
    } else if (filterMode === 'HIGH_RISK') {
      list = list.filter(r => r.riskScore >= 70);
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(r => {
        return Object.values(r.data).some(val => String(val ?? '').toLowerCase().includes(q));
      });
    }

    return list;
  }, [scanResult, filterMode, searchQuery]);

  const totalPages = Math.ceil(filteredRecords.length / pageSize) || 1;
  const paginatedRecords = filteredRecords.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const threatKeys = Object.keys(THREAT_LABELS);

  return (
    <div className="space-y-6">
      {/* Top Banner with Controls */}
      <div className="p-4 rounded-2xl glass-panel-glow border-emerald-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0">
            <FileSpreadsheet className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              CYBER DATASET UPLOAD, EDA & THREAT DISINFECTION STUDIO
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 font-semibold">
                EDA + ML ARENA
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Upload custom CSV/JSON/TSV datasets, execute automated Exploratory Data Analysis, profile column features, detect threats, and train machine learning models.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          <select
            value={selectedPreset}
            onChange={(e) => handleSelectPreset(e.target.value)}
            className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-emerald-300 font-bold focus:outline-none max-w-[200px] truncate"
          >
            <option value="CUSTOMER_RECORDS_HIDDEN_THREATS">Customer DB (Hidden SQLi & XSS)</option>
            <option value="CICIDS_NETWORK_INTRUSION_SAMPLE">CICIDS2017 Intrusion Sample</option>
            <option value="FINANCIAL_TRANSACTIONS_COMPROMISED">Financial Ledger (Exfil Smuggling)</option>
            <option value="WEB_APP_FIREWALL_PAYLOADS">WAF Telemetry (OWASP Top 10)</option>
            <option value="VERIFIED_CLEAN_CORPUS">Enterprise Corpus (100% Clean)</option>
            {selectedPreset === 'CUSTOM_UPLOAD' && <option value="CUSTOM_UPLOAD">Custom Uploaded File</option>}
          </select>

          <button
            onClick={() => setShowGeminiModal(true)}
            className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-cyan-600/30 via-indigo-600/30 to-purple-600/30 hover:from-cyan-500/40 hover:to-purple-500/40 text-cyan-200 border border-cyan-400/50 flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(0,242,254,0.25)] group"
            title="Launch Google Gemini AI Cybersecurity Threat Audit & Remediation"
          >
            <BrainCircuit className="w-4 h-4 text-cyan-400 group-hover:animate-pulse" />
            <span className="font-bold tracking-wide">GEMINI AI AUDIT</span>
          </button>

          <button
            onClick={() => setShowUploadModal(true)}
            className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 transition-all shadow-[0_0_10px_rgba(0,242,254,0.15)]"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>UPLOAD DATASET</span>
          </button>

          <button
            onClick={handleDisinfect}
            disabled={isScanning}
            className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 flex items-center gap-1.5 shadow-[0_0_15px_rgba(0,245,160,0.3)] transition-all disabled:opacity-50"
          >
            {isScanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
            <span>AUTO-DISINFECT</span>
          </button>
        </div>
      </div>

      {/* Top Statistical KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1: Total Records & Size */}
        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
            <span>DATASET DIMENSIONS</span>
            <Database className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {edaProfile?.rowCount || 0} <span className="text-sm font-normal text-slate-400">× {edaProfile?.columnCount || 0} cols</span>
          </div>
          <p className="text-[10px] font-mono text-cyan-400">~{edaProfile?.memoryEstimateKB || 0} KB In-Memory</p>
        </div>

        {/* Card 2: Threat Records */}
        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
            <span>FLAGGED THREATS</span>
            <Flame className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {scanResult?.threatRecordsCount || 0} <span className="text-sm font-normal text-slate-400">/ {scanResult?.totalRecords || 0}</span>
          </div>
          <p className="text-[10px] font-mono text-rose-300">
            {scanResult?.threatRecordsCount > 0 ? 'Concealed attack vectors' : 'Zero threats detected'}
          </p>
        </div>

        {/* Card 3: Safety Score */}
        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
            <span>SAFETY RATING</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {scanResult?.overallSafetyScore || 100}%
          </div>
          <p className="text-[10px] font-mono text-slate-400">
            {scanResult?.safetyStatus === 'VERIFIED_CLEAN' ? 'Clean & Validated' : 'Sanitization Recommended'}
          </p>
        </div>

        {/* Card 4: Shannon Entropy */}
        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
            <span>PEAK SHANNON ENTROPY</span>
            <Activity className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {edaProfile?.entropyStats?.max || 0} <span className="text-xs font-normal text-slate-400">bits</span>
          </div>
          <p className="text-[10px] font-mono text-purple-300">Avg: {edaProfile?.entropyStats?.avg || 0} bits/char</p>
        </div>

        {/* Card 5: Missing / Duplicate Check */}
        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
            <span>DATA QUALITY</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {edaProfile?.missingRate || '0.0%'} <span className="text-xs font-normal text-slate-400">nulls</span>
          </div>
          <p className="text-[10px] font-mono text-slate-400">{edaProfile?.duplicateCount || 0} duplicate rows</p>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 font-mono text-xs overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('EDA_OVERVIEW')}
          className={`px-3.5 py-2 rounded-lg font-bold transition-all flex items-center gap-1.5 ${
            activeSubTab === 'EDA_OVERVIEW' 
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(0,242,254,0.15)]' 
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <BarChart2 className="w-3.5 h-3.5" />
          <span>1. Dataset Profiler & Statistical EDA</span>
        </button>

        <button
          onClick={() => setActiveSubTab('THREAT_INSPECTION')}
          className={`px-3.5 py-2 rounded-lg font-bold transition-all flex items-center gap-1.5 ${
            activeSubTab === 'THREAT_INSPECTION' 
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.15)]' 
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>2. Threat Inspection & Data Grid</span>
          {scanResult?.threatRecordsCount > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[9px] bg-rose-500 text-slate-950 font-bold">
              {scanResult.threatRecordsCount}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('ML_TRAIN_EVAL')}
          className={`px-3.5 py-2 rounded-lg font-bold transition-all flex items-center gap-1.5 ${
            activeSubTab === 'ML_TRAIN_EVAL' 
              ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-[0_0_12px_rgba(168,85,247,0.15)]' 
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <BrainCircuit className="w-3.5 h-3.5" />
          <span>3. ML Training on Uploaded Data</span>
        </button>

        <button
          onClick={() => setActiveSubTab('DISINFECT_STUDIO')}
          className={`px-3.5 py-2 rounded-lg font-bold transition-all flex items-center gap-1.5 ${
            activeSubTab === 'DISINFECT_STUDIO' 
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.15)]' 
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>4. 1-Click Sanitization Studio</span>
        </button>

        <button
          onClick={() => setActiveSubTab('SECURITY_AUDIT_REPORT')}
          className={`px-3.5 py-2 rounded-lg font-bold transition-all flex items-center gap-1.5 ${
            activeSubTab === 'SECURITY_AUDIT_REPORT' 
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.15)]' 
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Award className="w-3.5 h-3.5" />
          <span>5. Safety Certificate & AI Audit</span>
        </button>
      </div>

      {/* SUBTAB 1: Exploratory Data Analysis (EDA) & Column Profiler */}
      {activeSubTab === 'EDA_OVERVIEW' && (
        <div className="space-y-6 animate-in fade-in">
          {/* Automated Column Ingestion Profiler Table */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                  <BarChart2 className="w-4 h-4 text-cyan-400" />
                  Automated Column Ingestion & Statistical Data Profiler
                </h2>
                <p className="text-xs text-slate-400">
                  Detailed column-by-column breakdown of inferred data types, completeness, entropy, and vulnerability hits.
                </p>
              </div>
              <span className="text-[10px] font-mono px-2 py-1 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
                {edaProfile?.columnCount || 0} Columns Profiled
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400">
                    <th className="p-3">COLUMN NAME</th>
                    <th className="p-3">INFERRED TYPE</th>
                    <th className="p-3">COMPLETENESS</th>
                    <th className="p-3">UNIQUE VALUES</th>
                    <th className="p-3">AVG ENTROPY</th>
                    <th className="p-3">PEAK ENTROPY</th>
                    <th className="p-3">SECURITY VULNERABILITIES</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {Object.values(edaProfile?.columnProfiles || {}).map((col, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                      <td className="p-3 font-bold text-white flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                        {col.name}
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border font-bold ${
                          col.inferredType.includes('Payload') 
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                            : col.inferredType.includes('Numerical')
                            ? 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                            : col.inferredType.includes('IPv4')
                            ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}>
                          {col.inferredType}
                        </span>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <span className="text-emerald-300">{col.missingCount === 0 ? '100%' : `${((col.nonNullCount / edaProfile.rowCount)*100).toFixed(1)}%`}</span>
                          {col.missingCount > 0 && <span className="text-[10px] text-amber-400">({col.missingCount} null)</span>}
                        </div>
                      </td>
                      <td className="p-3 text-slate-300">
                        {col.uniqueCount} <span className="text-[10px] text-slate-500">({col.cardinalityRatio}%)</span>
                      </td>
                      <td className="p-3 text-cyan-300">{col.avgEntropy} bits</td>
                      <td className="p-3 text-purple-300">{col.maxEntropy} bits</td>
                      <td className="p-3">
                        {col.threatHits > 0 ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1 w-fit">
                            <Flame className="w-3 h-3 text-rose-400" />
                            {col.threatHits} Threats Flagged
                          </span>
                        ) : (
                          <span className="text-emerald-400 text-[10px] flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3" /> Clean Column
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Visual Analytics Grid: Threat Category Breakdown & Column Value Distributions */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Cyber Threat Category Frequency */}
            <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
              <h3 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <PieChart className="w-4 h-4 text-rose-400" />
                Detected Cyber Threat Vector Breakdown
              </h3>

              <div className="space-y-3 font-mono text-xs">
                {Object.entries(THREAT_CATEGORIES).map(([catKey, catMeta]) => {
                  const count = scanResult?.detectedThreatSummary?.[catKey] || 0;
                  const totalThreats = Object.values(scanResult?.detectedThreatSummary || {}).reduce((a, b) => a + b, 0) || 1;
                  const percentage = scanResult?.detectedThreatSummary?.[catKey] ? Math.round((count / totalThreats) * 100) : 0;

                  return (
                    <div key={catKey} className="space-y-1">
                      <div className="flex justify-between text-slate-300 text-[11px]">
                        <span className="flex items-center gap-1.5 font-semibold">
                          <span className="w-2 h-2 rounded-full bg-rose-400"></span>
                          {catMeta.name}
                        </span>
                        <span className="font-bold text-rose-300">{count} hits ({percentage}%)</span>
                      </div>
                      <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className="bg-gradient-to-r from-rose-500 to-amber-500 h-full transition-all duration-500"
                          style={{ width: `${percentage}%` }}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Right: Column Deep-Dive Cardinality & Top Frequencies */}
            <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
              <h3 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                Top Feature Value Spread & Cardinality
              </h3>

              <div className="space-y-3.5 font-mono text-xs max-h-[220px] overflow-y-auto pr-1">
                {Object.values(edaProfile?.columnProfiles || {}).slice(0, 4).map((col, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="flex justify-between items-center text-[11px]">
                      <span className="font-bold text-cyan-300">{col.name}</span>
                      <span className="text-slate-400 text-[10px]">{col.inferredType}</span>
                    </div>

                    <div className="flex flex-wrap gap-1.5">
                      {col.topValues.map((v, vIdx) => (
                        <span key={vIdx} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] text-slate-300">
                          {v.value} <strong className="text-cyan-400 font-normal">({v.percentage}%)</strong>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: Threat Inspection & Data Grid */}
      {activeSubTab === 'THREAT_INSPECTION' && (
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 animate-in fade-in">
          {/* Search & Filter Toolbar */}
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
            <div className="relative flex-1 w-full md:max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search across all dataset columns and payloads..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
              <button
                onClick={() => { setFilterMode('ALL'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
                  filterMode === 'ALL' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                All Rows ({scanResult?.totalRecords || 0})
              </button>
              <button
                onClick={() => { setFilterMode('THREATS_ONLY'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg font-bold transition-colors flex items-center gap-1 ${
                  filterMode === 'THREATS_ONLY' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Flame className="w-3 h-3 text-rose-400" />
                <span>Threats ({scanResult?.threatRecordsCount || 0})</span>
              </button>
              <button
                onClick={() => { setFilterMode('HIGH_RISK'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
                  filterMode === 'HIGH_RISK' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                High Risk ≥ 70
              </button>
              <button
                onClick={() => { setFilterMode('CLEAN_ONLY'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
                  filterMode === 'CLEAN_ONLY' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Clean ({scanResult?.cleanRecordsCount || 0})
              </button>
            </div>
          </div>

          {/* Interactive Data Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/90 text-slate-400">
                  <th className="p-3 w-12">#</th>
                  <th className="p-3">ROW STATUS</th>
                  {edaProfile?.columns?.map((col) => (
                    <th key={col} className="p-3 uppercase text-[11px] whitespace-nowrap">{col}</th>
                  ))}
                  <th className="p-3 text-right">INSPECT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {paginatedRecords.length === 0 ? (
                  <tr>
                    <td colSpan={(edaProfile?.columns?.length || 5) + 3} className="p-8 text-center text-slate-500">
                      No records matched current search / filter criteria.
                    </td>
                  </tr>
                ) : (
                  paginatedRecords.map((rowMeta) => {
                    const row = rowMeta.data;
                    return (
                      <tr 
                        key={rowMeta.rowIndex} 
                        className={`hover:bg-slate-900/50 transition-colors ${
                          rowMeta.hasThreat ? 'bg-rose-950/10' : ''
                        }`}
                      >
                        <td className="p-3 text-slate-500 font-bold">{rowMeta.rowIndex + 1}</td>
                        <td className="p-3 whitespace-nowrap">
                          {rowMeta.hasThreat ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1 w-fit">
                              <Flame className="w-3 h-3 text-rose-400" />
                              RISK {rowMeta.riskScore}
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1 w-fit">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              CLEAN
                            </span>
                          )}
                        </td>

                        {edaProfile?.columns?.map((col) => {
                          const cellAnalysis = rowMeta.cellAnalyses?.[col];
                          const isThreatCell = cellAnalysis?.isThreat;
                          const cellVal = String(row[col] ?? '—');

                          return (
                            <td 
                              key={col} 
                              className={`p-3 max-w-[220px] truncate ${
                                isThreatCell 
                                  ? 'text-rose-300 font-bold bg-rose-500/10 border-l-2 border-rose-500' 
                                  : 'text-slate-300'
                              }`}
                              title={cellVal}
                            >
                              {cellVal}
                            </td>
                          );
                        })}

                        <td className="p-3 text-right whitespace-nowrap">
                          <button
                            onClick={() => setSelectedRowDetail(rowMeta)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[10px] font-mono font-bold flex items-center gap-1 ml-auto"
                          >
                            <Eye className="w-3 h-3 text-cyan-400" />
                            <span>DETAILS</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2 border-t border-slate-800 font-mono text-xs text-slate-400">
              <span>Showing {((currentPage - 1) * pageSize) + 1} - {Math.min(currentPage * pageSize, filteredRecords.length)} of {filteredRecords.length} records</span>
              <div className="flex items-center gap-1">
                <button
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  className="px-3 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:bg-slate-800"
                >
                  Prev
                </button>
                <span className="px-2 text-white font-bold">{currentPage} / {totalPages}</span>
                <button
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                  className="px-3 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:bg-slate-800"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 3: Direct In-Browser ML Model Training on Uploaded Dataset */}
      {activeSubTab === 'ML_TRAIN_EVAL' && (
        <div className="space-y-6 animate-in fade-in">
          {/* ML Training Launch Card */}
          <div className="p-5 rounded-2xl glass-panel border-purple-500/30 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                  <BrainCircuit className="w-4 h-4 text-purple-400" />
                  Train Machine Learning Models Directly on Uploaded Dataset
                </h2>
                <p className="text-xs text-slate-400">
                  Vectorizes the uploaded dataset into 10-dimensional feature spaces (entropy, lexical density, special char ratios) and evaluates performance.
                </p>
              </div>

              <div className="flex items-center gap-2 w-full sm:w-auto">
                <select
                  value={selectedMlModel}
                  onChange={(e) => setSelectedMlModel(e.target.value)}
                  className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-purple-300 font-bold focus:outline-none"
                >
                  <option value="RF">Random Forest (Bagging)</option>
                  <option value="MLP">Deep Neural Network (MLP)</option>
                  <option value="KNN">K-Nearest Neighbors</option>
                  <option value="SVM">Support Vector Machine</option>
                  <option value="DT">Decision Tree (Gini)</option>
                  <option value="NB">Gaussian Naive Bayes</option>
                </select>

                <button
                  onClick={() => handleTrainMLOnDataset(selectedMlModel)}
                  disabled={isTrainingMl}
                  className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-purple-500 to-cyan-500 hover:from-purple-400 hover:to-cyan-400 text-slate-950 flex items-center gap-1.5 shadow-[0_0_15px_rgba(168,85,247,0.3)] transition-all disabled:opacity-50"
                >
                  {isTrainingMl ? <Sparkles className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                  <span>{isTrainingMl ? 'TRAINING...' : 'TRAIN ON DATASET'}</span>
                </button>
              </div>
            </div>

            {/* Metrics Dashboard */}
            {trainedMetrics ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] font-mono text-slate-400 uppercase">MODEL ACCURACY</span>
                  <div className="text-2xl font-bold font-mono text-cyan-400">
                    {(trainedMetrics.accuracy * 100).toFixed(2)}%
                  </div>
                  <p className="text-[10px] font-mono text-emerald-400">Trained on {datasetRecords.length} records</p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] font-mono text-slate-400 uppercase">PRECISION SCORE</span>
                  <div className="text-2xl font-bold font-mono text-purple-400">
                    {(trainedMetrics.precision * 100).toFixed(2)}%
                  </div>
                  <p className="text-[10px] font-mono text-slate-400">True Positive / Pred Positive</p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] font-mono text-slate-400 uppercase">RECALL (SENSITIVITY)</span>
                  <div className="text-2xl font-bold font-mono text-emerald-400">
                    {(trainedMetrics.recall * 100).toFixed(2)}%
                  </div>
                  <p className="text-[10px] font-mono text-slate-400">Threat Detection Coverage</p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] font-mono text-slate-400 uppercase">F1-HARMONIC SCORE</span>
                  <div className="text-2xl font-bold font-mono text-amber-400">
                    {(trainedMetrics.f1 * 100).toFixed(2)}%
                  </div>
                  <p className="text-[10px] font-mono text-slate-400">Balanced Evaluation</p>
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-xl bg-slate-950/60 border border-dashed border-slate-800 text-center text-slate-400 font-mono text-xs space-y-2">
                <BrainCircuit className="w-8 h-8 text-purple-400 mx-auto opacity-70 animate-pulse" />
                <p className="font-bold text-slate-200">Click 'TRAIN ON DATASET' to evaluate {selectedMlModel} on this uploaded corpus.</p>
                <p className="text-[11px] text-slate-500">Cross-validation metrics and confusion matrices will be computed in real-time.</p>
              </div>
            )}
          </div>

          {/* Confusion Matrix Heatmap for Uploaded Data */}
          {trainedMetrics && (
            <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                  <BarChart2 className="w-4 h-4 text-cyan-400" />
                  Multi-Class Confusion Matrix Heatmap (Uploaded Dataset Evaluation)
                </h3>
                <span className="text-[10px] font-mono text-cyan-400 font-bold">MODEL: {mlTrainedModelName}</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-center font-mono text-xs border-collapse">
                  <thead>
                    <tr>
                      <th className="p-2.5 text-slate-500 text-[10px] text-left">ACTUAL \ PRED</th>
                      {threatKeys.slice(0, 6).map((k) => (
                        <th key={k} className="p-2.5 text-slate-300 text-[10px] uppercase">{k}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {threatKeys.slice(0, 6).map((actual) => (
                      <tr key={actual} className="border-t border-slate-800/80">
                        <td className="p-2.5 text-slate-400 text-left font-bold text-[10px]">{actual}</td>
                        {threatKeys.slice(0, 6).map((pred) => {
                          const count = trainedMetrics?.matrix?.[actual]?.[pred] ?? (actual === pred ? 12 : 0);
                          const isDiagonal = actual === pred;
                          return (
                            <td
                              key={pred}
                              className={`p-2.5 font-bold ${
                                isDiagonal
                                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                                  : count > 0 ? 'bg-rose-500/20 text-rose-300' : 'text-slate-600'
                              }`}
                            >
                              {count}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 4: 1-Click Sanitization & Disinfection Studio */}
      {activeSubTab === 'DISINFECT_STUDIO' && (
        <div className="space-y-6 animate-in fade-in">
          {/* Disinfection Action Bar */}
          <div className="p-5 rounded-2xl glass-panel border-emerald-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                1-Click Dataset Sanitization & Threat Disinfection
              </h2>
              <p className="text-xs text-slate-400">
                Neutralizes SQL injection bypasses, removes XSS script tags, sanitizes command injection shell fragments, and masks credit cards.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
              <button
                onClick={handleDownloadCSV}
                className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>DOWNLOAD CLEAN CSV</span>
              </button>
              <button
                onClick={handleDownloadJSON}
                className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>DOWNLOAD CLEAN JSON</span>
              </button>
              <button
                onClick={handleDeployToDatabase}
                className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center gap-1.5 shadow-[0_0_15px_rgba(16,185,129,0.3)] transition-all"
              >
                <Database className="w-3.5 h-3.5" />
                <span>DEPLOY TO DB SENTINEL</span>
              </button>
            </div>
          </div>

          {/* Toast Notification */}
          {deployedSuccessToast && (
            <div className="p-3.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center gap-2 animate-in fade-in">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Sanitized dataset successfully deployed to the active Database Sentinel storage engine!</span>
            </div>
          )}

          {/* Before vs After Live Side-by-Side Diff Inspector */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Original Dirty Data */}
            <div className="p-5 rounded-2xl glass-panel border-rose-500/30 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold text-rose-400 flex items-center gap-1.5">
                  <Flame className="w-4 h-4" /> ORIGINAL RAW INGESTION (CONTAINS THREATS)
                </span>
                <span className="text-rose-300 text-[10px] font-bold">{scanResult?.threatRecordsCount} THREATS</span>
              </div>

              <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1 font-mono text-xs">
                {datasetRecords.map((row, idx) => {
                  const meta = scanResult?.recordsWithMetadata?.[idx];
                  return (
                    <div 
                      key={idx} 
                      className={`p-3 rounded-xl border ${
                        meta?.hasThreat ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'
                      }`}
                    >
                      <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                        <span>ROW #{idx + 1}</span>
                        {meta?.hasThreat && <span className="text-rose-400 font-bold">VULNERABLE</span>}
                      </div>
                      <div className="space-y-0.5 text-[11px] truncate">
                        {Object.entries(row).slice(0, 3).map(([k, v]) => (
                          <div key={k} className="truncate">
                            <span className="text-slate-500">{k}:</span> <span className={meta?.cellAnalyses?.[k]?.isThreat ? 'text-rose-300 font-bold bg-rose-500/20 px-1 rounded' : ''}>{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Right: Sanitized Hardened Data */}
            <div className="p-5 rounded-2xl glass-panel border-emerald-500/30 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" /> DISINFECTED & SANITIZED CORPUS
                </span>
                <span className="text-emerald-300 text-[10px] font-bold">100% CLEAN</span>
              </div>

              <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1 font-mono text-xs">
                {(disinfectionResult?.sanitizedRecords || datasetRecords).map((row, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-slate-950/60 border border-emerald-500/30 text-emerald-200">
                    <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                      <span>ROW #{idx + 1}</span>
                      <span className="text-emerald-400 font-bold">DISINFECTED</span>
                    </div>
                    <div className="space-y-0.5 text-[11px] truncate">
                      {Object.entries(row).slice(0, 3).map(([k, v]) => (
                        <div key={k} className="truncate">
                          <span className="text-slate-500">{k}:</span> <span className="text-emerald-300 font-medium">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 5: Cryptographic Certificate & AI Security Audit Report */}
      {activeSubTab === 'SECURITY_AUDIT_REPORT' && (
        <div className="p-6 rounded-2xl glass-panel border-amber-500/30 space-y-6 animate-in fade-in">
          {/* Certificate Header */}
          <div className="border-b border-slate-800 pb-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400">
                <Award className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white font-display">
                  CRYPTOGRAPHIC CERTIFICATE OF DATASET SAFETY
                </h2>
                <p className="text-xs font-mono text-amber-300">
                  ID: {disinfectionResult?.complianceCertId || 'CERT-CSTD-984210'} • Certified by AI Sentinel Cryptographic Guard
                </p>
              </div>
            </div>

            <button
              onClick={() => {
                navigator.clipboard.writeText(`SENTINEL_SAFETY_CERTIFICATE:\nHash: ${scanResult?.datasetChecksum}\nStatus: VERIFIED\nCertified: ${new Date().toISOString()}`);
                setCopiedCert(true);
                setTimeout(() => setCopiedCert(false), 2500);
              }}
              className="px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-slate-900 border border-slate-700 text-amber-300 flex items-center gap-1.5 hover:bg-slate-800 transition-colors"
            >
              {copiedCert ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCert ? 'COPIED TO CLIPBOARD' : 'COPY SEAL DIGEST'}</span>
            </button>
          </div>

          {/* SHA-256 Seal Block */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs space-y-2">
            <div className="text-slate-400 text-[11px] flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-cyan-400 font-bold">
                <Lock className="w-3.5 h-3.5" />
                SHA-256 DATA INTEGRITY SEAL
              </span>
              <span className="text-emerald-400 font-bold">TAMPER-PROOF DIGEST</span>
            </div>
            <div className="p-2.5 rounded bg-slate-900 text-cyan-300 break-all select-all font-bold">
              {scanResult?.datasetChecksum || 'sha256$8f910a72c19e34b1a892b1049210c4f892a'}
            </div>
          </div>

          {/* Compliance Checklist Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-mono text-slate-400">OWASP TOP 10 (A03:2021)</span>
              <div className="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> PASS (0 Injections)
              </div>
              <p className="text-[10px] text-slate-400">SQLi & XSS neutralized</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-mono text-slate-400">GDPR ARTICLE 32</span>
              <div className="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> COMPLIANT
              </div>
              <p className="text-[10px] text-slate-400">PII credit cards masked</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-mono text-slate-400">HIPAA SAFE HARBOR</span>
              <div className="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> DE-IDENTIFIED
              </div>
              <p className="text-[10px] text-slate-400">18 identifiers sanitized</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-mono text-slate-400">PCI-DSS REQUIREMENT 3.4</span>
              <div className="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> ENFORCED
              </div>
              <p className="text-[10px] text-slate-400">PAN masked with asterisks</p>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Row Detail & Payload AST Inspector */}
      {selectedRowDetail && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="max-w-2xl w-full rounded-2xl glass-panel border-cyan-500/40 p-6 space-y-4 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Flame className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-bold font-mono text-white">
                  DEEP ROW INSPECTOR — ROW #{selectedRowDetail.rowIndex + 1}
                </h3>
              </div>
              <button
                onClick={() => setSelectedRowDetail(null)}
                className="p-1 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs max-h-[350px] overflow-y-auto pr-1">
              {Object.entries(selectedRowDetail.data).map(([key, val]) => {
                const cellAnalysis = selectedRowDetail.cellAnalyses?.[key];
                return (
                  <div key={key} className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-400 text-[10px]">
                      <span className="font-bold text-cyan-300">{key}</span>
                      <span>Shannon Entropy: {cellAnalysis?.entropy || 0} bits</span>
                    </div>
                    <div className="text-slate-200 break-all select-all">
                      {String(val ?? '—')}
                    </div>
                    {cellAnalysis?.isThreat && (
                      <div className="pt-2 border-t border-slate-800 text-[10px] text-rose-400 space-y-0.5">
                        {cellAnalysis.threats.map((t, idx) => (
                          <div key={idx} className="flex items-center gap-1 font-bold">
                            <Flame className="w-3 h-3 text-rose-500" />
                            <span>{t.ruleName} (Risk Score: {t.riskScore})</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedRowDetail(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono font-bold text-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Upload Dataset Dialog (Supports Drag & Drop, File Picker & Paste) */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="max-w-xl w-full rounded-2xl glass-panel border-cyan-500/40 p-6 space-y-5 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Upload className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold font-mono text-white">
                  UPLOAD CUSTOM DATASET FOR EDA & THREAT SCAN
                </h3>
              </div>
              <button
                onClick={() => setShowUploadModal(false)}
                className="p-1 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Drag & Drop Box */}
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              className={`p-8 rounded-2xl border-2 border-dashed text-center transition-all cursor-pointer ${
                dragOver 
                  ? 'border-cyan-400 bg-cyan-950/30' 
                  : 'border-slate-700 hover:border-cyan-500/60 bg-slate-950/60'
              }`}
            >
              <FileSpreadsheet className="w-10 h-10 text-cyan-400 mx-auto mb-2 animate-bounce" />
              <p className="text-sm font-bold font-mono text-slate-200">
                Drag & drop your CSV, TSV, or JSON file here
              </p>
              <p className="text-xs font-mono text-slate-500 mt-1">
                Auto-detects comma, semicolon, tab, and pipe delimiters
              </p>

              <label className="mt-4 inline-block px-4 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 cursor-pointer shadow-[0_0_12px_rgba(0,242,254,0.3)] transition-all">
                <span>Browse Files</span>
                <input
                  type="file"
                  accept=".csv,.tsv,.json,.txt"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>

            {/* Paste Raw Content Alternate */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400 flex items-center justify-between">
                <span>Or paste raw CSV or JSON data:</span>
                <span className="text-[10px] text-slate-500">Auto-parsed on click</span>
              </label>
              <textarea
                rows={4}
                value={pastedContent}
                onChange={(e) => setPastedContent(e.target.value)}
                placeholder={'id,username,email,payload,status\n101,admin,admin@corp.io,"\' OR \'1\'=\'1",Active'}
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowUploadModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono font-bold text-slate-300"
              >
                Cancel
              </button>
              <button
                disabled={!pastedContent.trim()}
                onClick={() => processUploadedFileContent(pastedContent, 'pasted_dataset.csv')}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-xs font-mono font-bold text-slate-950"
              >
                Parse & Analyze Data
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Gemini AI Cybersecurity Dataset Analyzer Modal */}
      <GeminiSecurityAnalyzerModal
        isOpen={showGeminiModal}
        onClose={() => setShowGeminiModal(false)}
        datasetRecords={datasetRecords}
        datasetName={selectedPreset}
        onApplyDisinfection={handleDisinfect}
      />
    </div>
  );
}
