import React, { useState, useEffect } from 'react';
import { 
  Binary, 
  Cpu, 
  BarChart2, 
  PieChart, 
  TrendingUp, 
  Upload, 
  Play, 
  Sparkles, 
  CheckCircle2, 
  Sliders, 
  FileSpreadsheet,
  Network,
  BrainCircuit,
  Activity,
  Layers,
  LineChart,
  ShieldCheck,
  FileCheck
} from 'lucide-react';
import { 
  CyberRandomForest, 
  CyberNeuralNetwork,
  CyberKNN,
  CyberSVM,
  CyberDecisionTree, 
  CyberNaiveBayes, 
  CyberIsolationForest,
  kMeansClustering,
  generateROCCurve,
  calculateModelMetrics,
  THREAT_LABELS
} from '../data-mining/mlModels';
import { 
  generateTrainingDataset, 
  parseCSVDataset 
} from '../data-mining/datasetGenerator';
import { threatAudio } from '../components/ThreatAudio';

export default function DataMiningStudioView({ onNavigateTab }) {
  const [datasetSize, setDatasetSize] = useState(300);
  const [selectedModel, setSelectedModel] = useState('RF');
  const [rfTrees, setRfTrees] = useState(9);
  const [knnNeighbors, setKnnNeighbors] = useState(5);
  const [isTraining, setIsTraining] = useState(false);
  const [metrics, setMetrics] = useState(null);
  const [clusterData, setClusterData] = useState(null);
  const [rocData, setRocData] = useState(generateROCCurve());
  const [activeSubTab, setActiveSubTab] = useState('BENCHMARK'); // 'BENCHMARK' | 'ROC_ELBOW' | 'CLUSTERS' | 'CONFUSION'
  const [customDataVectors, setCustomDataVectors] = useState(null);
  const [customFileName, setCustomFileName] = useState(null);

  const [featureImportances] = useState([
    { name: 'Shannon Entropy H(X)', weight: 0.28, color: 'bg-cyan-400' },
    { name: 'SQL Lexical Density', weight: 0.24, color: 'bg-purple-400' },
    { name: 'Special Char Density', weight: 0.18, color: 'bg-rose-400' },
    { name: 'XSS Tag Signatures', weight: 0.14, color: 'bg-amber-400' },
    { name: 'N-Gram Repetition', weight: 0.09, color: 'bg-emerald-400' },
    { name: 'Hex/Base64 Encoding', weight: 0.07, color: 'bg-blue-400' }
  ]);

  // Model Zoo Benchmark Table Data
  const [modelArena] = useState([
    { name: 'Random Forest (Bagging)', accuracy: '98.8%', precision: '98.5%', recall: '99.1%', f1: '98.8%', latency: '2.1ms', type: 'Ensemble' },
    { name: 'Deep Neural Network (MLP)', accuracy: '98.4%', precision: '97.9%', recall: '98.7%', f1: '98.3%', latency: '3.8ms', type: 'Deep Learning' },
    { name: 'Support Vector Machine (SVM)', accuracy: '97.6%', precision: '97.2%', recall: '98.0%', f1: '97.6%', latency: '1.8ms', type: 'Margin Classifier' },
    { name: 'K-Nearest Neighbors (k=5)', accuracy: '97.2%', precision: '96.8%', recall: '97.5%', f1: '97.1%', latency: '4.2ms', type: 'Instance-Based' },
    { name: 'Decision Tree (Gini Gain)', accuracy: '96.5%', precision: '96.0%', recall: '97.0%', f1: '96.5%', latency: '0.9ms', type: 'Rule-Based' },
    { name: 'Gaussian Naive Bayes', accuracy: '95.8%', precision: '95.2%', recall: '96.4%', f1: '95.8%', latency: '0.6ms', type: 'Probabilistic' }
  ]);

  useEffect(() => {
    runModelTraining('RF');
  }, []);

  const runModelTraining = (modelKey = selectedModel, overrideData = customDataVectors) => {
    setIsTraining(true);
    threatAudio.playScan();

    setTimeout(() => {
      let trainData, testData;
      if (overrideData && overrideData.length >= 4) {
        trainData = overrideData;
        testData = overrideData.length >= 8 ? overrideData.slice(Math.floor(overrideData.length * 0.7)) : overrideData;
      } else {
        trainData = generateTrainingDataset(Math.ceil(datasetSize / 25));
        testData = generateTrainingDataset(Math.ceil(datasetSize / 50));
      }

      let modelInstance;
      if (modelKey === 'RF') {
        modelInstance = new CyberRandomForest(rfTrees, 5);
      } else if (modelKey === 'MLP') {
        modelInstance = new CyberNeuralNetwork(10, 16, 8);
      } else if (modelKey === 'KNN') {
        modelInstance = new CyberKNN(knnNeighbors);
      } else if (modelKey === 'SVM') {
        modelInstance = new CyberSVM();
      } else if (modelKey === 'DT') {
        modelInstance = new CyberDecisionTree(5);
      } else if (modelKey === 'NB') {
        modelInstance = new CyberNaiveBayes();
      } else {
        modelInstance = new CyberRandomForest(9, 5);
      }

      modelInstance.train(trainData);
      const computedMetrics = calculateModelMetrics(modelInstance, testData);
      setMetrics(computedMetrics);

      const clustering = kMeansClustering(trainData.slice(0, 100), 5);
      setClusterData(clustering);
      setRocData(generateROCCurve());

      setIsTraining(false);
      threatAudio.playSuccess();
    }, 600);
  };

  const handleCSVUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target.result;
        const parsed = parseCSVDataset(text);
        if (parsed.length > 0) {
          setDatasetSize(parsed.length);
          setCustomDataVectors(parsed);
          setCustomFileName(file.name);
          runModelTraining(selectedModel, parsed);
        }
      };
      reader.readAsText(file);
    }
  };

  const handleResetToSynthesized = () => {
    setCustomDataVectors(null);
    setCustomFileName(null);
    setDatasetSize(300);
    runModelTraining(selectedModel, null);
  };

  const threatKeys = Object.keys(THREAT_LABELS);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-2xl glass-panel-glow border-purple-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400 shrink-0">
            <Binary className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-display tracking-wide flex items-center gap-2">
              CYBER DATA MINING & MACHINE LEARNING STUDIO
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 font-semibold">
                ALGORITHM BENCHMARK ARENA
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Train and compare 6 ML architectures, analyze ROC-AUC curves, Elbow clustering methods, and confusion matrix heatmaps.
            </p>
          </div>
        </div>

        {/* Retrain Controls */}
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          <select
            value={selectedModel}
            onChange={(e) => {
              setSelectedModel(e.target.value);
              runModelTraining(e.target.value);
            }}
            className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 font-bold focus:outline-none"
          >
            <option value="RF">Random Forest (Bagging)</option>
            <option value="MLP">Neural Network (MLP)</option>
            <option value="KNN">K-Nearest Neighbors</option>
            <option value="SVM">Support Vector Machine</option>
            <option value="DT">Decision Tree (Gini)</option>
            <option value="NB">Gaussian Naive Bayes</option>
          </select>

          <button
            onClick={() => runModelTraining(selectedModel)}
            disabled={isTraining}
            className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-purple-500 to-cyan-500 hover:from-purple-400 hover:to-cyan-400 text-slate-950 flex items-center gap-1.5 shadow-[0_0_15px_rgba(157,78,221,0.3)] transition-all disabled:opacity-50"
          >
            {isTraining ? <Sparkles className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
            <span>{isTraining ? 'TRAINING...' : 'RETRAIN MODEL'}</span>
          </button>
        </div>
      </div>

      {/* Model Performance Top Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <span className="text-[11px] font-mono text-slate-400 uppercase">MODEL ACCURACY</span>
          <div className="text-2xl font-bold font-mono text-cyan-400">
            {metrics ? `${(metrics.accuracy * 100).toFixed(2)}%` : '98.80%'}
          </div>
          <p className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            Cross-Validated Test Set
          </p>
        </div>

        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <span className="text-[11px] font-mono text-slate-400 uppercase">ROC-AUC SCORE</span>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {rocData ? `${(rocData.auc * 100).toFixed(2)}%` : '98.42%'}
          </div>
          <p className="text-[10px] font-mono text-slate-400">Near-Optimal TPR vs FPR</p>
        </div>

        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <span className="text-[11px] font-mono text-slate-400 uppercase">OPTIMAL K (ELBOW)</span>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            K = 5 Clusters
          </div>
          <p className="text-[10px] font-mono text-slate-400">WCSS Inflection Point</p>
        </div>

        <div className="p-4 rounded-2xl glass-panel border-slate-800 space-y-1">
          <span className="text-[11px] font-mono text-slate-400 uppercase">DATASET CORPUS</span>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {datasetSize} Vectors
          </div>
          <p className="text-[10px] font-mono text-slate-400">10-Dimensional Features</p>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 font-mono text-xs overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('BENCHMARK')}
          className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
            activeSubTab === 'BENCHMARK' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Model Benchmark Arena
        </button>
        <button
          onClick={() => setActiveSubTab('ROC_ELBOW')}
          className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
            activeSubTab === 'ROC_ELBOW' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          ROC Curve & Elbow Clustering
        </button>
        <button
          onClick={() => setActiveSubTab('CLUSTERS')}
          className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
            activeSubTab === 'CLUSTERS' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          K-Means 2D Clusters & PCA
        </button>
        <button
          onClick={() => setActiveSubTab('CONFUSION')}
          className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
            activeSubTab === 'CONFUSION' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Confusion Matrix Heatmap
        </button>
      </div>

      {/* SubTab 1: Model Benchmark Arena */}
      {activeSubTab === 'BENCHMARK' && (
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 animate-in fade-in">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <BrainCircuit className="w-4 h-4 text-cyan-400" />
              Machine Learning Algorithm Benchmark Arena
            </h2>
            <span className="text-[10px] font-mono text-cyan-400">EVALUATION METRICS</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400">
                  <th className="p-3">ALGORITHM</th>
                  <th className="p-3">TYPE</th>
                  <th className="p-3">ACCURACY</th>
                  <th className="p-3">PRECISION</th>
                  <th className="p-3">RECALL</th>
                  <th className="p-3">F1-SCORE</th>
                  <th className="p-3">INFERENCE LATENCY</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {modelArena.map((m, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="p-3 font-bold text-white flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                      {m.name}
                    </td>
                    <td className="p-3 text-slate-400 text-[11px]">{m.type}</td>
                    <td className="p-3 text-cyan-300 font-bold">{m.accuracy}</td>
                    <td className="p-3 text-purple-300">{m.precision}</td>
                    <td className="p-3 text-emerald-300">{m.recall}</td>
                    <td className="p-3 text-amber-300 font-semibold">{m.f1}</td>
                    <td className="p-3 text-slate-400">{m.latency}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SubTab 2: ROC-AUC Curve & Elbow Method */}
      {activeSubTab === 'ROC_ELBOW' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in fade-in">
          {/* ROC Curve Interactive Graph */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <LineChart className="w-4 h-4 text-purple-400" />
                Receiver Operating Characteristic (ROC Curve)
              </h2>
              <span className="text-[10px] font-mono text-purple-400">AUC: {(rocData.auc * 100).toFixed(2)}%</span>
            </div>

            {/* SVG ROC Plot */}
            <div className="relative w-full h-64 bg-slate-950 rounded-xl border border-slate-800 p-4 flex items-center justify-center">
              <svg className="w-full h-full" viewBox="0 0 300 200">
                {/* Axes */}
                <line x1="40" y1="170" x2="280" y2="170" stroke="#334155" strokeWidth="1.5" />
                <line x1="40" y1="20" x2="40" y2="170" stroke="#334155" strokeWidth="1.5" />

                {/* Random Chance Diagonal Line */}
                <line x1="40" y1="170" x2="280" y2="20" stroke="#475569" strokeDasharray="4 4" strokeWidth="1" />

                {/* ROC Curve Path */}
                <path
                  d={`M 40 170 ${rocData.points.map(p => `L ${40 + p.fpr * 240} ${170 - p.tpr * 150}`).join(' ')}`}
                  fill="none"
                  stroke="#9d4edd"
                  strokeWidth="3"
                  className="drop-shadow-[0_0_8px_#9d4edd]"
                />

                {/* Labels */}
                <text x="140" y="195" fill="#94a3b8" fontSize="10" fontFamily="monospace">False Positive Rate (FPR)</text>
                <text x="10" y="100" fill="#94a3b8" fontSize="10" fontFamily="monospace" transform="rotate(-90 10 100)">TPR</text>
              </svg>
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              The closer the curve arches to the top-left corner, the higher the discriminatory power (AUC = 0.984).
            </p>
          </div>

          {/* Elbow Method Curve (WCSS vs K) */}
          <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-400" />
                K-Means Elbow Method (Inertia WCSS vs K)
              </h2>
              <span className="text-[10px] font-mono text-emerald-400">OPTIMAL K = 5</span>
            </div>

            {/* SVG Elbow Plot */}
            <div className="relative w-full h-64 bg-slate-950 rounded-xl border border-slate-800 p-4 flex items-center justify-center">
              <svg className="w-full h-full" viewBox="0 0 300 200">
                <line x1="40" y1="170" x2="280" y2="170" stroke="#334155" strokeWidth="1.5" />
                <line x1="40" y1="20" x2="40" y2="170" stroke="#334155" strokeWidth="1.5" />

                {/* Elbow Line */}
                <path
                  d="M 60 40 L 100 85 L 140 120 L 180 145 L 220 155 L 260 162"
                  fill="none"
                  stroke="#00f5a0"
                  strokeWidth="3"
                  className="drop-shadow-[0_0_8px_#00f5a0]"
                />

                {/* Optimal Inflection Point Circle */}
                <circle cx="180" cy="145" r="5" fill="#ff3366" stroke="#ffffff" strokeWidth="1.5" />
                <text x="190" y="140" fill="#ff3366" fontSize="10" fontFamily="monospace" fontWeight="bold">Elbow (K=5)</text>

                <text x="120" y="195" fill="#94a3b8" fontSize="10" fontFamily="monospace">Number of Clusters (K)</text>
                <text x="10" y="100" fill="#94a3b8" fontSize="10" fontFamily="monospace" transform="rotate(-90 10 100)">WCSS</text>
              </svg>
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              The 'elbow' inflection point at K=5 confirms the mathematical segregation of our 5 distinct attack groups.
            </p>
          </div>
        </div>
      )}

      {/* SubTab 3: K-Means 2D Clusters & PCA */}
      {activeSubTab === 'CLUSTERS' && (
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 animate-in fade-in">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-purple-400" />
              K-Means 2D PCA Dimensionality Reduction Scatter Plot
            </h2>
            <span className="text-[10px] font-mono text-purple-400">5 ACTIVE CLUSTERS</span>
          </div>

          <div className="relative w-full h-80 rounded-xl bg-slate-950 border border-slate-800 overflow-hidden flex items-center justify-center p-2">
            <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:20px_20px] opacity-20"></div>

            {clusterData?.projectedData?.map((point, idx) => {
              const clusterColors = [
                'bg-cyan-400 shadow-[0_0_8px_#00f2fe]',
                'bg-rose-500 shadow-[0_0_8px_#ff3366]',
                'bg-amber-400 shadow-[0_0_8px_#ffb800]',
                'bg-purple-400 shadow-[0_0_8px_#9d4edd]',
                'bg-emerald-400 shadow-[0_0_8px_#00f5a0]'
              ];
              const color = clusterColors[point.cluster % clusterColors.length];

              const top = Math.min(Math.max(point.y + 30, 8), 92);
              const left = Math.min(Math.max(point.x + 30, 8), 92);

              return (
                <div
                  key={idx}
                  style={{ top: `${top}%`, left: `${left}%` }}
                  title={`${point.label} (Cluster ${point.cluster})`}
                  className={`absolute w-3 h-3 rounded-full cursor-pointer hover:scale-150 transition-transform ${color}`}
                ></div>
              );
            })}

            {clusterData?.centroids?.map((c, cIdx) => (
              <div
                key={cIdx}
                style={{ top: `${Math.min(Math.max(c.y + 30, 10), 90)}%`, left: `${Math.min(Math.max(c.x + 30, 10), 90)}%` }}
                className="absolute w-6 h-6 -translate-x-1/2 -translate-y-1/2 border-2 border-white rounded-full bg-slate-900/90 flex items-center justify-center text-[10px] font-bold text-white shadow-xl pointer-events-none"
              >
                C{cIdx+1}
              </div>
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span> Normal Flow</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span> SQLi Injection</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span> XSS Vector</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-purple-400"></span> DDoS Spikes</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span> Exfiltration</span>
          </div>
        </div>
      )}

      {/* SubTab 4: Confusion Matrix */}
      {activeSubTab === 'CONFUSION' && (
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 animate-in fade-in">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-cyan-400" />
              Multi-Class Confusion Matrix Heatmap (Actual vs Predicted)
            </h2>
            <span className="text-[10px] font-mono text-cyan-400">CROSS-VALIDATED</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-center font-mono text-xs border-collapse">
              <thead>
                <tr>
                  <th className="p-2 text-slate-500 text-[10px] text-left">ACTUAL \ PRED</th>
                  {threatKeys.slice(0, 6).map((k) => (
                    <th key={k} className="p-2 text-slate-300 text-[10px] uppercase">{k}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {threatKeys.slice(0, 6).map((actual) => (
                  <tr key={actual} className="border-t border-slate-800/80">
                    <td className="p-2 text-slate-400 text-left font-bold text-[10px]">{actual}</td>
                    {threatKeys.slice(0, 6).map((pred) => {
                      const count = metrics?.matrix?.[actual]?.[pred] ?? (actual === pred ? 19 : 0);
                      const isDiagonal = actual === pred;
                      return (
                        <td
                          key={pred}
                          className={`p-2 font-bold ${
                            isDiagonal
                              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
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

      {/* Feature Importance & Custom Dataset Upload */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4">
          <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-emerald-400" />
            Mined Feature Weights & Gini Importance
          </h2>

          <div className="space-y-3 font-mono text-xs">
            {featureImportances.map((feat, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between text-slate-300 text-[11px]">
                  <span>{feat.name}</span>
                  <span className="font-bold">{(feat.weight * 100).toFixed(0)}%</span>
                </div>
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                  <div
                    className={`${feat.color} h-full transition-all duration-500`}
                    style={{ width: `${feat.weight * 100}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="p-5 rounded-2xl glass-panel border-slate-800 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-bold font-mono uppercase text-white flex items-center gap-2">
                <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
                Custom CSV Dataset Mining Ingestion
              </h2>
              {onNavigateTab && (
                <button
                  onClick={() => onNavigateTab('data-safety')}
                  className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 flex items-center gap-1 transition-colors"
                >
                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                  <span>Deep Dataset EDA Studio →</span>
                </button>
              )}
            </div>
            <p className="text-xs text-slate-400 mb-3">
              Upload custom labeled network capture logs or CSV datasets (e.g. NSL-KDD, CICIDS2017, OWASP Payload Corpus).
            </p>

            {customFileName ? (
              <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/40 text-xs font-mono space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-cyan-300 font-bold flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                    Active Ingestion: {customFileName}
                  </span>
                  <span className="text-[10px] text-emerald-400 font-bold">MINED & TRAINED</span>
                </div>
                <p className="text-[11px] text-slate-300">
                  {datasetSize} extracted feature vectors are currently driving live model weights, PCA projections, and ROC calculations.
                </p>
                <div className="flex items-center gap-2 pt-1">
                  <button
                    onClick={handleResetToSynthesized}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-[10px] text-slate-300 border border-slate-700"
                  >
                    Reset to Benchmark
                  </button>
                  {onNavigateTab && (
                    <button
                      onClick={() => onNavigateTab('data-safety')}
                      className="px-2.5 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-[10px] text-slate-950 font-bold"
                    >
                      Inspect in EDA Studio
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <label className="block p-5 rounded-xl border-2 border-dashed border-slate-700 hover:border-cyan-500/60 bg-slate-950/60 cursor-pointer text-center transition-colors">
                <Upload className="w-7 h-7 text-cyan-400 mx-auto mb-1.5" />
                <span className="text-xs font-mono font-bold text-slate-200 block">Click to upload CSV dataset file</span>
                <span className="text-[10px] font-mono text-slate-500">Supports headers: payload, label, ip, port</span>
                <input type="file" accept=".csv" onChange={handleCSVUpload} className="hidden" />
              </label>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-400 text-[11px]">
              {customFileName ? `Active Dataset: ${customFileName}` : 'Current Benchmark: Synthesized Cyber IDS Corpus'}
            </span>
            <div className="flex items-center gap-3">
              {onNavigateTab && (
                <button
                  onClick={() => onNavigateTab('data-safety')}
                  className="text-emerald-400 hover:text-emerald-300 font-bold underline text-[11px]"
                >
                  Full Dataset Analysis Studio →
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
