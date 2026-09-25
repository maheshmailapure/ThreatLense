import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  SearchCheck, 
  Play, 
  ShieldAlert, 
  ShieldCheck, 
  Zap, 
  AlertTriangle, 
  ArrowRight,
  Activity,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { getDatasets, getModels, runDetection } from '../services/api';
import StatCard from '../components/StatCard';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Detection() {
  const [datasets, setDatasets] = useState([]);
  const [models, setModels] = useState([]);
  const [selectedDatasetId, setSelectedDatasetId] = useState('');
  const [selectedModel, setSelectedModel] = useState('Random Forest');
  const [limit, setLimit] = useState(500);

  const [loading, setLoading] = useState(true);
  const [detecting, setDetecting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const navigate = useNavigate();

  useEffect(() => {
    const initData = async () => {
      try {
        const [dsData, mdData] = await Promise.all([getDatasets(), getModels()]);
        setDatasets(dsData);
        setModels(mdData);
        if (dsData.length > 0) setSelectedDatasetId(dsData[0].id);
        if (mdData.length > 0) setSelectedModel(mdData[0].name);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    initData();
  }, []);

  const handleRunDetection = async (e) => {
    e.preventDefault();
    if (!selectedDatasetId) {
      setError('Please select a dataset to inspect.');
      return;
    }

    setError('');
    setDetecting(true);
    setResult(null);

    try {
      const data = await runDetection(
        parseInt(selectedDatasetId),
        selectedModel,
        limit === 0 ? null : parseInt(limit)
      );
      setResult(data);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Detection run failed.');
    } finally {
      setDetecting(false);
    }
  };

  if (loading) {
    return <LoadingSpinner message="Initializing detection engine..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100">Intrusion Detection Lab</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Execute batch network packet scanning, anomaly scoring, and automated alert triggering
        </p>
      </div>

      {/* Error alert */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Control Panel */}
      <div className="cyber-panel p-6">
        <form onSubmit={handleRunDetection} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {/* Model Selector */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Active Detection Model
              </label>
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="w-full bg-[#090d18] border border-slate-700/80 rounded-lg px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
              >
                {models.length > 0 ? (
                  models.map((m) => (
                    <option key={m.id} value={m.name}>
                      {m.name} ({m.accuracy ? `${m.accuracy}% Acc` : 'Trained'})
                    </option>
                  ))
                ) : (
                  <>
                    <option value="Random Forest">Random Forest</option>
                    <option value="SVM">Support Vector Machine (SVM)</option>
                    <option value="K-Means">K-Means Anomaly Detector</option>
                    <option value="Isolation Forest">Isolation Forest</option>
                  </>
                )}
              </select>
            </div>

            {/* Dataset Selector */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Target Dataset
              </label>
              <select
                value={selectedDatasetId}
                onChange={(e) => setSelectedDatasetId(e.target.value)}
                className="w-full bg-[#090d18] border border-slate-700/80 rounded-lg px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
              >
                {datasets.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.filename} ({d.total_records.toLocaleString()} rows)
                  </option>
                ))}
              </select>
            </div>

            {/* Batch Limit */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Sample Size
              </label>
              <select
                value={limit}
                onChange={(e) => setLimit(parseInt(e.target.value))}
                className="w-full bg-[#090d18] border border-slate-700/80 rounded-lg px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
              >
                <option value={100}>100 Packets (Quick)</option>
                <option value={500}>500 Packets (Standard)</option>
                <option value={1000}>1,000 Packets</option>
                <option value={0}>All Dataset Records</option>
              </select>
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              type="submit"
              disabled={detecting}
              className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs tracking-wide transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2 disabled:opacity-50"
            >
              {detecting ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  Running IDS Detection Pipeline...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Start Detection Scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Detection Results Summary */}
      {result && (
        <div className="space-y-6 animate-fadeIn">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            <StatCard
              title="Packets Inspected"
              value={result.total_processed}
              subtitle="Full scan completed"
              icon={Activity}
              color="blue"
              badgeText="100% Processed"
            />
            <StatCard
              title="Normal Traffic"
              value={result.normal_count}
              subtitle="Legitimate baseline"
              icon={ShieldCheck}
              color="emerald"
              badgeText={`${((result.normal_count / result.total_processed) * 100).toFixed(1)}%`}
            />
            <StatCard
              title="Attacks Detected"
              value={result.attack_count}
              subtitle="Signature attacks flagged"
              icon={ShieldAlert}
              color="rose"
              badgeText={`${((result.attack_count / result.total_processed) * 100).toFixed(1)}%`}
            />
            <StatCard
              title="Anomalies Found"
              value={result.anomaly_count}
              subtitle="High behavioral deviation"
              icon={Zap}
              color="amber"
              badgeText="Outliers"
            />
            <StatCard
              title="Alerts Generated"
              value={result.alerts_generated}
              subtitle="Pushed to SIEM queue"
              icon={AlertTriangle}
              color="rose"
              badgeText="High Priority"
            />
          </div>

          {/* Sample Detections Preview */}
          <div className="cyber-panel overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Detection Stream Preview (Top 25 Samples)
              </h3>
              <button
                onClick={() => navigate('/results')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center gap-1"
              >
                Inspect All in Results Table <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0c1220] text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-4">Prediction</th>
                    <th className="py-2.5 px-4">Attack Type</th>
                    <th className="py-2.5 px-4">Anomaly Score</th>
                    <th className="py-2.5 px-4">Anomaly?</th>
                    <th className="py-2.5 px-4">Risk Level</th>
                    <th className="py-2.5 px-4">Model</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {result.results?.slice(0, 25).map((row, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/40">
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          row.prediction === 'ATTACK' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {row.prediction}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-sans font-medium text-slate-200">{row.attack_type}</td>
                      <td className="py-2.5 px-4 text-cyan-400">{row.anomaly_score.toFixed(4)}</td>
                      <td className="py-2.5 px-4">
                        {row.is_anomaly ? (
                          <span className="text-amber-400 font-bold">YES</span>
                        ) : (
                          <span className="text-slate-400">NO</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          row.risk_level === 'CRITICAL' ? 'text-red-400' :
                          row.risk_level === 'HIGH' ? 'text-rose-400' :
                          row.risk_level === 'MEDIUM' ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {row.risk_level}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 font-sans">{row.model}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
