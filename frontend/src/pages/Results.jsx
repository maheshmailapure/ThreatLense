import React, { useState, useEffect } from 'react';
import { 
  ListFilter, 
  Search, 
  Download, 
  ChevronLeft, 
  ChevronRight, 
  Eye, 
  ShieldAlert, 
  ShieldCheck, 
  Zap,
  HelpCircle,
  X
} from 'lucide-react';
import { getDetectionResults, getDetectionById, exportDetectionCsvUrl } from '../services/api';
import DetectionExplanation from '../components/DetectionExplanation';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Results() {
  const [data, setData] = useState({ items: [], total: 0, page: 1, total_pages: 1 });
  const [loading, setLoading] = useState(true);

  // Filter states
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [prediction, setPrediction] = useState('');
  const [attackType, setAttackType] = useState('');
  const [riskLevel, setRiskLevel] = useState('');
  const [model, setModel] = useState('');
  const [isAnomalyOnly, setIsAnomalyOnly] = useState(false);

  // Inspector modal state
  const [selectedRecord, setSelectedRecord] = useState(null);

  const fetchResults = async () => {
    setLoading(true);
    try {
      const params = {
        page,
        page_size: 20,
        prediction: prediction || undefined,
        attack_type: attackType || undefined,
        risk_level: riskLevel || undefined,
        model: model || undefined,
        is_anomaly: isAnomalyOnly ? true : undefined,
        search: search || undefined
      };
      const res = await getDetectionResults(params);
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
  }, [page, prediction, attackType, riskLevel, model, isAnomalyOnly]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchResults();
  };

  const handleRowInspect = async (id) => {
    try {
      const fullDet = await getDetectionById(id);
      setSelectedRecord(fullDet);
    } catch (err) {
      console.error("Failed to load details:", err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Export */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100">Detection Results</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Query, filter, inspect, and export comprehensive IDS traffic detection logs ({data.total.toLocaleString()} total)
          </p>
        </div>

        <a
          href={exportDetectionCsvUrl()}
          download="ids_detection_results.csv"
          className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-cyan-400 flex items-center gap-2 transition-all"
        >
          <Download className="w-4 h-4" />
          Export Results (CSV)
        </a>
      </div>

      {/* Filter Bar */}
      <div className="cyber-panel p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by attack class, model name, risk level..."
              className="w-full bg-[#090d18] border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg transition-colors"
          >
            Search
          </button>
        </form>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2 border-t border-slate-800/80 text-xs">
          {/* Prediction filter */}
          <select
            value={prediction}
            onChange={(e) => { setPrediction(e.target.value); setPage(1); }}
            className="bg-[#090d18] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none"
          >
            <option value="">All Traffic Types</option>
            <option value="NORMAL">Normal Only</option>
            <option value="ATTACK">Attacks Only</option>
          </select>

          {/* Attack Category */}
          <select
            value={attackType}
            onChange={(e) => { setAttackType(e.target.value); setPage(1); }}
            className="bg-[#090d18] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none"
          >
            <option value="">All Attack Classes</option>
            <option value="Normal">Normal</option>
            <option value="DoS">DoS (Denial of Service)</option>
            <option value="Probe">Probe (Scanning)</option>
            <option value="R2L">R2L (Remote to Local)</option>
            <option value="U2R">U2R (Privilege Escalation)</option>
          </select>

          {/* Risk Level */}
          <select
            value={riskLevel}
            onChange={(e) => { setRiskLevel(e.target.value); setPage(1); }}
            className="bg-[#090d18] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none"
          >
            <option value="">All Risk Levels</option>
            <option value="LOW">Low Risk</option>
            <option value="MEDIUM">Medium Risk</option>
            <option value="HIGH">High Risk</option>
            <option value="CRITICAL">Critical Risk</option>
          </select>

          {/* Model */}
          <select
            value={model}
            onChange={(e) => { setModel(e.target.value); setPage(1); }}
            className="bg-[#090d18] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none"
          >
            <option value="">All Models</option>
            <option value="Random Forest">Random Forest</option>
            <option value="SVM">SVM</option>
            <option value="K-Means">K-Means</option>
            <option value="Isolation Forest">Isolation Forest</option>
          </select>

          {/* Anomaly Checkbox */}
          <label className="flex items-center gap-2 p-1.5 rounded bg-slate-900/60 border border-slate-800 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={isAnomalyOnly}
              onChange={(e) => { setIsAnomalyOnly(e.target.checked); setPage(1); }}
              className="rounded border-slate-700 bg-slate-900 text-amber-500 focus:ring-0"
            />
            <span className="text-amber-400 font-semibold text-[11px] flex items-center gap-1">
              <Zap className="w-3 h-3" /> Anomalies Only
            </span>
          </label>
        </div>
      </div>

      {/* Results Table */}
      <div className="cyber-panel overflow-hidden">
        {loading ? (
          <LoadingSpinner message="Filtering detection records..." />
        ) : data.items.length === 0 ? (
          <div className="p-8 text-center text-slate-400 text-xs">
            No detection records match the current query criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0c1220] text-slate-400 uppercase tracking-wider text-[10px] font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Prediction</th>
                  <th className="py-3 px-4">Attack Class</th>
                  <th className="py-3 px-4">Anomaly Score</th>
                  <th className="py-3 px-4">Anomaly Flag</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4">Model</th>
                  <th className="py-3 px-4 text-right font-sans">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {data.items.map((row) => (
                  <tr key={row.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 text-slate-400">#{row.id}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(row.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        row.prediction === 'ATTACK' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {row.prediction}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans font-medium text-slate-200">{row.attack_type}</td>
                    <td className="py-3 px-4 text-cyan-400 font-bold">{row.anomaly_score.toFixed(4)}</td>
                    <td className="py-3 px-4">
                      {row.is_anomaly ? (
                        <span className="text-amber-400 font-bold flex items-center gap-1">
                          <Zap className="w-3 h-3" /> YES
                        </span>
                      ) : (
                        <span className="text-slate-400">NO</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                        row.risk_level === 'CRITICAL' ? 'bg-red-500/15 text-red-400 border-red-500/30' :
                        row.risk_level === 'HIGH' ? 'bg-rose-500/15 text-rose-400 border-rose-500/30' :
                        row.risk_level === 'MEDIUM' ? 'bg-amber-500/15 text-amber-400 border-amber-500/30' : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {row.risk_level}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-sans">{row.model}</td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => handleRowInspect(row.id)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs inline-flex items-center gap-1 transition-colors"
                      >
                        <Eye className="w-3 h-3" /> Explain
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
          <div>
            Page {data.page} of {data.total_pages} ({data.total.toLocaleString()} total items)
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={data.page <= 1}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed text-slate-300"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(data.total_pages, p + 1))}
              disabled={data.page >= data.total_pages}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed text-slate-300"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Packet Inspector & Explainability Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="cyber-panel w-full max-w-3xl max-h-[85vh] flex flex-col overflow-hidden border-cyan-500/40 shadow-2xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-[#090e1a]">
              <div>
                <h3 className="font-bold text-slate-100 text-sm flex items-center gap-2">
                  <Eye className="w-4 h-4 text-cyan-400" />
                  Packet Inspection & Detection Rationale (ID #{selectedRecord.id})
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Logged at {new Date(selectedRecord.timestamp).toLocaleString()} • Scanned by {selectedRecord.model}
                </p>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 overflow-auto flex-1 space-y-5">
              {/* Detection Explanation Component */}
              <DetectionExplanation detection={selectedRecord} />

              {/* Raw Packet Attributes Grid */}
              <div className="space-y-2">
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Network Flow Attributes
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-[11px]">
                  {Object.entries(selectedRecord.input_features || {}).map(([key, val]) => (
                    <div key={key} className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <div className="text-slate-400 text-[10px] truncate">{key}</div>
                      <div className="font-semibold text-slate-200 mt-0.5 truncate">{String(val)}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="p-3 border-t border-slate-800 bg-[#090e1a] text-right">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
