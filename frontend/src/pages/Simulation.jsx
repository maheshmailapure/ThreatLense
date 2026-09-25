import React, { useState, useEffect } from 'react';
import { 
  Radio, 
  Play, 
  Square, 
  ShieldAlert, 
  ShieldCheck, 
  Zap, 
  AlertTriangle, 
  Sliders, 
  Activity,
  CheckCircle2,
  Info
} from 'lucide-react';
import { startSimulation, stopSimulation, getSimulationStatus, getModels, getDatasets } from '../services/api';
import StatCard from '../components/StatCard';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Simulation() {
  const [status, setStatus] = useState({
    is_running: false,
    processed_records: 0,
    attack_count: 0,
    anomaly_count: 0,
    alerts_count: 0,
    recent_detections: [],
    current_speed_ms: 500
  });

  const [models, setModels] = useState([]);
  const [datasets, setDatasets] = useState([]);
  const [selectedModel, setSelectedModel] = useState('Random Forest');
  const [selectedDatasetId, setSelectedDatasetId] = useState('');
  const [speedMs, setSpeedMs] = useState(500);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const init = async () => {
      try {
        const [modelsData, datasetsData, initialStatus] = await Promise.all([
          getModels(),
          getDatasets(),
          getSimulationStatus()
        ]);
        setModels(modelsData);
        setDatasets(datasetsData);
        setStatus(initialStatus);
        if (datasetsData.length > 0) setSelectedDatasetId(datasetsData[0].id);
        if (modelsData.length > 0) setSelectedModel(modelsData[0].name);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    init();
  }, []);

  // Poll status while simulation is running
  useEffect(() => {
    let interval = null;
    if (status.is_running) {
      interval = setInterval(async () => {
        try {
          const liveStatus = await getSimulationStatus();
          setStatus(liveStatus);
        } catch (err) {
          console.error(err);
        }
      }, 700);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [status.is_running]);

  const handleStart = async () => {
    try {
      const res = await startSimulation({
        dataset_id: selectedDatasetId ? parseInt(selectedDatasetId) : null,
        model_name: selectedModel,
        speed_ms: speedMs
      });
      setStatus(res);
    } catch (err) {
      console.error(err);
    }
  };

  const handleStop = async () => {
    try {
      const res = await stopSimulation();
      setStatus(res);
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) {
    return <LoadingSpinner message="Initializing real-time stream simulator..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100">Simulated Real-Time IDS Stream</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Stream sequential NSL-KDD network packets through the active ML detection & alert pipeline
        </p>
      </div>

      {/* Defensive Simulation Notice */}
      <div className="p-3.5 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center gap-3 text-blue-400 text-xs">
        <Info className="w-4 h-4 shrink-0" />
        <span>
          <strong>Defensive IDS Simulation:</strong> Live packet flows are streamed from recorded traffic datasets into the feature extraction and inference engine. No offensive packets are injected into real networks.
        </span>
      </div>

      {/* Control Station */}
      <div className="cyber-panel p-6">
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 items-end">
          {/* Model selection */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
              Inference Model
            </label>
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              disabled={status.is_running}
              className="w-full bg-[#090d18] border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              {models.map((m) => (
                <option key={m.id} value={m.name}>{m.name}</option>
              ))}
            </select>
          </div>

          {/* Dataset selection */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
              Traffic Source Dataset
            </label>
            <select
              value={selectedDatasetId}
              onChange={(e) => setSelectedDatasetId(e.target.value)}
              disabled={status.is_running}
              className="w-full bg-[#090d18] border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              {datasets.map((d) => (
                <option key={d.id} value={d.id}>{d.filename}</option>
              ))}
            </select>
          </div>

          {/* Speed slider */}
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
              <span className="font-semibold uppercase tracking-wider">Stream Interval</span>
              <span className="font-mono text-cyan-400 font-bold">{speedMs}ms</span>
            </div>
            <input
              type="range"
              min="100"
              max="1500"
              step="100"
              value={speedMs}
              onChange={(e) => setSpeedMs(parseInt(e.target.value))}
              disabled={status.is_running}
              className="w-full accent-cyan-500 cursor-pointer disabled:opacity-50"
            />
          </div>

          {/* Start / Stop Toggle */}
          <div>
            {status.is_running ? (
              <button
                onClick={handleStop}
                className="w-full py-2.5 rounded-lg bg-rose-500 hover:bg-rose-400 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-rose-500/25 transition-all"
              >
                <Square className="w-4 h-4 fill-current" />
                Halt IDS Stream
              </button>
            ) : (
              <button
                onClick={handleStart}
                className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 transition-all"
              >
                <Play className="w-4 h-4 fill-current" />
                Start Live Stream
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Live Stream Counters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Packets Scanned"
          value={status.processed_records}
          subtitle="Sequential flow ingestion"
          icon={Activity}
          color="blue"
          badgeText={status.is_running ? "STREAMING" : "IDLE"}
        />
        <StatCard
          title="Attacks Defended"
          value={status.attack_count}
          subtitle="Signature threats caught"
          icon={ShieldAlert}
          color="rose"
          badgeText="Real-Time"
        />
        <StatCard
          title="Anomalies Flagged"
          value={status.anomaly_count}
          subtitle="Outlier distance metrics"
          icon={Zap}
          color="amber"
          badgeText="Behavioral"
        />
        <StatCard
          title="Alerts Generated"
          value={status.alerts_count}
          subtitle="Sent to SOC queue"
          icon={AlertTriangle}
          color="rose"
          badgeText="Auto-Escalated"
        />
      </div>

      {/* Live Packet Feed Table */}
      <div className="cyber-panel overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Radio className={`w-4 h-4 ${status.is_running ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            Live Packet Ticker Stream
          </h3>
          <span className="text-[11px] font-mono text-cyan-400">
            {status.is_running ? 'Receiving Packets...' : 'Stream Inactive'}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0c1220] text-slate-400 uppercase tracking-wider text-[10px] font-semibold border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Packet ID</th>
                <th className="py-2.5 px-4">Time</th>
                <th className="py-2.5 px-4">Verdict</th>
                <th className="py-2.5 px-4">Attack Class</th>
                <th className="py-2.5 px-4">Anomaly Score</th>
                <th className="py-2.5 px-4">Risk Level</th>
                <th className="py-2.5 px-4">Model</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {status.recent_detections && status.recent_detections.length > 0 ? (
                status.recent_detections.slice().reverse().map((pkt) => (
                  <tr key={pkt.id} className="hover:bg-slate-800/40 animate-fadeIn">
                    <td className="py-2.5 px-4 text-cyan-400 font-semibold">#{pkt.id}</td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">{pkt.timestamp}</td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        pkt.prediction === 'ATTACK' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {pkt.prediction}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-sans font-medium text-slate-200">{pkt.attack_type}</td>
                    <td className="py-2.5 px-4 text-cyan-400 font-bold">{pkt.anomaly_score?.toFixed(4)}</td>
                    <td className="py-2.5 px-4">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        pkt.risk_level === 'CRITICAL' ? 'text-red-400 font-bold' :
                        pkt.risk_level === 'HIGH' ? 'text-rose-400' :
                        pkt.risk_level === 'MEDIUM' ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {pkt.risk_level}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 font-sans">{pkt.model}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400 text-xs font-sans">
                    Click "Start Live Stream" above to stream packets in real-time.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
