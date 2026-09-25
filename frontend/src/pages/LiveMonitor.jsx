import React, { useState, useEffect } from 'react';
import { Radio, ShieldAlert, ShieldCheck, Activity, RefreshCw, ArrowDownLeft, ArrowUpRight, Sliders, ShieldBan, Skull, CheckCircle2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { getSystemTelemetry, scanHostNetwork, getModels, containBlockPort, containBlockIP, containKillProcess } from '../services/api';
import { playIntrusionAlarm } from '../utils/audioAlarm';
import StatCard from '../components/StatCard';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';

export default function LiveMonitor({ onTriggerAlarm }) {
  const navigate = useNavigate();
  const [telemetry, setTelemetry] = useState(() => getCachedData('live_monitor_telemetry', null));
  const [scanResult, setScanResult] = useState(() => getCachedData('live_monitor_scan', null));
  const [models, setModels] = useState(() => getCachedData('ml_models', []));
  const [selectedModel, setSelectedModel] = useState('Random Forest');
  const [loading, setLoading] = useState(() => !hasCachedData('live_monitor_scan'));
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedConnection, setSelectedConnection] = useState(null);
  const [actionFeedback, setActionFeedback] = useState('');

  const lastAlarmKeyRef = React.useRef(null);

  const fetchData = async () => {
    try {
      const [telemData, scanData, modelsData] = await Promise.all([
        getSystemTelemetry().catch(err => { console.warn(err); return null; }),
        scanHostNetwork(50).catch(err => { console.warn(err); return null; }),
        getModels().catch(err => { console.warn(err); return []; })
      ]);
      if (telemData) {
        setTelemetry(telemData);
        setCachedData('live_monitor_telemetry', telemData);
      }
      if (scanData) {
        setScanResult(scanData);
        setCachedData('live_monitor_scan', scanData);
      }
      if (modelsData && modelsData.length > 0) {
        setModels(modelsData);
        setCachedData('ml_models', modelsData);
      }

      if (scanData?.verdict === 'ATTACK' && (scanData?.risk_level === 'CRITICAL' || scanData?.risk_level === 'HIGH')) {
        const threatKey = `${scanData.attack_type}-${scanData.source_ip}`;
        if (lastAlarmKeyRef.current !== threatKey) {
          lastAlarmKeyRef.current = threatKey;
          if (onTriggerAlarm) {
            onTriggerAlarm({
              title: `LIVE INTRUSION DETECTED: ${scanData.attack_type}`,
              attack_type: scanData.attack_type,
              risk_level: scanData.risk_level,
              source_ip: scanData.source_ip || 'Local Socket',
              anomaly_score: scanData.anomaly_score
            });
          }
        }
      } else if (scanData?.verdict === 'NORMAL') {
        lastAlarmKeyRef.current = null;
      }
    } catch (err) {
      console.error('Live monitor fetch failed:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    let interval;
    if (autoRefresh) interval = setInterval(fetchData, 4000);
    return () => { if (interval) clearInterval(interval); };
  }, [autoRefresh, selectedModel]);

  const handleStopPort = async (port, proto) => {
    if (!port || port <= 0) return;
    try {
      const res = await containBlockPort({ port, protocol: proto || 'TCP' });
      setActionFeedback(res?.message || `Port ${port} blocked in firewall.`);
      setTimeout(() => setActionFeedback(''), 4000);
      fetchData();
    } catch (err) {
      setActionFeedback(`Failed: ${err.message}`);
    }
  };

  const handleBlockIP = async (ip) => {
    if (!ip || ip.includes('127.0.0.1') || ip === 'Listening' || ip.includes('::1')) return;
    const cleanIP = ip.split(':')[0];
    try {
      const res = await containBlockIP({ ip: cleanIP });
      setActionFeedback(res?.message || `IP ${cleanIP} blocked in firewall.`);
      setTimeout(() => setActionFeedback(''), 4000);
      fetchData();
    } catch (err) {
      setActionFeedback(`Failed: ${err.message}`);
    }
  };

  const handleKillProc = async (pid, name) => {
    if (!pid || pid <= 4) return;
    try {
      const res = await containKillProcess({ pid, process_name: name });
      setActionFeedback(res?.message || `PID ${pid} terminated.`);
      setTimeout(() => setActionFeedback(''), 4000);
      fetchData();
    } catch (err) {
      setActionFeedback(`Failed: ${err.message}`);
    }
  };

  if (loading) return <LoadingSpinner message="Hooking into live network sockets & AI engine..." />;

  const connections = scanResult?.active_connections || [];

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 max-w-7xl mx-auto"
    >
      {/* Header */}
      <div className="neu-flat p-4 rounded-3xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-[#2563eb]">
            <Radio className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-extrabold text-slate-900 tracking-tight">
              Live Network Monitor
            </h1>
            <p className="text-xs text-slate-500 font-medium">
              Real-time socket inspection & anomaly classification
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Active AI Engine Badge */}
          <div className="neu-button flex items-center gap-2 px-3.5 py-2 rounded-2xl text-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-slate-500 text-[11px] font-bold">Engine:</span>
            <span className="text-[#2563eb] font-bold">Atria-Dawn-Preview (744B MoE)</span>
          </div>

          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-4 py-2 rounded-2xl text-xs font-bold transition-all ${
              autoRefresh
                ? 'neu-accent-btn'
                : 'neu-button text-slate-500'
            }`}
          >
            {autoRefresh ? 'LIVE' : 'PAUSED'}
          </button>

          <button
            onClick={() => { setRefreshing(true); fetchData(); }}
            disabled={refreshing}
            className="neu-button px-4 py-2 rounded-2xl text-xs font-bold text-slate-700 hover:text-slate-950 transition-all flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-[#2563eb]' : ''}`} />
            Scan
          </button>
        </div>
      </div>

      {/* Action Feedback Banner */}
      {actionFeedback && (
        <div className="p-3.5 rounded-2xl bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs font-bold flex items-center gap-2 shadow-sm animate-fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{actionFeedback}</span>
        </div>
      )}

      {/* KPI tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Monitored Sockets" value={connections.length} subtitle="Active TCP/UDP Streams" icon={Activity} badgeText="Real Telemetry" />
        <StatCard
          title="Threat Classification"
          value={scanResult?.verdict === 'ATTACK' ? scanResult.attack_type : 'NORMAL'}
          subtitle={`Risk: ${scanResult?.risk_level || 'LOW'} · Conf: ${scanResult?.confidence_score || 98.5}%`}
          icon={scanResult?.verdict === 'ATTACK' ? ShieldAlert : ShieldCheck}
          badgeText={scanResult?.verdict === 'ATTACK' ? 'Intrusion' : 'Clean'}
        />
        <StatCard title="Anomalous Flows" value={scanResult?.anomalies_detected || 0} subtitle="High Entropy Signatures" icon={Radio} badgeText="Outliers" />
        <StatCard title="Containment Actions" value="Live Shield" subtitle="Windows Firewall Ready" icon={ShieldCheck} badgeText="Active" />
      </div>

      {/* Attack alert banner */}
      {scanResult?.verdict === 'ATTACK' && (
        <div className="p-4 rounded-3xl neu-flat border-rose-300 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-rose-600 shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-bold text-rose-900">Intrusion Detected: {scanResult.attack_type}</div>
              <p className="text-[11px] text-rose-700 font-mono mt-0.5">
                Target: {scanResult.source_ip || 'Local Socket'} · Anomaly: {scanResult.anomaly_score}
              </p>
            </div>
          </div>
          <button
            onClick={() => navigate('/ai-decision')}
            className="px-4 py-2 rounded-2xl bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs transition-all shadow-md"
          >
            Mitigate Threat
          </button>
        </div>
      )}

      {/* Socket Table */}
      <div className="neu-flat rounded-[28px] p-6 overflow-hidden">
        <div className="pb-4 border-b border-slate-300/40 flex items-center justify-between">
          <div>
            <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">Active Socket Telemetry</h3>
          </div>
          <span className={`text-[11px] font-mono flex items-center gap-1.5 font-bold ${autoRefresh ? 'text-[#2563eb]' : 'text-slate-500'}`}>
            <Activity className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-spin' : ''}`} />
            {autoRefresh ? 'Streaming (4s)' : 'Paused'}
          </span>
        </div>

        <div className="overflow-x-auto mt-2">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[10px] text-slate-500 uppercase border-b border-slate-300/40 font-bold">
                <th className="text-left py-3 px-4">Local Socket</th>
                <th className="text-left py-3 px-4">Remote Endpoint</th>
                <th className="text-left py-3 px-4">Protocol · State</th>
                <th className="text-left py-3 px-4">Process (PID)</th>
                <th className="text-left py-3 px-4">Status</th>
                <th className="text-right py-3 px-4">Live Protection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/50 font-mono">
              {connections.map((conn, idx) => (
                <tr
                  key={idx}
                  className={`transition-colors cursor-pointer hover:bg-slate-200/40 ${selectedConnection === conn ? 'bg-blue-100/50' : ''}`}
                  onClick={() => setSelectedConnection(conn)}
                >
                  <td className="py-3 px-4 font-bold text-[#2563eb]">{conn.local_address}</td>
                  <td className="py-3 px-4 text-slate-800 font-medium">{conn.remote_address || 'Listening'}</td>
                  <td className="py-3 px-4">
                    <span className="text-slate-800 font-semibold">{conn.protocol}</span>
                    <span className="text-slate-500 text-[10px]"> · {conn.status}</span>
                  </td>
                  <td className="py-3 px-4 font-sans text-slate-800">
                    <span className="font-bold text-slate-900">{conn.process_name}</span> <span className="text-slate-500 font-mono text-[10px]">({conn.pid || 'sys'})</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                      conn.status === 'SYN_SENT' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                      conn.status === 'LISTEN' ? 'bg-blue-50 text-[#2563eb] border border-blue-200' :
                      'bg-emerald-50 text-emerald-800 border border-emerald-200'
                    }`}>
                      {conn.status === 'SYN_SENT' ? 'Suspicious' : conn.status === 'LISTEN' ? 'Listening' : 'Established'}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                      {conn.local_port > 0 && (
                        <button
                          onClick={() => handleStopPort(conn.local_port, conn.protocol)}
                          title={`Instantly block port ${conn.local_port} in Windows Firewall`}
                          className="px-2.5 py-1 rounded-xl text-[10px] font-bold bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 transition-all"
                        >
                          Stop Port
                        </button>
                      )}
                      {conn.remote_address && !conn.remote_address.includes('127.0.0.1') && !conn.remote_address.includes('::1') && (
                        <button
                          onClick={() => handleBlockIP(conn.remote_address)}
                          title={`Block remote IP ${conn.remote_address}`}
                          className="px-2.5 py-1 rounded-xl text-[10px] font-bold bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 transition-all"
                        >
                          Block IP
                        </button>
                      )}
                      {conn.pid && conn.pid > 4 && (
                        <button
                          onClick={() => handleKillProc(conn.pid, conn.process_name)}
                          title={`Terminate PID ${conn.pid}`}
                          className="px-2.5 py-1 rounded-xl text-[10px] font-bold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 transition-all"
                        >
                          Kill PID
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {connections.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400 font-sans font-medium">No active connections</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  );
}
