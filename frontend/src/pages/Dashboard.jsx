import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  RefreshCw, 
  ExternalLink,
  Cpu,
  Layers,
  Radio,
  Download,
  Volume2,
  VolumeX,
  Gauge,
  Sliders,
  Sparkles,
  CheckCircle2,
  TrendingUp,
  Server,
  Zap,
  Shield,
  ArrowRight
} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import gsap from 'gsap';
import { 
  getDashboardStats, 
  getDashboardCharts, 
  getAlerts, 
  updateAlertStatus,
  getSystemHardwareOverview,
  containBlockIP,
  containKillProcess
} from '../services/api';
import { subscribeToAlerts } from '../services/supabase';
import { playIntrusionAlarm, stopIntrusionAlarm, toggleMuteAlarm, getMuteState } from '../utils/audioAlarm';
import StatCard from '../components/StatCard';
import AlertTable from '../components/AlertTable';
import { NormalVsAttackChart, AttackCategoryBarChart, TimelineAreaChart } from '../components/TrafficChart';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';
import api from '../services/api';

export default function Dashboard({ onTriggerAlarm }) {
  const navigate = useNavigate();
  const [stats, setStats] = useState(() => getCachedData('dashboard_stats', null));
  const [charts, setCharts] = useState(() => getCachedData('dashboard_charts', null));
  const [alerts, setAlerts] = useState(() => getCachedData('dashboard_alerts', []));
  const [sys, setSys] = useState(() => getCachedData('dashboard_sys', null));
  const [agentSnapshot, setAgentSnapshot] = useState(() => getCachedData('agent_snapshot', null));
  const [loading, setLoading] = useState(() => !hasCachedData('dashboard_stats'));
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [muted, setMuted] = useState(() => getMuteState());
  const [actionFeedback, setActionFeedback] = useState('');
  
  const [calibrating, setCalibrating] = useState(false);
  const [calibrationProgress, setCalibrationProgress] = useState(100);
  const [sensitivity, setSensitivity] = useState(0.70);

  const wsRef = useRef(null);
  const lastTriggeredIncidentRef = useRef(null);
  const scoreRef = useRef(null);

  const fetchData = async () => {
    try {
      const [statsData, chartsData, alertsData, sysData] = await Promise.all([
        getDashboardStats().catch(() => null),
        getDashboardCharts().catch(() => null),
        getAlerts({ page: 1, page_size: 7 }).catch(() => ({ items: [] })),
        getSystemHardwareOverview().catch(() => null)
      ]);
      if (statsData) { setStats(statsData); setCachedData('dashboard_stats', statsData); }
      if (chartsData) { setCharts(chartsData); setCachedData('dashboard_charts', chartsData); }
      if (alertsData && alertsData.items) { setAlerts(alertsData.items); setCachedData('dashboard_alerts', alertsData.items); }
      if (sysData) { setSys(sysData); setCachedData('dashboard_sys', sysData); }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  // GSAP subtle pulse on score change
  useEffect(() => {
    if (scoreRef.current) {
      gsap.fromTo(
        scoreRef.current,
        { scale: 1.05, filter: 'brightness(1.2)' },
        { scale: 1.0, filter: 'brightness(1.0)', duration: 0.4, ease: 'power2.out' }
      );
    }
  }, [agentSnapshot?.host_anomaly?.anomaly_score]);

  useEffect(() => {
    fetchData();

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//127.0.0.1:8000/api/ws/agent`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const snapshot = JSON.parse(event.data);
          setAgentSnapshot(snapshot);
          setCachedData('agent_snapshot', snapshot);
          if (snapshot.system) {
            setSys(snapshot.system);
            setCachedData('dashboard_sys', snapshot.system);
          }

          if (snapshot.host_anomaly) {
            if (snapshot.host_anomaly.status === "CALIBRATING") {
              setCalibrating(true);
              setCalibrationProgress(snapshot.host_anomaly.calibration_progress || 0);
            } else {
              setCalibrating(false);
              setCalibrationProgress(100);
            }
          }

          const incidents = snapshot.active_incidents || [];
          if (incidents.length > 0) {
            const topInc = incidents[0];
            // Sound alarm ONLY if Atria AI confirmed the event is genuinely HARMFUL
            const isConfirmedHarmful = (topInc?.is_harmful === true || topInc?.ai_status === 'CONFIRMED_THREAT') && (topInc?.severity === 'CRITICAL' || topInc?.severity === 'HIGH');
            if (isConfirmedHarmful) {
              const threatKey = topInc.incident_id || topInc.threat_hash || topInc.title;
              let alarmedSet = new Set();
              try {
                alarmedSet = new Set(JSON.parse(sessionStorage.getItem('tl_alarmed_incidents') || '[]'));
              } catch (e) {}

              if (!alarmedSet.has(threatKey)) {
                try {
                  alarmedSet.add(threatKey);
                  sessionStorage.setItem('tl_alarmed_incidents', JSON.stringify([...alarmedSet]));
                } catch (e) {}

                playIntrusionAlarm(topInc.severity);
                if (onTriggerAlarm) {
                  onTriggerAlarm({
                    title: topInc.title,
                    attack_type: topInc.attack_category || topInc.title,
                    risk_level: topInc.severity,
                    source_ip: topInc.source_ip || topInc.process || 'Threat Engine',
                    id: threatKey
                  });
                }
              }
            }
          }
        } catch (e) {}
      };
    } catch (e) {}

    const unsub = subscribeToAlerts((newAlert) => {
      setAlerts((prev) => [newAlert, ...prev.slice(0, 6)]);
      if (newAlert.risk_level === 'CRITICAL' && newAlert.alert_type?.includes('CONFIRMED')) {
        const alertKey = `alert-${newAlert.id || newAlert.alert_type}`;
        let alarmedSet = new Set();
        try {
          alarmedSet = new Set(JSON.parse(sessionStorage.getItem('tl_alarmed_incidents') || '[]'));
        } catch (e) {}

        if (!alarmedSet.has(alertKey)) {
          try {
            alarmedSet.add(alertKey);
            sessionStorage.setItem('tl_alarmed_incidents', JSON.stringify([...alarmedSet]));
          } catch (e) {}

          playIntrusionAlarm(newAlert.risk_level);
          if (onTriggerAlarm) {
            onTriggerAlarm({
              title: newAlert.alert_type,
              attack_type: newAlert.attack_type || newAlert.alert_type,
              risk_level: newAlert.risk_level,
              source_ip: newAlert.ip_source || 'Host Socket',
              id: alertKey
            });
          }
        }
      }
    });

    let interval;
    if (autoRefresh) interval = setInterval(fetchData, 1000);

    return () => {
      if (interval) clearInterval(interval);
      if (unsub) unsub();
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.close();
      }
    };
  }, [autoRefresh]);

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a)));
    } catch (err) {}
  };

  const handleClearIncidents = async () => {
    try {
      await api.post('/api/agent/clear-incidents');
      stopIntrusionAlarm();
      setActionFeedback('Threat flags cleared.');
      setTimeout(() => setActionFeedback(''), 3000);
      fetchData();
    } catch (err) {}
  };

  const handleStartCalibration = async () => {
    try {
      setCalibrating(true);
      setCalibrationProgress(0);
      await api.post('/api/agent/calibrate-baseline?duration_seconds=30');
      setActionFeedback('Calibrating host baseline (30s)...');
      setTimeout(() => setActionFeedback(''), 4000);
    } catch (err) {}
  };

  const handleSensitivityChange = async (newVal) => {
    const val = parseFloat(newVal);
    setSensitivity(val);
    try {
      await api.post(`/api/agent/set-sensitivity?threshold=${val}`);
    } catch (err) {}
  };

  const handleToggleMute = () => {
    const isNowMuted = toggleMuteAlarm();
    setMuted(isNowMuted);
    if (isNowMuted) stopIntrusionAlarm();
  };

  const handleExportJSON = () => {
    const reportData = {
      timestamp: new Date().toISOString(),
      host: sys?.hostname || 'Host',
      anomaly: agentSnapshot?.host_anomaly || {},
      stats: stats,
      incidents: agentSnapshot?.active_incidents || []
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IDS_Telemetry_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return <LoadingSpinner message="Synchronizing live kernel telemetry..." />;
  }

  const mem = sys?.memory || {};
  const net = sys?.network || {};
  const hostAnomaly = agentSnapshot?.host_anomaly || {};
  const anomalyScore = hostAnomaly.anomaly_score !== undefined ? hostAnomaly.anomaly_score : 0.02;
  const isAnomaly = hostAnomaly.is_anomaly || false;
  const hasActiveThreats = (stats?.attack_records || 0) > 0 || (agentSnapshot?.active_incidents_count || 0) > 0 || isAnomaly;

  const scorePercent = Math.min(Math.round(anomalyScore * 100), 100);

  return (
    <div className="space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Soft UI Toolbar */}
      <motion.div 
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="neu-flat p-4 rounded-3xl flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-[#2563eb]">
            <Radio className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-extrabold text-slate-900 tracking-tight">
                Live Host Stream
              </span>
              <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full neu-inset text-emerald-700 font-bold">
                1s
              </span>
            </div>
            <div className="text-xs text-slate-500 font-medium">
              {sys?.hostname || 'Host'} • {sys?.os_name || 'Windows'}
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleStartCalibration}
            disabled={calibrating}
            className={`px-4 py-2 rounded-2xl text-xs font-semibold transition-all flex items-center gap-2 ${
              calibrating
                ? 'neu-inset text-amber-700 font-bold'
                : 'neu-button text-slate-700 hover:text-slate-900'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-600" />
            {calibrating ? `Calibrating (${calibrationProgress}%)` : 'Calibrate Baseline'}
          </button>

          <button
            onClick={handleToggleMute}
            className={`px-4 py-2 rounded-2xl text-xs font-semibold transition-all flex items-center gap-2 ${
              muted 
                ? 'neu-inset text-rose-600' 
                : 'neu-button text-slate-700 hover:text-slate-900'
            }`}
          >
            {muted ? <VolumeX className="w-3.5 h-3.5 text-rose-600" /> : <Volume2 className="w-3.5 h-3.5 text-[#2563eb]" />}
            {muted ? 'Muted' : 'Sound'}
          </button>

          <button
            onClick={handleExportJSON}
            className="px-4 py-2 rounded-2xl text-xs neu-button text-slate-700 hover:text-slate-900 transition-all flex items-center gap-2 font-semibold"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            Export
          </button>

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
            className="p-2.5 rounded-2xl neu-button text-slate-600 hover:text-slate-900 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-[#2563eb]' : ''}`} />
          </button>
        </div>
      </motion.div>

      {actionFeedback && (
        <motion.div 
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="p-3.5 rounded-2xl neu-inset text-slate-800 text-xs font-mono flex items-center justify-between"
        >
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>{actionFeedback}</span>
          </div>
          <button onClick={() => setActionFeedback('')} className="text-slate-500 hover:text-slate-800 text-[10px] font-bold">Dismiss</button>
        </motion.div>
      )}

      {/* Hero Dual Anomaly & Posture Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Anomaly Gauge Card (Matching Circular Dial in Reference Image) */}
        <div className="lg:col-span-8 neu-flat p-6 rounded-[28px] space-y-5">
          <div className="flex items-center justify-between border-b border-slate-300/40 pb-3">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-xl neu-circle flex items-center justify-center text-[#2563eb]">
                <Gauge className="w-4 h-4" />
              </div>
              <span className="text-sm font-bold text-slate-900 tracking-tight">
                Host Behavioral Anomaly
              </span>
            </div>
            <span className={`text-[11px] font-mono px-3 py-1 rounded-xl font-bold neu-inset ${
              isAnomaly 
                ? 'text-rose-600' 
                : 'text-emerald-700'
            }`}>
              {isAnomaly ? 'ANOMALY DETECTED' : (calibrating ? 'CALIBRATING...' : 'BASELINE NORMAL')}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-12 gap-5 items-center">
            {/* Tactile Circular Progress Meter */}
            <div className="sm:col-span-5 flex flex-col items-center justify-center py-2">
              <div className="relative w-36 h-36 flex items-center justify-center neu-circle p-2">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                  <defs>
                    <linearGradient id="neuBlueGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#3b82f6" />
                      <stop offset="100%" stopColor="#1d4ed8" />
                    </linearGradient>
                  </defs>
                  {/* Outer track */}
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    stroke="#d5dde7"
                    strokeWidth="8"
                    fill="none"
                  />
                  {/* Progress arc */}
                  <motion.circle
                    cx="50"
                    cy="50"
                    r="40"
                    stroke={scorePercent >= 70 ? '#ef4444' : 'url(#neuBlueGrad)'}
                    strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={2 * Math.PI * 40}
                    initial={{ strokeDashoffset: 2 * Math.PI * 40 }}
                    animate={{ strokeDashoffset: (2 * Math.PI * 40) * (1 - Math.max(scorePercent, 4) / 100) }}
                    transition={{ duration: 0.6, ease: 'easeOut' }}
                    fill="none"
                  />
                </svg>

                {/* Inner Embossed Disc */}
                <div 
                  ref={scoreRef}
                  className="absolute inset-4 rounded-full neu-circle flex flex-col items-center justify-center text-center p-2"
                >
                  <span className={`text-xl font-black font-mono leading-none ${scorePercent >= 70 ? 'text-rose-600' : 'text-[#2563eb]'}`}>
                    {scorePercent}%
                  </span>
                  <span className="text-[9px] uppercase font-bold text-slate-400 mt-1 tracking-wider">
                    Index
                  </span>
                </div>
              </div>
            </div>

            {/* Metrics cards */}
            <div className="sm:col-span-7 grid grid-cols-2 gap-3.5">
              <div className="p-4 rounded-2xl neu-inset">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Deviation</span>
                <div className="text-base font-mono font-bold text-slate-900 mt-1">
                  {hostAnomaly.z_deviation_max !== undefined ? `${hostAnomaly.z_deviation_max}σ` : '0.38σ'}
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 font-medium">Mahalanobis Vector</p>
              </div>

              <div className="p-4 rounded-2xl neu-inset">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Detector</span>
                <div className="text-xs font-extrabold text-[#2563eb] mt-1">Isolation Forest</div>
                <div className="text-[10px] text-slate-500 mt-0.5 font-mono">
                  Cutoff: <span className="text-slate-800 font-bold">{sensitivity.toFixed(2)}</span>
                </div>
              </div>

              <div className="col-span-2 p-3.5 rounded-2xl neu-inset grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs font-mono">
                <div>
                  <div className="text-[10px] text-slate-500 font-sans uppercase">In</div>
                  <div className="text-slate-800 font-bold">{hostAnomaly.telemetry_metrics?.packet_rate_in_sec || 0} p/s</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 font-sans uppercase">Out</div>
                  <div className="text-slate-800 font-bold">{hostAnomaly.telemetry_metrics?.packet_rate_out_sec || 0} p/s</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 font-sans uppercase">Throughput</div>
                  <div className="text-[#2563eb] font-bold">{(hostAnomaly.telemetry_metrics?.bytes_recv_kb_sec || 0).toFixed(1)} KB/s</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 font-sans uppercase">Sockets</div>
                  <div className="text-slate-800 font-bold">{hostAnomaly.telemetry_metrics?.active_sockets || 0}</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Posture & Slider */}
        <div className="lg:col-span-4 neu-flat p-6 rounded-[28px] flex flex-col justify-between space-y-5">
          <div>
            <span className="text-[11px] uppercase text-slate-500 font-bold tracking-wider">DEFCON Posture</span>
            <div className={`p-4 rounded-2xl neu-inset mt-3 flex items-center gap-3.5 ${
              hasActiveThreats ? 'text-rose-700' : 'text-slate-800'
            }`}>
              <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center shrink-0">
                {hasActiveThreats ? <ShieldAlert className="w-5 h-5 text-rose-600" /> : <ShieldCheck className="w-5 h-5 text-emerald-600" />}
              </div>
              <div>
                <div className="text-xs font-black uppercase tracking-wide">
                  {hasActiveThreats ? 'DEFCON 1 — Alert' : 'DEFCON 5 — Nominal'}
                </div>
                <div className="text-[11px] text-slate-500 font-medium">
                  {hasActiveThreats ? 'Host anomaly detected' : 'All telemetry nominal'}
                </div>
              </div>
            </div>
          </div>

          {/* Neumorphic Sensitivity Cutoff Slider */}
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between text-xs text-slate-700">
              <span className="flex items-center gap-1.5 font-bold">
                <Sliders className="w-3.5 h-3.5 text-[#2563eb]" /> Anomaly Threshold:
              </span>
              <span className="text-[#2563eb] font-black font-mono">{sensitivity.toFixed(2)}</span>
            </div>
            <input 
              type="range" 
              min="0.50" 
              max="0.95" 
              step="0.05"
              value={sensitivity}
              onChange={(e) => handleSensitivityChange(e.target.value)}
              className="neu-slider my-2"
            />
            <div className="flex justify-between text-[10px] text-slate-400 font-semibold px-1">
              <span>0.50 (Loose)</span>
              <span>0.70</span>
              <span>0.95 (Strict)</span>
            </div>
          </div>

          {hasActiveThreats && (
            <button
              onClick={handleClearIncidents}
              className="w-full py-2.5 rounded-2xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-mono font-bold transition-all shadow-md"
            >
              Clear Flagged Incidents
            </button>
          )}
        </div>
      </div>

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Monitored Packets"
          value={(stats?.total_records || 0).toLocaleString()}
          subtitle="In-Memory Kernel Ring"
          icon={Activity}
          badgeText="Live Stream"
        />
        <StatCard
          title="Active Anomalies"
          value={(stats?.attack_records || 0).toLocaleString()}
          subtitle={hasActiveThreats ? 'Active Outlier' : '0 Safe'}
          icon={ShieldAlert}
          badgeText={hasActiveThreats ? "Alert" : "Clean"}
        />
        <StatCard
          title="Anomaly Score"
          value={anomalyScore.toFixed(3)}
          subtitle="Outlier Vector Distance"
          icon={Gauge}
          badgeText="Isolation Forest"
        />
        <StatCard
          title="SIEM Alerts"
          value={(stats?.critical_alerts || 0).toLocaleString()}
          subtitle="Triage Action Queue"
          icon={AlertTriangle}
          badgeText="Queue"
        />
      </div>

      {/* Hardware Telemetry Bar */}
      <div className="neu-flat p-5 rounded-[24px] text-xs">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-300/40">
          <div className="space-y-1">
            <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Host</span>
            <div className="text-slate-900 font-extrabold text-xs">{sys?.hostname || 'Host'}</div>
            <div className="text-[11px] text-slate-500 font-medium">{sys?.os_name || 'Windows'}</div>
          </div>
          <div className="space-y-1 sm:pl-4 pt-3 sm:pt-0">
            <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">CPU Load</span>
            <div className="text-slate-900 font-bold text-xs font-mono">{sys?.cpu_usage_pct || 0}% ({sys?.cpu_cores_logical || 4} Cores)</div>
            <div className="w-full neu-inset h-2 rounded-full overflow-hidden p-0.5 mt-1">
              <div className="bg-gradient-to-r from-blue-500 to-indigo-600 h-full rounded-full" style={{ width: `${Math.min(sys?.cpu_usage_pct || 0, 100)}%` }} />
            </div>
          </div>
          <div className="space-y-1 sm:pl-4 pt-3 sm:pt-0">
            <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Memory</span>
            <div className="text-slate-900 font-bold text-xs font-mono">{mem.used_gb || 0} / {mem.total_gb || 0} GB</div>
            <div className="w-full neu-inset h-2 rounded-full overflow-hidden p-0.5 mt-1">
              <div className="bg-gradient-to-r from-blue-500 to-indigo-600 h-full rounded-full" style={{ width: `${Math.min(mem.percent_used || 0, 100)}%` }} />
            </div>
          </div>
          <div className="space-y-1 sm:pl-4 pt-3 sm:pt-0">
            <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Network</span>
            <div className="text-slate-900 font-bold text-xs font-mono">↓{net.bytes_recv_mb || 0}MB ↑{net.bytes_sent_mb || 0}MB</div>
            <div className="text-[11px] text-slate-500 font-medium">{net.packets_recv || 0} Packets</div>
          </div>
        </div>
      </div>

      {/* 3 Real-time Visual Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="neu-flat rounded-[28px] p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">Traffic Distribution</h3>
          </div>
          <NormalVsAttackChart data={charts?.normal_vs_attack || []} />
        </div>

        <div className="neu-flat rounded-[28px] p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">Vector Categories</h3>
          </div>
          <AttackCategoryBarChart data={charts?.attack_categories || []} />
        </div>

        <div className="neu-flat rounded-[28px] p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">Telemetry Timeline</h3>
          </div>
          <TimelineAreaChart data={charts?.detection_timeline || []} />
        </div>
      </div>

      {/* Atria AI Engine Autonomous Defense & Realtime Live Incidents */}
      <div className="neu-flat rounded-[28px] p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-300/40 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-2xl neu-circle flex items-center justify-center text-amber-500">
              <Zap className="w-5 h-5 fill-amber-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                  Atria AI Autonomous Neural Engine
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-md neu-inset text-emerald-700 font-bold flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
                  ACTIVE SENTINEL
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-medium">
                Autonomous Trigger-Based Threat Scanner • 0 Tokens Idle • Auto-Wake on Inbound Exploits & Suspicious Downloads
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Link
              to="/ai-decision"
              className="neu-button px-3 py-1.5 rounded-xl text-xs font-bold text-[#2563eb] hover:text-blue-700 transition-all flex items-center gap-1.5"
            >
              <Zap className="w-3.5 h-3.5 text-amber-500" />
              Atria AI Center
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* Active Live Incidents Inspected by Atria AI */}
        {agentSnapshot?.active_incidents && agentSnapshot.active_incidents.length > 0 ? (
          <div className="space-y-3">
            {agentSnapshot.active_incidents.map((inc, idx) => {
              const isConfirmed = inc.is_harmful === true || inc.ai_status === 'CONFIRMED_THREAT';
              const isBenign = inc.ai_status === 'BENIGN_VERIFIED';

              return (
                <div 
                  key={inc.incident_id || idx}
                  className={`p-4 rounded-2xl neu-inset flex flex-col md:flex-row md:items-center justify-between gap-4 border-l-4 transition-all ${
                    isConfirmed 
                      ? 'border-rose-600 bg-rose-50/20' 
                      : isBenign 
                        ? 'border-emerald-600 bg-emerald-50/20' 
                        : 'border-amber-500 bg-amber-50/20'
                  }`}
                >
                  <div className="space-y-1.5 max-w-2xl">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-black tracking-wider uppercase ${
                        isConfirmed 
                          ? 'bg-rose-600 text-white shadow-sm' 
                          : isBenign 
                            ? 'bg-emerald-600 text-white' 
                            : 'bg-amber-500 text-white animate-pulse'
                      }`}>
                        {isConfirmed ? 'CRITICAL THREAT CONFIRMED' : isBenign ? 'SAFE / BENIGN VERIFIED' : 'ATRIA AI ANALYZING'}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-800">
                        {inc.title || 'Security Telemetry Event'}
                      </span>
                    </div>

                    <p className="text-xs text-slate-600 font-mono">
                      {inc.evidence || 'Realtime system socket or download stream under inspection.'}
                    </p>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500 font-mono">
                      {inc.source_ip && <span>Remote: <strong className="text-slate-800">{inc.source_ip}</strong></span>}
                      {inc.target_port && <span>Port: <strong className="text-slate-800">{inc.target_port}</strong></span>}
                      {inc.process && <span>Process: <strong className="text-slate-800">{inc.process}</strong></span>}
                      {inc.confidence && <span>Confidence: <strong className="text-slate-800">{inc.confidence}%</strong></span>}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                      onClick={() => navigate('/ai-decision', { state: { incident: inc } })}
                      className="neu-button px-3.5 py-2 rounded-xl text-xs font-bold text-slate-800 hover:text-[#2563eb] transition-all flex items-center gap-1.5"
                    >
                      <Zap className="w-3.5 h-3.5 text-amber-500" />
                      Atria AI Report
                    </button>

                    {inc.containment?.can_block_ip && (
                      <button
                        onClick={async () => {
                          try {
                            await containBlockIP(inc.containment.target_ip);
                            setActionFeedback(`Netsh firewall rule applied: IP ${inc.containment.target_ip} blocked.`);
                            setTimeout(() => setActionFeedback(''), 4000);
                          } catch (e) {}
                        }}
                        className="px-3 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold font-mono transition-all shadow"
                      >
                        Block IP
                      </button>
                    )}

                    {inc.containment?.can_kill_process && (
                      <button
                        onClick={async () => {
                          try {
                            await containKillProcess(inc.containment.target_pid);
                            setActionFeedback(`Process PID ${inc.containment.target_pid} terminated.`);
                            setTimeout(() => setActionFeedback(''), 4000);
                          } catch (e) {}
                        }}
                        className="px-3 py-2 rounded-xl bg-slate-900 hover:bg-black text-white text-xs font-bold font-mono transition-all shadow"
                      >
                        Kill Process
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="p-4 rounded-2xl neu-inset flex items-center justify-between text-xs text-slate-600 font-mono">
            <div className="flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0" />
              <div>
                <span className="font-bold text-slate-800">Zero Active Incursions</span> • Atria AI Neural Sentinel Guarding Network Sockets & Downloads
              </div>
            </div>
            <span className="text-[10px] text-slate-500 font-sans font-semibold">Token Saver Active (0 consumed)</span>
          </div>
        )}
      </div>

      {/* Incident Triage & Active Defense Remediation Table */}
      <div className="neu-flat rounded-[28px] p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg neu-circle flex items-center justify-center text-[#2563eb]">
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>
            Incident Triage & Defense
          </h3>
          <Link
            to="/alerts"
            className="text-xs font-bold text-[#2563eb] hover:underline flex items-center gap-1 transition-colors"
          >
            All Incidents ({alerts.length})
            <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        <AlertTable 
          alerts={alerts} 
          onStatusChange={handleStatusChange} 
          onActionFeedback={(msg) => {
            setActionFeedback(msg);
            setTimeout(() => setActionFeedback(''), 3500);
          }} 
        />
      </div>
    </div>
  );
}
