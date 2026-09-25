import React, { useState, useEffect } from 'react';
import { 
  GitCommit, 
  Users, 
  Lock, 
  Zap, 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Layers, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  Radio, 
  Terminal, 
  HardDrive, 
  Eye, 
  ArrowRight,
  TrendingUp
} from 'lucide-react';
import { 
  getKillChainData, 
  getUEBAData, 
  getEncryptedTrafficData, 
  getPlaybooks, 
  executePlaybook 
} from '../services/api';
import StatCard from '../components/StatCard';
import LoadingSpinner from '../components/LoadingSpinner';

export default function AdvancedSOC() {
  const [activeTab, setActiveTab] = useState('killchain'); // 'killchain', 'ueba', 'encrypted', 'playbooks'
  
  // Data states
  const [killChain, setKillChain] = useState(null);
  const [ueba, setUeba] = useState(null);
  const [encryptedFlows, setEncryptedFlows] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  
  const [loading, setLoading] = useState(true);
  const [executingPlaybook, setExecutingPlaybook] = useState(null);
  const [executionResult, setExecutionResult] = useState(null);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [kcData, uebaData, encData, pbData] = await Promise.all([
          getKillChainData(),
          getUEBAData(),
          getEncryptedTrafficData(),
          getPlaybooks()
        ]);
        setKillChain(kcData);
        setUeba(uebaData);
        setEncryptedFlows(encData);
        setPlaybooks(pbData);
      } catch (err) {
        console.error("Failed to load Advanced SOC data:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, []);

  const handleExecutePlaybook = async (playbookId) => {
    setExecutingPlaybook(playbookId);
    setExecutionResult(null);
    try {
      const res = await executePlaybook({
        playbook_id: playbookId,
        parameters: { source_ip: '203.0.113.88', pid: 4920, username: 'compromised_dba' }
      });
      setExecutionResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setExecutingPlaybook(null);
    }
  };

  if (loading) return <LoadingSpinner message="Initializing Advanced SOC Architecture..." />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          Advanced SOC Intelligence & Defense Operations
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Cyber Kill Chain correlation, User Entity Behavior Analytics (UEBA), Encrypted TLS inspection, and SOAR automated incident playbooks
        </p>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveTab('killchain')}
          className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'killchain'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitCommit className="w-4 h-4" />
          Cyber Kill Chain Correlation
        </button>

        <button
          onClick={() => setActiveTab('ueba')}
          className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'ueba'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Users className="w-4 h-4" />
          UEBA Behavioral Profiling
        </button>

        <button
          onClick={() => setActiveTab('encrypted')}
          className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'encrypted'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Lock className="w-4 h-4" />
          Encrypted Traffic (TLS 1.3)
        </button>

        <button
          onClick={() => setActiveTab('playbooks')}
          className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'playbooks'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Zap className="w-4 h-4" />
          Automated SOAR Playbooks ({playbooks.length})
        </button>
      </div>

      {/* 1. CYBER KILL CHAIN TAB */}
      {activeTab === 'killchain' && (
        <div className="space-y-6 animate-fadeIn">
          {/* 7-Stage Matrix Header */}
          <div className="cyber-panel p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 mb-3 flex items-center gap-2">
              <GitCommit className="w-4 h-4 text-cyan-400" />
              Lockheed Martin / MITRE ATT&CK 7-Stage Threat Pipeline
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
              {killChain?.stages?.map((stg, idx) => (
                <div key={stg.id} className="p-3 rounded-lg bg-[#090d18] border border-slate-800 text-center">
                  <div className="text-cyan-400 font-mono text-[11px] font-bold">Stage 0{idx + 1}</div>
                  <div className="text-xs font-semibold text-slate-200 mt-1">{stg.name.split('. ')[1]}</div>
                  <div className="text-[10px] text-slate-400 mt-1 line-clamp-2">{stg.description}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Active Attack Campaigns */}
          <div className="space-y-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Correlated Multi-Stage Intrusion Campaigns
            </h3>

            {killChain?.campaigns?.map((camp) => (
              <div key={camp.id} className="cyber-panel p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        {camp.id}
                      </span>
                      <h4 className="text-sm font-bold text-slate-100">{camp.name}</h4>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">
                      Attacker: <span className="text-rose-400 font-mono font-bold">{camp.attacker_ip}</span> • Target: <span className="text-cyan-400 font-mono">{camp.target_host}</span>
                    </p>
                  </div>

                  <div className="text-right">
                    <span className="px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                      {camp.status} ({camp.progress_pct}% Kill Chain Progression)
                    </span>
                  </div>
                </div>

                {/* Stages Timeline */}
                <div className="space-y-3">
                  {camp.stages_activated.map((st, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                      <div className="w-6 h-6 rounded-full bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-xs font-mono font-bold text-rose-400 shrink-0 mt-0.5">
                        {i + 1}
                      </div>
                      <div className="flex-1">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                          <span className="text-xs font-bold text-slate-200">{st.stage_name}: <strong className="text-rose-400">{st.matched_threat}</strong></span>
                          <span className="text-[11px] font-mono text-cyan-400">Confidence: {st.confidence}%</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">{st.details}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 2. UEBA TAB */}
      {activeTab === 'ueba' && (
        <div className="space-y-6 animate-fadeIn">
          {/* UEBA Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              title="Monitored Entities"
              value={ueba?.metrics?.total_entities_monitored || 148}
              subtitle="Users & Host Devices"
              icon={Users}
              color="cyan"
              badgeText="Active Fleet"
            />
            <StatCard
              title="Critical Entity Threats"
              value={ueba?.metrics?.critical_risk_entities || 1}
              subtitle="Suspected Compromise"
              icon={ShieldAlert}
              color="rose"
              badgeText="Action Required"
            />
            <StatCard
              title="Lateral Movement"
              value={ueba?.metrics?.lateral_movement_attempts || 2}
              subtitle="Internal Subnet Pivots"
              icon={Activity}
              color="purple"
              badgeText="East-West Traffic"
            />
            <StatCard
              title="Avg Fleet Risk"
              value={`${ueba?.metrics?.avg_fleet_risk_score || 18.4}/100`}
              subtitle="Baseline Healthy"
              icon={ShieldCheck}
              color="emerald"
              badgeText="Behavioral Normal"
            />
          </div>

          {/* Entity Profile Cards */}
          <div className="cyber-panel overflow-hidden">
            <div className="p-4 border-b border-slate-800 bg-[#0a0f1d]">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                User & Device Behavioral Anomaly Profiles
              </h3>
            </div>

            <div className="divide-y divide-slate-800">
              {ueba?.entities?.map((ent) => (
                <div key={ent.entity_id} className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-900/40 transition-colors">
                  <div className="space-y-2">
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                        {ent.entity_id}
                      </span>
                      <h4 className="text-sm font-bold text-slate-100">{ent.name}</h4>
                      <span className="text-xs text-slate-400">({ent.role})</span>
                    </div>

                    <div className="space-y-1">
                      {ent.anomaly_indicators?.map((ind, idx) => (
                        <div key={idx} className="text-xs text-slate-300 flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${ind.severity === 'CRITICAL' ? 'bg-red-400' : 'bg-amber-400'}`}></span>
                          <strong className="text-slate-200">{ind.type}:</strong>
                          <span className="text-slate-400">{ind.detail}</span>
                        </div>
                      ))}
                      {ent.anomaly_indicators?.length === 0 && (
                        <div className="text-xs text-emerald-400 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Behavior fully conforms to historical 30-day baseline.
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-6 shrink-0">
                    <div className="text-right">
                      <div className="text-[10px] uppercase text-slate-400 font-sans">Baseline Deviation</div>
                      <div className="text-sm font-bold font-mono text-amber-400">{ent.baseline_deviation_pct}%</div>
                    </div>

                    <div className="text-right">
                      <div className="text-[10px] uppercase text-slate-400 font-sans">Risk Score</div>
                      <div className={`text-lg font-bold font-mono ${
                        ent.risk_score > 80 ? 'text-rose-400' : ent.risk_score > 50 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {ent.risk_score}/100
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 3. ENCRYPTED TRAFFIC TAB */}
      {activeTab === 'encrypted' && (
        <div className="space-y-6 animate-fadeIn">
          <div className="cyber-panel p-5 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border-cyan-500/30">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-1 flex items-center gap-2">
              <Lock className="w-4 h-4" />
              Encrypted TLS 1.3 Telemetry & Entropy Inspection Engine
            </h3>
            <p className="text-xs text-slate-300">
              Inspects encrypted session packets without decrypting payloads by evaluating packet length burst sequences, inter-arrival timing jitter, client hello ALPN, and Shannon entropy scores.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {encryptedFlows.map((flow) => (
              <div key={flow.flow_id} className={`cyber-panel p-5 flex flex-col justify-between space-y-4 ${
                flow.risk_level === 'CRITICAL' ? 'border-rose-500/50' : 'border-slate-800'
              }`}>
                <div>
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                    <span className="font-mono text-xs text-cyan-400 font-bold">{flow.flow_id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      flow.risk_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
                    }`}>
                      {flow.tls_version}
                    </span>
                  </div>

                  <div className="mt-3 space-y-2 text-xs">
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase">Verdict</span>
                      <strong className={flow.risk_level === 'CRITICAL' ? 'text-rose-400' : 'text-emerald-400'}>
                        {flow.verdict}
                      </strong>
                    </div>

                    <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 font-mono text-[11px]">
                      <div>
                        <span className="text-slate-500 text-[10px]">Entropy:</span>
                        <div className="text-slate-200 font-bold">{flow.entropy_score} / 8.0</div>
                      </div>
                      <div>
                        <span className="text-slate-500 text-[10px]">Timing Jitter:</span>
                        <div className="text-slate-200 font-bold">{flow.timing_jitter_ms} ms</div>
                      </div>
                    </div>

                    <div className="p-2.5 rounded bg-black/60 font-mono text-[10px] text-slate-300 space-y-1">
                      <div>SNI: {flow.features?.sni}</div>
                      <div>In/Out Ratio: {flow.features?.in_out_byte_ratio}</div>
                      <div>Periodicity: {flow.features?.mean_inter_arrival_time_ms} ms</div>
                    </div>
                  </div>
                </div>

                <p className="text-[11px] text-slate-400 leading-relaxed italic border-t border-slate-800 pt-2">
                  "{flow.forensic_rationale}"
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. SOAR AUTOMATED PLAYBOOKS TAB */}
      {activeTab === 'playbooks' && (
        <div className="space-y-6 animate-fadeIn">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {playbooks.map((pb) => (
              <div key={pb.id} className="cyber-panel p-5 flex flex-col justify-between space-y-4 hover:border-cyan-500/50 transition-all">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      {pb.target}
                    </span>
                    <span className="text-xs font-mono text-emerald-400 font-bold">{pb.status}</span>
                  </div>

                  <h3 className="text-sm font-bold text-slate-100 mt-2.5">{pb.name}</h3>
                  <p className="text-xs text-amber-400 mt-0.5">Trigger: {pb.trigger}</p>

                  <div className="mt-3 space-y-1 text-xs text-slate-400">
                    {pb.actions.map((act, i) => (
                      <div key={i} className="text-[11px]">{act}</div>
                    ))}
                  </div>

                  <div className="mt-3 p-2 rounded bg-black font-mono text-[10px] text-emerald-400 border border-slate-800">
                    <code>{pb.default_command}</code>
                  </div>
                </div>

                <button
                  onClick={() => handleExecutePlaybook(pb.id)}
                  disabled={executingPlaybook === pb.id}
                  className="w-full py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  {executingPlaybook === pb.id ? 'Executing Containment...' : 'Execute SOAR Playbook'}
                </button>
              </div>
            ))}
          </div>

          {/* Execution Result Log */}
          {executionResult && (
            <div className="p-5 rounded-xl bg-slate-900 border border-emerald-500/50 space-y-3 animate-fadeIn">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-bold text-slate-100 uppercase">
                    Playbook Execution Audit Trail: {executionResult.execution_id}
                  </span>
                </div>
                <span className="text-xs font-mono text-emerald-400 font-bold">{executionResult.status}</span>
              </div>

              <p className="text-xs text-slate-200 font-mono">
                {executionResult.containment_summary}
              </p>

              <div className="p-2.5 rounded bg-black font-mono text-xs text-emerald-400 border border-emerald-500/30">
                <code>Executed: {executionResult.command_executed}</code>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
