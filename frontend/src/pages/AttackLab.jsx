import React, { useState, useEffect } from 'react';
import {
  Flame, Globe, Server, Terminal, Play, Copy, Check,
  RefreshCw, Sliders, ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle2, Zap
} from 'lucide-react';
import { getAttackScenarios, simulateAttack, getModels } from '../services/api';
import { playIntrusionAlarm } from '../utils/audioAlarm';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';
import { motion } from 'framer-motion';

const SEVERITY_COLORS = {
  CRITICAL: 'text-red-400 bg-red-500/10',
  HIGH:     'text-orange-400 bg-orange-500/10',
  MEDIUM:   'text-yellow-400 bg-yellow-500/10',
  LOW:      'text-emerald-400 bg-emerald-500/10',
};

const TABS = [
  { id: 'web',     label: 'Web Application',   Icon: Globe },
  { id: 'network', label: 'Server & Network',   Icon: Server },
  { id: 'custom',  label: 'Custom Payload',     Icon: Terminal },
];

export default function AttackLab({ onTriggerAlarm }) {
  const [scenarios, setScenarios] = useState(() => getCachedData('attack_scenarios', []));
  const [models, setModels] = useState(() => getCachedData('ml_models', []));
  const [selectedModel, setSelectedModel] = useState('Random Forest');
  const [activeTab, setActiveTab] = useState('web');
  const [simulating, setSimulating] = useState(null); // scenario id being simulated
  const [attackResult, setAttackResult] = useState(null);
  const [copiedRule, setCopiedRule] = useState(false);
  const [loading, setLoading] = useState(() => !hasCachedData('attack_scenarios'));

  // Custom payload fields
  const [customTarget,  setCustomTarget]  = useState('192.168.1.100:80');
  const [customService, setCustomService] = useState('http');
  const [customPayload, setCustomPayload] = useState("UNION SELECT null, username, password FROM users WHERE admin=1--");

  useEffect(() => {
    Promise.all([
      getAttackScenarios().catch(err => { console.warn(err); return []; }),
      getModels().catch(err => { console.warn(err); return []; })
    ])
      .then(([sc, md]) => {
        if (sc && sc.length > 0) {
          setScenarios(sc);
          setCachedData('attack_scenarios', sc);
        }
        if (md && md.length > 0) {
          setModels(md);
          setCachedData('ml_models', md);
          setSelectedModel(md[0].name);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const fireResult = (res, sourceLabel) => {
    setAttackResult(res);
    if (res.prediction === 'ATTACK' || res.risk_level === 'CRITICAL' || res.risk_level === 'HIGH') {
      playIntrusionAlarm(res.risk_level);
      if (onTriggerAlarm) {
        onTriggerAlarm({
          title: res.scenario_name || res.attack_type || 'Attack Detected',
          attack_type: res.attack_type,
          risk_level: res.risk_level,
          anomaly_score: res.anomaly_score,
          source_ip: sourceLabel || '203.0.113.88',
        });
      }
    }
  };

  const handleLaunchScenario = async (scenario) => {
    setSimulating(scenario.id);
    setAttackResult(null);
    try {
      const res = await simulateAttack({ scenario_id: scenario.id, model_name: selectedModel });
      fireResult(res, scenario.name);
    } catch (err) {
      console.error('Attack simulation failed:', err);
    } finally {
      setSimulating(null);
    }
  };

  const handleLaunchCustom = async () => {
    setSimulating('custom');
    setAttackResult(null);
    const customFeatures = {
      duration: 1, protocol_type: 'tcp', service: customService, flag: 'SF',
      src_bytes: 1450, dst_bytes: 3200, land: 0, wrong_fragment: 0, urgent: 0,
      hot: 2, num_failed_logins: 0, logged_in: 1, num_compromised: 1, root_shell: 0,
      su_attempted: 0, num_root: 0, num_file_creations: 0, num_shells: 0,
      num_access_files: 1, num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
      count: 3, srv_count: 3, serror_rate: 0.0, srv_serror_rate: 0.0,
      rerror_rate: 0.0, srv_rerror_rate: 0.0, same_srv_rate: 1.0, diff_srv_rate: 0.0,
      srv_diff_host_rate: 0.0, dst_host_count: 20, dst_host_srv_count: 20,
      dst_host_same_srv_rate: 1.0, dst_host_diff_srv_rate: 0.0,
      dst_host_same_src_port_rate: 0.0, dst_host_srv_diff_host_rate: 0.0,
      dst_host_serror_rate: 0.0, dst_host_srv_serror_rate: 0.0,
      dst_host_rerror_rate: 0.0, dst_host_srv_rerror_rate: 0.0
    };
    try {
      const res = await simulateAttack({ scenario_id: 'custom', model_name: selectedModel, custom_payload: customFeatures });
      fireResult(res, customTarget);
    } catch (err) {
      console.error('Custom simulation failed:', err);
    } finally {
      setSimulating(null);
    }
  };

  const handleCopyFirewallRule = (rule) => {
    navigator.clipboard.writeText(rule);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2500);
  };

  if (loading) return <LoadingSpinner message="Loading attack scenarios & ML models..." />;

  const webScenarios     = scenarios.filter(s => s.target_type?.includes('Website') || s.target_type?.includes('Web Server'));
  const networkScenarios = scenarios.filter(s => !s.target_type?.includes('Website') && !s.target_type?.includes('Web Server'));
  const visibleScenarios = activeTab === 'web' ? webScenarios : networkScenarios;

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
            <Flame className="w-5 h-5 text-amber-500" />
          </div>
          <div>
            <h1 className="text-sm font-extrabold text-slate-900 tracking-tight">
              Attack Testing Lab
            </h1>
            <p className="text-xs text-slate-500 font-medium">
              Simulate intrusion vectors to verify AI detection & alarm pipeline
            </p>
          </div>
        </div>

        {/* Model selector */}
        <div className="neu-button flex items-center gap-2 px-3.5 py-2 rounded-2xl text-xs">
          <Sliders className="w-3.5 h-3.5 text-[#2563eb]" />
          <span className="text-slate-500 font-bold text-[11px]">Model:</span>
          <select
            value={selectedModel}
            onChange={(e) => setSelectedModel(e.target.value)}
            className="bg-transparent text-[#2563eb] font-bold focus:outline-none cursor-pointer"
          >
            {models.map((m) => (
              <option key={m.id} value={m.name} className="bg-[#edf4f0] text-slate-800">{m.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 neu-inset p-1.5 rounded-2xl w-fit">
        {TABS.map(({ id, label, Icon }) => (
          <button
            key={id}
            onClick={() => { setActiveTab(id); setAttackResult(null); }}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === id
                ? 'neu-accent-btn text-white'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Scenario Cards (Web / Network) */}
      {(activeTab === 'web' || activeTab === 'network') && (
        <div>
          {visibleScenarios.length === 0 ? (
            <div className="neu-flat rounded-[28px] p-10 text-center text-slate-500 font-medium text-xs">
              No scenarios loaded. Check backend connection.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {visibleScenarios.map((sc) => {
                const isBusy = simulating === sc.id;
                return (
                  <div
                    key={sc.id}
                    className="neu-flat rounded-[28px] p-6 flex flex-col justify-between gap-4"
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold neu-inset ${SEVERITY_COLORS[sc.severity] || 'text-slate-700'}`}>
                          {sc.severity}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono font-bold">{sc.target_type}</span>
                      </div>

                      <h3 className="text-sm font-extrabold text-slate-900">{sc.name}</h3>
                      <p className="text-xs text-slate-600 font-medium leading-relaxed">{sc.description}</p>

                      {/* Payload preview */}
                      <div className="neu-inset rounded-2xl p-3.5 font-mono text-[11px] text-slate-800 break-all">
                        <code>{sc.payload_preview}</code>
                      </div>
                    </div>

                    <button
                      onClick={() => handleLaunchScenario(sc)}
                      disabled={!!simulating}
                      className="w-full py-3 rounded-2xl neu-accent-btn font-bold text-xs tracking-wider uppercase transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                      {isBusy ? (
                        <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Running Simulation...</>
                      ) : (
                        <><Play className="w-3.5 h-3.5 fill-current" /> Launch Attack Test</>
                      )}
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Custom Payload Tab */}
      {activeTab === 'custom' && (
        <div className="neu-flat rounded-[28px] p-6 space-y-5">
          <div>
            <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2 mb-1">
              <Terminal className="w-4 h-4 text-[#2563eb]" />
              Custom Network Exploit Crafter
            </h3>
            <p className="text-xs text-slate-500 font-medium">
              Inject a custom payload into the ML detection pipeline to verify real-time classification.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1.5 ml-1">Target Endpoint</label>
              <div className="neu-inset rounded-2xl px-4 py-2.5">
                <input
                  type="text"
                  value={customTarget}
                  onChange={(e) => setCustomTarget(e.target.value)}
                  placeholder="192.168.1.100:80"
                  className="w-full bg-transparent border-none text-slate-900 font-mono text-xs focus:outline-none placeholder-slate-400 font-bold"
                />
              </div>
            </div>
            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1.5 ml-1">Service Protocol</label>
              <div className="neu-inset rounded-2xl px-4 py-2.5">
                <select
                  value={customService}
                  onChange={(e) => setCustomService(e.target.value)}
                  className="w-full bg-transparent border-none text-slate-900 font-mono text-xs focus:outline-none cursor-pointer font-bold"
                >
                  <option value="http" className="bg-[#edf4f0]">HTTP (Port 80/443)</option>
                  <option value="ssh" className="bg-[#edf4f0]">SSH (Port 22)</option>
                  <option value="ftp" className="bg-[#edf4f0]">FTP (Port 21)</option>
                  <option value="telnet" className="bg-[#edf4f0]">Telnet (Port 23)</option>
                  <option value="smtp" className="bg-[#edf4f0]">SMTP (Port 25)</option>
                </select>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1.5 ml-1">Exploit Payload</label>
            <div className="neu-inset rounded-2xl p-3">
              <textarea
                rows={3}
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                className="w-full bg-transparent border-none text-slate-900 font-mono text-xs focus:outline-none resize-none font-medium"
              />
            </div>
          </div>

          <button
            onClick={handleLaunchCustom}
            disabled={!!simulating}
            className="w-full py-3 rounded-2xl neu-accent-btn font-bold text-xs tracking-wider uppercase transition-all flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {simulating === 'custom' ? (
              <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Running Simulation...</>
            ) : (
              <><Play className="w-3.5 h-3.5 fill-current" /> Inject & Classify</>
            )}
          </button>
        </div>
      )}


      {/* Result Panel */}
      {attackResult && (
        <div className="neu-flat rounded-[28px] p-6 space-y-5">
          {/* Result header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-300/40 pb-4">
            <div className="flex items-center gap-3.5">
              <div className={`w-10 h-10 rounded-2xl neu-circle flex items-center justify-center shrink-0 ${
                attackResult.prediction === 'ATTACK' ? 'text-rose-600' : 'text-emerald-600'
              }`}>
                {attackResult.prediction === 'ATTACK' ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
              </div>
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  Simulation Result: {attackResult.scenario_name || 'Custom Payload'}
                </h3>
                <p className="text-[11px] text-slate-500 font-mono font-medium mt-0.5">
                  Detection #{attackResult.detection_id}
                  {attackResult.alert_id && ` · SIEM Alert #${attackResult.alert_id}`}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2.5 font-mono text-xs">
              <span className={`px-3 py-1 rounded-xl font-bold neu-inset ${
                attackResult.prediction === 'ATTACK' ? 'text-rose-600' : 'text-emerald-700'
              }`}>
                {attackResult.prediction}
              </span>
              <span className="px-3 py-1 rounded-xl font-bold neu-inset text-slate-800">
                Anomaly: {attackResult.anomaly_score?.toFixed(4)}
              </span>
            </div>
          </div>

          {/* AI Decision */}
          {attackResult.ai_decision && (
            <div className="space-y-4">
              <h4 className="text-xs font-black text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <Zap className="w-4 h-4 text-[#2563eb]" />
                AI Mitigation Analysis
                <span className="text-[10px] text-slate-500 font-normal normal-case">
                  (via {attackResult.ai_decision.source})
                </span>
              </h4>

              <div className="neu-inset rounded-2xl p-4 text-xs text-slate-800 leading-relaxed">
                <span className="block text-[10px] text-slate-500 font-bold uppercase mb-1">Threat Summary</span>
                {attackResult.ai_decision.threat_summary}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="neu-inset rounded-2xl p-4">
                  <span className="block text-[10px] text-rose-600 font-bold uppercase mb-1">Root Cause</span>
                  <span className="text-rose-950 font-bold">{attackResult.ai_decision.root_cause_analysis}</span>
                </div>
                <div className="neu-inset rounded-2xl p-4">
                  <span className="block text-[10px] text-amber-600 font-bold uppercase mb-1">Immediate Action</span>
                  <span className="text-amber-950 font-bold">{attackResult.ai_decision.immediate_action}</span>
                </div>
              </div>

              {/* Firewall Rule */}
              {attackResult.ai_decision.firewall_rule && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-bold text-emerald-700 uppercase tracking-wider">
                      Automated Firewall Rule
                    </span>
                    <button
                      onClick={() => handleCopyFirewallRule(attackResult.ai_decision.firewall_rule)}
                      className="text-xs text-[#2563eb] font-bold flex items-center gap-1 transition-colors"
                    >
                      {copiedRule ? (
                        <><Check className="w-3.5 h-3.5 text-emerald-600" /><span className="text-emerald-700">Copied!</span></>
                      ) : (
                        <><Copy className="w-3.5 h-3.5" />Copy Rule</>
                      )}
                    </button>
                  </div>
                  <div className="neu-inset rounded-2xl p-3.5 font-mono text-xs text-slate-800 overflow-x-auto">
                    <code>{attackResult.ai_decision.firewall_rule}</code>
                  </div>
                </div>
              )}

              {/* Mitigation Steps */}
              {attackResult.ai_decision.mitigation_steps?.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[11px] text-slate-600 uppercase font-bold tracking-wider">Mitigation Steps</span>
                  {attackResult.ai_decision.mitigation_steps.map((step, i) => (
                    <div key={i} className="flex items-start gap-2.5 text-xs text-slate-800 neu-inset p-3.5 rounded-2xl">
                      <CheckCircle2 className="w-4 h-4 text-[#2563eb] shrink-0 mt-0.5" />
                      <span className="font-semibold">{step}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

    </motion.div>
  );
}
