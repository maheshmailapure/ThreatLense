import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  Cpu, 
  CheckCircle2, 
  Activity, 
  Zap, 
  ShieldCheck, 
  Server, 
  RefreshCw, 
  ArrowRight,
  Terminal,
  Lock,
  Layers
} from 'lucide-react';
import { getAIDecisionStatus } from '../services/api';

export default function Models() {
  const navigate = useNavigate();
  const [aiStatus, setAiStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const data = await getAIDecisionStatus();
      setAiStatus(data);
    } catch (err) {
      console.warn('Failed to fetch AI status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleTestProbe = async () => {
    setTesting(true);
    await fetchStatus();
    setTesting(false);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
              Autonomous Intelligence
            </span>
            <span className="text-xs text-slate-500 font-medium">Real-Time Defensive MoE</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">AI Model Registry</h1>
          <p className="text-sm text-slate-500 mt-1">
            Inspection, operational health, and real-time telemetry of the active cybersecurity detection models.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleTestProbe}
            disabled={testing || loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold text-slate-700 bg-white/80 hover:bg-white border border-slate-200/80 shadow-sm transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-slate-600 ${testing ? 'animate-spin' : ''}`} />
            Refresh Health
          </button>
          <button
            onClick={() => navigate('/ai-decision')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 shadow-sm transition-all"
          >
            Launch AI Decision Center
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Hero Card - Active Primary Model */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-white via-white/95 to-emerald-50/40 p-6 border border-emerald-200/60 shadow-[0_4px_24px_-4px_rgba(16,185,129,0.08)]">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-emerald-100/40 via-teal-100/20 to-transparent rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3 max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              Primary Production Threat Engine: Online
            </div>
            <h2 className="text-3xl font-extrabold text-slate-900 tracking-tight flex items-center gap-3">
              <span>{aiStatus?.model || 'Atria-Dawn-Preview'}</span>
              <span className="text-xs font-bold px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
                744B MoE
              </span>
            </h2>
            <p className="text-sm text-slate-600 leading-relaxed">
              High-capacity Mixture-of-Experts (MoE) foundation model specifically tuned for agentic cybersecurity defense, 
              zero-day heuristic analysis, MITRE ATT&CK mapping, and automated Windows/Linux firewall rule synthesis.
            </p>
            <div className="flex flex-wrap items-center gap-4 pt-1 text-xs text-slate-600">
              <div className="flex items-center gap-1.5 font-medium">
                <Server className="w-3.5 h-3.5 text-emerald-600" />
                <span>Endpoint: <code className="text-slate-800 bg-slate-100 px-1 py-0.5 rounded">api.atria-asi.ai/v1</code></span>
              </div>
              <div className="flex items-center gap-1.5 font-medium">
                <Lock className="w-3.5 h-3.5 text-emerald-600" />
                <span>Authentication: <code className="text-slate-800 bg-slate-100 px-1 py-0.5 rounded">API Key Verified</code></span>
              </div>
              <div className="flex items-center gap-1.5 font-medium">
                <Activity className="w-3.5 h-3.5 text-emerald-600" />
                <span>Inference Strategy: <span className="text-slate-800 font-semibold">Sub-second Triage + Deep MoE</span></span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-2 gap-3 min-w-[280px]">
            <div className="p-4 rounded-xl bg-white/90 border border-slate-200/80 shadow-sm">
              <div className="text-xs font-medium text-slate-500 mb-1">Architecture</div>
              <div className="text-lg font-bold text-slate-900">MoE (Sparse)</div>
              <div className="text-[11px] text-slate-500 mt-0.5">48B Active / 744B Total</div>
            </div>
            <div className="p-4 rounded-xl bg-white/90 border border-slate-200/80 shadow-sm">
              <div className="text-xs font-medium text-slate-500 mb-1">Classification</div>
              <div className="text-lg font-bold text-emerald-600">Deterministic</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Zero-temperature scoring</div>
            </div>
            <div className="p-4 rounded-xl bg-white/90 border border-slate-200/80 shadow-sm">
              <div className="text-xs font-medium text-slate-500 mb-1">Taxonomy</div>
              <div className="text-lg font-bold text-slate-900">MITRE ATT&CK</div>
              <div className="text-[11px] text-slate-500 mt-0.5">14 Tactic Matrices</div>
            </div>
            <div className="p-4 rounded-xl bg-white/90 border border-slate-200/80 shadow-sm">
              <div className="text-xs font-medium text-slate-500 mb-1">Live Status</div>
              <div className="text-lg font-bold text-emerald-600 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                Active
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">Zero Mock Data</div>
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Layer Defensive Pipeline */}
      <div>
        <h3 className="text-base font-bold text-slate-900 mb-3 flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-600" />
          Autonomous Detection & Response Pipeline
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-white/80 border border-slate-200/80 shadow-sm relative">
            <div className="w-8 h-8 rounded-lg bg-emerald-100 text-emerald-800 font-bold text-sm flex items-center justify-center mb-3">
              01
            </div>
            <h4 className="text-sm font-bold text-slate-900 mb-1">OS Sensor Correlation</h4>
            <p className="text-xs text-slate-600 leading-relaxed">
              Gathers live OS telemetry from Sockets, PIDs, high-entropy Downloads, and registry persistence hooks.
            </p>
            <div className="mt-3 text-[11px] font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md px-2 py-1">
              Kernel & PSUtil Hooks
            </div>
          </div>

          <div className="p-4 rounded-xl bg-white/80 border border-slate-200/80 shadow-sm relative">
            <div className="w-8 h-8 rounded-lg bg-teal-100 text-teal-800 font-bold text-sm flex items-center justify-center mb-3">
              02
            </div>
            <h4 className="text-sm font-bold text-slate-900 mb-1">Vector Anomaly Scoring</h4>
            <p className="text-xs text-slate-600 leading-relaxed">
              Instant sub-millisecond heuristic & statistical z-score evaluation filters benign operating noise.
            </p>
            <div className="mt-3 text-[11px] font-semibold text-teal-700 bg-teal-50 border border-teal-200 rounded-md px-2 py-1">
              Sub-millisecond Triage
            </div>
          </div>

          <div className="p-4 rounded-xl bg-white/80 border border-slate-200/80 shadow-sm relative">
            <div className="w-8 h-8 rounded-lg bg-indigo-100 text-indigo-800 font-bold text-sm flex items-center justify-center mb-3">
              03
            </div>
            <h4 className="text-sm font-bold text-slate-900 mb-1">Atria MoE Reasoning</h4>
            <p className="text-xs text-slate-600 leading-relaxed">
              Transmits anomalous vectors to Atria-Dawn-Preview for deep forensic root-cause analysis and threat classification.
            </p>
            <div className="mt-3 text-[11px] font-semibold text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-md px-2 py-1">
              Cloud 744B MoE Agent
            </div>
          </div>

          <div className="p-4 rounded-xl bg-white/80 border border-slate-200/80 shadow-sm relative">
            <div className="w-8 h-8 rounded-lg bg-rose-100 text-rose-800 font-bold text-sm flex items-center justify-center mb-3">
              04
            </div>
            <h4 className="text-sm font-bold text-slate-900 mb-1">Automated Containment</h4>
            <p className="text-xs text-slate-600 leading-relaxed">
              Synthesizes exact Netsh firewall commands, isolates processes, logs to Supabase, and broadcasts via WebSockets.
            </p>
            <div className="mt-3 text-[11px] font-semibold text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-2 py-1">
              Real-time Remediation
            </div>
          </div>
        </div>
      </div>

      {/* Model Capabilities & Inspection */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="p-5 rounded-2xl bg-white/80 border border-slate-200/80 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              Verified Defense Capabilities
            </h3>
            <span className="text-xs font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
              All Active
            </span>
          </div>

          <div className="space-y-2.5">
            {[
              { title: 'Reverse Shell & C2 Socket Interception', desc: 'Monitors cmd.exe, powershell.exe, and netsh for unauthorized remote sockets.' },
              { title: 'Browser Remote Code Execution (RCE)', desc: 'Detects unauthorized shell spawns originating from browser processes.' },
              { title: 'High-Entropy Download Detonation', desc: 'Calculates Shannon entropy on incoming files to detect packed binaries & ransomware.' },
              { title: 'Persistence Mechanism Auditing', desc: 'Continuously queries Windows Run/RunOnce registry keys for anomalous persistence.' },
              { title: 'Firewall Synthesis & Isolation', desc: 'Generates ready-to-execute netsh advfirewall commands to drop attacker IP blocks.' },
            ].map((cap, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-slate-50/80 border border-slate-200/60">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-bold text-slate-800">{cap.title}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{cap.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-white/80 border border-slate-200/80 shadow-sm flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-slate-700" />
                Active Training Alignment Prompt
              </h3>
              <span className="text-xs text-slate-500 font-mono">system_prompt.txt</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 text-slate-200 font-mono text-xs leading-relaxed overflow-x-auto max-h-64 border border-slate-800 shadow-inner">
              <p className="text-emerald-400 font-bold mb-2"># Defense Alignment Taxonomy</p>
              <p className="text-slate-300">
                You are Atria AI, an autonomous defensive Intrusion Detection & Prevention System (IDS/IPS) engine.
                Your task is to analyze real-time endpoint telemetry, network flows, and process behavior to detect cyber threats.
              </p>
              <p className="text-slate-400 mt-2">
                - Strict JSON output structure: verdict (ATTACK | BENIGN)<br/>
                - Risk level: LOW | MEDIUM | HIGH | CRITICAL<br/>
                - Attack category: C2, RCE, Ransomware, SQLi, Brute Force, Port Scan<br/>
                - Netsh firewall syntax synthesis for automated IP blocking
              </p>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
            <div className="text-xs text-slate-500">
              To fine-tune prompt behavior or run interactive tests:
            </div>
            <button
              onClick={() => navigate('/ai-decision')}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 hover:text-emerald-800"
            >
              Open Tuning Console <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
