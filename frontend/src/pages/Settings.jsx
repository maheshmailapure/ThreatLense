import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Settings as SettingsIcon, 
  Sliders, 
  Server, 
  Save, 
  CheckCircle2, 
  Globe, 
  ShieldCheck, 
  Search, 
  Key, 
  ExternalLink,
  Cpu,
  AlertTriangle
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

export default function Settings() {
  const { user } = useAuth();
  const [anomalyThreshold, setAnomalyThreshold] = useState(0.65);
  const [saved, setSaved] = useState(false);
  const [health, setHealth] = useState(null);

  // Threat Intel State
  const [intelConfig, setIntelConfig] = useState(null);
  const [abuseKey, setAbuseKey] = useState('');
  const [vtKey, setVtKey] = useState('');
  const [otxKey, setOtxKey] = useState('');
  const [savingKeys, setSavingKeys] = useState(false);

  // Live Query Tool State
  const [testType, setTestType] = useState('ip');
  const [testQuery, setTestQuery] = useState('8.8.8.8');
  const [queryLoading, setQueryLoading] = useState(false);
  const [queryResult, setQueryResult] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [healthRes, configRes] = await Promise.all([
          api.get('/api/health').catch(() => ({ data: null })),
          api.get('/api/threat-intel/config').catch(() => ({ data: null }))
        ]);
        if (healthRes?.data) setHealth(healthRes.data);
        if (configRes?.data) setIntelConfig(configRes.data);
      } catch (err) {
        console.error(err);
      }
    };
    fetchData();
  }, []);

  const handleSaveThresholds = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleSaveKeys = async (e) => {
    e.preventDefault();
    setSavingKeys(true);
    try {
      const res = await api.post('/api/threat-intel/config', {
        abuseipdb_key: abuseKey || undefined,
        virustotal_key: vtKey || undefined,
        otx_key: otxKey || undefined
      });
      if (res.data) {
        setIntelConfig(res.data);
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      console.error(err);
    } finally {
      setSavingKeys(false);
    }
  };

  const handleRunIntelQuery = async (e) => {
    e.preventDefault();
    if (!testQuery) return;
    setQueryLoading(true);
    setQueryResult(null);
    try {
      let res;
      if (testType === 'ip') {
        res = await api.post('/api/threat-intel/check-ip', { ip: testQuery });
      } else {
        res = await api.post('/api/threat-intel/check-hash', { sha256: testQuery });
      }
      setQueryResult(res.data);
    } catch (err) {
      console.error(err);
      setQueryResult({ error: "Failed to perform threat intelligence query." });
    } finally {
      setQueryLoading(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 max-w-7xl mx-auto"
    >
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-indigo-600" />
          System Settings & Threat Intelligence
        </h1>
        <p className="text-xs font-medium text-slate-600 mt-1">
          Configure real-time detection thresholds, free threat intelligence API gateways, and test IoC reputations
        </p>
      </div>

      {saved && (
        <div className="p-3.5 rounded-2xl bg-emerald-50 border border-emerald-200/80 text-emerald-700 text-xs font-medium flex items-center gap-2 shadow-sm">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500" />
          <span>Configuration saved successfully.</span>
        </div>
      )}

      {/* Free Threat Intelligence API Providers Grid */}
      <div className="glass-panel rounded-2xl p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-slate-200/80 pb-3">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Free Threat Intelligence Integration Layer
            </h3>
          </div>
          <span className="text-[10px] font-mono font-bold text-emerald-800 bg-emerald-100 border border-emerald-300 px-2.5 py-0.5 rounded-full">
            Auxiliary Verification Layer
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-white/70 border border-slate-200/80 space-y-2 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900">URLhaus (abuse.ch)</span>
              <span className="text-[10px] text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-md font-bold">READY</span>
            </div>
            <p className="text-[11px] text-slate-600 font-medium">Community malware payload and URL threat feed.</p>
            <div className="text-[10px] font-mono font-semibold text-indigo-700">100% Free • No Key Needed</div>
          </div>

          <div className="p-4 rounded-xl bg-white/70 border border-slate-200/80 space-y-2 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900">AbuseIPDB</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md ${intelConfig?.abuseipdb?.enabled ? 'text-emerald-700 bg-emerald-50 border border-emerald-200' : 'text-slate-600 bg-slate-100 border border-slate-200'}`}>
                {intelConfig?.abuseipdb?.enabled ? 'ACTIVE' : 'OPTIONAL'}
              </span>
            </div>
            <p className="text-[11px] text-slate-600 font-medium">External IP address abuse reports & confidence scoring.</p>
            <div className="text-[10px] font-mono font-medium text-slate-500">1,000 checks/day (Free Tier)</div>
          </div>

          <div className="p-4 rounded-xl bg-white/70 border border-slate-200/80 space-y-2 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900">VirusTotal</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md ${intelConfig?.virustotal?.enabled ? 'text-emerald-700 bg-emerald-50 border border-emerald-200' : 'text-slate-600 bg-slate-100 border border-slate-200'}`}>
                {intelConfig?.virustotal?.enabled ? 'ACTIVE' : 'OPTIONAL'}
              </span>
            </div>
            <p className="text-[11px] text-slate-600 font-medium">Multi-engine antivirus file hash & domain scanner.</p>
            <div className="text-[10px] font-mono font-medium text-slate-500">500 checks/day (Public API)</div>
          </div>

          <div className="p-4 rounded-xl bg-white/70 border border-slate-200/80 space-y-2 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900">AlienVault OTX</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md ${intelConfig?.alienvault_otx?.enabled ? 'text-emerald-700 bg-emerald-50 border border-emerald-200' : 'text-slate-600 bg-slate-100 border border-slate-200'}`}>
                {intelConfig?.alienvault_otx?.enabled ? 'ACTIVE' : 'OPTIONAL'}
              </span>
            </div>
            <p className="text-[11px] text-slate-600 font-medium">Crowdsourced Indicators of Compromise (IoC).</p>
            <div className="text-[10px] font-mono font-medium text-slate-500">Open Threat Exchange</div>
          </div>
        </div>

        {/* Threat Intel API Keys Form */}
        <form onSubmit={handleSaveKeys} className="pt-3 border-t border-slate-200/80 space-y-3">
          <div className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
            <Key className="w-3.5 h-3.5 text-indigo-600" />
            Configure Optional Free API Keys
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <label className="text-[11px] font-semibold text-slate-700 block mb-1">AbuseIPDB API Key</label>
              <input
                type="password"
                placeholder="Enter AbuseIPDB Key"
                value={abuseKey}
                onChange={(e) => setAbuseKey(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-white/80 border border-slate-200/80 text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 font-mono text-xs shadow-sm"
              />
            </div>
            <div>
              <label className="text-[11px] font-semibold text-slate-700 block mb-1">VirusTotal API Key</label>
              <input
                type="password"
                placeholder="Enter VirusTotal Key"
                value={vtKey}
                onChange={(e) => setVtKey(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-white/80 border border-slate-200/80 text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 font-mono text-xs shadow-sm"
              />
            </div>
            <div>
              <label className="text-[11px] font-semibold text-slate-700 block mb-1">AlienVault OTX Key</label>
              <input
                type="password"
                placeholder="Enter AlienVault Key"
                value={otxKey}
                onChange={(e) => setOtxKey(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-white/80 border border-slate-200/80 text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 font-mono text-xs shadow-sm"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={savingKeys}
              className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-md shadow-indigo-500/20"
            >
              <Save className="w-3.5 h-3.5" />
              Save Threat Intel Keys
            </button>
          </div>
        </form>
      </div>

      {/* Live IoC Quick Check Tool & System Thresholds Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Intel Interactive Query Box */}
        <div className="glass-panel rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-200/80 pb-3">
            <Search className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Live IoC Threat Intelligence Lookup
            </h3>
          </div>

          <form onSubmit={handleRunIntelQuery} className="space-y-3 text-xs">
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => { setTestType('ip'); setTestQuery('8.8.8.8'); }}
                className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shadow-sm ${
                  testType === 'ip' ? 'bg-indigo-600 text-white' : 'bg-white/80 text-slate-700 border border-slate-200'
                }`}
              >
                IP Address
              </button>
              <button
                type="button"
                onClick={() => { setTestType('hash'); setTestQuery('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'); }}
                className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shadow-sm ${
                  testType === 'hash' ? 'bg-indigo-600 text-white' : 'bg-white/80 text-slate-700 border border-slate-200'
                }`}
              >
                SHA-256 Hash
              </button>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={testQuery}
                onChange={(e) => setTestQuery(e.target.value)}
                placeholder={testType === 'ip' ? 'Enter IP address (e.g. 185.220.101.5)' : 'Enter SHA-256 hash'}
                className="flex-1 px-3 py-2 rounded-xl bg-white/80 border border-slate-200/80 text-slate-900 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500/20 shadow-sm"
              />
              <button
                type="submit"
                disabled={queryLoading}
                className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-md shadow-indigo-500/20 disabled:opacity-50"
              >
                {queryLoading ? 'Querying...' : 'Check'}
              </button>
            </div>

            {queryResult && (
              <div className="p-4 rounded-xl bg-white/70 border border-slate-200/80 space-y-2 font-mono text-[11px] shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-slate-600 font-semibold">Target: {testQuery}</span>
                  <span className={`font-bold px-2 py-0.5 rounded ${queryResult.is_malicious ? 'bg-rose-100 text-rose-800 border border-rose-300' : 'bg-emerald-100 text-emerald-800 border border-emerald-300'}`}>
                    {queryResult.verdict || 'CLEAN'}
                  </span>
                </div>
                {queryResult.sources?.map((s, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/60 text-slate-800 text-[11px]">
                    <span className="font-bold text-indigo-700">{s.provider}:</span> {s.status || s.signature || JSON.stringify(s)}
                  </div>
                ))}
              </div>
            )}
          </form>
        </div>

        {/* Risk & Anomaly Engine Tuning */}
        <div className="glass-panel rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-200/80 pb-3">
            <Sliders className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Risk & Anomaly Engine Thresholds
            </h3>
          </div>

          <form onSubmit={handleSaveThresholds} className="space-y-4 text-xs">
            <div>
              <div className="flex justify-between mb-1.5">
                <label className="font-semibold text-slate-800">Anomaly Deviation Cutoff</label>
                <span className="font-mono text-indigo-700 font-bold">{anomalyThreshold}</span>
              </div>
              <input
                type="range"
                min="0.3"
                max="0.95"
                step="0.05"
                value={anomalyThreshold}
                onChange={(e) => setAnomalyThreshold(parseFloat(e.target.value))}
                className="w-full accent-indigo-600 cursor-pointer"
              />
              <p className="text-[11px] font-medium text-slate-500 mt-1">
                Packets with normalized centroid distance above this threshold are classified as zero-day anomalies.
              </p>
            </div>

            <div className="pt-2 border-t border-slate-200/80 space-y-2">
              <div className="text-[10px] font-bold uppercase text-slate-500">Risk Level Classifications</div>
              <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div className="p-2.5 rounded-xl bg-emerald-50 border border-emerald-200 text-slate-800">
                  <span className="text-emerald-700 font-bold">LOW:</span> Normal flow
                </div>
                <div className="p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-slate-800">
                  <span className="text-amber-700 font-bold">MEDIUM:</span> Anomaly &gt; 0.65
                </div>
                <div className="p-2.5 rounded-xl bg-orange-50 border border-orange-200 text-slate-800">
                  <span className="text-orange-700 font-bold">HIGH:</span> Known attack pattern
                </div>
                <div className="p-2.5 rounded-xl bg-rose-50 border border-rose-200 text-slate-800">
                  <span className="text-rose-700 font-bold">CRITICAL:</span> U2R / DoS Flood
                </div>
              </div>
            </div>

            <button
              type="submit"
              className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs flex items-center gap-2 transition-colors shadow-md shadow-indigo-500/20"
            >
              <Save className="w-3.5 h-3.5" />
              Save Thresholds
            </button>
          </form>
        </div>
      </div>
    </motion.div>
  );
}
