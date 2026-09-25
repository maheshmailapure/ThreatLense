import React, { useState } from 'react';
import {
  Globe, Search, Lock, Server, Clock, CheckCircle2,
  AlertTriangle, RefreshCw, Shield, Zap
} from 'lucide-react';
import { scanTargetWeb } from '../services/api';
import StatCard from '../components/StatCard';
import LoadingSpinner from '../components/LoadingSpinner';
import { motion } from 'framer-motion';

const PRESET_TARGETS = [
  { label: 'Example Domain', url: 'example.com' },
  { label: 'Cloudflare DNS',  url: '1.1.1.1' },
  { label: 'Google',          url: 'google.com' },
  { label: 'HTTPBin',         url: 'httpbin.org' }
];

const RISK_COLORS = {
  CRITICAL: 'text-rose-700 font-bold',
  HIGH:     'text-amber-700 font-bold',
  MEDIUM:   'text-yellow-800 font-bold',
  LOW:      'text-slate-600 font-medium',
};

export default function WebAuditor() {
  const [targetInput, setTargetInput] = useState('example.com');
  const [scanning, setScanning] = useState(false);
  const [auditResult, setAuditResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (targetToScan) => {
    const query = targetToScan || targetInput;
    if (!query.trim()) return;
    setScanning(true);
    setError(null);
    setAuditResult(null);
    try {
      const data = await scanTargetWeb(query.trim());
      setAuditResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Website audit failed. Check network connectivity.');
    } finally {
      setScanning(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 max-w-7xl mx-auto"
    >
      {/* Header */}
      <div className="neu-flat p-4 rounded-3xl flex items-center justify-between">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-[#2563eb]">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-extrabold text-slate-900 tracking-tight">
              Website & IP Security Auditor
            </h1>
            <p className="text-xs text-slate-500 font-medium">
              Inspect SSL/TLS, OWASP headers & AI posture for any public domain or IP
            </p>
          </div>
        </div>
      </div>

      {/* Scanner input */}
      <div className="neu-flat rounded-[28px] p-6 space-y-4">
        <form onSubmit={(e) => { e.preventDefault(); handleScan(); }} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 neu-inset rounded-2xl flex items-center px-4 py-2.5">
            <Globe className="w-4 h-4 text-slate-400 shrink-0 mr-3" />
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter domain or IP (e.g. example.com, 1.1.1.1)"
              className="w-full bg-transparent border-none text-slate-900 font-mono text-xs font-bold focus:outline-none placeholder-slate-400"
            />
          </div>
          <button
            type="submit"
            disabled={scanning}
            className="w-full sm:w-auto px-6 py-3 rounded-2xl neu-accent-btn font-bold text-xs tracking-wider uppercase transition-all flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {scanning ? <><RefreshCw className="w-4 h-4 animate-spin" /> Auditing...</> : <><Search className="w-4 h-4" /> Audit Security</>}
          </button>
        </form>

        <div className="flex items-center gap-2.5 flex-wrap pt-2">
          <span className="text-[11px] text-slate-500 font-bold">Quick targets:</span>
          {PRESET_TARGETS.map((t) => (
            <button
              key={t.url}
              onClick={() => { setTargetInput(t.url); handleScan(t.url); }}
              className="neu-button px-3 py-1.5 rounded-xl text-slate-700 text-[11px] font-mono font-bold transition-all"
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 rounded-2xl neu-inset text-rose-600 text-xs flex items-center gap-2.5 font-bold">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-500" />
          {error}
        </div>
      )}

      {/* Results */}
      {auditResult && (
        <div className="space-y-6">
          {/* KPI cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard title="Security Score" value={`${auditResult.security_score} / 100`} subtitle={`Grade ${auditResult.security_grade} · ${auditResult.posture_level}`} icon={Shield} badgeText={`Grade ${auditResult.security_grade}`} />
            <StatCard title="Resolved IP" value={auditResult.ip_address} subtitle={`Hostname: ${auditResult.hostname}`} icon={Server} badgeText="DNS Resolved" />
            <StatCard title="SSL/TLS" value={auditResult.ssl_tls?.ssl_valid ? (auditResult.ssl_tls?.version || 'TLS 1.3') : 'Unencrypted'} subtitle={auditResult.ssl_tls?.issuer || 'Certificate status'} icon={Lock} badgeText={auditResult.ssl_tls?.ssl_valid ? 'Valid SSL' : 'SSL Warning'} />
            <StatCard title="Response Latency" value={`${auditResult.response_time_ms} ms`} subtitle={`HTTP ${auditResult.status_code || 200}`} icon={Clock} badgeText="Telemetry" />
          </div>

          {/* SSL detail */}
          <div className="neu-flat rounded-[28px] p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-300/40 pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#2563eb]" />
                <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">SSL/TLS Inspection</h3>
              </div>
              <span className={`px-3 py-1 rounded-xl text-[10px] font-bold neu-inset ${auditResult.ssl_tls?.ssl_valid ? 'text-emerald-700' : 'text-rose-600'}`}>
                {auditResult.ssl_tls?.ssl_valid ? 'Secure Channel' : 'No SSL'}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
              {[
                { label: 'Certificate Issuer', value: auditResult.ssl_tls?.issuer || 'N/A', color: 'text-slate-900' },
                { label: 'Cipher Suite', value: auditResult.ssl_tls?.cipher || 'N/A', color: 'text-[#2563eb]' },
                { label: 'Expiration', value: auditResult.ssl_tls?.expires || 'Valid', color: 'text-slate-700' },
              ].map(({ label, value, color }) => (
                <div key={label} className="p-4 rounded-2xl neu-inset space-y-1">
                  <span className="text-[10px] text-slate-500 font-sans uppercase font-bold">{label}</span>
                  <div className={`font-bold ${color}`}>{value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* OWASP Headers Table */}
          <div className="neu-flat rounded-[28px] p-6 overflow-hidden">
            <div className="pb-4 border-b border-slate-300/40">
              <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">OWASP Security Headers</h3>
              <p className="text-[11px] text-slate-500 font-medium mt-0.5">
                Present: {auditResult.headers_present_count} · Missing: {auditResult.headers_missing_count}
              </p>
            </div>
            <div className="overflow-x-auto mt-2">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-[10px] text-slate-500 uppercase border-b border-slate-300/40 font-bold">
                    <th className="text-left py-3 px-4">Header</th>
                    <th className="text-left py-3 px-4">Status</th>
                    <th className="text-left py-3 px-4">Importance</th>
                    <th className="text-left py-3 px-4">Purpose</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/50 font-mono">
                  {auditResult.headers_found?.map((h) => (
                    <tr key={h.name} className="hover:bg-slate-200/40 transition-colors">
                      <td className="py-3 px-4 font-bold text-[#2563eb]">{h.name}</td>
                      <td className="py-3 px-4"><span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">PASS</span></td>
                      <td className="py-3 px-4 text-slate-700 font-medium">{h.importance}</td>
                      <td className="py-3 px-4 font-sans text-slate-600 font-medium">{h.description}</td>
                    </tr>
                  ))}
                  {auditResult.missing_headers?.map((m) => (
                    <tr key={m.key} className="hover:bg-slate-200/40 transition-colors">
                      <td className="py-3 px-4 font-bold text-rose-600">{m.name}</td>
                      <td className="py-3 px-4"><span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">MISSING</span></td>
                      <td className="py-3 px-4"><span className={RISK_COLORS[m.importance] || ''}>{m.importance}</span></td>
                      <td className="py-3 px-4 font-sans text-slate-600">
                        <strong className="text-slate-900 block font-bold">{m.description}</strong>
                        <span className="text-amber-700 font-semibold text-[11px]">Risk: {m.risk}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* AI Recommendations */}
          {auditResult.ai_recommendations?.length > 0 && (
            <div className="neu-flat rounded-[28px] p-6 space-y-4">
              <div className="flex items-center gap-2 border-b border-slate-300/40 pb-3">
                <Zap className="w-4 h-4 text-[#2563eb]" />
                <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">AI Hardening Recommendations</h3>
              </div>
              <div className="space-y-2">
                {auditResult.ai_recommendations.map((rec, i) => (
                  <div key={i} className="flex items-start gap-2.5 text-xs text-slate-800 neu-inset p-3.5 rounded-2xl">
                    <CheckCircle2 className="w-4 h-4 text-[#2563eb] shrink-0 mt-0.5" />
                    <span className="font-semibold">{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </motion.div>
  );
}

