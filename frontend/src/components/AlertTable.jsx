import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, Skull, ShieldBan, ShieldCheck, Zap, CheckCircle2 } from 'lucide-react';
import { containBlockIP, containBlockPort, containKillProcess, wakeAIOnDemand } from '../services/api';

const RISK_PILLS = {
  CRITICAL: 'bg-rose-50 text-rose-700 border border-rose-200 font-bold',
  HIGH:     'bg-amber-50 text-amber-700 border border-amber-200 font-bold',
  MEDIUM:   'bg-yellow-50 text-yellow-800 border border-yellow-200 font-bold',
  LOW:      'bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold',
};

export default function AlertTable({ alerts = [], onStatusChange, showActions = true, onActionFeedback }) {
  const [wakingAlertId, setWakingAlertId] = useState(null);
  const [wokenAlerts, setWokenAlerts] = useState({});

  if (!alerts || alerts.length === 0) {
    return (
      <div className="py-12 text-center text-slate-400 text-xs font-mono">
        <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-500/80" />
        No active security anomalies flagged on this endpoint.
      </div>
    );
  }

  const handleKill = async (alert) => {
    let pid = alert.pid;
    if (!pid && alert.source_ip && !isNaN(Number(alert.source_ip))) pid = Number(alert.source_ip);
    if (!pid && alert.attack_type) {
      const m = alert.attack_type.match(/PID:?\s*(\d+)/i);
      if (m) pid = Number(m[1]);
    }
    if (!pid && alert.description) {
      const m = alert.description.match(/PID:?\s*(\d+)/i);
      if (m) pid = Number(m[1]);
    }
    if (!pid) {
      if (onActionFeedback) onActionFeedback("No PID associated with this incident.");
      return;
    }
    try {
      const res = await containKillProcess({ pid, process_name: alert.process_name, alert_id: alert.id });
      if (onActionFeedback) onActionFeedback(res?.message || `PID ${pid} successfully killed.`);
      if (onStatusChange) onStatusChange(alert.id, 'RESOLVED');
    } catch (e) {
      if (onActionFeedback) onActionFeedback(`Failed to kill process: ${e.message}`);
    }
  };

  const handleBlock = async (alert) => {
    let ip = alert.ip_source || alert.source_ip;
    let port = alert.port || alert.target_port;
    if (!port && alert.description) {
      const m = alert.description.match(/:(\d{2,5})/);
      if (m) port = Number(m[1]);
    }

    if (port && port > 0) {
      try {
        const res = await containBlockPort({ port, alert_id: alert.id });
        if (onActionFeedback) onActionFeedback(res?.message || `Port ${port} blocked in Windows Firewall.`);
        if (onStatusChange) onStatusChange(alert.id, 'CONTAINED');
        return;
      } catch (e) {}
    }

    if (!ip || ip.includes('127.0.0.1') || ip === 'Local Host' || ip.includes('::1')) {
      if (onActionFeedback) onActionFeedback("No external IP/port found to block.");
      return;
    }
    try {
      const res = await containBlockIP({ ip, alert_id: alert.id });
      if (onActionFeedback) onActionFeedback(res?.message || `Firewall rule installed to block ${ip}.`);
      if (onStatusChange) onStatusChange(alert.id, 'CONTAINED');
    } catch (e) {
      if (onActionFeedback) onActionFeedback(`Block failed: ${e.message}`);
    }
  };

  const handleWakeAI = async (alert) => {
    setWakingAlertId(alert.id);
    try {
      const res = await wakeAIOnDemand({
        alert_id: alert.id,
        incident_data: {
          title: alert.alert_type,
          severity: alert.risk_level,
          process: alert.attack_type,
          evidence: alert.description
        }
      });
      setWokenAlerts(prev => ({ ...prev, [alert.id]: res.analysis }));
      if (onActionFeedback) onActionFeedback(`Atria AI Woken: ${res.analysis?.verdict || 'Analysis complete'} (${res.analysis?.mitigation_action || 'Firewall synthesized'})`);
      if (onStatusChange) onStatusChange(alert.id, 'INVESTIGATING');
    } catch (err) {
      if (onActionFeedback) onActionFeedback(`AI wake failed: ${err.message}`);
    } finally {
      setWakingAlertId(null);
    }
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs border-collapse">
        <thead className="text-[10px] text-slate-500 uppercase font-mono tracking-wider border-b border-slate-300/40">
          <tr>
            <th className="py-3 px-4 font-bold">ID</th>
            <th className="py-3 px-4 font-bold">Category</th>
            <th className="py-3 px-4 font-bold">Severity</th>
            <th className="py-3 px-4 font-bold">Vector</th>
            <th className="py-3 px-4 font-bold">Target</th>
            <th className="py-3 px-4 font-bold">Status</th>
            <th className="py-3 px-4 font-bold">Time</th>
            {showActions && <th className="py-3 px-4 text-right font-bold">Defense</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200/50 font-mono text-[11px]">
          {alerts.map((alert) => (
            <tr key={alert.id} className="hover:bg-slate-200/40 transition-colors">
              <td className="py-3 px-4 text-[#2563eb] font-bold">#{alert.id}</td>
              <td className="py-3 px-4 font-sans text-slate-800 font-semibold">{alert.alert_type}</td>
              <td className="py-3 px-4">
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] ${RISK_PILLS[alert.risk_level] || ''}`}>
                  {alert.risk_level}
                </span>
              </td>
              <td className="py-3 px-4 text-slate-600 font-sans truncate max-w-[160px]">{alert.attack_type || 'Outlier'}</td>
              <td className="py-3 px-4 text-slate-700 truncate max-w-[130px]">{alert.ip_source || alert.source_ip || 'Kernel'}</td>
              <td className="py-3 px-4">
                {onStatusChange ? (
                  <select
                    value={alert.status}
                    onChange={(e) => onStatusChange(alert.id, e.target.value)}
                    className="neu-inset text-slate-700 rounded-xl px-2.5 py-1 text-[10px] font-semibold focus:outline-none cursor-pointer"
                  >
                    <option value="NEW">NEW</option>
                    <option value="INVESTIGATING">INVESTIGATING</option>
                    <option value="RESOLVED">RESOLVED</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                  </select>
                ) : (
                  <span className="text-slate-500 text-[10px] uppercase font-bold">{alert.status}</span>
                )}
              </td>
              <td className="py-3 px-4 text-slate-400 text-[10px]">
                {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : 'Live'}
              </td>
              {showActions && (
                <td className="py-3 px-4 text-right font-sans">
                  <div className="flex items-center justify-end gap-1.5">
                    <button
                      onClick={() => handleWakeAI(alert)}
                      disabled={wakingAlertId === alert.id || !!wokenAlerts[alert.id]}
                      title="Trigger Atria AI MoE for on-demand deep analysis (saves background tokens)"
                      className={`px-2.5 py-1 rounded-xl text-[10px] font-bold flex items-center gap-1 transition-all ${
                        wokenAlerts[alert.id]
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          : 'bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200'
                      }`}
                    >
                      <Zap className={`w-3 h-3 ${wakingAlertId === alert.id ? 'animate-spin text-indigo-600' : ''}`} />
                      {wokenAlerts[alert.id] ? 'AI Woken' : wakingAlertId === alert.id ? 'Waking...' : 'Wake AI'}
                    </button>

                    <button
                      onClick={() => handleBlock(alert)}
                      title="Block Port or Remote IP via Windows Defender Firewall"
                      className="px-2.5 py-1 rounded-xl text-[10px] font-bold bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 flex items-center gap-1 transition-all"
                    >
                      <ShieldBan className="w-3 h-3" />
                      Block
                    </button>

                    <button
                      onClick={() => handleKill(alert)}
                      title="Kill Process"
                      className="px-2.5 py-1 rounded-xl text-[10px] font-bold bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 flex items-center gap-1 transition-all"
                    >
                      <Skull className="w-3 h-3" />
                      Kill
                    </button>

                    <Link
                      to={`/alerts/${alert.id}`}
                      className="p-1.5 rounded-xl neu-button text-slate-400 hover:text-slate-800 transition-all flex items-center justify-center"
                    >
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

