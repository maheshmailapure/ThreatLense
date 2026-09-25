import React from 'react';
import { AlertTriangle, VolumeX, ShieldAlert, Zap, ArrowRight } from 'lucide-react';
import { stopIntrusionAlarm } from '../utils/audioAlarm';
import { useNavigate } from 'react-router-dom';

export default function AlarmBanner({ activeAlarm, onDismiss }) {
  const navigate = useNavigate();

  if (!activeAlarm) return null;

  const handleSilence = () => {
    stopIntrusionAlarm();
    if (onDismiss) onDismiss();
  };

  const handleInvestigate = () => {
    stopIntrusionAlarm();
    if (onDismiss) onDismiss();
    navigate('/ai-decision', { state: { incident: activeAlarm } });
  };

  return (
    <div className="sticky top-0 z-50 bg-gradient-to-r from-red-600 via-rose-600 to-amber-600 text-white px-4 py-2.5 shadow-2xl shadow-rose-900/50 flex flex-col sm:flex-row items-center justify-between gap-3 animate-pulse">
      <div className="flex items-center gap-3">
        <div className="p-1.5 rounded-lg bg-black/30 backdrop-blur-sm">
          <ShieldAlert className="w-5 h-5 text-yellow-300 animate-bounce" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-extrabold uppercase tracking-widest text-xs bg-black/40 px-2 py-0.5 rounded text-yellow-300 flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5 text-yellow-300" />
              AUTOMATIC INTRUSION ALARM
            </span>
            <span className="font-mono text-xs font-bold text-white">
              {activeAlarm.title || activeAlarm.attack_type || 'Threat Detected'}
            </span>
          </div>
          <p className="text-[11px] text-white/90 font-mono mt-0.5">
            Risk: <strong className="text-yellow-200">{activeAlarm.risk_level || 'CRITICAL'}</strong> • Anomaly Score: {typeof activeAlarm.anomaly_score === 'number' ? activeAlarm.anomaly_score.toFixed(3) : '0.850'} • Source: {activeAlarm.source_ip || 'Network Stream'}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={handleInvestigate}
          className="px-3 py-1 rounded bg-black/40 hover:bg-black/60 text-white text-xs font-bold transition-all flex items-center gap-1.5 border border-white/20"
        >
          <Zap className="w-3.5 h-3.5 text-yellow-300" />
          AI Incident Response
          <ArrowRight className="w-3.5 h-3.5" />
        </button>

        <button
          onClick={handleSilence}
          className="px-3 py-1 rounded bg-white text-slate-950 hover:bg-slate-200 text-xs font-bold transition-all flex items-center gap-1.5 shadow"
        >
          <VolumeX className="w-3.5 h-3.5 text-red-600" />
          Silence Siren
        </button>
      </div>
    </div>
  );
}
