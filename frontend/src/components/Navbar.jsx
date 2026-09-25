import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { LogOut, Volume2, VolumeX, Shield } from 'lucide-react';
import { toggleMuteAlarm, getMuteState } from '../utils/audioAlarm';

export default function Navbar({ title = "" }) {
  const { user, logout } = useAuth();
  const [muted, setMuted] = useState(getMuteState());

  const handleToggleMute = () => {
    const isNowMuted = toggleMuteAlarm();
    setMuted(isNowMuted);
  };

  return (
    <header className="h-16 bg-[#edf4f0]/90 backdrop-blur-md border-b border-slate-300/40 px-6 flex items-center justify-between sticky top-0 z-20 shadow-[0_4px_12px_rgba(152,174,165,0.2)]">
      <div className="flex items-center gap-3">
        <img src="/threatlense_logo.png" alt="ThreatLense" className="h-8 w-auto object-contain" />
      </div>

      <div className="flex items-center gap-3">
        {/* Soft Status Indicator */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#e4ece7] shadow-[inset_2px_2px_5px_rgba(152,174,165,0.5),inset_-2px_-2px_5px_rgba(255,255,255,0.9)] text-[11px] font-semibold text-slate-600">
          <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)]" />
          <span>Shield Active</span>
        </div>

        {/* Mute toggle */}
        <button
          onClick={handleToggleMute}
          title={muted ? 'Unmute' : 'Mute'}
          className={`w-9 h-9 rounded-[12px] flex items-center justify-center transition-all ${
            muted
              ? 'bg-rose-50 text-rose-600 shadow-[inset_2px_2px_5px_rgba(244,63,94,0.3)]'
              : 'bg-[#edf4f0] shadow-[4px_4px_9px_rgba(152,174,165,0.45),-4px_-4px_9px_rgba(255,255,255,0.9)] text-slate-600 hover:text-slate-900 active:shadow-[inset_2px_2px_5px_rgba(152,174,165,0.5)]'
          }`}
        >
          {muted ? <VolumeX className="w-4 h-4 text-rose-600" /> : <Volume2 className="w-4 h-4 text-blue-600" />}
        </button>

      </div>
    </header>
  );
}
