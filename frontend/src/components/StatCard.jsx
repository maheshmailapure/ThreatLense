import React from 'react';

export default function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  badgeText,
}) {
  return (
    <div className="relative group overflow-hidden rounded-[22px] bg-[#edf4f0] p-5 shadow-[8px_8px_18px_rgba(152,174,165,0.48),-8px_-8px_18px_rgba(255,255,255,0.95)] border border-white/70 transition-all duration-200 hover:shadow-[10px_10px_22px_rgba(152,174,165,0.58),-10px_-10px_22px_rgba(255,255,255,1)]">
      <div className="relative flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-[11px] font-semibold tracking-wider uppercase text-slate-500">{title}</p>
          <div className="text-2xl font-bold font-mono text-slate-900 tracking-tight">
            {value !== undefined ? value.toLocaleString() : '0'}
          </div>
          {subtitle && (
            <p className="text-[11px] text-slate-500 font-medium truncate max-w-[190px]">{subtitle}</p>
          )}
        </div>

        {Icon && (
          <div className="w-10 h-10 rounded-[14px] bg-[#e4ece7] shadow-[inset_3px_3px_6px_rgba(152,174,165,0.5),inset_-3px_-3px_6px_rgba(255,255,255,0.9)] flex items-center justify-center text-[#2563eb] group-hover:scale-105 transition-transform">
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      {badgeText && (
        <div className="relative mt-3.5 pt-3 border-t border-slate-300/40 flex items-center justify-between text-[11px]">
          <span className="text-slate-400 font-medium uppercase text-[10px]">State</span>
          <span className="font-semibold text-white px-2.5 py-0.5 rounded-full bg-gradient-to-r from-blue-500 to-blue-700 shadow-[2px_2px_6px_rgba(37,99,235,0.35)] text-[10px]">
            {badgeText}
          </span>
        </div>
      )}
    </div>
  );
}

