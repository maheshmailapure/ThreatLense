import React from 'react';
import { HelpCircle } from 'lucide-react';

export default function DetectionExplanation({ detection }) {
  if (!detection || !detection.explanation) {
    return null;
  }

  const exp = detection.explanation;

  return (
    <div className="glass-panel rounded-[22px] p-5 space-y-4">
      <div className="flex items-center gap-2 pb-3 border-b border-slate-200/80">
        <HelpCircle className="w-4 h-4 text-indigo-600" />
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
          Detection Explanation
        </h4>
      </div>

      <div className="space-y-2 text-xs">
        <p className="text-slate-700 font-medium leading-relaxed">{exp.summary}</p>

        <div className="space-y-1.5 pt-2">
          {exp.factors && exp.factors.map((factor, idx) => (
            <div key={idx} className="flex items-start gap-2 text-slate-700">
              <span className="text-indigo-600 font-bold mt-0.5">•</span>
              <span>{factor}</span>
            </div>
          ))}
        </div>
      </div>

      {exp.top_influential_features && exp.top_influential_features.length > 0 && (
        <div className="pt-3 border-t border-slate-200/80 space-y-2">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-600">
            Top Influential Flow Features (Random Forest)
          </div>
          <div className="space-y-1.5 font-mono text-[11px]">
            {exp.top_influential_features.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between p-2.5 rounded-xl bg-slate-100/70 border border-slate-200/60">
                <span className="text-indigo-900 font-medium font-sans">{item.feature}</span>
                <div className="flex items-center gap-3">
                  <span className="text-slate-600">Value: <strong className="text-slate-900">{item.packet_value}</strong></span>
                  <span className="text-emerald-700 font-semibold">{item.importance}% importance</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
