import React from 'react';

export default function ConfusionMatrix({ matrixData, modelName = "Model" }) {
  if (!matrixData) {
    return (
      <div className="p-6 text-center text-slate-500 text-xs font-medium">
        No confusion matrix data available for {modelName}.
      </div>
    );
  }

  const tn = matrixData.true_negative || 0;
  const fp = matrixData.false_positive || 0;
  const fn = matrixData.false_negative || 0;
  const tp = matrixData.true_positive || 0;
  const total = tn + fp + fn + tp || 1;

  const tnPct = ((tn / total) * 100).toFixed(1);
  const fpPct = ((fp / total) * 100).toFixed(1);
  const fnPct = ((fn / total) * 100).toFixed(1);
  const tpPct = ((tp / total) * 100).toFixed(1);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-700">
          Confusion Matrix ({modelName})
        </h4>
        <span className="text-[11px] font-mono text-slate-500">Total Samples: {total.toLocaleString()}</span>
      </div>

      <div className="grid grid-cols-2 gap-3 font-mono">
        {/* True Negative */}
        <div className="p-4 rounded-2xl bg-emerald-500/[0.08] border border-emerald-500/30 text-center shadow-sm backdrop-blur-md">
          <div className="text-[11px] text-emerald-800 font-semibold tracking-wide uppercase font-sans">
            True Negative (TN)
          </div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{tn.toLocaleString()}</div>
          <div className="text-[11px] text-emerald-700 font-medium mt-0.5">{tnPct}% (Normal Classified as Normal)</div>
        </div>

        {/* False Positive */}
        <div className="p-4 rounded-2xl bg-amber-500/[0.08] border border-amber-500/30 text-center shadow-sm backdrop-blur-md">
          <div className="text-[11px] text-amber-800 font-semibold tracking-wide uppercase font-sans">
            False Positive (FP)
          </div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{fp.toLocaleString()}</div>
          <div className="text-[11px] text-amber-700 font-medium mt-0.5">{fpPct}% (Type I Error / False Alarm)</div>
        </div>

        {/* False Negative */}
        <div className="p-4 rounded-2xl bg-rose-500/[0.08] border border-rose-500/30 text-center shadow-sm backdrop-blur-md">
          <div className="text-[11px] text-rose-800 font-semibold tracking-wide uppercase font-sans">
            False Negative (FN)
          </div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{fn.toLocaleString()}</div>
          <div className="text-[11px] text-rose-700 font-medium mt-0.5">{fnPct}% (Type II Error / Missed Attack)</div>
        </div>

        {/* True Positive */}
        <div className="p-4 rounded-2xl bg-indigo-500/[0.08] border border-indigo-500/30 text-center shadow-sm backdrop-blur-md">
          <div className="text-[11px] text-indigo-800 font-semibold tracking-wide uppercase font-sans">
            True Positive (TP)
          </div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{tp.toLocaleString()}</div>
          <div className="text-[11px] text-indigo-700 font-medium mt-0.5">{tpPct}% (Attack Accurately Detected)</div>
        </div>
      </div>
    </div>
  );
}
