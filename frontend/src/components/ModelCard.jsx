import React from 'react';
import { Cpu, CheckCircle2, Clock } from 'lucide-react';

export default function ModelCard({ model, onSelect, isSelected }) {
  if (!model) return null;

  const isKMeans = model.name === 'K-Means';
  const isIso = model.name === 'Isolation Forest';
  const isUnsupervised = isKMeans || isIso;

  return (
    <div
      onClick={onSelect}
      className={`neu-flat rounded-[28px] p-5 cursor-pointer relative overflow-hidden transition-all duration-200 ${
        isSelected ? 'ring-2 ring-[#2563eb]' : ''
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-[#2563eb]">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h4 className="font-extrabold text-slate-900 text-sm">{model.name}</h4>
            <div className="flex items-center gap-1.5 text-xs text-slate-500 mt-0.5">
              <span className="font-mono text-slate-600 font-bold">v{model.version || '1.0'}</span>
              <span>•</span>
              <span className="text-[#2563eb] font-bold">
                {isUnsupervised ? 'Unsupervised' : 'Supervised'}
              </span>
            </div>
          </div>
        </div>

        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold neu-inset text-emerald-700 font-mono">
          <CheckCircle2 className="w-3 h-3 text-emerald-600" />
          TRAINED
        </span>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-3 gap-2 mt-4 pt-3 border-t border-slate-300/40 font-mono text-center">
        <div className="p-2.5 rounded-2xl neu-inset">
          <div className="text-[10px] uppercase text-slate-500 font-sans font-bold">Accuracy</div>
          <div className="text-xs font-black text-emerald-700 mt-0.5">
            {model.accuracy !== null && model.accuracy !== undefined ? `${(model.accuracy > 1 ? model.accuracy : model.accuracy * 100).toFixed(1)}%` : 'N/A'}
          </div>
        </div>

        <div className="p-2.5 rounded-2xl neu-inset">
          <div className="text-[10px] uppercase text-slate-500 font-sans font-bold">F1 Score</div>
          <div className="text-xs font-black text-[#2563eb] mt-0.5">
            {model.f1_score !== null && model.f1_score !== undefined ? `${(model.f1_score > 1 ? model.f1_score : model.f1_score * 100).toFixed(1)}%` : 'N/A'}
          </div>
        </div>

        <div className="p-2.5 rounded-2xl neu-inset">
          <div className="text-[10px] uppercase text-slate-500 font-sans font-bold">FPR</div>
          <div className="text-xs font-black text-rose-600 mt-0.5">
            {model.false_positive_rate !== null && model.false_positive_rate !== undefined ? `${(model.false_positive_rate > 1 ? model.false_positive_rate : model.false_positive_rate * 100).toFixed(1)}%` : 'N/A'}
          </div>
        </div>
      </div>

      <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500 pt-2 border-t border-slate-300/40">
        <span className="flex items-center gap-1 font-medium">
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          Time: {model.training_time ? `${model.training_time}s` : '< 1s'}
        </span>
        <span className="text-slate-600 font-bold truncate max-w-[110px]">
          {model.dataset_name || 'NSL-KDD'}
        </span>
      </div>
    </div>
  );
}

