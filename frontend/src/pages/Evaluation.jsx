import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  LineChart, 
  Cpu, 
  Layers, 
  CheckCircle2, 
  BarChart3
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { compareModels } from '../services/api';
import ConfusionMatrix from '../components/ConfusionMatrix';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';

export default function Evaluation() {
  const [data, setData] = useState(() => getCachedData('evaluation_compare', null));
  const [loading, setLoading] = useState(() => !hasCachedData('evaluation_compare'));
  const [selectedModelName, setSelectedModelName] = useState('Random Forest');

  useEffect(() => {
    const fetchEval = async () => {
      try {
        const res = await compareModels();
        if (res) {
          setData(res);
          setCachedData('evaluation_compare', res);
          if (res.models && res.models.length > 0) {
            setSelectedModelName(res.models[0].name);
          }
        }
      } catch (err) {
        console.error("Failed to load evaluation data:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchEval();
  }, []);

  if (loading) {
    return <LoadingSpinner message="Calculating academic evaluation metrics & matrices..." />;
  }

  const models = data?.models || [];
  const metadata = data?.metadata || {};
  const activeModel = models.find((m) => m.name === selectedModelName) || models[0];

  // Prepare chart comparison data
  const comparisonChartData = models.map((m) => ({
    name: m.name,
    Accuracy: m.accuracy || 0,
    Precision: m.precision || 0,
    Recall: m.recall || 0,
    F1_Score: m.f1_score || 0,
    FPR: m.false_positive_rate || 0,
  }));

  // Prepare PCA variance data
  const pcaChartData = (metadata.pca_explained_variance_ratio || []).map((val, idx) => ({
    name: `PC${idx + 1}`,
    variance: val,
  }));

  return (
    <motion.div 
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 max-w-7xl mx-auto"
    >
      {/* Header */}
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2">
          <LineChart className="w-5 h-5 text-indigo-600" />
          Model Benchmarks & Academic Evaluation
        </h1>
        <p className="text-xs font-medium text-slate-600 mt-1">
          Comparative benchmarks, confusion matrices, PCA scree variance, and academic defense telemetry
        </p>
      </div>

      {/* Model Benchmark Table */}
      <div className="glass-panel rounded-2xl overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-slate-200/80 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
            <LineChart className="w-4 h-4 text-indigo-600" />
            Model Benchmark Comparison Matrix (70:30 Split)
          </h3>
          <span className="text-[11px] font-mono font-semibold text-slate-500">NSL-KDD Test Set</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-[11px] text-slate-500 uppercase tracking-wider font-bold border-b border-slate-200/80 bg-slate-50/50">
              <tr>
                <th className="py-3 px-6 font-sans">Algorithm</th>
                <th className="py-3 px-6 font-sans">Paradigm</th>
                <th className="py-3 px-6 text-center">Accuracy</th>
                <th className="py-3 px-6 text-center">Precision</th>
                <th className="py-3 px-6 text-center">Recall</th>
                <th className="py-3 px-6 text-center">F1 Score</th>
                <th className="py-3 px-6 text-center">False Positive Rate (FPR)</th>
                <th className="py-3 px-6 text-right">Training Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/60">
              {models.map((m) => (
                <tr
                  key={m.id}
                  onClick={() => setSelectedModelName(m.name)}
                  className={`hover:bg-indigo-50/40 transition-colors cursor-pointer ${
                    selectedModelName === m.name ? 'bg-indigo-50/70 font-bold' : ''
                  }`}
                >
                  <td className="py-3.5 px-6 font-sans font-bold text-slate-900">{m.name}</td>
                  <td className="py-3.5 px-6 font-sans text-slate-600 font-medium text-[11px]">
                    {m.name === 'Random Forest' ? 'Ensemble Classifier' :
                     m.name === 'SVM' ? 'Support Vector Machine' :
                     m.name === 'K-Means' ? 'Centroid Clustering' : 'Isolation Forest'}
                  </td>
                  <td className="py-3.5 px-6 text-center text-emerald-700 font-bold">
                    {m.accuracy != null ? `${(m.accuracy * 100).toFixed(2)}%` : 'N/A'}
                  </td>
                  <td className="py-3.5 px-6 text-center text-slate-800 font-semibold">
                    {m.precision != null ? `${(m.precision * 100).toFixed(2)}%` : 'N/A'}
                  </td>
                  <td className="py-3.5 px-6 text-center text-slate-800 font-semibold">
                    {m.recall != null ? `${(m.recall * 100).toFixed(2)}%` : 'N/A'}
                  </td>
                  <td className="py-3.5 px-6 text-center text-indigo-700 font-bold">
                    {m.f1_score != null ? (m.f1_score * 100).toFixed(2) + '%' : 'N/A'}
                  </td>
                  <td className="py-3.5 px-6 text-center text-amber-700 font-bold">
                    {m.false_positive_rate != null ? (m.false_positive_rate * 100).toFixed(2) + '%' : 'N/A'}
                  </td>
                  <td className="py-3.5 px-6 text-right text-slate-600 font-medium">
                    {m.training_time != null ? `${m.training_time.toFixed(2)}s` : '--'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Comparative Bar Chart */}
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <div className="flex items-center gap-2 pb-3 border-b border-slate-200/80">
          <BarChart3 className="w-4 h-4 text-indigo-600" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Multi-Metric Comparative Benchmark Visualization
          </h3>
        </div>

        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={comparisonChartData} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}>
              <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: '#334155', fontSize: 11, fontWeight: 600 }} />
              <YAxis stroke="#94a3b8" domain={[0, 1]} tick={{ fill: '#64748b', fontSize: 10 }} />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'rgba(255, 255, 255, 0.95)', 
                  borderColor: 'rgba(226, 232, 240, 0.8)', 
                  borderRadius: '16px',
                  boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.08)',
                  backdropFilter: 'blur(12px)',
                  color: '#0f172a',
                  fontWeight: 600,
                  fontSize: '12px'
                }} 
              />
              <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px', fontWeight: 600, color: '#334155' }} />
              <Bar dataKey="Accuracy" fill="#4f46e5" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Precision" fill="#6366f1" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Recall" fill="#818cf8" radius={[4, 4, 0, 0]} />
              <Bar dataKey="F1_Score" fill="#059669" radius={[4, 4, 0, 0]} />
              <Bar dataKey="FPR" fill="#e11d48" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Model Confusion Matrix & PCA Scree */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div className="glass-panel rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200/80">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-indigo-600" />
              Confusion Matrix: {activeModel?.name}
            </h3>
            <span className="text-[11px] font-mono font-semibold text-indigo-700">Test Split (30%)</span>
          </div>

          {activeModel?.metrics_json?.confusion_matrix ? (
            <ConfusionMatrix matrix={activeModel.metrics_json.confusion_matrix} />
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs font-medium">
              No confusion matrix recorded for {activeModel?.name}.
            </div>
          )}
        </div>

        {/* PCA Scree Variance */}
        <div className="glass-panel rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200/80">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-600" />
              PCA Scree Plot (Explained Variance Ratio)
            </h3>
            <span className="text-[11px] font-mono font-semibold text-slate-600">10 Components</span>
          </div>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={pcaChartData} margin={{ top: 10, right: 10, left: -10, bottom: 10 }}>
                <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: '#334155', fontSize: 10, fontWeight: 600 }} />
                <YAxis stroke="#94a3b8" tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: 'rgba(255, 255, 255, 0.95)', 
                    borderColor: 'rgba(226, 232, 240, 0.8)', 
                    borderRadius: '16px',
                    boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.08)',
                    backdropFilter: 'blur(12px)',
                    color: '#0f172a',
                    fontWeight: 600,
                    fontSize: '12px'
                  }} 
                />
                <Bar dataKey="variance" fill="#4f46e5" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
