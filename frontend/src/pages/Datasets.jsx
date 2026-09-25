import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Upload, 
  Database, 
  Trash2, 
  Eye, 
  Cpu, 
  CheckCircle2, 
  AlertCircle, 
  FileText
} from 'lucide-react';
import { getDatasets, uploadDataset, deleteDataset, getDatasetPreview } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';

export default function Datasets() {
  const [datasets, setDatasets] = useState(() => getCachedData('datasets_list', []));
  const [loading, setLoading] = useState(() => !hasCachedData('datasets_list'));
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [previewData, setPreviewData] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const navigate = useNavigate();

  const fetchDatasets = async () => {
    try {
      const data = await getDatasets();
      if (data) {
        setDatasets(data);
        setCachedData('datasets_list', data);
      }
    } catch (err) {
      console.error("Error loading datasets:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDatasets();
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setError('');
    setSuccess('');
    setUploading(true);

    try {
      const newDataset = await uploadDataset(file);
      setSuccess(`Dataset "${newDataset.filename}" uploaded & indexed successfully!`);
      await fetchDatasets();
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to upload dataset.');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Are you sure you want to delete dataset "${name}"?`)) return;
    try {
      await deleteDataset(id);
      setDatasets((prev) => prev.filter((d) => d.id !== id));
      setSuccess(`Dataset "${name}" deleted.`);
    } catch (err) {
      setError('Failed to delete dataset.');
    }
  };

  const handlePreview = async (id) => {
    setPreviewLoading(true);
    try {
      const preview = await getDatasetPreview(id, 10);
      setPreviewData(preview);
    } catch (err) {
      setError('Failed to load dataset preview.');
    } finally {
      setPreviewLoading(false);
    }
  };

  if (loading) {
    return <LoadingSpinner message="Retrieving indexed cybersecurity datasets..." />;
  }

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
          <Database className="w-5 h-5 text-indigo-600" />
          Dataset Management
        </h1>
        <p className="text-xs font-medium text-slate-600 mt-1">
          Ingest, validate, and inspect NSL-KDD benchmark & network flow datasets
        </p>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3.5 rounded-2xl bg-rose-50 border border-rose-200/80 text-rose-700 text-xs font-medium flex items-center gap-2 shadow-sm">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-500" />
          <span>{error}</span>
        </div>
      )}
      {success && (
        <div className="p-3.5 rounded-2xl bg-emerald-50 border border-emerald-200/80 text-emerald-700 text-xs font-medium flex items-center gap-2 shadow-sm">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500" />
          <span>{success}</span>
        </div>
      )}

      {/* Drag & Drop Upload Zone */}
      <div className="glass-panel rounded-2xl p-8 transition-colors text-center border-2 border-dashed border-indigo-200 hover:border-indigo-400">
        <Upload className="w-8 h-8 mx-auto text-indigo-600 mb-2" />
        <h3 className="text-sm font-bold text-slate-900">Upload NSL-KDD or Flow Dataset</h3>
        <p className="text-xs font-medium text-slate-600 mt-1 max-w-md mx-auto">
          Supports <code className="text-indigo-700 font-mono font-semibold">KDDTrain+.txt</code>, <code className="text-indigo-700 font-mono font-semibold">KDDTest+.txt</code>, or custom flow <code className="text-indigo-700 font-mono font-semibold">.csv</code> files. Automatic header & 41-feature detection.
        </p>

        <label className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs cursor-pointer transition-all shadow-md shadow-indigo-500/20">
          <Upload className="w-3.5 h-3.5" />
          <span>{uploading ? 'Processing File...' : 'Select Dataset File'}</span>
          <input
            type="file"
            accept=".csv,.txt,.data"
            onChange={handleFileUpload}
            disabled={uploading}
            className="hidden"
          />
        </label>
      </div>

      {/* Datasets Table */}
      <div className="glass-panel rounded-2xl overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-slate-200/80 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-600" />
            Indexed Datasets ({datasets.length})
          </h3>
        </div>

        {datasets.length === 0 ? (
          <div className="p-8 text-center text-slate-600 text-xs font-medium">
            No datasets uploaded yet. Upload a dataset above or run seed.py.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[11px] text-slate-500 uppercase tracking-wider font-bold border-b border-slate-200/80 bg-slate-50/50">
                <tr>
                  <th className="py-3 px-6">Dataset Name</th>
                  <th className="py-3 px-6">Records</th>
                  <th className="py-3 px-6">Features</th>
                  <th className="py-3 px-6">Missing / Dupes</th>
                  <th className="py-3 px-6">Uploaded</th>
                  <th className="py-3 px-6">Status</th>
                  <th className="py-3 px-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/60 font-mono">
                {datasets.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-500/5 transition-colors">
                    <td className="py-3.5 px-6 font-sans font-bold text-slate-900 flex items-center gap-2">
                      <FileText className="w-4 h-4 text-indigo-600 shrink-0" />
                      <span>{d.filename}</span>
                    </td>
                    <td className="py-3.5 px-6 text-indigo-700 font-semibold">{d.total_records.toLocaleString()}</td>
                    <td className="py-3.5 px-6 text-slate-800 font-semibold">{d.total_features} cols</td>
                    <td className="py-3.5 px-6 text-slate-600 font-sans font-medium">
                      {d.meta_info?.missing_values || 0} / {d.meta_info?.duplicates || 0}
                    </td>
                    <td className="py-3.5 px-6 text-slate-500 text-[11px] font-sans font-medium">
                      {new Date(d.uploaded_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-6">
                      <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                        {d.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-6 text-right font-sans space-x-2">
                      <button
                        onClick={() => handlePreview(d.id)}
                        className="px-3 py-1.5 rounded-xl bg-white/80 hover:bg-white text-slate-700 border border-slate-200/80 text-xs inline-flex items-center gap-1.5 transition-all shadow-sm font-semibold"
                      >
                        <Eye className="w-3.5 h-3.5 text-indigo-600" /> Preview
                      </button>

                      <button
                        onClick={() => navigate('/models', { state: { selectedDatasetId: d.id } })}
                        className="px-3 py-1.5 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-xs inline-flex items-center gap-1.5 transition-all font-semibold shadow-sm"
                      >
                        <Cpu className="w-3.5 h-3.5" /> Train
                      </button>

                      <button
                        onClick={() => handleDelete(d.id, d.filename)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Dataset Preview Modal */}
      <AnimatePresence>
        {previewData && (
          <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-md z-50 flex items-center justify-center p-4">
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel bg-white/95 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden shadow-2xl border border-slate-200/80"
            >
              <div className="px-6 py-4 border-b border-slate-200/80 flex items-center justify-between bg-slate-50/50">
                <div>
                  <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
                    <Database className="w-4 h-4 text-indigo-600" />
                    Dataset Preview: {previewData.filename}
                  </h3>
                  <p className="text-[11px] font-medium text-slate-500 mt-0.5">
                    Showing first {previewData.sample_records?.length} rows of {previewData.total_records?.toLocaleString()} records
                  </p>
                </div>
                <button
                  onClick={() => setPreviewData(null)}
                  className="px-3 py-1.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-xs font-semibold text-slate-700 shadow-sm"
                >
                  Close
                </button>
              </div>

              <div className="p-4 overflow-auto flex-1 font-mono text-[11px]">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-100 border-b border-slate-200 text-indigo-900 font-bold">
                      {previewData.columns?.slice(0, 10).map((col) => (
                        <th key={col} className="p-2.5 whitespace-nowrap">{col}</th>
                      ))}
                      {previewData.columns?.length > 10 && <th className="p-2.5">...</th>}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {previewData.sample_records?.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-50">
                        {previewData.columns?.slice(0, 10).map((col) => (
                          <td key={col} className="p-2.5 whitespace-nowrap text-slate-800 font-medium">
                            {String(row[col])}
                          </td>
                        ))}
                        {previewData.columns?.length > 10 && <td className="p-2.5 text-slate-400">...</td>}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="px-6 py-3.5 border-t border-slate-200/80 bg-slate-50/50 flex items-center justify-between text-xs text-slate-600 font-medium">
                <span>Memory footprint: <strong className="text-slate-900">{previewData.meta_info?.memory_usage_mb || '< 1'} MB</strong></span>
                <button
                  onClick={() => {
                    const id = previewData.id;
                    setPreviewData(null);
                    navigate('/models', { state: { selectedDatasetId: id } });
                  }}
                  className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-sm"
                >
                  Proceed to Model Training
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
