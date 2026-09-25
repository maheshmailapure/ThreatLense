import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  ArrowLeft, 
  Clock, 
  Activity,
  FileText
} from 'lucide-react';
import { getAlert, updateAlertStatus } from '../services/api';
import DetectionExplanation from '../components/DetectionExplanation';
import LoadingSpinner from '../components/LoadingSpinner';

const riskBadges = {
  CRITICAL: 'bg-rose-100 text-rose-800 border-rose-300',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-300',
  MEDIUM: 'bg-amber-100 text-amber-800 border-amber-300',
  LOW: 'bg-emerald-100 text-emerald-800 border-emerald-300',
};

export default function AlertDetails() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);

  const fetchDetail = async () => {
    try {
      const data = await getAlert(id);
      setAlert(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
  }, [id]);

  const handleStatusChange = async (newStatus) => {
    setUpdating(true);
    try {
      await updateAlertStatus(id, newStatus);
      setAlert((prev) => ({ ...prev, status: newStatus }));
    } catch (err) {
      console.error(err);
    } finally {
      setUpdating(false);
    }
  };

  if (loading) {
    return <LoadingSpinner message={`Loading incident packet #${id}...`} />;
  }

  if (!alert) {
    return (
      <div className="glass-panel rounded-2xl p-8 text-center text-slate-600 text-sm font-medium">
        Alert #{id} not found.
      </div>
    );
  }

  const det = alert.detection;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 max-w-7xl mx-auto"
    >
      {/* Header & Back Button */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/alerts')}
            className="p-2.5 rounded-xl bg-white/80 hover:bg-white border border-slate-200/80 text-slate-700 shadow-sm transition-all"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">{alert.alert_type}</h1>
              <span className="text-xs font-mono font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-md border border-indigo-200">#{alert.id}</span>
            </div>
            <p className="text-xs font-medium text-slate-500 mt-0.5">
              Incident logged at {new Date(alert.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        {/* Triage Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
            <button
              key={st}
              onClick={() => handleStatusChange(st)}
              disabled={updating || alert.status === st}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all shadow-sm ${
                alert.status === st
                  ? 'bg-indigo-600 text-white'
                  : 'bg-white/80 border border-slate-200/80 text-slate-700 hover:bg-white'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Incident Overview Card */}
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-200/80">
          <span className={`px-2.5 py-1 rounded-full text-[11px] font-bold border ${riskBadges[alert.risk_level] || ''}`}>
            {alert.risk_level} RISK
          </span>
          <span className="text-xs font-mono text-slate-600">
            Attack Class: <strong className="text-slate-900">{alert.attack_type || 'Unknown'}</strong>
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-white/70 border border-slate-200/80 shadow-sm">
            <span className="text-slate-500 text-[10px] uppercase font-sans font-bold block">Source Endpoint</span>
            <div className="font-bold text-indigo-700 mt-0.5 text-sm">{alert.ip_source || 'Host Socket'}</div>
          </div>
          <div className="p-3.5 rounded-xl bg-white/70 border border-slate-200/80 shadow-sm">
            <span className="text-slate-500 text-[10px] uppercase font-sans font-bold block">Destination</span>
            <div className="font-bold text-slate-800 mt-0.5 text-sm">{alert.ip_destination || 'Internal'}</div>
          </div>
          <div className="p-3.5 rounded-xl bg-white/70 border border-slate-200/80 shadow-sm">
            <span className="text-slate-500 text-[10px] uppercase font-sans font-bold block">Inference Engine</span>
            <div className="font-bold text-slate-800 mt-0.5 text-sm">{alert.model || 'Random Forest'}</div>
          </div>
          <div className="p-3.5 rounded-xl bg-white/70 border border-slate-200/80 shadow-sm">
            <span className="text-slate-500 text-[10px] uppercase font-sans font-bold block">Status</span>
            <div className="font-bold text-indigo-700 mt-0.5 text-sm">{alert.status}</div>
          </div>
        </div>

        <div>
          <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1.5">Description</span>
          <p className="text-xs font-medium text-slate-700 bg-white/80 p-3.5 rounded-xl border border-slate-200/80 leading-relaxed shadow-sm">
            {alert.description}
          </p>
        </div>
      </div>

      {/* Detection Explanation & Raw Features */}
      {det && (
        <div className="space-y-4">
          <DetectionExplanation detection={det} />
        </div>
      )}
    </motion.div>
  );
}
