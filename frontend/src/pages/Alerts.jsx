import React, { useState, useEffect } from 'react';
import { AlertTriangle, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { motion } from 'framer-motion';
import { getAlerts, updateAlertStatus } from '../services/api';
import AlertTable from '../components/AlertTable';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';

export default function Alerts() {
  const [data, setData] = useState(() => getCachedData('alerts_page_1', { items: [], total: 0, page: 1, total_pages: 1 }));
  const [loading, setLoading] = useState(() => !hasCachedData('alerts_page_1'));
  const [page, setPage] = useState(1);
  const [riskLevel, setRiskLevel] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');

  const fetchAlertsData = async () => {
    try {
      const res = await getAlerts({
        page,
        page_size: 20,
        risk_level: riskLevel || undefined,
        status: status || undefined,
        search: search || undefined
      });
      setData(res);
      if (page === 1 && !riskLevel && !status && !search) {
        setCachedData('alerts_page_1', res);
      }
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAlertsData(); }, [page, riskLevel, status]);

  const handleSearchSubmit = (e) => { e.preventDefault(); setPage(1); fetchAlertsData(); };

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      setData((prev) => ({ ...prev, items: prev.items.map((item) => item.id === alertId ? { ...item, status: newStatus } : item) }));
    } catch (err) { console.error(err); }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 max-w-7xl mx-auto"
    >
      {/* Header */}
      <div className="neu-flat p-4 rounded-3xl flex items-center justify-between">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-[#2563eb]">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-extrabold text-slate-900 tracking-tight">
              Incident Queue
            </h1>
            <p className="text-xs text-slate-500 font-medium">
              {(data?.total || 0).toLocaleString()} logged security incidents
            </p>
          </div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="neu-flat rounded-[28px] p-5 space-y-4">
        <form onSubmit={handleSearchSubmit} className="flex gap-3">
          <div className="relative flex-1 neu-inset rounded-2xl flex items-center px-4 py-2.5">
            <Search className="w-4 h-4 text-slate-400 shrink-0 mr-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search incidents by IP, category, or signature..."
              className="w-full bg-transparent border-none text-xs text-slate-900 placeholder-slate-400 focus:outline-none font-medium"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2.5 neu-accent-btn font-bold text-xs rounded-2xl transition-all"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap gap-3 pt-3 border-t border-slate-300/40">
          <select
            value={riskLevel}
            onChange={(e) => { setRiskLevel(e.target.value); setPage(1); }}
            className="neu-button px-4 py-2 rounded-2xl text-slate-700 font-bold text-xs focus:outline-none cursor-pointer"
          >
            <option value="" className="bg-[#edf4f0]">All Severities</option>
            <option value="CRITICAL" className="bg-[#edf4f0]">Critical</option>
            <option value="HIGH" className="bg-[#edf4f0]">High</option>
            <option value="MEDIUM" className="bg-[#edf4f0]">Medium</option>
            <option value="LOW" className="bg-[#edf4f0]">Low</option>
          </select>
          <select
            value={status}
            onChange={(e) => { setStatus(e.target.value); setPage(1); }}
            className="neu-button px-4 py-2 rounded-2xl text-slate-700 font-bold text-xs focus:outline-none cursor-pointer"
          >
            <option value="" className="bg-[#edf4f0]">All States</option>
            <option value="NEW" className="bg-[#edf4f0]">New</option>
            <option value="INVESTIGATING" className="bg-[#edf4f0]">Investigating</option>
            <option value="RESOLVED" className="bg-[#edf4f0]">Resolved</option>
            <option value="FALSE_POSITIVE" className="bg-[#edf4f0]">False Positive</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="neu-flat rounded-[28px] p-6 overflow-hidden">
        {loading ? (
          <LoadingSpinner message="Filtering incident queue..." />
        ) : (
          <AlertTable alerts={data.items} onStatusChange={handleStatusChange} showActions={true} />
        )}

        {/* Pagination */}
        <div className="mt-4 pt-4 border-t border-slate-300/40 flex items-center justify-between text-xs text-slate-500 font-mono">
          <span>Page {data.page} of {data.total_pages} ({data.total.toLocaleString()} total)</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={data.page <= 1}
              className="p-2 rounded-xl neu-button disabled:opacity-40 text-slate-700 transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(data.total_pages, p + 1))}
              disabled={data.page >= data.total_pages}
              className="p-2 rounded-xl neu-button disabled:opacity-40 text-slate-700 transition-colors"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

