import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User, AlertCircle, ArrowRight, Activity } from 'lucide-react';

export default function Login() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('Admin@1234');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Invalid username or password. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#eaf1ed] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Ambient light green glowing backdrop */}
      <div className="absolute -top-24 -left-24 w-96 h-96 rounded-full bg-emerald-200/40 blur-[110px] pointer-events-none" />
      <div className="absolute -bottom-24 -right-24 w-96 h-96 rounded-full bg-teal-200/35 blur-[120px] pointer-events-none" />

      <motion.div 
        initial={{ opacity: 0, scale: 0.96, y: 12 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.35, ease: 'easeOut' }}
        className="max-w-md w-full neu-flat rounded-[32px] p-8 sm:p-10 relative z-10 space-y-6"
      >
        {/* Embossed Circular Icon Header */}
        <div className="text-center">
          <div className="w-16 h-16 rounded-full neu-circle flex items-center justify-center mx-auto mb-4 text-[#2563eb]">
            <Shield className="w-7 h-7" />
          </div>
          <h2 className="text-2xl font-black text-slate-900 tracking-tight">ThreatLense Console</h2>
          <p className="text-xs font-medium text-slate-500 mt-1">
            Endpoint Security & Threat Telemetry
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="p-3.5 rounded-2xl neu-inset flex items-center gap-2.5 text-rose-600 text-xs font-medium">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-500" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1.5 ml-1">
              Analyst Username
            </label>
            <div className="neu-inset rounded-2xl flex items-center px-4 py-3">
              <User className="w-4 h-4 text-slate-400 shrink-0 mr-3" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                className="w-full bg-transparent border-none text-xs font-semibold text-slate-800 placeholder-slate-400 focus:outline-none font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1.5 ml-1">
              Access Password
            </label>
            <div className="neu-inset rounded-2xl flex items-center px-4 py-3">
              <Lock className="w-4 h-4 text-slate-400 shrink-0 mr-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-transparent border-none text-xs font-semibold text-slate-800 placeholder-slate-400 focus:outline-none font-mono"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-4 py-3.5 rounded-2xl neu-accent-btn font-bold text-xs tracking-wider uppercase transition-all flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <Activity className="w-4 h-4 animate-spin" />
                Authenticating...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                Authenticate Access <ArrowRight className="w-4 h-4" />
              </span>
            )}
          </button>
        </form>

        {/* Default Credentials Helper */}
        <div className="pt-5 border-t border-slate-300/40 text-center">
          <div className="text-[10px] text-slate-500 mb-2 font-bold uppercase tracking-wider">Default Credentials</div>
          <div className="inline-flex items-center gap-2 text-xs font-mono font-bold neu-inset px-4 py-2 rounded-xl text-[#2563eb]">
            <span>admin</span> / <span>Admin@1234</span>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

