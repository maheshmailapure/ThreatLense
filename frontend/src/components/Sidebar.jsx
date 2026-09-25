import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Database, 
  Cpu, 
  AlertTriangle, 
  LineChart, 
  Radio, 
  Settings, 
  Flame, 
  Globe, 
  FileDown, 
  Server, 
  Zap,
  Shield
} from 'lucide-react';
import { 
  getDashboardStats, 
  getDashboardCharts
} from '../services/api';
import { setCachedData } from '../services/dataCache';

const section1_monitoring = [
  { name: 'Dashboard',               href: '/dashboard',      icon: LayoutDashboard },
  { name: 'Live Monitor',            href: '/live-monitor',   icon: Radio },
  { name: 'Topology',                href: '/topology',       icon: Server },
  { name: 'Web Auditor',             href: '/web-auditor',    icon: Globe },
  { name: 'Interceptor',             href: '/malware-scanner',icon: FileDown },
];

const section2_defense = [
  { name: 'Validation Lab',          href: '/attack-lab',     icon: Flame },
  { name: 'Atria AI Engine',         href: '/ai-decision',    icon: Zap },
  { name: 'Incidents',               href: '/alerts',         icon: AlertTriangle },
];

const section3_analytics = [
  { name: 'Model Registry',          href: '/models',         icon: Cpu },
  { name: 'Settings',                href: '/settings',       icon: Settings },
];

export default function Sidebar() {
  const prefetchData = (href) => {
    try {
      if (href === '/dashboard') {
        getDashboardStats().then(d => d && setCachedData('dashboard_stats', d)).catch(() => {});
        getDashboardCharts().then(d => d && setCachedData('dashboard_charts', d)).catch(() => {});
      }
    } catch (e) {}
  };

  const renderNavGroup = (items) => (
    <div className="space-y-1.5">
      {items.map((item) => (
        <NavLink
          key={item.name}
          to={item.href}
          onMouseEnter={() => prefetchData(item.href)}
          className={({ isActive }) =>
            `flex items-center gap-3 px-3.5 py-2.5 rounded-[16px] text-xs font-semibold transition-all select-none ${
              isActive
                ? 'neu-accent-btn text-white font-bold'
                : 'text-slate-600 hover:text-slate-900 hover:shadow-[4px_4px_10px_rgba(152,174,165,0.4),-4px_-4px_10px_rgba(255,255,255,0.8)]'
            }`
          }
        >
          <item.icon className="w-4 h-4 shrink-0" />
          <span className="truncate">{item.name}</span>
        </NavLink>
      ))}
    </div>
  );

  return (
    <aside className="w-60 shrink-0 bg-[#edf4f0]/95 backdrop-blur-md border-r border-slate-300/40 flex flex-col h-full select-none z-30 shadow-[4px_0_15px_rgba(152,174,165,0.25)]">
      {/* Tactile Application Header */}
      <div className="h-16 flex items-center px-4 border-b border-slate-300/30 justify-center">
        <img src="/threatlense_logo.png" alt="ThreatLense" className="h-9 w-auto object-contain max-w-[200px]" />
      </div>

      {/* Nav groups */}
      <div className="flex-1 py-4 px-3 space-y-5 overflow-y-auto">
        <div>
          <div className="px-3 pb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
            Monitoring
          </div>
          {renderNavGroup(section1_monitoring)}
        </div>
        <div>
          <div className="px-3 pb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
            Active Defense
          </div>
          {renderNavGroup(section2_defense)}
        </div>
        <div>
          <div className="px-3 pb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
            Intelligence
          </div>
          {renderNavGroup(section3_analytics)}
        </div>
      </div>

      {/* Soft Inset Status Footer */}
      <div className="p-3.5 m-3 rounded-[18px] bg-[#e4ece7] shadow-[inset_3px_3px_6px_rgba(152,174,165,0.5),inset_-3px_-3px_6px_rgba(255,255,255,0.9)] border border-white/50">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-600 font-semibold flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
            Daemon
          </span>
          <span className="text-emerald-700 font-bold text-[10px] uppercase">Active</span>
        </div>
      </div>
    </aside>
  );
}
