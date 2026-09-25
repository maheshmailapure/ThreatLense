import React, { useState, useEffect } from 'react';
import {
  Network, Server, Cpu, HardDrive, Activity, ArrowDownLeft, ArrowUpRight,
  Radio, RefreshCw, Search, ShieldAlert, ShieldCheck, Globe, Wifi, CheckCircle2,
  AlertTriangle, ArrowRight, Laptop, Layers, Compass
} from 'lucide-react';
import {
  getSystemHardwareOverview, getOpenListeningPorts,
  getLiveTrafficFlows, getNetworkInterfacesDetail
} from '../services/api';
import StatCard from '../components/StatCard';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';
import { motion } from 'framer-motion';

const RISK_COLORS = {
  CRITICAL: 'text-rose-700 bg-rose-50 border-rose-200',
  HIGH:     'text-amber-700 bg-amber-50 border-amber-200',
  MEDIUM:   'text-yellow-700 bg-yellow-50 border-yellow-200',
  LOW:      'text-emerald-700 bg-emerald-50 border-emerald-200',
};

export default function SystemNetworkTopology() {
  const [activeTab, setActiveTab] = useState('topology_map');
  const [systemOverview, setSystemOverview] = useState(() => getCachedData('topology_sys', null));
  const [openPorts, setOpenPorts] = useState(() => getCachedData('topology_ports', []));
  const [trafficFlows, setTrafficFlows] = useState(() => getCachedData('topology_flows', null));
  const [interfaces, setInterfaces] = useState(() => getCachedData('topology_ifaces', []));
  const [loading, setLoading] = useState(() => !hasCachedData('topology_sys'));
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [portSearch, setPortSearch] = useState('');
  const [flowSearch, setFlowSearch] = useState('');
  const [flowFilter, setFlowFilter] = useState('ALL');

  const fetchData = async () => {
    try {
      const [sys, ports, flows, ifaces] = await Promise.all([
        getSystemHardwareOverview().catch(err => { console.warn(err); return null; }),
        getOpenListeningPorts().catch(err => { console.warn(err); return []; }),
        getLiveTrafficFlows(80).catch(err => { console.warn(err); return { flows: [] }; }),
        getNetworkInterfacesDetail().catch(err => { console.warn(err); return []; })
      ]);
      if (sys) {
        setSystemOverview(sys);
        setCachedData('topology_sys', sys);
      }
      if (ports && ports.length > 0) {
        setOpenPorts(ports);
        setCachedData('topology_ports', ports);
      }
      if (flows) {
        setTrafficFlows(flows);
        setCachedData('topology_flows', flows);
      }
      if (ifaces && ifaces.length > 0) {
        setInterfaces(ifaces);
        setCachedData('topology_ifaces', ifaces);
      }
    } catch (err) {
      console.error('Failed to load topology data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    let iv;
    if (autoRefresh) {
      iv = setInterval(fetchData, 1000);
    }
    return () => { if (iv) clearInterval(iv); };
  }, [autoRefresh]);

  if (loading) return <LoadingSpinner message="Scanning host hardware, open sockets & network flows..." />;

  const flowsList = trafficFlows?.flows || [];
  const filteredPorts = openPorts.filter(p =>
    p.port.toString().includes(portSearch) ||
    p.service_name.toLowerCase().includes(portSearch.toLowerCase()) ||
    p.process_name.toLowerCase().includes(portSearch.toLowerCase()) ||
    p.bind_address.includes(portSearch)
  );

  const filteredFlows = flowsList.filter(f => {
    const matchesFilter =
      flowFilter === 'ALL' ||
      (flowFilter === 'INBOUND' && f.direction === 'INBOUND') ||
      (flowFilter === 'OUTBOUND' && f.direction === 'OUTBOUND') ||
      (flowFilter === 'PUBLIC_WAN' && f.remote_type === 'PUBLIC_WAN') ||
      (flowFilter === 'ESTABLISHED' && f.state === 'ESTABLISHED');

    const matchesSearch =
      !flowSearch ||
      f.local_endpoint.toLowerCase().includes(flowSearch.toLowerCase()) ||
      f.remote_endpoint.toLowerCase().includes(flowSearch.toLowerCase()) ||
      f.process_name.toLowerCase().includes(flowSearch.toLowerCase()) ||
      f.protocol.toLowerCase().includes(flowSearch.toLowerCase());

    return matchesFilter && matchesSearch;
  });

  const activeAdaptersCount = interfaces.filter(i => i.is_up && (i.ipv4_addresses?.length > 0 || i.bytes_recv_mb > 0)).length;
  const totalSocketsCount = (trafficFlows?.total_active_flows || 0) + openPorts.length;
  const externalWanFlows = flowsList.filter(f => f.remote_type === 'PUBLIC_WAN');

  const TABS = [
    { id: 'topology_map', label: 'Interactive Topology Map', Icon: Compass },
    { id: 'traffic',      label: `Active Sockets & Flows (${flowsList.length})`, Icon: Activity },
    { id: 'ports',        label: `Listening Services (${openPorts.length})`, Icon: Radio },
    { id: 'processes',    label: 'Process Bandwidth', Icon: Layers },
    { id: 'interfaces',   label: `Network Adapters (${interfaces.length})`, Icon: Network },
    { id: 'system',       label: 'Host Hardware Specs', Icon: Server },
  ];

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-5 max-w-7xl mx-auto"
    >
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Network className="w-4 h-4 text-[#0071e3]" />
            Network Topology & Flows
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Host socket graphs, adapter interfaces, and active bandwidth
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
              autoRefresh
                ? 'bg-[#0071e3] text-white border-[#0071e3] shadow-xs'
                : 'bg-white text-slate-700 border-slate-200'
            }`}
          >
            {autoRefresh ? 'LIVE' : 'PAUSED'}
          </button>

          <button
            onClick={() => { setRefreshing(true); fetchData(); }}
            disabled={refreshing}
            className="glass-pill px-3 py-1.5 rounded-lg text-xs font-medium text-slate-700 hover:text-slate-950 transition-all flex items-center gap-1.5 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-[#0071e3]' : ''}`} />
            Scan
          </button>
        </div>
      </div>

      {/* 4 Top KPI StatCards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          title="Active Sockets"
          value={totalSocketsCount.toString()}
          subtitle={`${trafficFlows?.inbound_flows || 0} In · ${trafficFlows?.outbound_flows || 0} Out`}
          icon={Activity}
          badgeText="Live"
        />
        <StatCard
          title="Throughput"
          value={`${((trafficFlows?.bytes_received_mb || 0) + (trafficFlows?.bytes_sent_mb || 0)).toFixed(1)} MB`}
          subtitle={`↓ ${trafficFlows?.bytes_received_mb || 0} MB · ↑ ${trafficFlows?.bytes_sent_mb || 0} MB`}
          icon={ArrowDownLeft}
          badgeText="NIC"
        />
        <StatCard
          title="Listening Ports"
          value={openPorts.length.toString()}
          subtitle={`${openPorts.filter(p => p.risk_level === 'CRITICAL' || p.risk_level === 'HIGH').length} Exposed`}
          icon={Radio}
          badgeText="Local"
        />
        <StatCard
          title="Adapters"
          value={`${activeAdaptersCount} / ${interfaces.length}`}
          subtitle={`${systemOverview?.hostname || 'Host'} (${systemOverview?.os_name || 'Windows'})`}
          icon={Wifi}
          badgeText="Active"
        />
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-200 overflow-x-auto gap-1 pb-1">
        {TABS.map(({ id, label, Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
              activeTab === id
                ? 'bg-[#0071e3] text-white font-semibold shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
            }`}
          >
            <Icon className="w-3.5 h-3.5 shrink-0" />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {/* TAB 1: Interactive Visual Topology Map */}
      {activeTab === 'topology_map' && (
        <div className="glass-panel rounded-[22px] p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-200/80 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Compass className="w-4 h-4 text-indigo-600" />
                Live Node Topology Architecture
              </h2>
              <p className="text-xs text-slate-500 font-medium mt-0.5">
                Visualizing host node, hardware adapters, local listening daemons, and active external socket flows
              </p>
            </div>
            <span className="text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-md border border-emerald-200 font-bold">
              Live Synchronized (1s)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center">
            {/* Node 1: Host Machine */}
            <div className="p-4 rounded-2xl bg-white/80 border border-indigo-200/80 space-y-2 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-indigo-700 font-bold uppercase">Root Node</span>
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              </div>
              <div className="flex items-center gap-2">
                <Laptop className="w-6 h-6 text-indigo-600" />
                <div>
                  <div className="text-xs font-bold text-slate-900">{systemOverview?.hostname || 'HOST'}</div>
                  <div className="text-[10px] text-slate-500 font-medium">{systemOverview?.os_name || 'Windows'}</div>
                </div>
              </div>
              <div className="pt-2 border-t border-slate-200/80 text-[10px] text-slate-600 font-mono space-y-1 font-medium">
                <div>CPU: <span className="text-slate-900 font-bold">{systemOverview?.cpu_usage_pct || 0}%</span></div>
                <div>RAM: <span className="text-slate-900 font-bold">{systemOverview?.memory?.used_gb || 0} / {systemOverview?.memory?.total_gb || 0} GB</span></div>
                <div>Uptime: <span className="text-slate-900 font-bold">{systemOverview?.uptime || 'N/A'}</span></div>
              </div>
            </div>

            {/* Node 2: Network Adapters */}
            <div className="p-4 rounded-2xl bg-white/80 border border-slate-200/80 space-y-2 shadow-sm">
              <div className="text-[10px] font-mono text-slate-600 font-bold uppercase">Active Adapters</div>
              <div className="space-y-1.5">
                {interfaces.slice(0, 3).map((iface, idx) => (
                  <div key={idx} className="p-2 rounded-xl bg-slate-50/90 border border-slate-200/60 text-[11px] flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <Wifi className="w-3.5 h-3.5 text-indigo-600" />
                      <span className="text-slate-800 font-medium truncate max-w-[90px]">{iface.name}</span>
                    </div>
                    <span className="font-mono text-[10px] text-emerald-700 font-bold">{iface.ipv4_addresses?.[0] || '127.0.0.1'}</span>
                  </div>
                ))}
              </div>
              <div className="text-[10px] text-slate-500 font-mono font-medium text-center">
                Total Adapters: {interfaces.length}
              </div>
            </div>

            {/* Node 3: Listening Services */}
            <div className="p-4 rounded-2xl bg-white/80 border border-slate-200/80 space-y-2 shadow-sm">
              <div className="text-[10px] font-mono text-slate-600 font-bold uppercase">Listening Daemons</div>
              <div className="space-y-1.5">
                {openPorts.slice(0, 3).map((port, idx) => (
                  <div key={idx} className="p-2 rounded-xl bg-slate-50/90 border border-slate-200/60 text-[11px] flex items-center justify-between">
                    <span className="text-slate-800 font-medium truncate max-w-[95px]">{port.process_name || 'System'}</span>
                    <span className="font-mono text-[10px] text-indigo-700 font-bold">:{port.port}</span>
                  </div>
                ))}
              </div>
              <div className="text-[10px] text-slate-500 font-mono font-medium text-center">
                Listening Ports: {openPorts.length}
              </div>
            </div>

            {/* Node 4: External Endpoints */}
            <div className="p-4 rounded-2xl bg-white/80 border border-slate-200/80 space-y-2 shadow-sm">
              <div className="text-[10px] font-mono text-slate-600 font-bold uppercase">Remote Endpoints</div>
              <div className="space-y-1.5">
                {externalWanFlows.slice(0, 3).map((f, idx) => (
                  <div key={idx} className="p-2 rounded-xl bg-slate-50/90 border border-slate-200/60 text-[11px] flex items-center justify-between">
                    <span className="text-slate-800 font-mono text-[10px] truncate max-w-[100px]">{f.remote_ip}</span>
                    <span className="text-[10px] text-indigo-700 font-mono font-bold">:{f.remote_port}</span>
                  </div>
                ))}
                {externalWanFlows.length === 0 && (
                  <div className="p-2 rounded-xl bg-slate-50/90 border border-slate-200/60 text-[10px] text-slate-500 font-medium text-center">
                    Clean Local Network Loop
                  </div>
                )}
              </div>
              <div className="text-[10px] text-slate-500 font-mono font-medium text-center">
                WAN Flows: {externalWanFlows.length}
              </div>
            </div>
          </div>

          {/* TCP State Distribution Matrix */}
          <div className="pt-4 border-t border-slate-200/80">
            <div className="text-xs font-bold text-slate-800 mb-3 flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-indigo-600" />
              TCP Connection State Machine
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 font-mono text-xs">
              {Object.entries(trafficFlows?.state_distribution || { ESTABLISHED: flowsList.length, LISTEN: openPorts.length }).map(([state, count]) => (
                <div key={state} className="p-2.5 rounded-xl bg-white/80 border border-slate-200/80 text-center shadow-sm">
                  <div className="text-[10px] text-slate-500 font-semibold">{state}</div>
                  <div className="text-sm font-bold text-slate-900 mt-0.5">{count}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Traffic Flows */}
      {activeTab === 'traffic' && (
        <div className="glass-panel rounded-[22px] p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-indigo-600" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Real-Time Host Socket Connections ({filteredFlows.length})
              </h3>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter IP, port, process..."
                  value={flowSearch}
                  onChange={(e) => setFlowSearch(e.target.value)}
                  className="pl-8 pr-3 py-1 rounded-xl bg-white/80 border border-slate-200/80 text-slate-900 text-xs font-mono font-medium focus:outline-none focus:border-indigo-500 shadow-inner"
                />
              </div>

              <div className="flex gap-1">
                {['ALL', 'ESTABLISHED', 'INBOUND', 'OUTBOUND', 'PUBLIC_WAN'].map((f) => (
                  <button
                    key={f}
                    onClick={() => setFlowFilter(f)}
                    className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all ${
                      flowFilter === f ? 'bg-indigo-600 text-white shadow-sm' : 'bg-white/80 text-slate-600 border border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-200/80 text-slate-500 font-mono text-[10px] uppercase font-bold bg-slate-50/50">
                  <th className="py-2.5 px-3">Direction</th>
                  <th className="py-2.5 px-3">Local Endpoint</th>
                  <th className="py-2.5 px-3">Remote Endpoint</th>
                  <th className="py-2.5 px-3">Zone / Classification</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3">State</th>
                  <th className="py-2.5 px-3">Process (PID)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/60 font-mono text-[11px]">
                {filteredFlows.map((f, idx) => (
                  <tr key={idx} className="hover:bg-indigo-50/40 transition-colors">
                    <td className="py-2.5 px-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold ${
                        f.direction === 'INBOUND' ? 'bg-indigo-50 text-indigo-700 border border-indigo-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}>
                        {f.direction === 'INBOUND' ? <ArrowDownLeft className="w-3 h-3" /> : <ArrowUpRight className="w-3 h-3" />}
                        {f.direction}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-800 font-bold">{f.local_endpoint}</td>
                    <td className="py-2.5 px-3 text-slate-700 font-medium">{f.remote_endpoint}</td>
                    <td className="py-2.5 px-3">
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                        f.remote_type === 'PUBLIC_WAN' ? 'bg-amber-50 text-amber-800 border border-amber-200' : 'bg-slate-100 text-slate-700 border border-slate-200'
                      }`}>
                        {f.remote_zone}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-indigo-700 font-bold">{f.protocol}</td>
                    <td className="py-2.5 px-3 text-slate-600 font-semibold">{f.state}</td>
                    <td className="py-2.5 px-3 text-slate-900 font-sans font-semibold">
                      {f.process_name} {f.pid ? `(${f.pid})` : ''}
                    </td>
                  </tr>
                ))}
                {filteredFlows.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-6 text-center text-slate-500 font-sans font-medium text-xs">
                      No matching network socket flows found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Listening Ports */}
      {activeTab === 'ports' && (
        <div className="glass-panel rounded-[22px] p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-indigo-600" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Listening Ports & Exposure Risk ({filteredPorts.length})
              </h3>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search ports or services..."
                value={portSearch}
                onChange={(e) => setPortSearch(e.target.value)}
                className="pl-8 pr-3 py-1 rounded-xl bg-white/80 border border-slate-200/80 text-slate-900 text-xs font-mono font-medium focus:outline-none focus:border-indigo-500 shadow-inner"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-200/80 text-slate-500 font-mono text-[10px] uppercase font-bold bg-slate-50/50">
                  <th className="py-2.5 px-3">Port</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3">Bind Address</th>
                  <th className="py-2.5 px-3">Scope</th>
                  <th className="py-2.5 px-3">Service / Description</th>
                  <th className="py-2.5 px-3">Security Risk</th>
                  <th className="py-2.5 px-3">Process (PID)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/60 font-mono text-[11px]">
                {filteredPorts.map((p, idx) => (
                  <tr key={idx} className="hover:bg-indigo-50/40 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-indigo-700">:{p.port}</td>
                    <td className="py-2.5 px-3 text-slate-600 font-medium">{p.protocol}</td>
                    <td className="py-2.5 px-3 text-slate-800 font-medium">{p.bind_address}</td>
                    <td className="py-2.5 px-3 text-slate-600">{p.bind_scope}</td>
                    <td className="py-2.5 px-3 text-slate-900 font-sans font-semibold text-xs">{p.service_name}</td>
                    <td className="py-2.5 px-3">
                      <span className={`text-[10px] px-2.5 py-0.5 rounded-full font-bold border ${RISK_COLORS[p.risk_level] || 'text-slate-600'}`}>
                        {p.risk_level}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-800 font-medium">
                      {p.process_name} {p.pid ? `(${p.pid})` : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: Process Bandwidth */}
      {activeTab === 'processes' && (
        <div className="glass-panel rounded-[22px] p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-200/80 pb-3">
            <Layers className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Top Windows Processes by Network Socket Count
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {(trafficFlows?.top_processes || []).map((proc, idx) => (
              <div key={idx} className="p-3.5 rounded-2xl bg-white/80 border border-slate-200/80 space-y-2 shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 truncate">{proc.process}</span>
                  <span className="text-[10px] font-mono font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-md border border-indigo-200">
                    {proc.active_sockets} Sockets
                  </span>
                </div>
                <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden border border-slate-200/60">
                  <div
                    className="bg-indigo-600 h-full rounded-full"
                    style={{ width: `${Math.min((proc.active_sockets / (flowsList.length || 1)) * 100, 100)}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: Network Adapters */}
      {activeTab === 'interfaces' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {interfaces.map((iface, idx) => (
            <div key={idx} className="glass-panel rounded-[22px] p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-200/80 pb-2.5">
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-indigo-600" />
                  <span className="text-xs font-bold text-slate-900">{iface.name}</span>
                </div>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${iface.is_up ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-600 border border-slate-200'}`}>
                  {iface.is_up ? 'ONLINE' : 'DOWN'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded-xl bg-white/70 border border-slate-200/60 shadow-sm">
                  <div className="text-[10px] text-slate-500 font-semibold font-sans">IPv4 Address</div>
                  <div className="text-slate-900 mt-0.5 font-bold">{iface.ipv4_addresses?.[0] || 'Unassigned'}</div>
                </div>
                <div className="p-2.5 rounded-xl bg-white/70 border border-slate-200/60 shadow-sm">
                  <div className="text-[10px] text-slate-500 font-semibold font-sans">MAC Address</div>
                  <div className="text-slate-800 mt-0.5 font-medium">{iface.mac_address || 'N/A'}</div>
                </div>
                <div className="p-2.5 rounded-xl bg-white/70 border border-slate-200/60 shadow-sm">
                  <div className="text-[10px] text-slate-500 font-semibold font-sans">Link Speed / MTU</div>
                  <div className="text-slate-800 mt-0.5 font-medium">{iface.speed_mbps} Mbps • MTU {iface.mtu}</div>
                </div>
                <div className="p-2.5 rounded-xl bg-white/70 border border-slate-200/60 shadow-sm">
                  <div className="text-[10px] text-slate-500 font-semibold font-sans">Data Transferred</div>
                  <div className="text-indigo-700 mt-0.5 font-bold">↓ {iface.bytes_recv_mb} MB • ↑ {iface.bytes_sent_mb} MB</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 6: Host Hardware Specs */}
      {activeTab === 'system' && systemOverview && (
        <div className="glass-panel rounded-[22px] p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-200/80 pb-3">
            <Server className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Host Hardware & OS Specifications
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3.5 rounded-xl bg-white/80 border border-slate-200/80 shadow-sm">
              <div className="text-[10px] text-slate-500 font-semibold font-sans">Operating System</div>
              <div className="text-slate-900 font-bold mt-1">{systemOverview.os_name} ({systemOverview.architecture})</div>
            </div>
            <div className="p-3.5 rounded-xl bg-white/80 border border-slate-200/80 shadow-sm">
              <div className="text-[10px] text-slate-500 font-semibold font-sans">Processor Cores</div>
              <div className="text-slate-900 font-bold mt-1">{systemOverview.cpu?.logical_cores || 4} Logical Cores ({systemOverview.cpu_usage_pct}%)</div>
            </div>
            <div className="p-3.5 rounded-xl bg-white/80 border border-slate-200/80 shadow-sm">
              <div className="text-[10px] text-slate-500 font-semibold font-sans">Physical Memory (RAM)</div>
              <div className="text-indigo-700 font-bold mt-1">{systemOverview.memory?.used_gb} / {systemOverview.memory?.total_gb} GB ({systemOverview.memory?.percent_used}%)</div>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
}
