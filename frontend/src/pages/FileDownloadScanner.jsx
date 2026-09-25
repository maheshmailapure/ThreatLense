import React, { useState, useEffect } from 'react';
import {
  FileDown, ShieldAlert, ShieldCheck, AlertTriangle, Radio, RefreshCw,
  Copy, Check, Zap, CheckCircle2, XCircle, Activity, Fingerprint, Play,
  Ban, Unlock, FolderOpen
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  getDownloadWatcherStatus,
  scanRealSystemDownloads,
  toggleDownloadWatcher,
  scanCustomTextPayload,
  executePolicyDecision
} from '../services/api';
import { playIntrusionAlarm } from '../utils/audioAlarm';
import LoadingSpinner from '../components/LoadingSpinner';
import { getCachedData, setCachedData, hasCachedData } from '../services/dataCache';
import { motion } from 'framer-motion';

// Pipeline steps definition
const PIPELINE_STEPS = [
  { id: 'begin',    label: 'Download Begins',            sub: 'Incoming packet stream initiated',      Icon: FileDown },
  { id: 'browser',  label: 'Browser Detects File',       sub: 'Socket & file handle registered',       Icon: Radio },
  { id: 'agent',    label: 'Security Agent Scan',         sub: 'MD5 hash, entropy & heuristic check',   Icon: Fingerprint },
  { id: 'decision', label: 'Threat Evaluation',           sub: 'Decision branch: clean or suspicious',  Icon: Activity },
];

export default function FileDownloadScanner({ onTriggerAlarm }) {
  const navigate = useNavigate();
  const [watcherStatus, setWatcherStatus] = useState(() => getCachedData('watcher_status', null));
  const [scanData, setScanData] = useState(() => getCachedData('download_scan_data', null));
  const [loading, setLoading] = useState(() => !hasCachedData('download_scan_data'));
  const [refreshing, setRefreshing] = useState(false);
  const [copiedHash, setCopiedHash] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [policyMessage, setPolicyMessage] = useState(null);
  const [activeStep, setActiveStep] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [simulatedResult, setSimulatedResult] = useState(null);

  const fetchData = async () => {
    try {
      const [status, results] = await Promise.all([
        getDownloadWatcherStatus().catch(err => { console.warn(err); return null; }),
        scanRealSystemDownloads().catch(err => { console.warn(err); return null; })
      ]);
      if (status) {
        setWatcherStatus(status);
        setCachedData('watcher_status', status);
      }
      if (results) {
        setScanData(results);
        setCachedData('download_scan_data', results);
      }

      if (results?.trigger_alarm && results.new_threats?.length > 0) {
        const top = results.new_threats[0];
        setSelectedThreat(top);

        // Single-shot deduplicated alarm: only play once per unique threat hash across session
        const threatHash = top.md5_hash || top.filename;
        let alarmedSet = new Set();
        try {
          alarmedSet = new Set(JSON.parse(sessionStorage.getItem('tl_alarmed_downloads') || '[]'));
        } catch (e) {}

        if (!alarmedSet.has(threatHash) && top.is_harmful === true) {
          try {
            alarmedSet.add(threatHash);
            sessionStorage.setItem('tl_alarmed_downloads', JSON.stringify([...alarmedSet]));
          } catch (e) {}

          playIntrusionAlarm('CRITICAL');
          if (onTriggerAlarm) {
            onTriggerAlarm({
              title: `CONFIRMED MALICIOUS DOWNLOAD: ${top.threat_name}`,
              risk_level: 'CRITICAL',
              source_ip: top.source_url || top.filename,
              anomaly_score: top.entropy_score,
              attack_type: 'Host File Interception (R2L)'
            });
          }
        }
      }
    } catch (err) {
      console.error('Scan failed:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 2500);
    return () => clearInterval(iv);
  }, []);

  const handleToggleWatcher = async () => {
    if (!watcherStatus) return;
    try {
      const res = await toggleDownloadWatcher(!watcherStatus.watcher_enabled);
      setWatcherStatus(prev => ({ ...prev, watcher_enabled: res.watcher_enabled }));
    } catch (err) { console.error(err); }
  };

  const handleCopy = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleSimulatePipeline = async (type) => {
    setSimulating(true);
    setSimulatedResult(null);
    setPolicyMessage(null);
    const isMalicious = type === 'malicious';
    const filename   = isMalicious ? 'Q3_Invoice_Financial.pdf.exe' : 'Quarterly_Security_Report.pdf';
    const payload    = isMalicious
      ? "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
      : "%PDF-1.4\n1 0 obj\n<< /Title (Benign Report) >>\nendobj\n%%EOF";
    const sourceUrl  = isMalicious ? 'http://198.51.100.42/payloads/invoice.pdf.exe' : 'https://internal-server.local/report.pdf';

    for (const step of PIPELINE_STEPS) {
      setActiveStep(step.id);
      await new Promise(r => setTimeout(r, 450));
    }

    try {
      const result = await scanCustomTextPayload(filename, payload, sourceUrl);
      setSimulatedResult(result);
      setActiveStep(result.is_malicious ? 'alert' : 'continue');
      if (result.is_malicious) {
        playIntrusionAlarm();
        if (onTriggerAlarm) {
          onTriggerAlarm({
            title: `MALICIOUS DOWNLOAD DETECTED: ${result.threat_name}`,
            risk_level: 'CRITICAL',
            source_ip: sourceUrl,
            anomaly_score: result.entropy_score,
            attack_type: 'Malicious Dropper (R2L)'
          });
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSimulating(false);
      fetchData();
    }
  };

  const handlePolicyAction = async (filename, action, md5Hash) => {
    try {
      const res = await executePolicyDecision(filename, action, md5Hash);
      setPolicyMessage(res.action_taken);
      setSelectedThreat(null);
      fetchData();
    } catch (err) { console.error(err); }
  };

  if (loading) return <LoadingSpinner message="Connecting to host Downloads directory..." />;

  const filesList      = scanData?.files || [];
  const maliciousCount = filesList.filter(f => f.is_malicious).length;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 max-w-7xl mx-auto"
    >
      {/* Header */}
      <div className="neu-flat p-4 rounded-3xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-amber-500">
            <Zap className="w-5 h-5 fill-amber-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-extrabold text-slate-900 tracking-tight">
                Atria AI Download Interceptor & Scanner
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-md neu-inset text-emerald-700 font-bold">
                AUTONOMOUS
              </span>
            </div>
            <p className="text-xs text-slate-500 font-medium">
              Autonomous screening of incoming files — Atria AI evaluates payloads, prevents false sirens, and executes instant quarantine
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleToggleWatcher}
            className={`px-4 py-2 rounded-2xl text-xs font-bold transition-all ${
              watcherStatus?.watcher_enabled
                ? 'neu-accent-btn'
                : 'neu-button text-slate-600'
            }`}
          >
            Atria Watcher: {watcherStatus?.watcher_enabled ? 'ACTIVE' : 'PAUSED'}
          </button>
          <button
            onClick={() => { setRefreshing(true); fetchData(); }}
            disabled={refreshing}
            className="neu-button px-4 py-2 rounded-2xl text-xs font-bold text-slate-800 hover:text-[#2563eb] transition-all flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-[#2563eb]' : ''}`} />
            Scan Downloads
          </button>
        </div>
      </div>

      {/* Metric tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Directory Watcher', value: watcherStatus?.watcher_enabled ? 'ACTIVE' : 'PAUSED', sub: 'Real-time file monitoring', color: watcherStatus?.watcher_enabled ? 'text-[#2563eb]' : 'text-slate-500' },
          { label: 'Threats Intercepted', value: maliciousCount, sub: 'Malicious files detected', color: maliciousCount > 0 ? 'text-rose-600' : 'text-emerald-700' },
          { label: 'Files Monitored', value: filesList.length, sub: 'In host Downloads folder', color: 'text-slate-900' },
          { label: 'Entropy Cutoff', value: '7.4 / 8.0', sub: 'Shannon entropy threshold', color: 'text-purple-700' },
        ].map(({ label, value, sub, color }) => (
          <div key={label} className="neu-flat rounded-[28px] p-5 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">{label}</span>
            <div className={`text-xl font-black ${color}`}>{value}</div>
            <div className="text-[11px] text-slate-500 font-medium">{sub}</div>
          </div>
        ))}
      </div>

      {/* Monitored path banner */}
      <div className="neu-flat rounded-[28px] p-5 flex items-center gap-3.5">
        <div className="w-10 h-10 rounded-2xl neu-circle text-[#2563eb] flex items-center justify-center shrink-0">
          <FolderOpen className="w-5 h-5" />
        </div>
        <div>
          <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider block">Monitored System Directory</span>
          <span className="text-xs font-mono font-bold text-slate-900">
            {watcherStatus?.downloads_folder_path || 'C:\\Users\\...\\Downloads'}
          </span>
        </div>
        <div className="ml-auto text-right text-[11px] font-mono font-bold">
          <span className="text-slate-500 block font-normal">Auto-refresh</span>
          <span className="text-[#2563eb]">5s stream</span>
        </div>
      </div>

      {/* Threat alert banner */}
      {selectedThreat && (
        <div className="p-6 rounded-[28px] neu-flat border-rose-300 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl neu-circle flex items-center justify-center text-rose-600 shrink-0">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-200 text-rose-800 mr-2">CRITICAL</span>
                <span className="text-sm font-extrabold text-rose-950">{selectedThreat.threat_name}</span>
                <p className="text-xs text-rose-800 font-mono mt-0.5">
                  {selectedThreat.filename} · {selectedThreat.size_bytes} bytes · Entropy {selectedThreat.entropy_score}/8.0
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => handlePolicyAction(selectedThreat.filename, 'block', selectedThreat.md5_hash)}
                className="px-4 py-2 rounded-2xl bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs transition-all shadow-md flex items-center gap-1.5"
              >
                <Ban className="w-3.5 h-3.5" /> Block & Quarantine
              </button>
              <button
                onClick={() => handlePolicyAction(selectedThreat.filename, 'allow', selectedThreat.md5_hash)}
                className="neu-button px-4 py-2 rounded-2xl text-slate-800 font-bold text-xs transition-all flex items-center gap-1.5"
              >
                <Unlock className="w-3.5 h-3.5 text-emerald-600" /> Allow
              </button>
            </div>
          </div>
          {selectedThreat.threat_indicators?.length > 0 && (
            <div className="space-y-1.5 pt-3 border-t border-rose-200/70">
              {selectedThreat.threat_indicators.map((ind, idx) => (
                <div key={idx} className="flex items-center gap-2 text-xs text-rose-900 font-mono font-medium">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                  {ind}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Policy confirmation */}
      {policyMessage && (
        <div className="p-4 rounded-2xl neu-inset text-emerald-800 text-xs font-mono font-bold flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
          {policyMessage}
        </div>
      )}

      {/* Pipeline Simulation */}
      <div className="neu-flat rounded-[28px] p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-extrabold text-slate-900">Download Verification Pipeline</h3>
            <p className="text-xs text-slate-500 font-medium mt-0.5">Test detection pipeline with simulated safe or malicious streams</p>
          </div>
          <div className="flex items-center gap-2.5">
            <button
              onClick={() => handleSimulatePipeline('malicious')}
              disabled={simulating}
              className="px-4 py-2.5 rounded-2xl bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs transition-all shadow-md flex items-center gap-1.5 disabled:opacity-50"
            >
              <Play className="w-3 h-3 fill-current" />
              {simulating ? 'Running...' : 'Test Malicious (.exe)'}
            </button>
            <button
              onClick={() => handleSimulatePipeline('safe')}
              disabled={simulating}
              className="px-4 py-2.5 rounded-2xl neu-accent-btn font-bold text-xs transition-all flex items-center gap-1.5 disabled:opacity-50"
            >
              <Play className="w-3 h-3 fill-current" />
              {simulating ? 'Running...' : 'Test Safe (.pdf)'}
            </button>
          </div>
        </div>

        {/* Step indicators */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
          {PIPELINE_STEPS.map(({ id, label, sub, Icon }) => (
            <div
              key={id}
              className={`p-4 rounded-2xl text-center transition-all ${
                activeStep === id
                  ? 'neu-inset text-[#2563eb]'
                  : 'neu-button'
              }`}
            >
              <Icon className={`w-5 h-5 mx-auto mb-1.5 ${activeStep === id ? 'text-[#2563eb]' : 'text-slate-400'}`} />
              <div className={`text-xs font-bold ${activeStep === id ? 'text-[#2563eb]' : 'text-slate-800'}`}>{label}</div>
              <div className="text-[10px] text-slate-500 font-medium mt-0.5">{sub}</div>
            </div>
          ))}
        </div>

        {/* Branch outcomes */}
        {(activeStep === 'alert' || activeStep === 'continue' || simulatedResult) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className={`p-4 rounded-2xl transition-all ${
              activeStep === 'continue' ? 'neu-inset text-emerald-800' : 'neu-flat'
            }`}>
              <div className="flex items-center gap-2 text-emerald-700 font-bold text-xs mb-1">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                Clean — Continue Download
              </div>
              <p className="text-[11px] text-slate-600 font-medium">Hash verified safe, entropy within normal baseline.</p>
            </div>
            <div className={`p-4 rounded-2xl transition-all ${
              activeStep === 'alert' ? 'neu-inset text-rose-800' : 'neu-flat'
            }`}>
              <div className="flex items-center gap-2 text-rose-700 font-bold text-xs mb-1">
                <ShieldAlert className="w-4 h-4 text-rose-600" />
                Malicious — Alarm Triggered
              </div>
              <p className="text-[11px] text-slate-600 font-medium">Audio siren + SOC incident + Policy Quarantine</p>
            </div>
          </div>
        )}

        {/* Simulation result detail */}
        {simulatedResult && (
          <div className={`p-5 rounded-2xl neu-inset ${simulatedResult.is_malicious ? 'text-rose-900' : 'text-slate-800'}`}>
            <div className="flex items-center gap-2 mb-3">
              {simulatedResult.is_malicious
                ? <ShieldAlert className="w-4 h-4 text-rose-600" />
                : <ShieldCheck className="w-4 h-4 text-emerald-600" />}
              <span className="text-xs font-extrabold">
                {simulatedResult.is_malicious ? simulatedResult.threat_name : 'File is Clean — No Threats Detected'}
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div><span className="text-slate-500 font-sans block text-[10px] uppercase font-bold">MD5</span><span className="font-bold truncate block">{simulatedResult.md5_hash?.slice(0, 14)}...</span></div>
              <div><span className="text-slate-500 font-sans block text-[10px] uppercase font-bold">Entropy</span><span className="font-bold">{simulatedResult.entropy_score}/8.0</span></div>
              <div><span className="text-slate-500 font-sans block text-[10px] uppercase font-bold">Size</span><span className="font-bold">{simulatedResult.size_bytes} B</span></div>
              <div><span className="text-slate-500 font-sans block text-[10px] uppercase font-bold">Risk Score</span><span className="font-bold">{simulatedResult.risk_score}/10</span></div>
            </div>
          </div>
        )}
      </div>

      {/* Downloads Table */}
      <div className="neu-flat rounded-[28px] p-6 overflow-hidden">
        <div className="pb-4 border-b border-slate-300/40 flex items-center justify-between">
          <div>
            <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">Live Downloads Stream</h3>
            <p className="text-[11px] text-slate-500 font-medium mt-0.5">Host Downloads directory — auto-screened every 5s</p>
          </div>
          <span className="text-[11px] text-[#2563eb] font-mono font-bold flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 animate-pulse" />
            Live
          </span>
        </div>

        <div className="overflow-x-auto mt-2">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[10px] text-slate-500 uppercase border-b border-slate-300/40 font-bold">
                <th className="text-left py-3 px-4">Status</th>
                <th className="text-left py-3 px-4">Filename</th>
                <th className="text-left py-3 px-4">Size</th>
                <th className="text-left py-3 px-4">Entropy</th>
                <th className="text-left py-3 px-4">MD5 Hash</th>
                <th className="text-left py-3 px-4">Policy</th>
                <th className="text-left py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/50 font-mono">
              {filesList.map((f, i) => (
                <tr key={i} className={`transition-colors hover:bg-slate-200/40 ${f.is_malicious ? 'bg-rose-100/40' : ''}`}>
                  <td className="py-3 px-4">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold flex items-center gap-1 w-max ${
                      f.is_malicious && f.is_harmful 
                        ? 'bg-rose-100 text-rose-800 border border-rose-200' 
                        : f.ai_status === 'BENIGN_VERIFIED' 
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                          : f.is_preexisting 
                            ? 'bg-slate-100 text-slate-700 border border-slate-200' 
                            : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    }`}>
                      {f.is_malicious && f.is_harmful ? (
                        <>
                          <XCircle className="w-3 h-3 text-rose-600" />
                          CONFIRMED THREAT
                        </>
                      ) : f.ai_status === 'BENIGN_VERIFIED' ? (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                          ATRIA VERIFIED SAFE
                        </>
                      ) : f.is_preexisting ? (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-slate-500" />
                          PRE-EXISTING SAFE
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                          CLEAN
                        </>
                      )}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`font-bold ${f.is_malicious ? 'text-rose-900' : 'text-slate-900'}`}>{f.filename}</span>
                    {f.threat_name && f.threat_name !== 'None' && (
                      <span className="block text-[10px] text-rose-700 font-sans font-medium">{f.threat_name}</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-slate-700 font-medium">
                    {f.size_bytes > 1048576
                      ? `${(f.size_bytes / 1048576).toFixed(2)} MB`
                      : `${(f.size_bytes / 1024).toFixed(1)} KB`}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`font-bold ${f.entropy_score > 7.4 ? 'text-rose-700' : 'text-slate-800'}`}>
                      {f.entropy_score}/8.0
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5 text-slate-700">
                      <span className="truncate max-w-[100px]">{f.md5_hash}</span>
                      <button onClick={() => handleCopy(f.md5_hash)} className="text-slate-400 hover:text-[#2563eb] transition-colors">
                        {copiedHash === f.md5_hash ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                      f.policy_status === 'BLOCKED & QUARANTINED' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                      f.policy_status === 'ALLOWED BY ANALYST'   ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                      f.is_malicious                             ? 'bg-amber-50 text-amber-800 border border-amber-200' :
                      'bg-slate-100 text-slate-700 border border-slate-200'
                    }`}>
                      {f.policy_status || (f.is_malicious ? 'PENDING' : 'ALLOWED')}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {f.is_malicious ? (
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => handlePolicyAction(f.filename, 'block', f.md5_hash)}
                          className="px-2.5 py-1 rounded-xl bg-rose-600 hover:bg-rose-700 text-white font-bold text-[10px] transition-all shadow-sm"
                        >Block</button>
                        <button
                          onClick={() => handlePolicyAction(f.filename, 'allow', f.md5_hash)}
                          className="neu-button px-2.5 py-1 rounded-xl text-slate-700 font-bold text-[10px] transition-all"
                        >Allow</button>
                      </div>
                    ) : (
                      <span className="text-[11px] text-slate-500 font-medium">Verified Safe</span>
                    )}
                  </td>
                </tr>
              ))}
              {filesList.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-500 font-sans font-medium text-xs">
                    No files found in Downloads directory. Any new file will appear and be scanned automatically.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  );
}

