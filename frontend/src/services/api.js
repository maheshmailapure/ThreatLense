import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request Interceptor: Attach JWT Token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ids_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => Promise.reject(error));

// Response Interceptor: Handle 401 Unauthorized
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      if (window.location.pathname !== '/login') {
        localStorage.removeItem('ids_token');
        localStorage.removeItem('ids_user');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// Auth APIs
export const login = async (username, password) => {
  const response = await api.post('/api/auth/login', { username, password });
  return response.data;
};

export const getCurrentUser = async () => {
  const response = await api.get('/api/auth/me');
  return response.data;
};

// Dataset APIs
export const uploadDataset = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await api.post('/api/datasets/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
};

export const getDatasets = async () => {
  const response = await api.get('/api/datasets');
  return response.data;
};

export const getDataset = async (id) => {
  const response = await api.get(`/api/datasets/${id}`);
  return response.data;
};

export const getDatasetPreview = async (id, limit = 15) => {
  const response = await api.get(`/api/datasets/${id}/preview?limit=${limit}`);
  return response.data;
};

export const deleteDataset = async (id) => {
  const response = await api.delete(`/api/datasets/${id}`);
  return response.data;
};

// Model APIs
export const trainModels = async (trainConfig) => {
  const response = await api.post('/api/models/train', trainConfig);
  return response.data;
};

export const getModels = async () => {
  const response = await api.get('/api/models');
  return response.data;
};

export const getModel = async (id) => {
  const response = await api.get(`/api/models/${id}`);
  return response.data;
};

// Detection APIs
export const runDetection = async (datasetId, modelName, limit = 1000) => {
  const response = await api.post('/api/detection/run', {
    dataset_id: datasetId,
    model_name: modelName,
    limit: limit,
  });
  return response.data;
};

export const getDetectionResults = async (params = {}) => {
  const response = await api.get('/api/detection/results', { params });
  return response.data;
};

export const getDetectionById = async (id) => {
  const response = await api.get(`/api/detection/results/${id}`);
  return response.data;
};

export const exportDetectionCsvUrl = () => {
  const token = localStorage.getItem('ids_token');
  return `/api/detection/export${token ? `?token=${token}` : ''}`;
};

// Alerts APIs
export const getAlerts = async (params = {}) => {
  const response = await api.get('/api/alerts', { params });
  return response.data;
};

export const getAlert = async (id) => {
  const response = await api.get(`/api/alerts/${id}`);
  return response.data;
};

export const updateAlertStatus = async (id, status) => {
  const response = await api.put(`/api/alerts/${id}/status`, { status });
  return response.data;
};

// Dashboard APIs
export const getDashboardStats = async () => {
  const response = await api.get('/api/dashboard/stats');
  return response.data;
};

export const getDashboardCharts = async () => {
  const response = await api.get('/api/dashboard/charts');
  return response.data;
};

// Evaluation APIs
export const compareModels = async () => {
  const response = await api.get('/api/evaluation/compare');
  return response.data;
};

export const getModelEvaluation = async (modelName) => {
  const response = await api.get(`/api/evaluation/${encodeURIComponent(modelName)}`);
  return response.data;
};

// Simulation APIs
export const startSimulation = async (config = {}) => {
  const response = await api.post('/api/simulation/start', config);
  return response.data;
};

export const stopSimulation = async () => {
  const response = await api.post('/api/simulation/stop');
  return response.data;
};

export const getSimulationStatus = async () => {
  const response = await api.get('/api/simulation/status');
  return response.data;
};

// Live Host & Network Monitor APIs
export const getSystemTelemetry = async () => {
  const response = await api.get('/api/live-monitor/telemetry');
  return response.data;
};

export const scanHostNetwork = async (maxConnections = 50) => {
  const response = await api.get(`/api/live-monitor/scan?max_connections=${maxConnections}`);
  return response.data;
};

export const testAttackScenario = async (payload) => {
  const response = await api.post('/api/live-monitor/test-attack', payload);
  return response.data;
};

// Atria AI Cloud Threat Detection & Incident APIs
export const getAtriaConfig = async () => {
  const response = await api.get('/api/ai-decision/status');
  return response.data;
};
export const getAIDecisionStatus = getAtriaConfig;

export const testAtriaGateway = async () => {
  const response = await api.post('/api/ai-decision/test-atria');
  return response.data;
};

export const updateAtriaTraining = async (systemPrompt, rules) => {
  const response = await api.post('/api/ai-decision/train-rules', {
    system_prompt: systemPrompt,
    rules: rules
  });
  return response.data;
};

export const detectTelemetryWithAtria = async (telemetry) => {
  const response = await api.post('/api/ai-decision/detect-telemetry', { telemetry });
  return response.data;
};

export const getOllamaConfig = async () => {
  const response = await api.get('/api/ai-decision/config');
  return response.data;
};

export const updateOllamaConfig = async (config) => {
  const response = await api.post('/api/ai-decision/config', config);
  return response.data;
};

export const testOllamaGateway = async (config) => {
  const response = await api.post('/api/ai-decision/test-atria');
  return response.data;
};

export const analyzeIncidentWithAI = async (payload) => {
  const response = await api.post('/api/ai-decision/analyze-incident', payload);
  return response.data;
};

// Live System Containment & Trigger Actions
export const containBlockIP = async ({ ip, rule_name, alert_id }) => {
  const response = await api.post('/api/ai-decision/contain/block-ip', { ip, rule_name, alert_id });
  return response.data;
};

export const containBlockPort = async ({ port, protocol, rule_name, alert_id }) => {
  const response = await api.post('/api/ai-decision/contain/block-port', { port, protocol, rule_name, alert_id });
  return response.data;
};

export const containKillProcess = async ({ pid, process_name, alert_id }) => {
  const response = await api.post('/api/ai-decision/contain/kill-process', { pid, process_name, alert_id });
  return response.data;
};

export const containQuarantineFile = async ({ filepath, alert_id }) => {
  const response = await api.post('/api/ai-decision/contain/quarantine-file', { filepath, alert_id });
  return response.data;
};

export const wakeAIOnDemand = async ({ incident_data, alert_id }) => {
  const response = await api.post('/api/ai-decision/wake-ai', { incident_data, alert_id });
  return response.data;
};

// Attack Testing Lab APIs
export const getAttackScenarios = async () => {
  const response = await api.get('/api/attack-lab/scenarios');
  return response.data;
};

export const simulateAttack = async (payload) => {
  const response = await api.post('/api/attack-lab/simulate', payload);
  return response.data;
};

// Advanced SOC Operations APIs
export const getKillChainData = async () => {
  const response = await api.get('/api/advanced-soc/kill-chain');
  return response.data;
};

export const getUEBAData = async () => {
  const response = await api.get('/api/advanced-soc/ueba');
  return response.data;
};

export const getEncryptedTrafficData = async () => {
  const response = await api.get('/api/advanced-soc/encrypted-traffic');
  return response.data;
};

export const getPlaybooks = async () => {
  const response = await api.get('/api/advanced-soc/playbooks');
  return response.data;
};

export const executePlaybook = async (payload) => {
  const response = await api.post('/api/advanced-soc/playbooks/execute', payload);
  return response.data;
};

// Web & IP Defensive Security Auditor APIs
export const scanTargetWeb = async (target) => {
  const response = await api.post('/api/web-auditor/scan', { target });
  return response.data;
};

// System & Network Deep Analysis APIs
export const getSystemHardwareOverview = async () => {
  const response = await api.get('/api/system-network/overview');
  return response.data;
};

export const getOpenListeningPorts = async () => {
  const response = await api.get('/api/system-network/open-ports');
  return response.data;
};

export const getLiveTrafficFlows = async (maxFlows = 60) => {
  const response = await api.get(`/api/system-network/traffic-flows?max_flows=${maxFlows}`);
  return response.data;
};

export const getNetworkInterfacesDetail = async () => {
  const response = await api.get('/api/system-network/interfaces');
  return response.data;
};

// Automatic System Download Watcher APIs
export const getDownloadWatcherStatus = async () => {
  const response = await api.get('/api/file-scanner/watcher-status');
  return response.data;
};

export const scanRealSystemDownloads = async () => {
  const response = await api.post('/api/file-scanner/scan-downloads');
  return response.data;
};

export const toggleDownloadWatcher = async (enabled) => {
  const response = await api.post('/api/file-scanner/toggle-watcher', { enabled });
  return response.data;
};

export const scanCustomTextPayload = async (filename, content, sourceUrl) => {
  const response = await api.post('/api/file-scanner/scan-text', {
    filename,
    content,
    source_url: sourceUrl
  });
  return response.data;
};

export const executePolicyDecision = async (filename, action, md5Hash) => {
  const response = await api.post('/api/file-scanner/policy-decision', {
    filename,
    action,
    md5_hash: md5Hash
  });
  return response.data;
};

export default api;
