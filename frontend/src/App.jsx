import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet, useLocation } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import AlarmBanner from './components/AlarmBanner';
import SplashScreen from './components/SplashScreen';
import { AnimatePresence, motion } from 'framer-motion';

import Dashboard from './pages/Dashboard';
import LiveMonitor from './pages/LiveMonitor';
import SystemNetworkTopology from './pages/SystemNetworkTopology';
import FileDownloadScanner from './pages/FileDownloadScanner';
import AIDecisionCenter from './pages/AIDecisionCenter';
import AttackLab from './pages/AttackLab';
import WebAuditor from './pages/WebAuditor';
import Datasets from './pages/Datasets';
import Models from './pages/Models';
import Alerts from './pages/Alerts';
import AlertDetails from './pages/AlertDetails';
import Evaluation from './pages/Evaluation';
import Settings from './pages/Settings';

function AnimatedLayout({ activeAlarm, onDismissAlarm }) {
  const location = useLocation();

  return (
    <div className="flex h-screen w-full text-slate-900 flex-col bg-[#eaf1ed] antialiased selection:bg-blue-600 selection:text-white relative overflow-hidden">
      {/* Subtle very light green ambient aura behind the UI components */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-[12%] -left-[8%] w-[55vw] h-[55vw] rounded-full bg-emerald-200/40 blur-[130px]" />
        <div className="absolute top-[28%] -right-[10%] w-[48vw] h-[48vw] rounded-full bg-teal-200/30 blur-[140px]" />
        <div className="absolute -bottom-[15%] left-[20%] w-[58vw] h-[58vw] rounded-full bg-emerald-100/45 blur-[150px]" />
      </div>

      <AlarmBanner activeAlarm={activeAlarm} onDismiss={onDismissAlarm} />
      <div className="flex flex-1 min-h-0 w-full overflow-hidden bg-transparent relative z-10">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden bg-transparent">
          <Navbar />
          <main className="flex-1 min-h-0 p-5 lg:p-6 overflow-y-auto scroll-smooth bg-transparent">
            <AnimatePresence mode="wait">
              <motion.div
                key={location.pathname}
                initial={{ opacity: 0, y: 8, filter: 'blur(4px)' }}
                animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
                exit={{ opacity: 0, y: -8, filter: 'blur(4px)' }}
                transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                className="w-full"
              >
                <Outlet />
              </motion.div>
            </AnimatePresence>
          </main>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [activeAlarm, setActiveAlarm] = useState(null);
  const [showSplash, setShowSplash] = useState(true);

  return (
    <AuthProvider>
      <AnimatePresence>
        {showSplash && (
          <SplashScreen onComplete={() => setShowSplash(false)} />
        )}
      </AnimatePresence>

      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          {/* No login required: directly redirect /login to /dashboard */}
          <Route path="/login" element={<Navigate to="/dashboard" replace />} />

          <Route
            element={
              <ProtectedRoute>
                <AnimatedLayout
                  activeAlarm={activeAlarm}
                  onDismissAlarm={() => setActiveAlarm(null)}
                />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard"       element={<Dashboard onTriggerAlarm={setActiveAlarm} />} />
            <Route path="/live-monitor"    element={<LiveMonitor onTriggerAlarm={setActiveAlarm} />} />
            <Route path="/topology"        element={<SystemNetworkTopology />} />
            <Route path="/malware-scanner" element={<FileDownloadScanner onTriggerAlarm={setActiveAlarm} />} />
            <Route path="/web-auditor"     element={<WebAuditor />} />
            <Route path="/ai-decision"     element={<AIDecisionCenter />} />
            <Route path="/attack-lab"      element={<AttackLab onTriggerAlarm={setActiveAlarm} />} />
            <Route path="/datasets"        element={<Navigate to="/ai-decision" replace />} />
            <Route path="/models"          element={<Models />} />
            <Route path="/alerts"          element={<Alerts />} />
            <Route path="/alerts/:id"      element={<AlertDetails />} />
            <Route path="/evaluation"      element={<Navigate to="/ai-decision" replace />} />
            <Route path="/settings"        element={<Settings />} />
          </Route>

          <Route path="/"  element={<Navigate to="/dashboard" replace />} />
          <Route path="*"  element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
